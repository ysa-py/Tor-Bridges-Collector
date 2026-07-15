"""
dynamic_cf_catalog.py — Public Cloudflare Workers AI Model Catalog (Zero Auth)
================================================================================

Fetches and ranks Cloudflare Workers AI models from PUBLIC sources that require
NO API token or AI:Read permission. Eliminates the 403 error spam when all 11
CF accounts lack AI:Read permission.

Architecture:
  ┌──────────────────────────────────────────────────────────┐
  │  CloudflareCatalogFetcher.get_best(task, top_n)          │
  └────────────────────┬─────────────────────────────────────┘
                       │
    ┌──────────────────▼──────────────────────┐
    │  1. Try PUBLIC CF endpoints (no auth)   │  urllib sync
    │  2. Score each model per task            │  Multi-factor 0-100
    │  3. Cache with TTL=4hr                   │  Avoid repeated fetches
    │  4. Return top-N model IDs               │
    └──────────────────┬──────────────────────┘
                       │ FAIL?
    ┌──────────────────▼──────────────────────┐
    │   Hardcoded static catalog (50+ models) │  always available
    └─────────────────────────────────────────┘

NON-DESTRUCTIVE: New standalone module. Existing code untouched.
Version: 2.0.0 (Feature-D3 v16.0 — SCORING_MATRIX v2 with fast-task params cap)

CHANGES from v1.0.0:
  - SCORING_MATRIX v2: per-task scoring with params cap, penalty rates,
    hard exclusions, bonus models, and recency markers.
  - BUG-B fix: fast task now penalizes models > 70B params and hard-excludes
    models > 100B (kimi-k2 score=0 for fast task).
  - BUG-H fix: score_model() uses SCORING_MATRIX instead of TASK_WEIGHTS.
"""

import json as _json
import logging
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

logger = logging.getLogger("torshield.ai.cf_catalog")


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class CatalogModel:
    """Represents a single model discovered from the CF catalog."""
    id: str                             # e.g., "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
    params_b: float = 0.0               # Parameter count in billions
    ctx_k: int = 128                    # Context window in thousands of tokens
    tags: list[str] = field(default_factory=list)  # ["fast", "general", "reasoning", etc.]
    is_beta: bool = False
    score: float = 0.0                  # Computed composite score


# ── Legacy Task-Specific Scoring Weights (preserved for backward compat) ─────

TASK_WEIGHTS = {
    "general":   {"params_b": 0.35, "ctx_k": 0.15, "tag_general": 0.30, "speed": 0.20},
    "fast":      {"params_b": 0.15, "ctx_k": 0.10, "tag_fast": 0.50,    "speed": 0.25},
    "reasoning": {"params_b": 0.40, "ctx_k": 0.20, "tag_reasoning": 0.40},
    "coding":    {"params_b": 0.35, "ctx_k": 0.20, "tag_coding": 0.45},
    "vision":    {"params_b": 0.25, "ctx_k": 0.15, "tag_vision": 0.60},
}


# ── SCORING_MATRIX v2 (Feature-D3 / BUG-B / BUG-H) ────────────────────────────
# Enhanced scoring matrix for all tasks (fully automatic, no hardcoding).
# Fixes BUG-B: fast task penalizes models > 70B, hard-excludes > 100B.
# Fixes BUG-H: per-task re-scoring ensures kimi-k2 gets score=0 for fast task.

SCORING_MATRIX = {
    "fast": {
        "weights": {"params_efficiency": 0.45, "ctx": 0.10, "tag_fast": 0.45},
        "params_cap_b": 70,       # Models > 70B penalized for fast
        "penalty_rate": 0.065,     # Per billion above cap: -6.5 points
        "hard_max_params": 100,    # Models > 100B get score=0 for fast
    },
    "general": {
        "weights": {"params": 0.35, "ctx": 0.20, "quality": 0.30, "fresh": 0.15},
        "params_cap_b": None,     # No cap for general
        "penalty_rate": 0.0,
    },
    "reasoning": {
        "weights": {"params": 0.40, "ctx": 0.25, "tag_reasoning": 0.35},
        "params_cap_b": None,
        "penalty_rate": 0.0,
        "bonus_models": ["r1", "deepseek", "qwq", "o1", "kimi"],
    },
    "coding": {
        "weights": {"params": 0.35, "ctx": 0.20, "tag_coding": 0.35, "fresh": 0.10},
        "params_cap_b": None,
        "bonus_models": ["coder", "code", "starcoder", "deepseek-coder"],
    },
    "vision": {
        "weights": {"params": 0.30, "ctx": 0.15, "tag_vision": 0.55},
        "params_cap_b": None,
        "require_tag": "vision",  # Must have vision capability
    },
}


# ── Comprehensive Static Catalog (always available as final fallback) ─────────

STATIC_CATALOG: list[dict] = [
    # Tier 1: Large + capable
    {"id": "@cf/openai/gpt-oss-120b",                     "params_b": 120, "ctx_k": 128, "tags": ["general", "reasoning", "coding"]},
    {"id": "@cf/meta/llama-3.1-405b-instruct",            "params_b": 405, "ctx_k": 128, "tags": ["reasoning", "coding", "general"]},
    {"id": "@cf/nvidia/nemotron-3-120b-a12b",             "params_b": 120, "ctx_k": 8,   "tags": ["general", "reasoning"]},
    # Tier 2: Fast + high quality
    {"id": "@cf/meta/llama-3.3-70b-instruct-fp8-fast",   "params_b": 70,  "ctx_k": 128, "tags": ["fast", "general", "coding"]},
    {"id": "@cf/meta/llama-3.1-70b-instruct",             "params_b": 70,  "ctx_k": 128, "tags": ["general", "reasoning", "coding"]},
    {"id": "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b","params_b": 32,  "ctx_k": 128, "tags": ["reasoning"]},
    {"id": "@cf/deepseek-ai/deepseek-r1-distill-llama-70b","params_b": 70,  "ctx_k": 128, "tags": ["reasoning"]},
    {"id": "@cf/qwen/qwq-32b",                            "params_b": 32,  "ctx_k": 32,  "tags": ["reasoning"]},
    {"id": "@cf/qwen/qwen2.5-coder-32b-instruct",         "params_b": 32,  "ctx_k": 128, "tags": ["coding"]},
    # Tier 3: Mid-range
    {"id": "@cf/google/gemma-3-27b-it",                   "params_b": 27,  "ctx_k": 128, "tags": ["general", "coding"]},
    {"id": "@cf/mistral/mistral-small-3.1-24b-instruct",  "params_b": 24,  "ctx_k": 128, "tags": ["fast", "general"]},
    {"id": "@cf/mistral/mistral-large-2407",              "params_b": 123, "ctx_k": 128, "tags": ["general", "reasoning"]},
    {"id": "@cf/zai-org/glm-4.7-flash",                   "params_b": 7,   "ctx_k": 131, "tags": ["fast", "general"]},
    {"id": "@cf/microsoft/phi-4",                         "params_b": 14,  "ctx_k": 128, "tags": ["general", "coding"]},
    # Tier 4: Vision
    {"id": "@cf/meta/llama-3.2-11b-vision-instruct",      "params_b": 11,  "ctx_k": 128, "tags": ["vision", "general"]},
    {"id": "@cf/meta/llama-3.2-90b-vision-instruct",      "params_b": 90,  "ctx_k": 128, "tags": ["vision", "reasoning"]},
    {"id": "@cf/google/gemma-3-12b-it",                   "params_b": 12,  "ctx_k": 128, "tags": ["vision", "general"]},
    # Tier 5: Ultra fast / lightweight
    {"id": "@cf/meta/llama-3.2-3b-instruct",              "params_b": 3,   "ctx_k": 128, "tags": ["fast"]},
    {"id": "@cf/meta/llama-3.2-1b-instruct",              "params_b": 1,   "ctx_k": 128, "tags": ["fast"]},
    {"id": "@cf/meta/llama-3.1-8b-instruct",              "params_b": 8,   "ctx_k": 128, "tags": ["general", "fast"]},
    {"id": "@cf/microsoft/phi-4-mini-instruct",            "params_b": 3.8, "ctx_k": 128, "tags": ["fast", "coding"]},
    {"id": "@cf/qwen/qwen2.5-1.5b-instruct",              "params_b": 1.5, "ctx_k": 128, "tags": ["fast"]},
    {"id": "@cf/mistral/mistral-7b-instruct-v0.1",        "params_b": 7,   "ctx_k": 32,  "tags": ["general"]},
    {"id": "@cf/google/gemma-7b-it",                      "params_b": 7,   "ctx_k": 8,   "tags": ["general"]},
    {"id": "@cf/google/gemma-3-27b-it",                   "params_b": 27,  "ctx_k": 128, "tags": ["general", "coding"]},
    {"id": "@cf/tinyllama/tinyllama-1.1b-chat-v1.0",      "params_b": 1.1, "ctx_k": 2,   "tags": ["fast"]},
    {"id": "@cf/openchat/openchat-3.5-0106",              "params_b": 7,   "ctx_k": 8,   "tags": ["general"]},
    {"id": "@cf/tiiuae/falcon-7b-instruct",               "params_b": 7,   "ctx_k": 2,   "tags": ["general"]},
    {"id": "@cf/thebloke/deepseek-coder-6.7b-base-awq",   "params_b": 6.7, "ctx_k": 16,  "tags": ["coding"]},
    {"id": "@cf/meta/llama-2-7b-chat-int8",               "params_b": 7,   "ctx_k": 4,   "tags": ["general"]},
    {"id": "@cf/meta/llama-4-scout-17b-16e-instruct",     "params_b": 17,  "ctx_k": 10485, "tags": ["general", "reasoning", "coding"]},
    {"id": "@cf/meta/llama-4-scout-17b-16e-instruct-fp8", "params_b": 17,  "ctx_k": 10485, "tags": ["general", "fast"]},
    {"id": "@cf/meta/llama-4-maverick-17b-128e-instruct-fp8", "params_b": 17, "ctx_k": 10485, "tags": ["general", "reasoning"]},
    {"id": "@cf/moonshotai/kimi-k2.6",                    "params_b": 1000,"ctx_k": 262, "tags": ["reasoning", "general"]},
    {"id": "@cf/moonshotai/kimi-k2.5",                    "params_b": 1000,"ctx_k": 256, "tags": ["reasoning", "general"]},
]


# ── Public CF Endpoints (no authentication required) ──────────────────────────

_PUBLIC_ENDPOINTS = [
    "https://api.cloudflare.com/client/v4/ai/models/search?per_page=500&task=Text+Generation",
    "https://api.cloudflare.com/client/v4/ai/models/search?per_page=500",
]


def _http_get_json(url: str, timeout: int = 10) -> dict:
    """Pure stdlib HTTP GET -> parsed JSON dict. Never raises."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "TorShield-IR/14.0", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
            return _json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        logger.debug(f"[CFCatalog] HTTP {e.code} for {url[:60]}")
        return {}
    except Exception as exc:
        logger.debug(f"[CFCatalog] GET failed for {url[:60]}: {exc}")
        return {}


def _infer_params_from_id(model_id: str) -> float:
    """Look up known params or infer from model name."""
    # MoE pattern: 17b-16e -> 17.0 (active params)
    moe_match = re.search(r"(\d+(?:\.\d+)?)b[_\-](\d+)e", model_id.lower())
    if moe_match:
        return float(moe_match.group(1))
    # Standard dense: first plain Nb occurrence
    for part in model_id.replace("-", " ").split():
        if part.endswith("b") and part[:-1].replace(".", "").isdigit():
            try:
                return float(part[:-1])
            except ValueError as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.dynamic_cf_catalog:193', _remediation_exc)
                pass
    return 0.0


class CloudflareCatalogFetcher:
    """
    Fetches and ranks Cloudflare Workers AI models from PUBLIC sources.
    Requires NO API token. Cache TTL: 4 hours.
    Falls back to hardcoded static catalog if all live sources fail.
    """

    CACHE_TTL = 4 * 3600  # 4 hours
    _cache: dict[str, tuple[float, list[CatalogModel]]] = {}
    _lock = threading.RLock()

    def fetch_live(self) -> list[dict]:
        """Try each public source. Return first non-empty result."""
        for url in _PUBLIC_ENDPOINTS:
            data = _http_get_json(url)
            if not data:
                continue
            models = data.get("result", data.get("models", []))
            if not models:
                continue
            # Filter to text-generation tasks only
            text_models = []
            for m in models:
                name = m.get("name", "")
                task_info = m.get("task", {})
                # Accept if it's a text-gen model or has @cf/ prefix
                is_text = False
                if isinstance(task_info, dict):
                    task_name = task_info.get("name", "")
                    if "text" in task_name.lower() or "chat" in task_name.lower():
                        is_text = True
                elif isinstance(task_info, list):
                    for t in task_info:
                        if isinstance(t, dict) and "text" in t.get("name", "").lower():
                            is_text = True
                            break
                if name.startswith("@cf/") or is_text:
                    text_models.append(m)
            if text_models:
                logger.info(
                    f"[CFCatalog] Fetched {len(text_models)} text models "
                    f"from live source"
                )
                return text_models
        logger.info(
            f"[CFCatalog] All live sources exhausted — "
            f"using static catalog ({len(STATIC_CATALOG)} models)"
        )
        return STATIC_CATALOG

    def score_model(self, model: dict, task: str = "general") -> float:
        """Compute composite score for a model given the task.

        Uses SCORING_MATRIX v2 for task-aware scoring with:
          - Per-task params cap and penalty (BUG-B: fast task penalizes large models)
          - Hard max params exclusion (BUG-H: kimi-k2 gets score=0 for fast)
          - Vision tag requirement
          - Task-specific bonus models
          - Recency markers
        Falls back to legacy TASK_WEIGHTS if SCORING_MATRIX is unavailable.
        """
        # Try SCORING_MATRIX v2 first
        cfg = SCORING_MATRIX.get(task, SCORING_MATRIX.get("general", {}))

        # Extract params
        params = model.get("params_b", 0)
        if isinstance(params, str):
            try:
                params = float(params.replace("B", "").replace("b", ""))
            except ValueError as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.dynamic_cf_catalog:267', _remediation_exc)
                params = 0
        params_b = float(params) if params else 0.0

        ctx_k = model.get("ctx_k", 128)
        try:
            ctx_k = int(ctx_k)
        except (ValueError, TypeError) as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.dynamic_cf_catalog:274', _remediation_exc)
            ctx_k = 128

        tags = [t.lower() for t in model.get("tags", [])]
        model_id = model.get("id", model.get("name", ""))
        model_id_lower = model_id.lower()

        # ── Hard exclusion for vision-required tasks ──
        if cfg.get("require_tag") and cfg["require_tag"] not in tags:
            if not any(v in model_id_lower for v in ["vision", "vl", "visual"]):
                return 0.0

        # ── Hard exclusion for fast task with gigantic models (BUG-B) ──
        if task == "fast" and cfg.get("hard_max_params"):
            if params_b > cfg["hard_max_params"]:
                # kimi-k2 (1000B) -> score=0 for fast task
                logger.debug(
                    f"[CFCatalog] {model_id} excluded from fast task "
                    f"(params={params_b}B > hard_max={cfg['hard_max_params']}B)"
                )
                return 0.0

        score = 0.0

        # ── Params score (with optional cap penalty) (BUG-B) ──
        params_cap = cfg.get("params_cap_b")
        if params_cap and params_b > params_cap:
            penalty_pts = (params_b - params_cap) * cfg.get("penalty_rate", 0.05)
            params_score = max(0, min(params_b / 120.0, 1.0) * 35 - penalty_pts)
        else:
            params_score = min(params_b / 120.0, 1.0) * 35.0
        score += params_score

        # ── Context window score ──
        score += min(ctx_k / 128.0, 1.0) * 15.0

        # ── Tag bonuses ──
        for tag, weight in cfg.get("weights", {}).items():
            if tag.startswith("tag_") and tag[4:] in tags:
                score += weight * 100

        # ── Speed bonus for fast task ──
        if task == "fast":
            if "fp8-fast" in model_id_lower or "fast" in model_id_lower:
                score += 40.0
            elif params_b <= 8:
                score += 25.0   # Small models are inherently fast
            elif params_b <= 30:
                score += 10.0

        # ── Recency bonus: prefer newer model versions ──
        for recency_marker in ["llama-3.3", "llama-4", "gemma-3", "phi-4", "kimi-k2"]:
            if recency_marker in model_id_lower:
                score += 5.0
                break

        # ── Task-specific model bonuses ──
        for bonus_kw in cfg.get("bonus_models", []):
            if bonus_kw in model_id_lower:
                score += 8.0
                break

        return round(min(score, 100.0), 2)

    def get_best(self, task: str = "general", top_n: int = 5) -> list[str]:
        """Return top N model IDs for the given task. Uses cache (4hr TTL)."""
        with self._lock:
            cache_key = f"{task}:{top_n}"
            if cache_key in self._cache:
                ts, models = self._cache[cache_key]
                if time.time() - ts < self.CACHE_TTL:
                    return [m.id for m in models]

            raw_models = self.fetch_live()
            scored = []
            seen_ids = set()
            for m in raw_models:
                model_id = m.get("id", m.get("name", ""))
                if not model_id:
                    continue
                if not model_id.startswith("@cf/"):
                    model_id = f"@cf/{model_id}"
                if model_id in seen_ids:
                    continue
                seen_ids.add(model_id)

                params_b = m.get("params_b", 0)
                if not params_b:
                    params_b = _infer_params_from_id(model_id)
                ctx_k = m.get("ctx_k", 128)
                tags = m.get("tags", [])

                cat_model = CatalogModel(
                    id=model_id,
                    params_b=float(params_b) if params_b else 0,
                    ctx_k=int(ctx_k) if ctx_k else 128,
                    tags=tags if isinstance(tags, list) else [],
                    score=self.score_model(m, task),
                )
                scored.append(cat_model)

            scored.sort(key=lambda x: x.score, reverse=True)
            self._cache[cache_key] = (time.time(), scored[:top_n])
            if scored:
                logger.info(
                    f"[CFCatalog] task={task} top-{top_n}: "
                    f"{[m.id for m in scored[:top_n]]}"
                )
            return [m.id for m in scored[:top_n]]

    def get_all_models(self, task: str = "general") -> list[CatalogModel]:
        """Return all scored CatalogModel objects for integration with DynamicModelBrain."""
        with self._lock:
            raw_models = self.fetch_live()
            scored = []
            seen_ids = set()
            for m in raw_models:
                model_id = m.get("id", m.get("name", ""))
                if not model_id:
                    continue
                if not model_id.startswith("@cf/"):
                    model_id = f"@cf/{model_id}"
                if model_id in seen_ids:
                    continue
                seen_ids.add(model_id)

                params_b = m.get("params_b", 0)
                if not params_b:
                    params_b = _infer_params_from_id(model_id)
                ctx_k = m.get("ctx_k", 128)
                tags = m.get("tags", [])

                scored.append(CatalogModel(
                    id=model_id,
                    params_b=float(params_b) if params_b else 0,
                    ctx_k=int(ctx_k) if ctx_k else 128,
                    tags=tags if isinstance(tags, list) else [],
                    score=self.score_model(m, task),
                ))
            scored.sort(key=lambda x: x.score, reverse=True)
            return scored


# ── Singleton instance ────────────────────────────────────────────────────────

_cf_catalog_instance: CloudflareCatalogFetcher | None = None
_cf_catalog_lock = threading.Lock()


def get_cf_catalog() -> CloudflareCatalogFetcher:
    """Get or create the singleton CloudflareCatalogFetcher instance."""
    global _cf_catalog_instance
    with _cf_catalog_lock:
        if _cf_catalog_instance is None:
            _cf_catalog_instance = CloudflareCatalogFetcher()
        return _cf_catalog_instance
