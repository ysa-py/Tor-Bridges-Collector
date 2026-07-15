#!/usr/bin/env python3
"""
model_selector_v3.py — Drop-in replacement for torshield.ai.model_selector
Integrates DynamicModelBrainV3 into the existing health-check flow.

USAGE in ai_gateway_health_check.py:
  # OLD:
  from torshield.ai.model_selector import ModelSelector
  # NEW:
  from scripts.model_selector_v3 import ModelSelectorV3 as ModelSelector
"""


import asyncio
import logging
import os

from torshield_ai_gateway.dynamic_brain_v3 import (
    CF_GATEWAY_BLACKLIST,
    DynamicModelBrainV3,
)

logger = logging.getLogger("torshield.ai.model_selector_v3")


# ═══════════════════════════════════════════════════════════════════════
# Score table for display (matches engineering prompt priorities)
# ═══════════════════════════════════════════════════════════════════════
SCORE_OVERRIDE: dict[str, float] = {
    "@cf/moonshotai/kimi-k2.6":                    120.0,
    "@cf/openai/gpt-oss-120b":                      95.0,
    "@cf/nvidia/nemotron-3-120b-a12b":              90.0,
    "@cf/meta/llama-4-scout-17b-16e-instruct":      88.0,
    "@cf/zai-org/glm-4.7-flash":                    85.0,
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b": 78.0,
    "@cf/qwen/qwq-32b":                             75.0,
    "@cf/meta/llama-3.1-70b-instruct":              62.0,
    # Deprecated via AI Gateway — kept for score reference only
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast":    30.0,  # BLACKLISTED
}


class ModelSelectorV3:
    """
    Smart model selector backed by DynamicModelBrainV3.
    Fetches live model lists, scores, probes, and returns the best
    verified-working model for your task.
    """

    def __init__(self, brain: DynamicModelBrainV3 | None = None):
        self._brain = brain or DynamicModelBrainV3.from_env()
        self._initialized = False

    async def initialize(
        self,
        probe_url: str | None = None,
        task: str = "fast",
        top_k_probe: int = 5,
    ) -> None:
        """
        Async init — fetches live model list and probes top candidates.
        Call once at startup.
        """
        logger.info("[ModelSelector] Fetching live model list with probe verification…")
        await self._brain.refresh(
            probe_cf_gateway_url=probe_url,
            top_k_probe=top_k_probe,
        )
        self._initialized = True
        best = self._brain.get_best()
        if best:
            logger.info(
                f"[ModelSelector] Live fetch: {len(self._brain._registry)} models"
            )
            logger.info(
                f"[ModelSelector] Selected [{task}]: {best.name} "
                f"(score={best.score})"
            )
        else:
            logger.warning("[ModelSelector] WARNING: No available model found!")

    def get_model(self, task: str = "fast") -> str | None:
        """Return the best model name for the given task."""
        m = self._brain.get_for_task(task)
        return m.name if m else None

    def get_top_models(self, n: int = 5) -> list[tuple[str, float, int]]:
        """Return top N models as (name, score, tier) tuples."""
        return [
            (m.name, m.score, m.tier)
            for m in self._brain.top_n(n)
        ]

    def is_model_blacklisted(self, model_name: str) -> bool:
        return model_name in CF_GATEWAY_BLACKLIST

    def log_top_models(self, n: int = 5) -> None:
        for i, m in enumerate(self._brain.top_n(n), 1):
            score = SCORE_OVERRIDE.get(m.name, m.score)
            logger.info(
                f"[ModelSelector]   #{i} {m.name} "
                f"score={score} tier={m.tier}"
            )


# ═══════════════════════════════════════════════════════════════════════
# PATCH: fixes for health_check.py integration
# ═══════════════════════════════════════════════════════════════════════
"""
HOW TO INTEGRATE INTO ai_gateway_health_check.py
─────────────────────────────────────────────────

1. Replace ModelSelector import:

   # OLD:
   from torshield.ai.model_selector import ModelSelector
   selector = ModelSelector()
   
   # NEW (add at top of file):
   from scripts.model_selector_v3 import ModelSelectorV3
   selector = ModelSelectorV3()

2. In your Step 2 (Model Selector check), change to async init:

   # OLD:
   top_model = selector.get_top_model(task=task)
   
   # NEW:
   first_cf_gw_url = os.environ.get("CF_AI_GATEWAY_URL_1")  # probe slot 1
   await selector.initialize(probe_url=first_cf_gw_url, task=task)
   top_model = selector.get_model(task=task)
   
   # Skip blacklisted models immediately:
   if top_model and selector.is_model_blacklisted(top_model):
       logger.warning(f"Top model {top_model} is blacklisted, using next best")
       top_model = selector.get_model("reasoning")  # fallback

3. In cloudflare_ai_gateway provider, before each slot:

   # Skip if model returned 400 on ANY slot previously (model-level bug)
   if model_name in blacklisted_this_run:
       logger.warning(f"Skipping {model_name} — blacklisted this run")
       model_name = selector.get_model("fast")  # get next best

4. Add to CF_GATEWAY_BLACKLIST in dynamic_brain_v3.py if new 400s appear:

   CF_GATEWAY_BLACKLIST.add("@cf/new-broken-model-id")
"""


# ═══════════════════════════════════════════════════════════════════════
# ROOT CAUSE ANALYSIS — from health_check log June 13 2026
# ═══════════════════════════════════════════════════════════════════════
"""
ISSUE 1: dynamic_brain — CF fetch returns 0 models (HTTP 403)
  Root cause: CF_API_TOKEN_{n} tokens lack "Workers AI:Read" permission
  Fix: DynamicModelBrainV3 falls back to curated static registry (CF_STATIC_REGISTRY)
  Action needed: Add Workers AI read scope to CF API tokens in GitHub Secrets

ISSUE 2: cloudflare_ai_gateway — ALL 11 slots HTTP 400 BAD_REQUEST
  Root cause: @cf/meta/llama-3.3-70b-instruct-fp8-fast is DEPRECATED via AI Gateway
  Evidence: 66 × HTTP 400 across all slots — model-level failure, not slot-level
  Fix: Model added to CF_GATEWAY_BLACKLIST → probe skips it → kimi-k2.6 selected
  Action needed: Remove llama-3.3-70b from selector scoring, never use via AI Gateway

ISSUE 3: portkey — all 3 slots HTTP 400
  Root cause: PORTKEY_HEALTH_MODEL env var is empty (see log: PORTKEY_HEALTH_MODEL=)
  Fix: Set PORTKEY_HEALTH_MODEL=claude-sonnet-4-6 or gpt-4o-mini in GitHub Secrets
  Fallback: brain will auto-select from PORTKEY_STATIC_REGISTRY

ISSUE 4: Brain shows 0 CF, 0 Portkey models
  Root cause: Both 403 (CF) + Portkey env empty → falls back to static registry
  Fix: DynamicModelBrainV3 starts from static registry → always ≥13 CF models

RESULT AFTER FIXES:
  cerebras       → ✓ OK (already works)
  cloudflare_ai_gateway → ✓ kimi-k2.6 or gpt-oss-120b (after blacklist)
  cloudflare_workers_ai → ✓ OK (already works)
  portkey        → ✓ claude-sonnet-4-6 (after PORTKEY_HEALTH_MODEL fix)
"""

if __name__ == "__main__":
#     import asyncio  # disabled: redundant redefinition (F811)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-8s %(message)s")

    async def test():
        sel = ModelSelectorV3()
        probe_url = os.environ.get("CF_AI_GATEWAY_URL_1")
        await sel.initialize(probe_url=probe_url, task="fast")
        print(f"\nBest model (fast): {sel.get_model('fast')}")
        print(f"Best model (reasoning): {sel.get_model('reasoning')}")
        print("\nTop 5 models:")
        sel.log_top_models(5)

    asyncio.run(test())
