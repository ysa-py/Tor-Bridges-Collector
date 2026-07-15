"""
portkey_model_registry.py — Portkey Dynamic Model Discovery via Probing
========================================================================

Discovers working Portkey models by probing the Portkey API with a short
test request. Caches per (api_key_hash, gateway_url) for 2 hours.

This solves BUG-1 (P0 CRITICAL): Portkey HTTP 400 on ALL 3 slots because
the model resolver passes @cf/ model names that Portkey cannot handle.
Instead of guessing, this module PROBES the Portkey API to find models
that actually work with the user's Portkey key configuration.

NON-DESTRUCTIVE: New standalone module. Existing code untouched.
Version: 1.0.0 (Feature-3 / Fix-19.0)
"""

import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.request

logger = logging.getLogger("torshield.ai.portkey_registry")


# ── Models most likely to work with Portkey's free tier / virtual keys ────────

PORTKEY_MODEL_PROBE_LIST = [
    # Groq (fast, free tier friendly via Portkey virtual keys):
    "llama-3.3-70b-versatile",
    "llama-3.1-70b-versatile",
    "llama-3.1-8b-instant",
    "meta-llama/llama-3.3-70b-instruct",
    # Together AI:
    "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
    # Standard Portkey models:
    "meta/llama-3.1-70b-instruct",
    "meta/llama-3.1-8b-instruct",
    # If user has PORTKEY_PROVIDER_KEY (Groq/OpenAI key etc.):
    "gpt-4o-mini",
    "claude-3-haiku-20240307",
    "gemini-1.5-flash-8b",
    "mistral-7b-instruct",
    "gpt-3.5-turbo",
]

# Models that are always safe to try (no @cf/ prefix, no workers-ai/)
PORTKEY_SAFE_FALLBACKS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "meta/llama-3.1-70b-instruct",
    "gpt-4o-mini",
]


class PortkeyModelRegistry:
    """
    Discovers working Portkey models by probing.
    Caches per (api_key_hash, gateway_url) for 2 hours.

    This is the BUG-1 fix for Portkey: instead of sending @cf/ models
    that always 400, we probe the API to find a model that works.
    """

    _cache: dict[str, tuple[float, str | None]] = {}
    _lock = threading.RLock()
    CACHE_TTL = 7200  # 2 hours

    def _build_probe_headers(self, api_key: str, provider_key: str = "") -> dict:
        """Build Portkey authentication headers for probing."""
        headers = {"Content-Type": "application/json"}

        if api_key.startswith("pk-"):
            headers["x-portkey-api-key"] = api_key
        elif api_key.startswith("sk-"):
            headers["Authorization"] = f"Bearer {api_key}"
            headers["x-portkey-provider"] = "openai"
        else:
            # Generic key — try both headers
            headers["x-portkey-api-key"] = api_key
            headers["Authorization"] = f"Bearer {api_key}"

        # If a provider key is available, add provider routing
        # FEATURE-D1: Auto-detect provider from key format
        if provider_key:
            detected_provider = self._detect_provider_from_key(provider_key)
            headers["x-portkey-provider"] = detected_provider
            headers["Authorization"] = f"Bearer {provider_key}"

        return headers

    @staticmethod
    def _detect_provider_from_key(key: str) -> str:
        """Detect the Portkey provider name from the API key format."""
        key_lower = key.lower()
        if key_lower.startswith("sk-ant-"):
            return "anthropic"
        elif key_lower.startswith("sk-") and len(key) > 40:
            return "openai"
        elif key_lower.startswith("gsk_"):
            return "groq"
        elif key_lower.startswith("cerebras"):
            return "cerebras"
        elif "together" in key_lower:
            return "together-ai"
        elif "mistral" in key_lower:
            return "mistral"
        elif "cohere" in key_lower:
            return "cohere"
        # Default to cerebras (most common in TorShield CI)
        return "cerebras"

    def _probe_model(
        self,
        gateway_url: str,
        headers: dict,
        model_id: str,
        timeout: int = 8,
    ) -> str | None:
        """
        Probe a single model against the Portkey API.
        Returns model_id if HTTP 200, None otherwise.
        Never raises exceptions — all errors are caught and logged.
        """
        url = f"{gateway_url.rstrip('/')}/chat/completions"
        payload = json.dumps({
            "model": model_id,
            "messages": [{"role": "user", "content": "1+1=?"}],
            "max_tokens": 5,
        }).encode("utf-8")

        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    return model_id
        except urllib.error.HTTPError as e:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.portkey_model_registry:142', e)
            if e.code == 400:
                logger.debug(f"[PortkeyRegistry] Probe {model_id} -> 400 (unsupported)")
            elif e.code == 401:
                logger.debug(f"[PortkeyRegistry] Probe {model_id} -> 401 (needs BYOK key)")
            elif e.code == 404:
                logger.debug(f"[PortkeyRegistry] Probe {model_id} -> 404 (not found)")
            else:
                logger.debug(f"[PortkeyRegistry] Probe {model_id} -> HTTP {e.code}")
        except Exception as e:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.portkey_model_registry:151', e)
            logger.debug(f"[PortkeyRegistry] Probe {model_id} -> error: {e}")

        return None

    def get_working_model(
        self,
        api_key: str,
        gateway_url: str,
        provider_key: str = "",
    ) -> str | None:
        """
        Discover a working Portkey model by probing.
        Returns the first model from probe list that returns HTTP 200.
        Returns None only if ALL models fail (slot should be skipped gracefully).
        """
        # Check cache first
        cache_key = f"{hash(api_key)}:{hash(gateway_url)}"
        with self._lock:
            if cache_key in self._cache:
                ts, model = self._cache[cache_key]
                if time.time() - ts < self.CACHE_TTL:
                    if model:
                        logger.debug(
                            f"[PortkeyRegistry] Cached working model: {model}"
                        )
                    return model

        # Build headers
        headers = self._build_probe_headers(api_key, provider_key)

        # Probe each model
        for model_id in PORTKEY_MODEL_PROBE_LIST:
            result = self._probe_model(gateway_url, headers, model_id)
            if result:
                logger.info(
                    f"[PortkeyRegistry] Working model found: {model_id}"
                )
                with self._lock:
                    self._cache[cache_key] = (time.time(), model_id)
                return model_id

        logger.warning(
            "[PortkeyRegistry] No working model found for this key. "
            "Hint: Add PORTKEY_PROVIDER_KEY (Groq/Together API key) "
            "or configure virtual keys at portkey.ai/dashboard"
        )
        with self._lock:
            self._cache[cache_key] = (time.time(), None)
        return None

    def get_safe_model(self, requested_model: str = "") -> str:
        """
        Return a Portkey-safe model ID. Never returns @cf/ or workers-ai/ models.
        This is a fast synchronous fallback that doesn't probe — just replaces
        CF model IDs with safe equivalents.
        """
        # If PORTKEY_HEALTH_MODEL is set and not empty, use it
        env_model = os.environ.get("PORTKEY_HEALTH_MODEL", "").strip()
        if env_model and not env_model.startswith("@cf/") and not env_model.startswith("workers-ai/"):
            return env_model

        # If model is already Portkey-safe, use it
        if requested_model and not requested_model.startswith("@cf/") and not requested_model.startswith("workers-ai/"):
            return requested_model

        # Return first safe fallback
        return PORTKEY_SAFE_FALLBACKS[0]


# ── Singleton instance ────────────────────────────────────────────────────────

_registry_instance: PortkeyModelRegistry | None = None
_registry_lock = threading.Lock()


def get_portkey_registry() -> PortkeyModelRegistry:
    """Get or create the singleton PortkeyModelRegistry instance."""
    global _registry_instance
    with _registry_lock:
        if _registry_instance is None:
            _registry_instance = PortkeyModelRegistry()
        return _registry_instance
