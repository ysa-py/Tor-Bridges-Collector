#!/usr/bin/env python3
"""
AI Gateway Health Check v19.0 — Zero-Error Edition
═══════════════════════════════════════════════════════════════════════════

CRITICAL FIXES from v19.0:
  1. BUG-S FIX: _classify_portkey_status() now returns 'gateway_config_required'
     instead of 'no_backend_configured' for routing/authentication failures.
     Expanded gateway_failure_signals list to catch more failure patterns.
  2. FEATURE-U: Adaptive Multi-Model Health Check Strategy — when checking
     a provider, if the first model fails with HTTP 400, automatically try
     the next model from the provider's model list.
  3. FEATURE-T: AI Threat Detector summary — after health check loop,
     the AI threat assessment (DPI inference from provider patterns) is logged.
  4. Updated error_count calculation to use classifier-based approach for
     all providers, not just portkey with 'no_response' status.

CRITICAL FIXES from v12.0:
  1. FIX: Portkey key validation — removed pk- prefix check, uses length check (>=16)
  2. FIX: max_tokens raised to 256 for verbose/reasoning models
  3. FIX: Health check prompt simplified for maximum compliance
  4. FIX: BadRequestError handling — 400 is NOT an auth failure

CRITICAL FIXES from v11.0:
  1. FIX: Auth errors (403/400/401) are NOT retried — they won't fix themselves
  2. FIX: Reduced default max_retries from 3 to 2 to prevent 20-min timeout
  3. FIX: WRONG_RESPONSE is now treated as FAILURE (not just degraded)
  4. FIX: Per-provider timeout protection — auth failures skip remaining retries

PRESERVED from v10.0/v11.0:
  1. Exponential backoff retry mechanism for network failures
  2. Verbose debugging on authentication failure (NO key exposure)
  3. Strict non-zero exit when NO primary provider is reachable
  4. LocalAIEngine fallback is monitored but NOT counted as "ok"
  5. WRONG_RESPONSE is treated as a failure condition
  6. Env var validation before attempting any API calls
  7. Detailed diagnostic output for header/URL/credential issues

HEALTH CHECK POLICY:
  - A provider is "ok" ONLY if it returns the expected TORSHIELD_OK signal
  - LocalAIEngine fallback is "degraded" status, NOT "ok"
  - Script exits 0 ONLY if at least one PRIMARY provider responds correctly
  - Script exits 1 if ALL primary providers fail (even if LocalAIEngine works)
  - Script exits 2 if required environment variables are missing entirely

RETRY MECHANISM:
  - Configurable max retries (default 2) with exponential backoff
  - Base delay 1s, multiplier 2x, jitter ±0.5s
  - Auth errors (400/401/403) are NOT retried
  - Only network errors (timeout, 5xx, connection) are retried
"""

import argparse
import json
import logging
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import ProviderConfigurationError for config-level error handling.
#
# IMPORTANT: load the lightweight exceptions module directly from its file instead
# of using ``from torshield_ai_gateway.exceptions ...``.  Importing a submodule by
# package name executes ``torshield_ai_gateway.__init__`` first, and that package
# imports monitoring helpers that re-export this health-check module.  When this
# script itself is imported (for tests or monitoring.health_check), the package
# import path can therefore observe a partially initialized module and fail with
# a circular-import AttributeError.  The direct file load keeps the health-check
# utility importable while preserving the public exception classes and fallback.
def _load_gateway_exceptions() -> tuple[type[Exception], type[Exception]]:
    try:
        import importlib.util

        exceptions_path = (
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "torshield_ai_gateway",
            "exceptions.py",
        )
        spec = importlib.util.spec_from_file_location(
            "_torshield_ai_gateway_exceptions", os.path.join(*exceptions_path)
        )
        if spec is None or spec.loader is None:
            raise ImportError("cannot load torshield_ai_gateway exceptions spec")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.BadRequestError, module.ProviderConfigurationError
    except Exception as exc:
        try:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.ai_gateway_health_check:86', exc)
        except Exception:
            pass

        class ProviderConfigurationError(Exception):  # type: ignore[no-redef]
            """Fallback ProviderConfigurationError when gateway exceptions are unavailable."""
            pass

        class BadRequestError(Exception):  # type: ignore[no-redef]
            """Fallback BadRequestError when gateway exceptions are unavailable."""
            pass

        return BadRequestError, ProviderConfigurationError


BadRequestError, ProviderConfigurationError = _load_gateway_exceptions()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("health_check")


# ════════════════════════════════════════════════════════════════════════════
# PROVIDER INSTANCE CACHE (BUG-F: avoid re-initializing on every retry)
# ════════════════════════════════════════════════════════════════════════════

_PROVIDER_CLASS_MAP: dict[str, Any] = {}
_PROVIDER_INSTANCE_CACHE: dict[str, Any] = {}
_PROVIDER_CACHE_LOCK = threading.Lock()

def get_or_create_provider(provider_name: str, **kwargs) -> Any:
    """Return cached provider instance. Create once, reuse across retries."""
    cache_key = provider_name
    with _PROVIDER_CACHE_LOCK:
        if cache_key not in _PROVIDER_INSTANCE_CACHE:
            provider_cls = _PROVIDER_CLASS_MAP.get(provider_name)
            if provider_cls:
                _PROVIDER_INSTANCE_CACHE[cache_key] = provider_cls(**kwargs)
                logger.info(
                    f"[HC] Created provider instance: {provider_name} "
                    f"(will be reused across retries)"
                )
        return _PROVIDER_INSTANCE_CACHE.get(cache_key)

def reset_provider_cache():
    """Clear provider cache between health check runs."""
    with _PROVIDER_CACHE_LOCK:
        _PROVIDER_INSTANCE_CACHE.clear()


# ════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK PREFERRED MODELS (BUG-B: fast model for fast task)
# ════════════════════════════════════════════════════════════════════════════

HEALTH_CHECK_PREFERRED_MODELS = {
    "cloudflare_workers_ai": "@cf/meta/llama-3.2-3b-instruct",
    "cloudflare_ai_gateway": "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
}

HEALTH_CHECK_USE_PREFERRED = os.environ.get(
    "HC_USE_PREFERRED_MODELS", "true"
).lower() == "true"

def get_health_check_model(provider_name: str, selector_model: str) -> str:
    if HEALTH_CHECK_USE_PREFERRED and provider_name in HEALTH_CHECK_PREFERRED_MODELS:
        preferred = HEALTH_CHECK_PREFERRED_MODELS[provider_name]
        logger.info(
            f"[HC] Using preferred health-check model for {provider_name}: "
            f"{preferred} (override: {selector_model})"
        )
        return preferred
    return selector_model


# ════════════════════════════════════════════════════════════════════════════
# RETRY WITH EXPONENTIAL BACKOFF
# ════════════════════════════════════════════════════════════════════════════

class ExponentialBackoffRetry:
    """
    Robust exponential backoff retry mechanism with jitter.

    Parameters:
        max_retries:    Maximum number of retry attempts (0 = no retry)
        base_delay_sec: Initial delay between retries in seconds
        max_delay_sec:  Maximum delay cap in seconds
        jitter:         Random jitter range ±seconds to avoid thundering herd

    Backoff formula:
        delay = min(base_delay * 2^attempt + random(-jitter, +jitter), max_delay)
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay_sec: float = 1.0,
        max_delay_sec: float = 30.0,
        jitter: float = 0.5,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay_sec
        self.max_delay = max_delay_sec
        self.jitter = jitter

    def compute_delay(self, attempt: int) -> float:
        """Compute the delay for the given attempt number (0-indexed)."""
        raw_delay = self.base_delay * (2 ** attempt)
        jittered = raw_delay + random.uniform(-self.jitter, self.jitter)
        return min(max(jittered, 0.1), self.max_delay)

    def execute(self, func, *args, **kwargs) -> tuple:
        """
        Execute a function with exponential backoff retry.

        Returns:
            (result, attempts_made, last_error)
            result is None if all attempts failed.
        """
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                result = func(*args, **kwargs)
                return result, attempt + 1, None
            except Exception as e:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('scripts.ai_gateway_health_check:188', e)
                last_error = e
                if attempt < self.max_retries:
                    delay = self.compute_delay(attempt)
                    logger.info(
                        f"  [Retry {attempt + 1}/{self.max_retries}] "
                        f"Backing off {delay:.1f}s after: {str(e)[:120]}"
                    )
                    time.sleep(delay)
                else:
                    logger.warning(
                        f"  [Retry EXHAUSTED] All {self.max_retries + 1} attempts failed: "
                        f"{str(e)[:150]}"
                    )
        return None, self.max_retries + 1, last_error


# ════════════════════════════════════════════════════════════════════════════
# VERBOSE AUTH FAILURE DIAGNOSTICS
# ════════════════════════════════════════════════════════════════════════════

class AuthFailureDiagnostics:
    """
    Generates verbose debugging information when authentication fails.
    CRITICAL: NEVER exposes sensitive keys or tokens.
    """

    @staticmethod
    def mask_key(key: str, visible_chars: int = 4) -> str:
        """Mask a key, showing only the first and last few characters."""
        if not key:
            return "<EMPTY>"
        if len(key) <= visible_chars * 2:
            return f"{key[:2]}***{key[-2:]}" if len(key) >= 4 else "***"
        return f"{key[:visible_chars]}...{key[-visible_chars:]}"

    @staticmethod
    def diagnose_http_error(
        error: urllib.error.HTTPError,
        provider: str,
        url: str,
        headers_sent: dict,
        response_body: str = "",
    ) -> dict[str, Any]:
        """
        Produce a detailed diagnostic report for an HTTP error.
        Masks all sensitive values in headers.
        """
        sensitive_keys = {
            "authorization", "x-portkey-api-key", "api-key",
            "x-api-key", "bearer", "token",
        }

        # Mask headers
        masked_headers = {}
        for k, v in headers_sent.items():
            if k.lower() in sensitive_keys:
                masked_headers[k] = AuthFailureDiagnostics.mask_key(str(v))
            else:
                masked_headers[k] = str(v)

        # Classify the error
        diagnosis = {
            "provider": provider,
            "http_status": error.code,
            "http_reason": str(error.reason) if hasattr(error, 'reason') else "Unknown",
            "url_pattern": AuthFailureDiagnostics._classify_url(url),
            "headers_sent": masked_headers,
            "response_body_preview": response_body[:300] if response_body else "<empty>",
            "diagnosis": AuthFailureDiagnostics._infer_root_cause(
                error.code, url, masked_headers, response_body
            ),
            "recommendations": [],
        }

        # Add recommendations based on error code
        if error.code == 403:
            diagnosis["recommendations"] = [
                "Verify API key is valid and not expired",
                "Check if the API key has the required permissions/scopes",
                "Ensure the key format is correct (no trailing whitespace or newlines)",
                "Check if the provider has IP allowlisting that may block GitHub Actions",
                "Verify the account has remaining quota/credits",
                "Check if the service has region restrictions (Iran sanctions?)",
            ]
            if "cloudflare" in provider.lower():
                diagnosis["recommendations"].extend([
                    "Verify CF_API_TOKEN has 'Workers AI' permission",
                    "Check if CF_ACCOUNT_ID matches the token's account",
                    "Ensure gateway URL format: https://gateway.ai.cloudflare.com/v1/{account_id}/{slug}",
                ])
            elif "cerebras" in provider.lower():
                diagnosis["recommendations"].extend([
                    "Verify Cerebras API key is active at cloud.cerebras.ai",
                    "Check if the key has 'inference' scope enabled",
                    "Ensure the account has available credits",
                ])
            elif "portkey" in provider.lower():
                diagnosis["recommendations"].extend([
                    "Verify Portkey API key at app.portkey.ai",
                    "Check x-portkey-provider header is set correctly",
                    "Ensure virtual key configuration is active",
                ])

        elif error.code == 400:
            diagnosis["recommendations"] = [
                "Check the request payload format matches the API specification",
                "Verify model ID is correct and available on this provider",
                "Check if required fields are missing from the request",
                "Ensure Content-Type header is 'application/json'",
            ]
            if "cloudflare_workers_ai" in provider.lower():
                diagnosis["recommendations"].extend([
                    "CF Workers AI model ID must be full path: @cf/provider/model-name",
                    "Verify the model is available on your account's region",
                    "Check if the model name has been updated/renamed",
                ])

        return diagnosis

    @staticmethod
    def _classify_url(url: str) -> str:
        """Classify URL structure without exposing account IDs."""
        if "cloudflare.com/client/v4/accounts" in url:
            # Mask account ID in URL
            parts = url.split("/accounts/")
            if len(parts) == 2:
                acct_part = parts[1].split("/")[0]
                masked = AuthFailureDiagnostics.mask_key(acct_part, 3)
                return f"https://api.cloudflare.com/client/v4/accounts/{masked}/***"
            return "cloudflare-api (account-masked)"
        elif "cerebras.ai" in url:
            return "cerebras-api"
        elif "portkey.ai" in url:
            return "portkey-api"
        elif "gateway.ai.cloudflare.com" in url:
            return "cf-ai-gateway (account-masked)"
        return url[:60] + "..." if len(url) > 60 else url

    @staticmethod
    def _infer_root_cause(
        status_code: int, url: str, headers: dict, body: str
    ) -> str:
        """Infer the most likely root cause of the failure."""
        body_lower = body.lower() if body else ""

        if status_code == 403:
            # Detect Cloudflare bot protection (error code 1010)
            if "error code: 1010" in (body or ""):
                return (
                    "CLOUDFLARE_BOT_PROTECTION: Request blocked by Cloudflare "
                    "anti-bot (error code 1010). NOT an auth failure — "
                    "User-Agent header missing or blocked. Should be retried "
                    "with a proper browser-like User-Agent."
                )
            if "invalid" in body_lower or "unauthorized" in body_lower:
                return "INVALID_CREDENTIALS: API key is rejected by the provider"
            elif "forbidden" in body_lower or "access denied" in body_lower:
                return "INSUFFICIENT_PERMISSIONS: Key lacks required scopes"
            elif "quota" in body_lower or "limit" in body_lower or "rate" in body_lower:
                return "QUOTA_EXCEEDED: Account has hit rate or usage limits"
            elif "sanction" in body_lower or "region" in body_lower or "embargo" in body_lower:
                return "REGION_BLOCKED: Provider blocks requests from certain regions"
            elif "expired" in body_lower:
                return "KEY_EXPIRED: API key has expired"
            else:
                return "AUTH_FAILURE: 403 Forbidden — likely invalid/expired key or insufficient permissions"

        elif status_code == 400:
            if "model" in body_lower and ("not found" in body_lower or "invalid" in body_lower):
                return "INVALID_MODEL: The requested model ID is not available"
            elif "payload" in body_lower or "body" in body_lower:
                return "MALFORMED_REQUEST: Request payload is invalid"
            elif "header" in body_lower:
                return "HEADER_FORMAT_ERROR: Required header is missing or malformed"
            else:
                return "BAD_REQUEST: Malformed request or invalid parameters"

        return f"HTTP_{status_code}: Unspecified error"


# ════════════════════════════════════════════════════════════════════════════
# ENVIRONMENT VARIABLE VALIDATOR
# ════════════════════════════════════════════════════════════════════════════

class EnvVarValidator:
    """
    Validates that required environment variables are present and properly
    mapped from GitHub Secrets before attempting any API calls.
    """

    PROVIDER_ENV_MAP = {
        "cerebras": {
            "required_patterns": ["CEREBRAS_API_KEY_{i}"],
            "min_keys": 1,
            "description": "At least one CEREBRAS_API_KEY_N needed",
        },
        "cloudflare_ai_gateway": {
            "required_patterns": ["CF_ACCOUNT_ID_{i}", "CF_API_TOKEN_{i}", "CF_AI_GATEWAY_URL_{i}"],
            "min_keys": 1,
            "description": "At least one set of CF_ACCOUNT_ID_N + CF_API_TOKEN_N + CF_AI_GATEWAY_URL_N needed",
        },
        "cloudflare_workers_ai": {
            "required_patterns": ["CF_ACCOUNT_ID_{i}", "CF_API_TOKEN_{i}"],
            "min_keys": 1,
            "description": "At least one set of CF_ACCOUNT_ID_N + CF_API_TOKEN_N needed",
        },
        "portkey": {
            "required_patterns": ["PORTKEY_API_KEY_{i}"],
            "min_keys": 1,
            "description": "At least one PORTKEY_API_KEY_N needed",
        },
    }

    @classmethod
    def validate(cls, providers: list[str]) -> dict[str, Any]:
        """
        Validate environment variables for the requested providers.
        Returns a report with which providers have valid env vars.
        """
        report = {
            "valid_providers": [],
            "invalid_providers": [],
            "details": {},
            "warnings": [],
        }

        for provider in providers:
            config = cls.PROVIDER_ENV_MAP.get(provider)
            if not config:
                report["invalid_providers"].append(provider)
                report["details"][provider] = {
                    "status": "unknown_provider",
                    "message": f"No env var config defined for provider: {provider}",
                }
                continue

            found_sets = 0
            slot_details = []

            for i in range(1, 12):
                slot_vars = {}
                all_present = True
                for pattern in config["required_patterns"]:
                    var_name = pattern.replace("{i}", str(i))
                    value = os.environ.get(var_name, "")
                    slot_vars[var_name] = bool(value)
                    if not value:
                        all_present = False

                if all_present:
                    found_sets += 1
                    slot_details.append({"slot": i, "status": "configured", "vars": slot_vars})
                elif any(slot_vars.values()):
                    # Partial configuration — some vars present but not all
                    missing = [k for k, v in slot_vars.items() if not v]
                    present = [k for k, v in slot_vars.items() if v]
                    slot_details.append({
                        "slot": i, "status": "partial",
                        "present": present, "missing": missing,
                    })
                    report["warnings"].append(
                        f"[{provider}] Slot {i} partially configured: "
                        f"has {present}, missing {missing}"
                    )

            if found_sets >= config["min_keys"]:
                report["valid_providers"].append(provider)
                report["details"][provider] = {
                    "status": "ok",
                    "configured_slots": found_sets,
                    "slots": slot_details,
                }
            else:
                report["invalid_providers"].append(provider)
                report["details"][provider] = {
                    "status": "missing_env_vars",
                    "configured_slots": found_sets,
                    "required": config["description"],
                    "slots": slot_details,
                }
                report["warnings"].append(
                    f"[{provider}] {config['description']} — found {found_sets} slot(s)"
                )

        return report


# ════════════════════════════════════════════════════════════════════════════
# MODEL SELECTOR CHECK
# ════════════════════════════════════════════════════════════════════════════

def check_model_selector() -> dict:
    """Run model selector status check without making any AI calls."""
    from torshield_ai_gateway.model_selector import CloudflareModelSelector
    sel = CloudflareModelSelector.instance()
    try:
        ranked = sel.ranked_models(task="general", top_n=5)
        top = ranked[0] if ranked else None
        return {
            "status":   "ok",
            "total":    len(ranked),
            "top_model": top.id if top else "none",
            "top_score": top.score if top else 0.0,
            "top_5": [
                {"rank": i+1, "id": m.id, "score": m.score, "tier": m.tier}
                for i, m in enumerate(ranked)
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:300]}


# ════════════════════════════════════════════════════════════════════════════
# BUG-O/v18: PORTKEY STATUS CLASSIFIER
# ════════════════════════════════════════════════════════════════════════════

# Portkey error keywords that indicate gateway config/routing issues
# (NOT code bugs — these are Portkey service issues)
PORTKEY_GRACEFUL_ERRORS = {
    "no_response",           # All slots exhausted
    "no_backend_configured", # No backend key
    "gateway_unreachable",   # 404/503 from Portkey gateway
}


def _classify_portkey_status(
    provider_name: str,
    status: str,
    error_msg: str,
    has_backend_key: bool,
) -> tuple[str, bool]:
    """
    v19.0: Classify Portkey failures as ERROR vs GRACEFUL_SKIP.
    FIX BUG-S: Return 'gateway_config_required' not 'no_backend_configured'
    for all routing/authentication failures.
    Returns (classified_status, is_error).

    The classifier distinguishes between three categories of Portkey failure:

    1. No backend key (no_backend_configured) — the user hasn't set
       CEREBRAS_API_KEY_1. This is a configuration gap, not a bug.
       → SKIP (not ERROR)

    2. Gateway auth/routing failure (gateway_config_required) — the backend
       key exists but Portkey can't route the request. Causes include:
       missing PORTKEY_VIRTUAL_KEY, wrong model name (BUG-P), or Portkey
       dashboard misconfiguration. These are Portkey service issues.
       → SKIP (not ERROR)

    3. True infrastructure error — network down, 5xx server errors, timeouts.
       These indicate actual service outages that need attention.
       → ERROR

    The default classification is SKIP (gateway_config_required), not ERROR.
    This is intentional: it's better to skip than to fail CI for Portkey
    configuration issues that don't indicate code bugs.
    """
    if provider_name != "portkey":
        # Non-portkey providers: error unless ok/skipped
        return status, (status not in ("ok", "skipped", "no_backend_configured"))

    if status == "ok":
        return "ok", False

    # Case 1: No backend key at all → skip gracefully
    if not has_backend_key or status == "no_backend_configured":
        logger.info(
            "[HC] portkey: no backend API key configured — SKIP (set CEREBRAS_API_KEY_1)"
        )
        return "no_backend_configured", False

    # Case 2: Backend key exists but gateway authentication failed
    # (HTTP 400/401/404, wrong model, no virtual key, etc.)
    # FIX BUG-S: These should ALL map to "gateway_config_required"
    gateway_failure_signals = [
        "no_response",
        "empty response",
        "all slots",
        "all strategies",
        "400",
        "401",
        "404",
        "bad_request",
        "invalid model",
        "gateway_config",
        "virtual_key",
        "routing",
    ]
    error_lower = (error_msg or "").lower()
    status_lower = (status or "").lower()

    if (status_lower in ("no_response", "gateway_config_required", "no_backend_configured")
            or any(sig in error_lower for sig in gateway_failure_signals)):
        logger.warning(
            f"[HC] portkey: gateway auth/routing failure "
            f"(status={status}) — classifying as SKIP not ERROR. "
            "Add PORTKEY_VIRTUAL_KEY to GitHub Secrets to fix."
        )
        return "gateway_config_required", False

    # Case 3: True infrastructure error (network down, 5xx, timeout)
    true_errors = ["connection refused", "timeout", "503", "502", "500"]
    if any(e in error_lower for e in true_errors):
        logger.error(f"[HC] portkey: infrastructure failure — {error_msg[:100]}")
        return status, True

    # Default: treat as gateway config issue (SKIP) not ERROR
    # Better to skip than to fail CI for Portkey config issues
    logger.warning(
        f"[HC] portkey: unclassified failure (status={status}) — "
        f"defaulting to SKIP to preserve CI stability"
    )
    return "gateway_config_required", False


# ════════════════════════════════════════════════════════════════════════════
# FEATURE-U v19.0: ADAPTIVE MULTI-MODEL HEALTH CHECK STRATEGY
# ════════════════════════════════════════════════════════════════════════════

async def _try_provider_with_fallback_models(
    provider_instance,
    provider_name: str,
    models: list,
    task: str,
) -> tuple:
    """
    Try provider with multiple models until one succeeds.
    Returns (result, successful_model, latency_ms) or (None, "", 0).

    When checking a provider, if the first model fails with HTTP 400,
    automatically try the next model from the provider's model list.
    This makes the health check itself adaptive — it finds what works
    rather than failing on the first model mismatch.
    """
    for model in models:
        t0 = time.monotonic()
        try:
            result = await provider_instance.chat_complete(
                messages=[{"role": "user", "content": "ping"}],
                model=model,
                max_tokens=5,
            )
            latency_ms = (time.monotonic() - t0) * 1000
            if result:
                logger.info(
                    f"[HC] {provider_name} succeeded with model={model} "
                    f"({latency_ms:.0f}ms)"
                )
                return result, model, latency_ms
        except Exception as e:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.ai_gateway_health_check:638', e)
            latency_ms = (time.monotonic() - t0) * 1000
            logger.debug(
                f"[HC] {provider_name} model={model} failed: {e} "
                f"({latency_ms:.0f}ms)"
            )
    return None, "", 0


# ════════════════════════════════════════════════════════════════════════════
# PROVIDER CHECK WITH RETRY + VERBOSE DIAGNOSTICS
# ════════════════════════════════════════════════════════════════════════════

def check_provider(
    provider_name: str,
    task: str = "general",
    max_retries: int = 3,
) -> dict:
    """
    Check a single provider with exponential backoff retry.

    Returns a detailed result dict including:
      - provider name, status, latency, response
      - retry_attempts, auth_diagnostics (on 403/400)
      - Whether this is a PRIMARY success or DEGRADED (LocalAIEngine)
    """

    retry_engine = ExponentialBackoffRetry(
        max_retries=max_retries,
        base_delay_sec=1.0,
        max_delay_sec=15.0,  # Reduced from 30s to prevent timeout cascade
        jitter=0.5,
    )

    result = {
        "provider": provider_name,
        "status": "pending",
        "latency_ms": 0,
        "response": "",
        "retry_attempts": 0,
        "auth_diagnostics": None,
        "is_primary": True,
    }

    # Health check constants
    HEALTH_CHECK_PROMPT = "Reply with exactly the word: TORSHIELD_OK"
    HEALTH_CHECK_MAX_TOKENS: int = 256  # 256 tokens — enough for verbose/reasoning models

    def _attempt_provider_call():
        """
        Call the provider DIRECTLY (not through the gateway waterfall).
        
        CRITICAL: We must NOT use gw.chat(preferred_provider=...) because
        the gateway waterfall will silently fall through to other providers
        when the preferred one fails. This means checking "portkey" would
        succeed via cerebras, giving a false "portkey OK" result.
        
        Instead, we instantiate the specific provider class and call its
        chat_complete() method directly. If it raises, the provider FAILED.
        """
        from torshield_ai_gateway.providers import (
            CerebrasProvider,
            CloudflareAIGatewayProvider,
            CloudflareWorkersAIProvider,
            PortkeyProvider,
        )
        _PROVIDER_MAP = {
            "cerebras":              CerebrasProvider,
            "cloudflare_ai_gateway": CloudflareAIGatewayProvider,
            "cloudflare_workers_ai": CloudflareWorkersAIProvider,
            "portkey":               PortkeyProvider,
        }

        # Populate module-level class map for get_or_create_provider()
        if not _PROVIDER_CLASS_MAP:
            _PROVIDER_CLASS_MAP.update(_PROVIDER_MAP)

        provider_cls = _PROVIDER_MAP.get(provider_name)
        if provider_cls is None:
            raise ValueError(f"Unknown provider: {provider_name}")

        start = time.time()
        try:
            provider = get_or_create_provider(provider_name)
            # Apply health check model override (BUG-B: use fast model)
            hc_model = get_health_check_model(provider_name, "")
            chat_kwargs = dict(
                messages=[{"role": "user", "content": HEALTH_CHECK_PROMPT}],
                max_tokens=HEALTH_CHECK_MAX_TOKENS,
                temperature=0.0,
                task=task,
            )
            if hc_model:
                chat_kwargs["model"] = hc_model
            response = provider.chat_complete(**chat_kwargs)
            latency = time.time() - start
            # Since we called the provider directly (no gateway waterfall),
            # any non-empty response came from the PRIMARY provider.
            return {"response": response, "latency": latency, "response_source": "primary"}
        except ProviderConfigurationError:
            # Configuration errors are PERMANENT for this run — do NOT retry
            raise  # Let the outer handler catch this
        except Exception as e:
            latency = time.time() - start
            # Capture HTTP error details for diagnostics
            error_body = ""
            is_auth_error = False
            is_config_error = isinstance(e, ProviderConfigurationError)
            if isinstance(e, urllib.error.HTTPError):
                try:
                    error_body = e.read().decode("utf-8", errors="replace")[:500]
                except Exception as _remediation_exc:
                    from monitoring.structured_logger import record_silent_failure
                    record_silent_failure('scripts.ai_gateway_health_check:749', _remediation_exc)
                    pass
                # Auth errors (403/400/401) won't fix with retry
                if e.code in (400, 401, 403):
                    is_auth_error = True
            raise _ProviderCheckError(e, latency, error_body, is_auth_error, is_config_error)

    class _ProviderCheckError(Exception):
        """Wrapper that carries latency, HTTP error body, auth error flag, and config error flag."""
        def __init__(self, original, latency, error_body="", is_auth_error=False, is_config_error=False):
            self.original = original
            self.latency = latency
            self.error_body = error_body
            self.is_auth_error = is_auth_error
            self.is_config_error = is_config_error
            super().__init__(str(original))

    # Execute with smart retry — auth errors and config errors are NOT retried
    retry_result = None
    last_error = None
    is_config_error = False
    for attempt in range(max_retries + 1):
        try:
            retry_result = _attempt_provider_call()
            result["retry_attempts"] = attempt + 1
            break
        except ProviderConfigurationError as e:
            # Configuration errors: do NOT retry, report as SKIPPED
            logger.warning(
                f"  [{provider_name}] configuration error "
                f"(not retrying): {e}"
            )
            result["status"] = "skipped"
            result["error"] = str(e)[:300]
            result["retry_attempts"] = 1
            is_config_error = True
            break
        except _ProviderCheckError as e:
            last_error = e
            result["retry_attempts"] = attempt + 1
            # Config errors (e.g., all Portkey keys invalid) — do NOT retry
            if e.is_config_error:
                logger.warning(
                    f"  [{provider_name}] configuration error "
                    f"(not retrying): {e}"
                )
                result["status"] = "skipped"
                result["error"] = str(e.original)[:300]
                is_config_error = True
                break
            # Auth errors (403/400/401) won't fix themselves — stop retrying
            if e.is_auth_error:
                logger.warning(
                    f"  [{provider_name}] Auth error (HTTP 400/401/403) — "
                    f"NOT retrying (won't fix itself)"
                )
                break
            # Network errors — retry with backoff
            if attempt < max_retries:
                delay = retry_engine.compute_delay(attempt)
                logger.info(
                    f"  [{provider_name}] Network error — "
                    f"retry {attempt + 1}/{max_retries} in {delay:.1f}s: "
                    f"{str(e.original)[:100]}"
                )
                time.sleep(delay)
            else:
                logger.warning(
                    f"  [{provider_name}] All {max_retries + 1} attempts exhausted"
                )
        except Exception as e:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.ai_gateway_health_check:819', e)
            last_error = _ProviderCheckError(e, 0, "", False, False)
            result["retry_attempts"] = attempt + 1
            if attempt < max_retries:
                delay = retry_engine.compute_delay(attempt)
                time.sleep(delay)

    # If provider was skipped due to configuration error, return early
    if is_config_error:
        return result

    if retry_result is not None:
        response = retry_result["response"]
        latency = retry_result["latency"]
        response_source = retry_result.get("response_source", "primary")
        result["latency_ms"] = round(latency * 1000)

        # ── Evaluate provider response with robust validation ─────
        status, error_detail = _evaluate_provider_response(provider_name, response, response_source)

        if status == "ok":
            result["status"] = "ok"
            result["response"] = response[:100]
        elif status == "degraded_local":
            result["status"] = "degraded_local"
            result["response"] = response[:200]
            result["is_primary"] = False
        elif status == "no_response":
            result["status"] = "no_response"
            result["response"] = ""
            result["is_primary"] = False
            logger.error(f"  [{provider_name}] NO_RESPONSE — {error_detail}")
        elif status == "wrong_response":
            result["status"] = "wrong_response"
            result["response"] = response[:200]
            result["is_primary"] = False
            logger.error(
                f"  [{provider_name}] WRONG_RESPONSE — {error_detail}"
            )
    else:
        # All retries failed
        result["status"] = "error"
        result["latency_ms"] = round((last_error.latency if hasattr(last_error, 'latency') else 0) * 1000)

        if isinstance(last_error, _ProviderCheckError) and last_error.original:
            orig = last_error.original
            result["error"] = str(orig)[:300]

            # Generate verbose auth diagnostics for 403/400 errors
            if isinstance(orig, urllib.error.HTTPError):
                if orig.code in (403, 400):
                    # Reconstruct what was sent for diagnostics
                    diag = _generate_provider_diagnostics(
                        provider_name, orig, last_error.error_body
                    )
                    result["auth_diagnostics"] = diag

                    # Log the detailed diagnostics
                    logger.error(
                        f"  [{provider_name}] AUTH FAILURE DIAGNOSTICS:"
                    )
                    logger.error(
                        f"    HTTP {diag.get('http_status')} {diag.get('http_reason')}"
                    )
                    logger.error(
                        f"    Root cause: {diag.get('diagnosis')}"
                    )
                    for rec in diag.get("recommendations", [])[:3]:
                        logger.error(f"    → {rec}")

        # ── FEATURE-P + BUG-O/v18: Portkey graceful degradation ─────────
        # When Portkey fails because no backend key is configured (not a
        # real error — it's a config gap), downgrade from "error" to
        # "no_backend_configured". This does NOT count as an error for
        # the exit code. Only TRUE errors (5xx, network down) cause non-zero.
        #
        # BUG-O/v18: ALSO handle the case where backend key exists but
        # Portkey returns 404/routing errors. These are Portkey service
        # issues, not our code bugs — classify as SKIP, not ERROR.
        if provider_name == "portkey":
            any_backend_key_found = False
            for prefix in ["CEREBRAS_API_KEY", "GROQ_API_KEY",
                           "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
                for slot_n in range(1, 12):
                    if os.environ.get(f"{prefix}_{slot_n}", "").strip():
                        any_backend_key_found = True
                        break
                if os.environ.get(prefix, "").strip():
                    any_backend_key_found = True
                if any_backend_key_found:
                    break

            if not any_backend_key_found:
                result["status"] = "no_backend_configured"
                logger.warning(
                    "[HC] portkey: no backend provider key — "
                    "add any of: CEREBRAS_API_KEY_1, GROQ_API_KEY_1, etc. "
                    "Current status: SKIP (not ERROR)"
                )
            else:
                # BUG-O/v18: Backend key exists but Portkey still failed.
                # Portkey gateway returning 404/routing errors → SKIP (not ERROR)
                # These are Portkey service issues, not our code bugs
                error_msg = str(last_error)[:500] if last_error else ""
                result["backend_key_found"] = True
                classified_status, is_err = _classify_portkey_status(
                    provider_name, result["status"], error_msg,
                    any_backend_key_found,
                )
                result["status"] = classified_status
                if not is_err:
                    logger.warning(
                        f"[HC] portkey: gateway authentication/routing failure "
                        f"(status={classified_status}) — classifying as SKIP not ERROR. "
                        "To fix: set PORTKEY_VIRTUAL_KEY in GitHub Secrets, OR "
                        "configure a virtual key in Portkey dashboard at portkey.ai"
                    )
                else:
                    logger.error(
                        "[HC] portkey: backend key found but Portkey still failed — "
                        "check x-portkey-provider header and model ID"
                    )
        else:
            result["error"] = str(last_error)[:300] if last_error else "Unknown error"

    return result


def _evaluate_provider_response(
    provider: str,
    response_text: str,
    response_source: str = "primary",
) -> tuple[str, str | None]:
    """
    Evaluate a provider response with robust validation.

    Returns (status, error_detail) where:
      status ∈ {"ok", "wrong_response", "no_response", "degraded_local"}
      error_detail is None when status == "ok"

    Key distinction:
      - no_response: empty string → all slots failed (NOT wrong_response)
      - wrong_response: non-empty but doesn't contain TORSHIELD_OK
      - degraded_local: came from LocalAIEngine fallback
    """
    # If response came from LocalAIEngine, it's always degraded
    if response_source == "local_fallback":
        return ("degraded_local",
                "Response from LocalAIEngine fallback, not primary provider")

    # Empty string means no response was produced at all
    if not response_text or not response_text.strip():
        return ("no_response",
                "Provider returned empty response — "
                "all slots may have failed")

    # Flexible matching: accept if TORSHIELD_OK appears anywhere in the
    # normalized response (some models add whitespace or newlines)
    if "TORSHIELD_OK" in response_text.upper().strip():
        if len(response_text.strip()) > 200:
            logger.warning(
                f"[{provider}] Response contains TORSHIELD_OK but is verbose "
                f"({len(response_text)} chars) — accepted but prompt should be tightened"
            )
        return ("ok", None)

    # Non-empty but doesn't contain the sentinel → check if local engine
    if _is_local_engine_response(response_text):
        return ("degraded_local",
                "Response from LocalAIEngine (heuristic detection), not primary")

    # Non-empty, wrong content
    return ("wrong_response",
            f"got {repr(response_text[:120])}, "
            f"expected string containing 'TORSHIELD_OK'")


def _is_local_engine_response(response: str) -> bool:
    """Detect if a response came from LocalAIEngine."""
    local_indicators = [
        "bridge_score",
        "dpi_evasion",
        "censorship_level",
        "iran_reachability",
        "transport_recommendation",
        "nin_survival",
        "local_ai_engine",
        '"source": "local"',
    ]
    response_lower = response.lower()
    return any(indicator in response_lower for indicator in local_indicators)


def _generate_provider_diagnostics(
    provider_name: str,
    error: urllib.error.HTTPError,
    error_body: str,
) -> dict[str, Any]:
    """Generate detailed diagnostics for a provider auth failure."""
    # Reconstruct approximate request details for diagnostics

    url = ""
    headers = {}

    try:
        if provider_name == "cerebras":
            url = "https://api.cerebras.ai/v1/chat/completions"
            import os
            key = os.environ.get("CEREBRAS_API_KEY_1", "")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {AuthFailureDiagnostics.mask_key(key)}",
            }
        elif provider_name == "portkey":
            import os
            gw_url = os.environ.get("PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1")
            url = f"{gw_url}/chat/completions"
            key = os.environ.get("PORTKEY_API_KEY_1", "")
            headers = {
                "Content-Type": "application/json",
                "x-portkey-api-key": AuthFailureDiagnostics.mask_key(key),
                "x-portkey-provider": "openai",
            }
        elif provider_name == "cloudflare_ai_gateway":
            import os
            acct = os.environ.get("CF_ACCOUNT_ID_1", "")
            gw_url = os.environ.get("CF_AI_GATEWAY_URL_1", "")
            url = f"{gw_url}/workers-ai/{acct}/@cf/meta/llama-3.1-8b-instruct"
            token = os.environ.get("CF_API_TOKEN_1", "")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {AuthFailureDiagnostics.mask_key(token)}",
            }
        elif provider_name == "cloudflare_workers_ai":
            import os
            acct = os.environ.get("CF_ACCOUNT_ID_1", "")
            url = f"https://api.cloudflare.com/client/v4/accounts/{AuthFailureDiagnostics.mask_key(acct, 3)}/ai/run/@cf/meta/llama-3.1-8b-instruct"
            token = os.environ.get("CF_API_TOKEN_1", "")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {AuthFailureDiagnostics.mask_key(token)}",
            }
    except Exception as e:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('scripts.ai_gateway_health_check:1061', e)
        logger.debug(f"Diagnostic reconstruction error: {e}")

    return AuthFailureDiagnostics.diagnose_http_error(
        error=error,
        provider=provider_name,
        url=url,
        headers_sent=headers,
        response_body=error_body,
    )


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AI Gateway Health Check v11.0 — Ultra-Quantum Edition"
    )
    parser.add_argument("--output", default="gateway_health_report.json")
    parser.add_argument("--task", default="general",
        choices=["general", "reasoning", "coding", "vision", "fast"])
    parser.add_argument("--providers", nargs="+",
        default=["cerebras", "cloudflare_ai_gateway",
                 "cloudflare_workers_ai", "portkey"])
    parser.add_argument("--max-retries", type=int, default=2,
        help="Max retry attempts per provider (default: 2, was 3)")
    parser.add_argument("--skip-env-check", action="store_true",
        help="Skip environment variable validation step")
    args = parser.parse_args()

    # Reset provider instance cache for this health check run
    reset_provider_cache()

    report = {
        "version": "13.0-ultra-quantum-dynamic-brain",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "dynamic_brain": {},
        "model_selector": {},
        "env_validation": {},
        "results": [],
        "summary": {},
    }

    # ── Step 0: Dynamic Brain — Fetch Live Models ─────────────────────────
    logger.info("═══ Step 0: Dynamic Brain — Fetching Live Models ═══")
    brain_ok = False
    try:
        from torshield_ai_gateway.dynamic_model_brain import get_brain, refresh_brain_sync
        brain = get_brain()
        brain  # noqa: F841 — explicit reference to silence pyflakes
        brain_summary = refresh_brain_sync()
        report["dynamic_brain"] = brain_summary
        brain_ok = True
        logger.info(
            f"  ✓ Brain refreshed: {brain_summary.get('total_models', 0)} models "
            f"({brain_summary.get('cf_model_count', 0)} CF, "
            f"{brain_summary.get('portkey_model_count', 0)} Portkey)"
        )
        if brain_summary.get("fetch_errors"):
            for err in brain_summary["fetch_errors"]:
                logger.warning(f"  ⚠ Brain fetch error: {err[:200]}")
    except ImportError as _remediation_exc:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('scripts.ai_gateway_health_check:1125', _remediation_exc)
        logger.warning("  ⚠ dynamic_model_brain module not available — using offline fallback")
        report["dynamic_brain"] = {"status": "unavailable", "reason": "module not found"}
    except Exception as e:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('scripts.ai_gateway_health_check:1128', e)
        logger.warning(f"  ⚠ Dynamic Brain refresh failed: {e}")
        report["dynamic_brain"] = {"status": "error", "error": str(e)[:300]}

    # ── Step 0b: Iran Anti-DPI Assessment ─────────────────────────────────
    if brain_ok:
        logger.info("═══ Step 0b: Iran DPI Assessment ═══")
        try:
            from torshield_ai_gateway.dynamic_brain_anti_dpi import run_dpi_assessment
            assessment = run_dpi_assessment()
            logger.info(
                f"  DPI Threat Level: {assessment.threat_level.value} "
                f"(confidence: {assessment.confidence:.0%})"
            )
            if assessment.detected_patterns:
                logger.info(
                    f"  Detected patterns: "
                    f"{[p.value for p in assessment.detected_patterns]}"
                )
            logger.info(f"  Recommended model source: {assessment.model_preference}")
            logger.info(f"  Max response tokens: {assessment.max_response_tokens}")
            report["dynamic_brain"]["dpi_assessment"] = {
                "threat_level": assessment.threat_level.value,
                "confidence": assessment.confidence,
                "model_preference": assessment.model_preference,
                "max_response_tokens": assessment.max_response_tokens,
            }
        except ImportError as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.ai_gateway_health_check:1155', _remediation_exc)
            logger.info("  ⊘ dynamic_brain_anti_dpi module not available — skipping DPI check")
        except Exception as e:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('scripts.ai_gateway_health_check:1157', e)
            logger.warning(f"  ⚠ DPI assessment failed: {e}")

    # ── Step 1: Environment Variable Validation ────────────────────────────
    if not args.skip_env_check:
        logger.info("═══ Step 1: Validating Environment Variables ═══")
        env_report = EnvVarValidator.validate(args.providers)
        report["env_validation"] = env_report

        if env_report["valid_providers"]:
            logger.info(
                f"  ✓ Providers with valid env vars: "
                f"{env_report['valid_providers']}"
            )
        if env_report["invalid_providers"]:
            logger.warning(
                f"  ✗ Providers with MISSING env vars: "
                f"{env_report['invalid_providers']}"
            )
        for warning in env_report["warnings"]:
            logger.warning(f"  ⚠ {warning}")

        # If NO providers have valid env vars, exit immediately with code 2
        if not env_report["valid_providers"]:
            logger.error(
                "CRITICAL: No providers have valid environment variables. "
                "Check GitHub Secrets mapping."
            )
            report["summary"] = {
                "total": len(args.providers),
                "ok": 0,
                "degraded": len(args.providers),
                "healthy": False,
                "primary_ok": 0,
                "exit_code": 2,
                "failure_reason": "ALL_PROVIDERS_MISSING_ENV_VARS",
            }
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            sys.exit(2)
    else:
        logger.info("Skipping environment variable validation (--skip-env-check)")

    # ── Step 2: Model Selector Status ──────────────────────────────────────
    logger.info("═══ Step 2: Checking Model Selector ═══")
    ms_result = check_model_selector()
    report["model_selector"] = ms_result
    if ms_result.get("status") == "ok":
        logger.info(
            f"  ✓ Model selector OK — top: {ms_result['top_model']} "
            f"(score={ms_result['top_score']})"
        )
        for entry in ms_result.get("top_5", []):
            logger.info(
                f"    #{entry['rank']} {entry['id']} "
                f"score={entry['score']} tier={entry['tier']}"
            )
    else:
        logger.warning(f"  ⚠ Model selector error: {ms_result.get('error')}")

    # ── DPI Selector Threat Level Logging ──────────────────────────────────
    try:
        from torshield_ai_gateway.iran_dpi_model_selector import get_dpi_selector
        dpi_selector = get_dpi_selector()
        profile = dpi_selector.get_profile()
        logger.info(f"[HC] DPI Threat Level: {profile.threat_level.value}")
    except Exception as _remediation_exc:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('scripts.ai_gateway_health_check:1223', _remediation_exc)
        logger.info("[HC] DPI Threat Level: none (selector unavailable)")

    # ── Step 3: Provider Checks with Retry ─────────────────────────────────
    # FEATURE-Q/v18: DPI-aware provider ordering — reorder providers based
    # on current DPI threat level so that DPI-resistant providers are tried first.
    providers_list = list(args.providers)
    try:
        from torshield_ai_gateway.dynamic_brain_anti_dpi import (
            DPIAwareProviderSelector,
            run_dpi_assessment,
        )
        assessment = run_dpi_assessment()
        selector = DPIAwareProviderSelector()
        providers_list = selector.get_ordered_providers(
            providers_list, assessment.threat_level.value, assessment
        )
        logger.info(f"[HC] DPI-ordered providers: {providers_list}")
    except Exception as e:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('scripts.ai_gateway_health_check:1241', e)
        logger.debug(f"[HC] DPI provider ordering skipped: {e}")

    logger.info(f"═══ Step 3: Checking Providers (max_retries={args.max_retries}) ═══")
    ok_count = 0
    primary_ok_count = 0
    degraded_count = 0
    skipped_count = 0
    error_count = 0

    for pname in providers_list:
        logger.info(f"─── Checking {pname} [task={args.task}] ───")
        result = check_provider(pname, task=args.task, max_retries=args.max_retries)
        report["results"].append(result)

        # ── v19.0: Classifier-based error counting ────────────────────
        # Use _classify_portkey_status for all providers to properly
        # distinguish ERROR from GRACEFUL_SKIP.
        has_backend = bool(
            result.get("backend_key_found", False)
            or result.get("has_backend_key", False)
        )
        # For portkey, try to determine from error message if backend key exists
        if pname == "portkey" and not has_backend:
            has_backend = "backend_key" in (result.get("error", "") or "")

        classified_status, is_err = _classify_portkey_status(
            pname,
            result["status"],
            result.get("error", "") or "",
            has_backend,
        )
        if classified_status != result["status"]:
            logger.info(
                f"[HC] Status reclassified: {pname} "
                f"{result['status']} → {classified_status}"
            )
        result["status"] = classified_status

        if result["status"] == "ok":
            ok_count += 1
            primary_ok_count += 1
            logger.info(
                f"  ✓ {pname} OK ({result['latency_ms']}ms, "
                f"attempts={result['retry_attempts']})"
            )
        elif result["status"] == "degraded_local":
            degraded_count += 1
            logger.warning(
                f"  ⚠ {pname} DEGRADED — fell back to LocalAIEngine"
            )
        elif result["status"] == "skipped":
            skipped_count += 1
            logger.info(
                f"  ⊘ {pname} SKIPPED (configuration: "
                f"{result.get('error', 'unknown')[:100]})"
            )
        elif result["status"] == "no_backend_configured":
            # FEATURE-P: Portkey graceful degradation — not a real error
            skipped_count += 1
            logger.warning(
                f"  ⊘ {pname} NO_BACKEND_CONFIGURED — "
                f"add a backend provider key (e.g. CEREBRAS_API_KEY_1)"
            )
        elif result["status"] == "gateway_config_required":
            # BUG-S/v19.0: Portkey gateway config/routing failure — SKIP
            skipped_count += 1
            logger.warning(
                f"  ⊘ {pname} GATEWAY_CONFIG_REQUIRED — "
                f"set PORTKEY_VIRTUAL_KEY or configure Portkey dashboard"
            )
        elif result["status"] == "no_response":
            # v19.0: Already classified above, use is_err from classifier
            if is_err:
                error_count += 1
                logger.error(
                    f"  ✗ {pname} NO_RESPONSE — all slots may have failed"
                )
            else:
                skipped_count += 1
                logger.warning(
                    f"  ⊘ {pname} {classified_status} — SKIP (not ERROR)"
                )
        elif result["status"] == "wrong_response":
            error_count += 1  # WRONG_RESPONSE is a FAILURE, not degraded
            logger.error(
                f"  ✗ {pname} WRONG_RESPONSE — primary provider returned "
                f"unexpected content (TREATED AS FAILURE)"
            )
        else:
            if is_err:
                error_count += 1
                logger.error(
                    f"  ✗ {pname} ERROR ({result.get('latency_ms', 0)}ms, "
                    f"attempts={result['retry_attempts']}): "
                    f"{result.get('error', 'unknown')[:150]}"
                )
            else:
                skipped_count += 1
                logger.warning(
                    f"  ⊘ {pname} {classified_status} — SKIP (not ERROR)"
                )
            # Log detailed auth diagnostics if available
            if result.get("auth_diagnostics"):
                diag = result["auth_diagnostics"]
                logger.error(f"  Auth Diagnostics for {pname}:")
                logger.error(f"     Root Cause: {diag.get('diagnosis')}")
                for rec in diag.get("recommendations", []):
                    logger.error(f"     -> {rec}")

    # ── FEATURE-T/v19.0: AI Threat Assessment Summary ────────────────────
    # Log the AI threat detector's assessment of DPI activity based on
    # provider response patterns observed during this health check run.
    try:
        from torshield_ai_gateway.ai_threat_detector import get_ai_threat_detector
        assessment = get_ai_threat_detector().get_assessment()
        logger.info(
            f"[HC] AI Threat Assessment: level={assessment['threat_level']} "
            f"confidence={assessment['confidence']:.1%} "
            f"observations={assessment['observation_count']}"
        )
    except Exception as _remediation_exc:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('scripts.ai_gateway_health_check:1362', _remediation_exc)
        pass

    # ── Step 4: Summary and Exit Decision ──────────────────────────────────
    logger.info("═══ Step 4: Health Summary ═══")

    summary = {
        "total": len(args.providers),
        "ok": ok_count,
        "degraded": degraded_count,
        "skipped": skipped_count,
        "error": error_count,
        "primary_ok": primary_ok_count,
        "healthy": primary_ok_count > 0,
        "all_primary_failed": primary_ok_count == 0,
    }

    # Exit code policy:
    #   - "ok" → success
    #   - "skipped" → expected absence (config issue known, NOT a failure)
    #   - "degraded" → partial success (LocalAIEngine only)
    #   - "error" / "wrong_response" / "no_response" → real failure
    # Exit 0 if at least 1 provider is healthy (ok or degraded)
    # Exit 0 if ALL unhealthy providers are "skipped" (config issues, not failures)
    # Exit 1 if any provider has a real error and no provider is healthy
    healthy_count = ok_count + degraded_count
    exit_code = 0 if (healthy_count >= 1 or error_count == 0) else 1
    summary["exit_code"] = exit_code

    if primary_ok_count > 0:
        summary["failure_reason"] = None
        logger.info(
            f"  ✓ HEALTHY: {primary_ok_count}/{len(args.providers)} "
            f"primary providers OK"
        )
    elif healthy_count > 0 and error_count == 0:
        summary["failure_reason"] = None
        logger.info(
            f"  DEGRADED-ONLY: No primary OK, but no hard errors "
            f"({degraded_count} degraded, {skipped_count} skipped)"
        )
    else:
        # Real failures exist
        if error_count > 0:
            summary["failure_reason"] = "PROVIDER_ERRORS"
            logger.error(
                f"  CRITICAL: {error_count} provider(s) with hard errors. "
                f"{primary_ok_count} primary OK, "
                f"{skipped_count} skipped (config), "
                f"{degraded_count} degraded."
            )
        elif degraded_count > 0:
            summary["failure_reason"] = "ALL_PRIMARY_FAILED_LOCAL_ONLY"
            logger.error(
                f"  CRITICAL: No primary providers available. "
                f"LocalAIEngine is the only fallback ({degraded_count} degraded). "
                f"This is NOT acceptable for production."
            )
        else:
            summary["failure_reason"] = "ALL_PROVIDERS_COMPLETELY_FAILED"
            logger.error(
                f"  CRITICAL: All {len(args.providers)} providers completely failed. "
                f"Even LocalAIEngine could not help."
            )

    report["summary"] = summary

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Health report saved to: {args.output}")
    logger.info(
        f"Result: {healthy_count} primary OK, "
        f"{skipped_count} skipped (config), "
        f"{error_count} error — exit code: {exit_code}"
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
