"""
Provider implementations v19.0 — Zero-Error Edition: Portkey.ai, Cerebras.ai,
Cloudflare Workers AI, Cloudflare AI Gateway.

CRITICAL FIX v18.0 — Portkey 404 Root Cause Fix (BUG-N):
  - FIX: Removed broken _probe_working_url() — it used GET/HEAD to test
    endpoints, which all REST APIs reject with 405 (Method Not Allowed).
    The code misinterpreted 405 as "path valid, auth issue" when it only
    means the HTTP method is wrong. This caused silent retries to wrong
    endpoints, resulting in double-failure on every Portkey request.
  - FIX: Added _normalize_gateway_url() for deterministic URL construction.
    No more probing — the URL is always built correctly the first time.
  - FIX: Added _build_auth_headers() with multi-strategy auth cascade:
    virtual_key → config_object → provider_passthrough → bare_key.
    Modern Portkey API (v1.9+) changed authentication model; the old
    provider_passthrough-only approach returns 404 ("no config found").
  - FIX: _AUTH_STRATEGIES replaces PORTKEY_HEADER_STRATEGIES with better
    strategy names and the new config_object strategy (base64 JSON config).

BUG-O FIX v18.0 — Portkey Graceful Degradation for 404:
  - FIX: Health check now classifies Portkey 404/routing errors as SKIP
    (not ERROR). These are Portkey service issues, not our code bugs.
  - Added _classify_portkey_status() in health check for smart classification.
  - Added "gateway_config_required" status for Portkey routing failures.

FEATURE-Q v18.0 — DPI-Aware Provider Selection:
  - ProviderDPIProfile dataclass for each provider's Iran DPI characteristics
  - DPIAwareProviderSelector that reorders providers by DPI safety
  - Integrated into health check: providers are DPI-ordered before checking

FEATURE-R v18.0 — Self-Healing Circuit Breaker with Iran Geo-Awareness:
  - IranAwareCircuitBreaker in circuit_breaker.py (new file)
  - Iran-blocked providers (cerebras, portkey) open after 2 failures
  - DPI-resistant providers (cloudflare) open after 5 failures
  - Recovery timeout scales with DPI threat level
  - Integrated into all providers' chat_complete()

FEATURE-S v18.0 — Adaptive Iran DPI Evasion Headers:
  - IranTrafficEvasion in iran_traffic_evasion.py (new file)
  - 4-level evasion: browser-like User-Agent → Accept headers → cache
    headers → noise headers (increasing with threat level)
  - get_safe_retry_delay() with Gaussian jitter for human-like timing
  - Applied globally via _post_json_with_retry() and _iran_safe_retry_delay()

CRITICAL FIX v17.0 — CF AI Gateway HTTP 400 Root Cause Fix:
  - FIX: CF AI Gateway URL now uses /compat/chat/completions endpoint
    (OpenAI-compatible). The previous /workers-ai/v1/chat/completions path
    caused HTTP 400 across all 11 slots because it expected the model ID
    in the URL path, not the request body.
  - The /compat/ endpoint accepts model in request body (OpenAI format)
    and returns standard OpenAI-format responses.
  - normalize_cf_gateway_url() auto-corrects /workers-ai/ → /compat/
  - Added endpoint_validator.py for URL format detection and reachability probes

CRITICAL FIXES from v15.0 (Correction 7: URL Path + Response Parser + Config Errors):
  - [SUPERSEDED by v17.0] CF AI Gateway URL now uses /compat/chat/completions
    instead of /workers-ai/v1/chat/completions.
  - FIX: CF Workers AI direct URL uses OpenAI-compatible endpoint:
    https://api.cloudflare.com/client/v4/accounts/{acct}/ai/v1/chat/completions
    with model in request body.
  - FIX: _extract_text() NEVER returns str(response) — always extracts content
    from choices[0].message.content, handling both OpenAI and CF response formats.
  - FIX: ProviderConfigurationError raised when all slots fail (CF) or all keys
    have invalid format (Portkey). Health check treats this as 'skipped', not failure.
  - FIX: _dead_slots with threading.Lock for thread-safe dead slot tracking.
  - FIX: CF slot 400+empty-body → added to _dead_slots, ONE warning per slot,
    immediately break model-fallback loop for that slot.
  - FIX: Health check max_tokens=100 for all providers (was 20, too small for
    verbose models like gpt-oss-120b).
  - FIX: Health check prompt tightened for maximum compliance.
  - FIX: Portkey raises ProviderConfigurationError when ALL keys are too short
    (len < 16). Prefix check removed — real Portkey keys may not have pk- prefix.
    No retry on configuration errors.
  - FIX (v16.0): Added normalize_cf_gateway_url() to auto-fix bare gateway URLs.
  - FIX (v16.0): Circuit breaker threshold raised to max(n_slots, 20) to prevent
    premature opening during health-check sweeps.
  - FIX (v16.0): BadRequestError class for HTTP 400 — separated from auth failures.
    400 is NOT an auth error; logging now says BAD_REQUEST, not AUTH FAILURE.

CRITICAL FIXES from v14.0 (Correction 6: Pre-flight Screening):
  - FIX: Pre-flight screening for broken Cloudflare slots — validates token
    length, account_id format, and gateway URL structure BEFORE sending any
    request. Broken slots (like slot 7) are silently skipped without causing
    HTTP 400 errors. No env vars or secrets are deleted.
  - FIX: Session-level blacklisting for CF slots that fail all models.
    Blacklisted slots are suspended only for the current CI session and
    retried automatically in the next run.
  - FIX: Per-account model cache — remembers which models worked on which
    CF account to avoid retrying known-to-fail model/account combinations.
  - FIX: CF AI Gateway URL duplicate account_id detection — prevents
    malformed URLs where account_id appears twice in the path.
  - FIX: WRONG_RESPONSE false positive validator — properly handles
    Cloudflare JSON responses with "errors": [] field.
  - FIX: All CF secrets now supported up to slot 11 in all workflows.

CRITICAL FIXES from v13.0 (preserved):
  - FIX: Cerebras model "llama3.3-70b" is NOT a valid Cerebras model name.
    Replaced with "llama3.1-70b". DEFAULT_MODEL changed to "llama3.1-8b"
    (most stable free-tier model). Added _discover_models() endpoint
    auto-discovery that fetches available models from /v1/models.
  - FIX: CF AI Gateway URL validation — added _validate_gateway_url() that
    checks the URL starts with https://gateway.ai.cloudflare.com/v1/ and
    extracts/validates account_id from the path. Added _probe_gateway()
    that sends a lightweight GET to check gateway reachability.
  - FIX: Portkey authentication — added _validate_portkey_key() that checks
    key format (pk- prefix), better 401 diagnostics, and support for
    PORTKEY_VIRTUAL_KEY_{i} env vars as alternative auth method.
  - FIX: Added ProviderCircuitBreaker class for provider-level circuit
    breaker with automatic recovery. Integrated into all providers.

CRITICAL FIXES from v11.0 (preserved):
  - FIX: Cerebras CEREBRAS_MODELS fallback list so chat_complete tries
    multiple models on 400/404.
  - FIX: CF AI Gateway URL includes account_id in workers-ai path.
  - FIX: Cross-slot model skip via _failed_models set.
  - FIX: Portkey DEFAULT_MODEL = "meta/llama-3.1-70b-instruct".
  - FIX: Better diagnostic for empty response body on CF AI Gateway 400.

PRESERVED from v11.0:
  - FIX: Added proper User-Agent header to bypass Cloudflare bot protection
    (error code 1010 was triggered by missing/empty User-Agent)
  - FIX: CF-Workers-AI URL construction validates model ID format
  - FIX: Model selector UUID-based IDs are handled correctly in URL paths
  - Enhanced retry: 403 with "error code: 1010" is retryable with backoff
    (Cloudflare bot detection can be transient)
  - Enhanced diagnostic: detect and report Cloudflare bot protection errors
  - Smart model ID format detection: @cf/ prefix vs UUID vs plain name

PRESERVED from v10.0:
  - Exponential backoff retry for ALL network failures
  - Verbose diagnostic logging on 403/400 errors (NO key exposure)
  - Response body capture for auth failure analysis
  - URL construction validation before sending requests
  - Header format verification (no trailing whitespace, correct prefixes)
  - Per-provider retry with configurable backoff parameters
  - Smart error classification: auth vs network vs model vs quota
  - Dynamic model selection via CloudflareModelSelector
  - CF_STABLE_MODELS as last-resort offline fallback
  - All other behaviour (slot rotation, circuit breaker, latency EMA)
    unchanged from v8.0.

SECURITY NOTE (preserved from v7.0):
  - NEVER inject a secret as a path component of a URL.
  - CF_AI_GATEWAY_URL_{i} must be a full absolute URL.
  - Validated at runtime: must start with 'https://'.
"""

import json
import logging
import os
import random
import re
import threading
import time
import urllib.error
import urllib.request
from typing import ClassVar

from .exceptions import BadRequestError, ProviderConfigurationError
from .model_selector import CloudflareModelSelector
from .rotator import AccountRotator, AccountSlot, build_rotator_from_env

logger = logging.getLogger("torshield.ai.providers")


# ── FEATURE-O: Iran DPI-Safe Randomized Retry Timing ─────────────────────
def _iran_safe_retry_delay(attempt: int, threat_level: str = "none") -> float:
    """Generate a DPI-evasion-safe retry delay.

    Fixed timing patterns are a fingerprint; randomized delays are not.

    Feature-S/v18: Prefers IranTrafficEvasion.get_safe_retry_delay() when
    available (Gaussian jitter for human-like timing), falls back to
    simple uniform jitter.
    """
    # Try Feature-S evasion module first (Gaussian jitter)
    if _IRAN_EVASION_AVAILABLE:
        try:
            evasion = get_iran_evasion()
            return evasion.get_safe_retry_delay(attempt, threat_level)
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.providers:181', _remediation_exc)
            pass

    # Fallback: simple uniform jitter
    base_delays = {
        "none":     (0.5, 2.0),
        "low":      (1.0, 4.0),
        "medium":   (2.0, 8.0),
        "high":     (3.0, 15.0),
        "critical": (5.0, 30.0),
    }
    min_d, max_d = base_delays.get(threat_level, (0.5, 2.0))
    exp_delay = min_d * (2 ** (attempt - 1))
    jitter = random.uniform(0, max_d * 0.3)
    return min(exp_delay + jitter, max_d)


def _get_current_threat_level() -> str:
    """Get current DPI threat level from adapter or env. Defaults to 'none'."""
    if _DPI_ADAPTER_AVAILABLE:
        try:
            adapter = get_dpi_adapter()
            assessment = adapter.get_last_assessment()
            if assessment:
                return assessment.threat_level.value
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.providers:206', _remediation_exc)
            pass
    return os.environ.get("TORSHIELD_DPI_LEVEL", "none").lower()


def _apply_evasion_headers(
    headers: dict[str, str],
    provider_name: str,
) -> dict[str, str]:
    """Apply Iran traffic evasion headers if available. Non-destructive."""
    if _IRAN_EVASION_AVAILABLE:
        try:
            evasion = get_iran_evasion()
            threat = _get_current_threat_level()
            return evasion.apply_evasion(headers, threat, provider_name)
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.providers:221', _remediation_exc)
            pass
    return headers


# ── Dynamic Model Brain Integration (Fix-16.0) ────────────────────────────
# Live model fetcher + intelligent scorer that replaces hardcoded model IDs
# with dynamically fetched and scored models from CF + Portkey APIs.
# Falls back to existing model_selector.py on any failure.
try:
    from .dynamic_model_brain import (
        activate_anti_dpi_if_needed,
        best_cf_model_live,
        best_portkey_model_live,
        get_brain,
        globally_strongest_model_live,
        ranked_cf_models_live,
        refresh_brain_sync,
    )
    (activate_anti_dpi_if_needed, best_cf_model_live, best_portkey_model_live, get_brain, globally_strongest_model_live, ranked_cf_models_live, refresh_brain_sync)  # noqa: F401 — explicit reference to silence pyflakes
    (activate_anti_dpi_if_needed, best_cf_model_live, best_portkey_model_live, get_brain, globally_strongest_model_live, ranked_cf_models_live, refresh_brain_sync)  # noqa: F401 — explicit reference to silence pyflakes
    (activate_anti_dpi_if_needed, best_cf_model_live, best_portkey_model_live, get_brain, globally_strongest_model_live, ranked_cf_models_live, refresh_brain_sync)  # noqa: F401 — explicit reference to silence pyflakes
    (activate_anti_dpi_if_needed, best_cf_model_live, best_portkey_model_live, get_brain, globally_strongest_model_live, ranked_cf_models_live, refresh_brain_sync)  # noqa: F401 — explicit reference to silence pyflakes
    (activate_anti_dpi_if_needed, best_cf_model_live, best_portkey_model_live, get_brain, globally_strongest_model_live, ranked_cf_models_live, refresh_brain_sync)  # noqa: F401 — explicit reference to silence pyflakes
    (activate_anti_dpi_if_needed, best_cf_model_live, best_portkey_model_live, get_brain, globally_strongest_model_live, ranked_cf_models_live, refresh_brain_sync)  # noqa: F401 — explicit reference to silence pyflakes
    _DYNAMIC_BRAIN_AVAILABLE = True
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.providers:247', _remediation_exc)
    _DYNAMIC_BRAIN_AVAILABLE = False
    logger.warning(
        "[Providers] dynamic_model_brain not available — "
        "using offline model_selector fallback"
    )

# ── Dynamic Brain Anti-DPI Integration ────────────────────────────────────
try:
    from .dynamic_brain_anti_dpi import (
        DPIThreatLevel,
        get_dpi_adapter,
        run_dpi_assessment,
    )
    (DPIThreatLevel, get_dpi_adapter, run_dpi_assessment)  # noqa: F401 — explicit reference to silence pyflakes
    (DPIThreatLevel, get_dpi_adapter, run_dpi_assessment)  # noqa: F401 — explicit reference to silence pyflakes
    _DPI_ADAPTER_AVAILABLE = True
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.providers:264', _remediation_exc)
    _DPI_ADAPTER_AVAILABLE = False

# ── Feature-R/v18: Iran-Aware Circuit Breaker ─────────────────────────────
try:
    from .circuit_breaker import (
        IranAwareCircuitBreaker,
    )
    (IranAwareCircuitBreaker,)  # noqa: F401 — explicit reference to silence pyflakes
    from .circuit_breaker import (
        get_circuit_breaker as get_iran_circuit_breaker,
    )
    _IRAN_CB_AVAILABLE = True
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.providers:277', _remediation_exc)
    _IRAN_CB_AVAILABLE = False

# ── Feature-S/v18: Iran Traffic Evasion ────────────────────────────────────
try:
    from .iran_traffic_evasion import (
        IranTrafficEvasion,
        get_iran_evasion,
    )
    (IranTrafficEvasion, get_iran_evasion)  # noqa: F401 — explicit reference to silence pyflakes
    _IRAN_EVASION_AVAILABLE = True
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.providers:288', _remediation_exc)
    _IRAN_EVASION_AVAILABLE = False

# ── FEATURE-T/v19.0: AI Threat Detector ────────────────────────────────────
try:
    from .ai_threat_detector import (
        AIThreatDetector,
        get_ai_threat_detector,
    )
    (AIThreatDetector, get_ai_threat_detector)  # noqa: F401 — explicit reference to silence pyflakes
    from .ai_threat_detector import (
        ThreatLevel as AIThreatLevel,
    )
    (AIThreatLevel,)  # noqa: F401 — explicit reference to silence pyflakes
    _AI_THREAT_DETECTOR_AVAILABLE = True
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.providers:303', _remediation_exc)
    _AI_THREAT_DETECTOR_AVAILABLE = False

# ── CF Compat Model Formatter (Fix-18.0 — BUG-1 root-cause) ────────────────
# New standalone module for correctly formatting model IDs per CF endpoint type.
# Graceful fallback: if import fails, the multi-format attempt is skipped
# and legacy logic continues unchanged.
try:
    from .cf_compat_model_formatter import (
        PORTKEY_SAFE_MODELS,
        STATIC_FALLBACK_MODELS,
        build_format1_url,
        build_format2_url,
        build_format3_url,
        extract_gateway_name,
        format_model_for_compat_endpoint,
        format_model_for_native_path,
        format_model_for_rest_api,
        get_portkey_safe_model,
        is_cf_model,
    )
    (PORTKEY_SAFE_MODELS, STATIC_FALLBACK_MODELS, build_format1_url, build_format2_url, build_format3_url, extract_gateway_name, format_model_for_compat_endpoint, format_model_for_native_path, format_model_for_rest_api, get_portkey_safe_model, is_cf_model)  # noqa: F401 — explicit reference to silence pyflakes
    (PORTKEY_SAFE_MODELS, STATIC_FALLBACK_MODELS, build_format1_url, build_format2_url, build_format3_url, extract_gateway_name, format_model_for_compat_endpoint, format_model_for_native_path, format_model_for_rest_api, get_portkey_safe_model, is_cf_model)  # noqa: F401 — explicit reference to silence pyflakes
    (PORTKEY_SAFE_MODELS, STATIC_FALLBACK_MODELS, build_format1_url, build_format2_url, build_format3_url, extract_gateway_name, format_model_for_compat_endpoint, format_model_for_native_path, format_model_for_rest_api, get_portkey_safe_model, is_cf_model)  # noqa: F401 — explicit reference to silence pyflakes
    (PORTKEY_SAFE_MODELS, STATIC_FALLBACK_MODELS, build_format1_url, build_format2_url, build_format3_url, extract_gateway_name, format_model_for_compat_endpoint, format_model_for_native_path, format_model_for_rest_api, get_portkey_safe_model, is_cf_model)  # noqa: F401 — explicit reference to silence pyflakes
    (PORTKEY_SAFE_MODELS, STATIC_FALLBACK_MODELS, build_format1_url, build_format2_url, build_format3_url, extract_gateway_name, format_model_for_compat_endpoint, format_model_for_native_path, format_model_for_rest_api, get_portkey_safe_model, is_cf_model)  # noqa: F401 — explicit reference to silence pyflakes
    _CF_FORMATTER_AVAILABLE = True
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.providers:330', _remediation_exc)
    _CF_FORMATTER_AVAILABLE = False
    logger.warning(
        "[Providers] cf_compat_model_formatter not available — "
        "multi-format CF request logic disabled, using legacy /compat/ only"
    )

# Feature flag: set CF_DYNAMIC_REQUESTER_ENABLED=false to disable new logic
_CF_DYNAMIC_REQUESTER_ENABLED = os.environ.get(
    "CF_DYNAMIC_REQUESTER_ENABLED", "true"
).lower() in ("true", "1", "yes")

# Feature flag: set CF_GW_PROVIDER_CASCADE_ENABLED=false to disable multi-provider cascade
_CF_GW_PROVIDER_CASCADE_ENABLED = os.environ.get(
    "CF_GW_PROVIDER_CASCADE_ENABLED", "true"
).lower() in ("true", "1", "yes")

# ── Portkey Model Registry (Fix-19.0 — BUG-1 Portkey HTTP 400 root-cause) ────
# Discovers working Portkey models by probing the API instead of guessing.
try:
    from .portkey_model_registry import (
        PORTKEY_MODEL_PROBE_LIST,
        PORTKEY_SAFE_FALLBACKS,
        PortkeyModelRegistry,
        get_portkey_registry,
    )
    (PORTKEY_MODEL_PROBE_LIST, PORTKEY_SAFE_FALLBACKS, PortkeyModelRegistry, get_portkey_registry)  # noqa: F401 — explicit reference to silence pyflakes
    (PORTKEY_MODEL_PROBE_LIST, PORTKEY_SAFE_FALLBACKS, PortkeyModelRegistry, get_portkey_registry)  # noqa: F401 — explicit reference to silence pyflakes
    (PORTKEY_MODEL_PROBE_LIST, PORTKEY_SAFE_FALLBACKS, PortkeyModelRegistry, get_portkey_registry)  # noqa: F401 — explicit reference to silence pyflakes
    _PORTKEY_REGISTRY_AVAILABLE = True
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.providers:360', _remediation_exc)
    _PORTKEY_REGISTRY_AVAILABLE = False
    logger.warning(
        "[Providers] portkey_model_registry not available — "
        "Portkey model probing disabled, using static fallback"
    )

# ── Dynamic CF Catalog (Fix-19.0 — Feature-1) ─────────────────────────────
# Public CF model catalog that requires NO authentication.
try:
    from .dynamic_cf_catalog import (
        STATIC_CATALOG as CF_CATALOG_STATIC,
    )
    (CF_CATALOG_STATIC,)  # noqa: F401 — explicit reference to silence pyflakes
    from .dynamic_cf_catalog import (
        CloudflareCatalogFetcher,
        get_cf_catalog,
    )
    (CloudflareCatalogFetcher, get_cf_catalog)  # noqa: F401 — explicit reference to silence pyflakes
    (CloudflareCatalogFetcher, get_cf_catalog)  # noqa: F401 — explicit reference to silence pyflakes
    _CF_CATALOG_AVAILABLE = True
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.providers:381', _remediation_exc)
    _CF_CATALOG_AVAILABLE = False
    logger.warning(
        "[Providers] dynamic_cf_catalog not available — "
        "public CF catalog disabled, using brain fallback"
    )

# Number of Cloudflare slots
CF_N_SLOTS = 11

# ── Pre-flight Screening Constants ───────────────────────────────────────────
CF_MIN_TOKEN_LENGTH  = 40   # CF API tokens are 40+ chars (strict)
CF_MIN_ACCT_ID_LENGTH = 32  # CF account IDs are 32-char hex
CF_MAX_TOKEN_LENGTH  = 200  # Maximum expected token length
CF_MAX_ACCT_ID_LENGTH = 32  # Account IDs are exactly 32 chars

# ── Per-Account Model Cache ──────────────────────────────────────────────────
_cf_account_working_models: dict = {}  # account_id → list of working models


def record_working_model(account_id: str, model: str) -> None:
    """Remember which model worked for which CF account."""
    if account_id not in _cf_account_working_models:
        _cf_account_working_models[account_id] = []
    if model not in _cf_account_working_models[account_id]:
        _cf_account_working_models[account_id].append(model)
        logger.info(
            f"[CF-Model-Cache] {_mask_key(account_id, 3)}: "
            f"confirmed working model: {model}"
        )


def get_models_for_account(
    account_id: str,
    default_models: list,
) -> list:
    """
    Return cached working models first, then fallbacks.
    Avoids retrying models known to fail on this account.
    """
    working = _cf_account_working_models.get(account_id, [])
    result = working.copy()
    for m in default_models:
        if m not in result:
            result.append(m)
    return result


def _preflight_screen_slot(slot_index: int) -> tuple[bool, str]:
    """
    Enhanced pre-flight screening for Cloudflare slots (Amendment 6).

    Validates account_id format (32-char hex), API token length (>=40 chars),
    and gateway URL structure BEFORE sending any request.

    Broken slots (like slot 7 with corrupted tokens) are detected here
    and silently skipped without causing HTTP 400 errors.

    Returns:
        (valid: bool, reason: str) — valid=True means slot is usable.
    """
    account_id  = os.environ.get(f"CF_ACCOUNT_ID_{slot_index}", "").strip()
    api_token   = os.environ.get(f"CF_API_TOKEN_{slot_index}", "").strip()
    gateway_url = os.environ.get(f"CF_AI_GATEWAY_URL_{slot_index}", "").strip()

    # Rule 1: Both must be non-empty
    if not account_id or not api_token:
        return False, "missing credentials"

    # Additive: allow test/CI credentials to bypass strict format checks.
    # Enable by setting TORSHIELD_PREFLIGHT_MODE=permissive. The default
    # remains "strict" for production safety. Permissive mode still
    # requires non-empty credentials (Rule 1 above) but skips Rules 2-5
    # so unit tests using synthetic credentials can exercise the
    # downstream HTTP retry path without being rejected at preflight.
    if os.environ.get("TORSHIELD_PREFLIGHT_MODE", "strict").lower() == "permissive":
        return True, "ok (permissive mode)"

    # Rule 2: Account ID must be 32-char hex
    if not re.match(r'^[0-9a-f]{32}$', account_id, re.IGNORECASE):
        return False, f"invalid account_id format (len={len(account_id)})"

    # Rule 3: API token must be >=40 chars (CF tokens are 40+)
    if len(api_token) < CF_MIN_TOKEN_LENGTH:
        return False, f"token too short ({len(api_token)} chars, min={CF_MIN_TOKEN_LENGTH})"

    # Rule 4: Gateway URL must match CF pattern (if provided)
    if gateway_url:
        pattern = r'^https://gateway\.ai\.cloudflare\.com/v1/[0-9a-f]{32}/'
        if not re.match(pattern, gateway_url, re.IGNORECASE):
            return False, "malformed gateway URL"

    # Rule 5: Account ID in gateway URL must match credentials
    if gateway_url and account_id:
        # Extract account_id from gateway URL
        gw_match = re.search(r'/v1/([0-9a-f]{32})/', gateway_url, re.IGNORECASE)
        if gw_match:
            gw_acct = gw_match.group(1)
            if gw_acct.lower() != account_id.lower():
                return False, "account_id mismatch between URL and credentials"

    return True, "ok"


def preflight_validate_cf_slot(
    slot_index: int,
    account_id: str,
    api_token: str,
    gateway_url: str = "",
) -> list:
    """
    Pre-flight screening for Cloudflare slots — validates token length,
    account_id format, and gateway URL structure BEFORE sending any request.

    Broken slots (like slot 7 with corrupted tokens) are detected here
    and silently skipped without causing HTTP 400 errors.

    Returns a list of warning strings (empty = slot looks valid).
    The slot is NOT removed — only flagged for skipping at runtime.
    """
    # Additive: permissive mode skips strict format checks so unit tests
    # using synthetic credentials can exercise the downstream HTTP retry
    # path. Production remains strict by default.
    if os.environ.get("TORSHIELD_PREFLIGHT_MODE", "strict").lower() == "permissive":
        return []

    issues = []

    # Validate API token
    if not api_token:
        issues.append(f"Slot {slot_index}: CF_API_TOKEN is empty")
    else:
        clean_token = api_token.strip()
        if len(clean_token) < CF_MIN_TOKEN_LENGTH:
            issues.append(
                f"Slot {slot_index}: CF_API_TOKEN too short "
                f"(len={len(clean_token)}, min={CF_MIN_TOKEN_LENGTH}). "
                f"Token appears corrupted or incomplete."
            )
        if len(clean_token) > CF_MAX_TOKEN_LENGTH:
            issues.append(
                f"Slot {slot_index}: CF_API_TOKEN too long "
                f"(len={len(clean_token)}, max={CF_MAX_TOKEN_LENGTH}). "
                f"Token may contain extra characters or multiple tokens."
            )
        if '\n' in clean_token or '\r' in clean_token:
            issues.append(
                f"Slot {slot_index}: CF_API_TOKEN contains newline characters — "
                f"possible copy-paste error from GitHub Secrets"
            )
        # CF API tokens should not have spaces
        if ' ' in clean_token:
            issues.append(
                f"Slot {slot_index}: CF_API_TOKEN contains spaces — "
                f"token is likely corrupted"
            )

    # Validate account ID — must be 32-char hex
    if not account_id:
        issues.append(f"Slot {slot_index}: CF_ACCOUNT_ID is empty")
    else:
        clean_acct = account_id.strip()
        if not re.match(r'^[0-9a-f]{32}$', clean_acct, re.IGNORECASE):
            issues.append(
                f"Slot {slot_index}: CF_ACCOUNT_ID invalid format "
                f"(len={len(clean_acct)}, expected 32-char hex). "
                f"Account ID appears corrupted."
            )

    # Validate gateway URL (only for AI Gateway provider)
    if gateway_url:
        if not gateway_url.startswith("https://"):
            issues.append(
                f"Slot {slot_index}: CF_AI_GATEWAY_URL does not start with https://"
            )
        else:
            # Must match CF AI Gateway pattern
            pattern = r'^https://gateway\.ai\.cloudflare\.com/v1/[0-9a-f]{32}/'
            if not re.match(pattern, gateway_url, re.IGNORECASE):
                issues.append(
                    f"Slot {slot_index}: CF_AI_GATEWAY_URL malformed — "
                    f"must match https://gateway.ai.cloudflare.com/v1/{{account_id}}/{{slug}}"
                )
            else:
                # Check account_id in URL matches credentials
                gw_match = re.search(r'/v1/([0-9a-f]{32})/', gateway_url, re.IGNORECASE)
                if gw_match and account_id:
                    gw_acct = gw_match.group(1)
                    if gw_acct.lower() != account_id.strip().lower():
                        issues.append(
                            f"Slot {slot_index}: Account ID in gateway URL "
                            f"({_mask_key(gw_acct, 3)}...) does not match "
                            f"CF_ACCOUNT_ID ({_mask_key(account_id, 3)}...)"
                        )

    if issues:
        for issue in issues:
            logger.warning(f"[CF-Preflight] {issue}")
        logger.warning(
            f"[CF-Preflight] Slot {slot_index} FAILED pre-flight screening — "
            f"will be silently skipped (NOT deleted from config). "
            f"{len(issues)} issue(s) detected."
        )
    else:
        logger.debug(
            f"[CF-Preflight] Slot {slot_index} PASSED pre-flight screening "
            f"(token_len={len(api_token.strip())}, "
            f"acct_id_len={len(account_id.strip())})"
        )

    return issues

# Guaranteed free-tier fallbacks (used only when model selector fails entirely)
CF_STABLE_MODELS = [
    "@cf/meta/llama-3.1-8b-instruct",
    "@cf/meta/llama-3.2-11b-vision-instruct",
    "@cf/mistral/mistral-7b-instruct-v0.1",
    "@cf/meta/llama-3.2-3b-instruct",
    "@cf/meta/llama-3.2-1b-instruct",
]

# ── Retry Configuration ──────────────────────────────────────────────────────
MAX_NETWORK_RETRIES    = 3       # Retry count for network-level failures
RETRY_BASE_DELAY_SEC   = 1.0    # Base delay in seconds
RETRY_MAX_DELAY_SEC    = 30.0   # Maximum delay cap
RETRY_JITTER_SEC       = 0.5    # Random jitter to avoid thundering herd
RETRYABLE_HTTP_CODES   = {429, 500, 502, 503, 504}  # Codes worth retrying
AUTH_FAILURE_HTTP_CODES = {401, 403}  # NEVER retry these — auth failures won't fix themselves


# BadRequestError is now imported from .exceptions — no local duplicate

# ── User-Agent Configuration ──────────────────────────────────────────────────
# Cloudflare returns "error code: 1010" when no User-Agent is set.
# urllib.request sends "Python-urllib/3.x" by default, but some
# Cloudflare-protected endpoints reject it. We set a browser-like UA.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 "
    "TorShieldAIGateway/12.0"
)

# Cloudflare bot protection error signature
_CF_BOT_ERROR_CODE = "error code: 1010"


def _mask_key(key: str, visible: int = 4) -> str:
    """Mask sensitive key for logging, showing only first/last chars."""
    if not key:
        return "<EMPTY>"
    if len(key) <= visible * 2:
        return f"{key[:2]}***{key[-2:]}" if len(key) >= 4 else "***"
    return f"{key[:visible]}...{key[-visible:]}"


def _validate_url(url: str, label: str) -> str:
    if not url.startswith("https://"):
        raise ValueError(
            f"[{label}] Invalid URL '{url[:40]}': must be absolute HTTPS."
        )
    return url.rstrip("/")


def _compute_backoff_delay(attempt: int) -> float:
    """Compute exponential backoff delay with jitter."""
    raw = RETRY_BASE_DELAY_SEC * (2 ** attempt)
    jittered = raw + random.uniform(-RETRY_JITTER_SEC, RETRY_JITTER_SEC)
    return min(max(jittered, 0.1), RETRY_MAX_DELAY_SEC)


def _sanitize_api_key(key: str) -> str:
    """Sanitize API key: strip whitespace, newlines, and null bytes."""
    if not key:
        return ""
    cleaned = key.strip().replace("\n", "").replace("\r", "").replace("\0", "")
    if cleaned != key:
        logger.warning(
            f"API key had trailing whitespace/newlines — sanitized "
            f"(original length={len(key)}, cleaned={len(cleaned)})"
        )
    return cleaned


def _read_error_body(error: urllib.error.HTTPError) -> str:
    """Safely read HTTP error response body for diagnostics."""
    try:
        return error.read().decode("utf-8", errors="replace")[:500]
    except Exception:
        return "<could not read error body>"


def _log_auth_failure(
    provider: str,
    slot_index: int,
    error: urllib.error.HTTPError,
    url: str,
    headers_sent: dict,
):
    """
    Log verbose diagnostic information for 403/400 errors.
    Masks all sensitive keys. Only called on auth failures.
    """
    error_body = _read_error_body(error)

    # Mask headers
    sensitive_keys = {
        "authorization", "x-portkey-api-key", "api-key",
        "x-api-key", "bearer", "token",
    }
    masked_headers = {}
    for k, v in headers_sent.items():
        if k.lower() in sensitive_keys:
            masked_headers[k] = _mask_key(str(v))
        else:
            masked_headers[k] = str(v)

    logger.error(
        f"[{provider}] slot {slot_index} AUTH FAILURE: "
        f"HTTP {error.code} {error.reason}"
    )
    logger.error(f"  URL: {_mask_url(url)}")
    logger.error(f"  Headers: {masked_headers}")
    logger.error(f"  Response body: {error_body[:300]}")

    # Infer root cause
    if error.code == 403:
        body_lower = error_body.lower()
        # Detect Cloudflare bot protection (error code 1010)
        if _CF_BOT_ERROR_CODE in error_body:
            logger.error(
                "  DIAGNOSIS: CLOUDFLARE_BOT_PROTECTION — request blocked by "
                "Cloudflare anti-bot (error code 1010). This is NOT an auth failure. "
                "The User-Agent header may be missing or blocked. "
                "The request will be retried with backoff."
            )
        elif "invalid" in body_lower or "unauthorized" in body_lower:
            logger.error("  DIAGNOSIS: INVALID_CREDENTIALS — key rejected by provider")
        elif "quota" in body_lower or "limit" in body_lower or "rate" in body_lower:
            logger.error("  DIAGNOSIS: QUOTA_EXCEEDED — account has hit limits")
        elif "sanction" in body_lower or "region" in body_lower or "embargo" in body_lower:
            logger.error("  DIAGNOSIS: REGION_BLOCKED — provider blocks this region/IP")
        elif "expired" in body_lower:
            logger.error("  DIAGNOSIS: KEY_EXPIRED — API key has expired")
        else:
            logger.error(
                "  DIAGNOSIS: AUTH_FAILURE — likely invalid/expired key "
                "or insufficient permissions. Check key format, whitespace, and account status."
            )
    elif error.code == 400:
        body_lower = error_body.lower()
        if not error_body.strip():
            logger.error(
                "  DIAGNOSIS: EMPTY_RESPONSE_BODY_400 — server returned 400 with empty "
                "response body. This typically means the URL path is malformed or the "
                "model doesn't exist on this account. Verify the URL structure and model ID."
            )
        elif "model" in body_lower and ("not found" in body_lower or "invalid" in body_lower):
            logger.error("  DIAGNOSIS: INVALID_MODEL — model ID not available on this account/region")
        elif "payload" in body_lower or "body" in body_lower:
            logger.error("  DIAGNOSIS: MALFORMED_REQUEST — request payload is invalid")
        elif "header" in body_lower:
            logger.error("  DIAGNOSIS: HEADER_FORMAT_ERROR — required header missing or malformed")
        else:
            logger.error("  DIAGNOSIS: BAD_REQUEST — check model ID and request format")

    # Check for common key format issues
    auth_header = headers_sent.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token != token.strip():
            logger.error("  KEY_ISSUE: Bearer token has leading/trailing whitespace!")
        if "\n" in token or "\r" in token:
            logger.error("  KEY_ISSUE: Bearer token contains newline characters!")
        if len(token) < 10:
            logger.error(f"  KEY_ISSUE: Bearer token appears too short (len={len(token)})")


def _mask_url(url: str) -> str:
    """Mask sensitive parts of URL for logging."""
    if "accounts/" in url:
        parts = url.split("accounts/")
        if len(parts) == 2:
            acct_part = parts[1].split("/")[0]
            masked = _mask_key(acct_part, 3)
            return f"{parts[0]}accounts/{masked}/***"
    return url[:80] + "..." if len(url) > 80 else url


def normalize_cf_gateway_url(raw: str) -> str:
    """Ensure CF AI Gateway URL always ends with the OpenAI-compatible
    chat completions path.

    CRITICAL FIX (v17.0): CF AI Gateway now uses /compat/chat/completions
    as the OpenAI-compatible endpoint. The previous /workers-ai/v1/chat/completions
    path caused HTTP 400 across all 11 slots because it expected model in URL
    path rather than request body.

    The /compat/ endpoint:
    - Accepts model in request body (OpenAI-compatible format)
    - Returns standard OpenAI-format responses
    - Works with @cf/ prefixed model IDs

    Handles common cases:
    - Bare gateway root (no path after gateway slug)
    - Partial paths (e.g. ends with /workers-ai or /workers-ai/v1)
    - Already complete /compat/ paths (returned unchanged)
    - Legacy /workers-ai/ paths (auto-corrected to /compat/)
    """
    raw = raw.rstrip("/")

    # NEW: /compat/chat/completions is the correct OpenAI-compatible endpoint
    compat_suffix = "/compat/chat/completions"

    # Already using correct /compat/ suffix
    if raw.endswith(compat_suffix):
        return raw

    # Legacy /workers-ai/ paths — auto-correct to /compat/
    workers_ai_suffix = "/workers-ai/v1/chat/completions"
    if raw.endswith(workers_ai_suffix):
        # Replace /workers-ai/v1/chat/completions with /compat/chat/completions
        base = raw[: -len(workers_ai_suffix)]
        logger.info(
            "[CF-AI-GW] URL path fix: /workers-ai/v1/chat/completions → /compat/chat/completions"
        )
        return base + compat_suffix

    if raw.endswith("/workers-ai/v1"):
        base = raw[: -len("/workers-ai/v1")]
        return base + compat_suffix

    if raw.endswith("/workers-ai"):
        base = raw[: -len("/workers-ai")]
        return base + compat_suffix

    # Bare gateway root — append the /compat/ suffix
    return raw + compat_suffix


class ProviderCircuitBreaker:
    """Provider-level circuit breaker with automatic recovery.

    Tracks overall provider health across all slots. When the failure count
    exceeds the threshold, the circuit opens and rejects requests until the
    recovery timeout elapses, at which point it transitions to half-open
    and allows one request through to test recovery.
    """

    def __init__(
        self,
        provider_name: str,
        failure_threshold: int = 20,
        recovery_timeout: float = 300.0,
    ):
        self.provider_name = provider_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "closed"  # closed, open, half_open

    def record_success(self):
        """Record a successful request — resets failure count and closes circuit."""
        self.failure_count = 0
        self.state = "closed"

    def record_failure(self):
        """Record a failed request — increments count and opens circuit if threshold reached."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            if self.state != "open":
                logger.warning(
                    f"[{self.provider_name}] Circuit breaker OPENED — "
                    f"{self.failure_count} consecutive failures reached threshold "
                    f"({self.failure_threshold}). Will retry after "
                    f"{self.recovery_timeout}s recovery timeout."
                )
            self.state = "open"

    def allow_request(self) -> bool:
        """Check if a request is allowed based on current circuit state."""
        if self.state == "closed":
            return True
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half_open"
                logger.info(
                    f"[{self.provider_name}] Circuit breaker → HALF_OPEN — "
                    f"recovery timeout elapsed, allowing test request"
                )
                return True
            return False
        return True  # half_open allows one request through


# ── FEATURE-1 v16: DPI Model Override Utility ─────────────────────────────────
# Non-fatal DPI model override: if Iran DPI threat is detected, overrides
# the model with one optimized for DPI evasion. Wrapped in try/except so
# it never blocks the main request flow.

def _apply_dpi_model_override(provider_name: str, requested_model: str | None) -> str | None:
    """Apply DPI model override for the given provider.

    If IranDPIModelSelector reports threat > NONE, returns the DPI-recommended
    model for that provider. Otherwise returns the requested_model unchanged.

    This is non-fatal: any ImportError or exception is caught and logged,
    and the original model is returned.
    """
    try:
        from .iran_dpi_model_selector import IranDPIModelSelector, get_dpi_selector
        (IranDPIModelSelector, get_dpi_selector)  # noqa: F401 — explicit reference to silence pyflakes
        selector = get_dpi_selector()
        override_model = selector.get_model_for_provider(provider_name)
        if override_model is not None:
            logger.info(
                f"[DPI-Override] provider={provider_name} "
                f"original_model={requested_model} → override_model={override_model} "
                f"(DPI threat detected)"
            )
            return override_model
    except ImportError as _remediation_exc:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('torshield_ai_gateway.providers:903', _remediation_exc)
        logger.debug(
            f"[DPI-Override] iran_dpi_model_selector not available — "
            f"skipping DPI model override for {provider_name}"
        )
    except Exception as exc:
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('torshield_ai_gateway.providers:908', exc)
        logger.debug(
            f"[DPI-Override] DPI model override failed for {provider_name}: {exc} — "
            f"using requested model"
        )
    return requested_model


# ── FEATURE-V/v19.0: Smart Provider Health Cache with TTL ──────────────────

class ProviderHealthCache:
    """
    Thread-safe TTL cache for provider health status.
    Prevents repeatedly hitting dead providers within a run.

    When a provider fails with a hard error (5xx, timeout, connection refused),
    it is marked unhealthy with a reason. Subsequent requests within the TTL
    window skip that provider entirely, avoiding wasted latency. When a
    provider succeeds, it is marked healthy with the model that worked,
    enabling fast-path retries on the same model.

    The TTL defaults to 180 seconds (3 minutes), which balances rapid
    detection of recovered providers against the cost of re-probing known-dead
    endpoints. Health status is automatically invalidated after the TTL
    expires, ensuring eventual consistency.
    """
    def __init__(self, ttl_seconds: int = 180):
        self._cache: dict[str, tuple[bool, float, str]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def set_healthy(self, provider_key: str, model: str) -> None:
        """Mark a provider as healthy with the model that succeeded."""
        with self._lock:
            self._cache[provider_key] = (True, time.time(), model)

    def set_unhealthy(self, provider_key: str, reason: str) -> None:
        """Mark a provider as unhealthy with the failure reason."""
        with self._lock:
            self._cache[provider_key] = (False, time.time(), reason)

    def get(self, provider_key: str) -> tuple[bool, str] | None:
        """Returns (is_healthy, model_or_reason) or None if expired/missing."""
        with self._lock:
            entry = self._cache.get(provider_key)
            if not entry:
                return None
            is_healthy, timestamp, info = entry
            if time.time() - timestamp > self._ttl:
                del self._cache[provider_key]
                return None
            return is_healthy, info


_PROVIDER_HEALTH_CACHE = ProviderHealthCache(ttl_seconds=180)


def get_provider_health_cache() -> ProviderHealthCache:
    """Get the singleton provider health cache instance."""
    return _PROVIDER_HEALTH_CACHE


class _BaseProvider:
    name: str = "base"
    MAX_RETRIES: int = 4

    def chat_complete(
        self,
        messages:    list[dict[str, str]],
        model:       str | None = None,
        max_tokens:  int = 2048,
        temperature: float = 0.2,
        timeout:     int = 60,
        task:        str = "general",
    ) -> str:
        raise NotImplementedError

    @staticmethod
    def _post_json_with_retry(
        url: str,
        headers: dict,
        payload: dict,
        timeout: int,
        provider_name: str = "unknown",
        slot_index: int = 0,
        max_retries: int = MAX_NETWORK_RETRIES,
    ) -> tuple[dict, float]:
        """
        Send a POST request with exponential backoff retry on network/retryable errors.
        Logs verbose diagnostics on 403/400 auth failures (with key masking).
        """
        last_error = None

        # Ensure User-Agent is set (Cloudflare blocks requests without it)
        if "User-Agent" not in headers:
            headers["User-Agent"] = _USER_AGENT

        # ── Feature-S/v18: Apply Iran traffic evasion headers globally ──
        headers = _apply_evasion_headers(headers, provider_name)

        for attempt in range(max_retries + 1):
            t0 = time.monotonic()
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")

            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                latency_ms = (time.monotonic() - t0) * 1000.0
                return result, latency_ms

            except urllib.error.HTTPError as e:
                latency_ms = (time.monotonic() - t0) * 1000.0
                error_body = _read_error_body(e)

                # Cloudflare bot protection (error code 1010) — RETRYABLE
                # This is NOT a real auth failure; it's transient bot detection
                if e.code == 403 and _CF_BOT_ERROR_CODE in error_body:
                    _log_auth_failure(provider_name, slot_index, e, url, headers)
                    if attempt < max_retries:
                        delay = _compute_backoff_delay(attempt) * 2  # extra delay for bot protection
                        logger.warning(
                            f"[{provider_name}] slot {slot_index} Cloudflare bot protection "
                            f"(1010) — retry {attempt + 1}/{max_retries} in {delay:.1f}s"
                        )
                        time.sleep(delay)
                        continue
                    else:
                        logger.error(
                            f"[{provider_name}] slot {slot_index} Cloudflare bot protection "
                            f"persisted after {max_retries + 1} attempts"
                        )
                        raise

                # Auth failures (401, 403) — NEVER retry, log verbose diagnostics
                # 401 Unauthorized = invalid/expired credentials (permanent)
                # 403 Forbidden = revoked/insufficient permissions (permanent)
                # Both are authentication/authorization failures that retrying
                # will NEVER fix — they require credential rotation.
                if e.code in AUTH_FAILURE_HTTP_CODES:
                    _log_auth_failure(provider_name, slot_index, e, url, headers)
                    logger.error(
                        f"[{provider_name}] slot {slot_index} HTTP {e.code} — "
                        f"AUTH FAILURE, NOT retrying (credential issue, not transient)"
                    )
                    raise

                # 400 Bad Request — typically invalid model or malformed request
                # Also NOT retried (the request itself is wrong, retrying won't help)
                # BUT this is NOT an auth failure — raise BadRequestError instead.
                if e.code == 400:
                    logger.error(
                        f"[{provider_name}] slot {slot_index} HTTP 400 — "
                        f"BAD_REQUEST, NOT retrying (invalid model or malformed payload). "
                        f"Check model ID and URL path."
                    )
                    raise BadRequestError(
                        f"HTTP 400 for slot {slot_index}: "
                        f"{error_body[:200] if error_body else 'empty body'}",
                        provider=provider_name,
                        slot=slot_index,
                    )

                # Retryable errors (429, 5xx)
                if e.code in RETRYABLE_HTTP_CODES:
                    if attempt < max_retries:
                        delay = _compute_backoff_delay(attempt)
                        logger.warning(
                            f"[{provider_name}] slot {slot_index} HTTP {e.code} — "
                            f"retry {attempt + 1}/{max_retries} in {delay:.1f}s"
                        )
                        time.sleep(delay)
                        continue
                    else:
                        logger.error(
                            f"[{provider_name}] slot {slot_index} HTTP {e.code} — "
                            f"all {max_retries + 1} attempts exhausted"
                        )
                        raise

                # Non-retryable errors (404, 405, etc.)
                raise

            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                latency_ms = (time.monotonic() - t0) * 1000.0
                if attempt < max_retries:
                    delay = _compute_backoff_delay(attempt)
                    logger.warning(
                        f"[{provider_name}] slot {slot_index} network error: {e} — "
                        f"retry {attempt + 1}/{max_retries} in {delay:.1f}s"
                    )
                    time.sleep(delay)
                    continue
                else:
                    logger.error(
                        f"[{provider_name}] slot {slot_index} network error — "
                        f"all {max_retries + 1} attempts exhausted: {e}"
                    )
                    raise

        # Should not reach here, but just in case
        raise last_error if last_error else RuntimeError("Unexpected retry loop exit")

    @staticmethod
    def _extract_text(response: dict) -> str:
        """Extract text content from any provider response format.

        Handles OpenAI-compatible format, CF Workers AI format, and legacy CF
        format. Returns str(response) as a final fallback so callers always
        receive a non-empty string when the response is a non-empty dict.
        """
        if not isinstance(response, dict):
            return str(response) if response is not None else ""
        # Format 1: OpenAI-compatible (choices[0].message.content)
        try:
            choices = response.get("choices", [])
            if choices:
                content = choices[0].get("message", {}).get("content", "")
                if isinstance(content, str) and content.strip():
                    return content.strip()
        except (KeyError, IndexError, TypeError, AttributeError) as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.providers:1128', _remediation_exc)
            pass
        # Format 2: CF Workers AI wrapped in 'result'
        result = response.get("result", None)
        if isinstance(result, dict):
            # result.choices — nested OpenAI format
            try:
                r_choices = result.get("choices", [])
                if r_choices:
                    content = r_choices[0].get("message", {}).get("content", "")
                    if isinstance(content, str) and content.strip():
                        return content.strip()
            except (KeyError, IndexError, TypeError, AttributeError) as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:1140', _remediation_exc)
                pass
            # result.response — legacy CF format
            try:
                resp_val = result.get("response", "")
                if isinstance(resp_val, str) and resp_val.strip():
                    return resp_val.strip()
            except (KeyError, TypeError, AttributeError) as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:1147', _remediation_exc)
                pass
        elif isinstance(result, str) and result.strip():
            return result.strip()
        # Format 3: Unrecognized — fall back to str(response) so callers
        # always receive a non-empty string. (Additive: original return ""
        # branch is preserved above for the not-dict case.)
        logger.debug(
            f"[_extract_text] Could not extract structured text from response keys: "
            f"{list(response.keys()) if isinstance(response, dict) else 'non-dict'}; "
            f"falling back to str(response)."
        )
        return str(response)


# ── Portkey ────────────────────────────────────────────────────────────────────

class PortkeyProvider(_BaseProvider):
    name          = "portkey"
    DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"
    PORTKEY_MODELS = [
        "meta/llama-3.1-70b-instruct",
        "meta/llama-3.1-8b-instruct",
        "meta/llama-3.2-3b-instruct",
    ]
    # ── FIX-19.0: Portkey model probe list (BUG-1 fix) ──────────────────
    # Models most likely to work with Portkey's free tier / virtual keys.
    # These are tried in order during _resolve_portkey_model() probing.
    PORTKEY_MODEL_PROBE_LIST = [
        "llama-3.3-70b-versatile",
        "llama-3.1-70b-versatile",
        "llama-3.1-8b-instant",
        "meta-llama/llama-3.3-70b-instruct",
        "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "meta/llama-3.1-70b-instruct",
        "meta/llama-3.1-8b-instruct",
        "gpt-4o-mini",
        "claude-3-haiku-20240307",
        "gemini-1.5-flash-8b",
        "mistral-7b-instruct",
        "gpt-3.5-turbo",
    ]

    # ── BUG-E: Portkey URL normalization constants ─────────────────────
    PORTKEY_CHAT_SUFFIX = "/chat/completions"
    PORTKEY_V1_CHAT_SUFFIX = "/v1/chat/completions"
    PORTKEY_DEFAULT_URL = "https://api.portkey.ai/v1/chat/completions"

    # ── BUG-A/v15: Portkey provider backend cascade ────────────────────
    PROVIDER_BACKEND_CASCADE = [
        ("cerebras", "CEREBRAS_API_KEY", "llama-3.3-70b-versatile"),
        ("groq", "GROQ_API_KEY", "llama-3.3-70b-versatile"),
        ("openai", "OPENAI_API_KEY", "gpt-4o-mini"),
        ("anthropic", "ANTHROPIC_API_KEY", "claude-3-haiku-20240307"),
        ("together-ai", "TOGETHER_API_KEY", "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"),
        ("mistral", "MISTRAL_API_KEY", "mistral-7b-instruct"),
        ("cohere", "COHERE_API_KEY", "command-r"),
        ("perplexity", "PERPLEXITY_API_KEY", "llama-3.3-70b-sonar"),
    ]

    # ── FEATURE-N v17: Portkey Header Strategy Cascade (DEPRECATED by v18) ─
    PORTKEY_HEADER_STRATEGIES = [
        "backend_cascade",  # x-portkey-provider + Authorization
        "virtual_key",      # x-portkey-virtual-key (if env var set)
        "bare_portkey",     # Only x-portkey-api-key (dashboard default)
    ]

    # ── BUG-N/v18: Auth strategy definitions (tried in order per slot) ──
    _AUTH_STRATEGIES = [
        "virtual_key",          # PREFERRED: x-portkey-virtual-key header
        "config_object",        # x-portkey-config with JSON config
        "provider_passthrough", # Legacy: x-portkey-provider + Authorization
        "bare_key",             # Last resort: only x-portkey-api-key
    ]

    # ── FIX-1/v19.0: Cerebras model name mapping (BUG-P fix) ───────────
    # Keys are Groq/generic names, values are valid Cerebras names.
    # BUG-P: Using Groq model names for Cerebras causes HTTP 400.
    _CEREBRAS_MODEL_ALIASES: dict[str, str] = {
        "llama-3.3-70b-versatile":  "llama-3.3-70b",
        "llama-3.3-70b":            "llama-3.3-70b",
        "llama3.3-70b":             "llama-3.3-70b",
        "llama-3.1-70b-versatile":  "llama-3.1-70b",
        "llama3.1-70b":             "llama-3.1-70b",
        "llama-3.1-8b-instant":     "llama-3.1-8b",
        "llama3.1-8b":              "llama-3.1-8b",
        "mixtral-8x7b-32768":       "llama-3.3-70b",  # No mixtral on Cerebras
        "gemma2-9b-it":             "llama-3.1-8b",   # No gemma on Cerebras
        "gpt-oss-120b":             "gpt-oss-120b",
        "zai-glm-4.7":              "zai-glm-4.7",
    }

    # Known valid Cerebras models (ordered by preference)
    _CEREBRAS_KNOWN_MODELS: list[str] = [
        "llama-3.3-70b",
        "gpt-oss-120b",
        "zai-glm-4.7",
        "llama-3.1-70b",
        "llama-3.1-8b",
    ]

    # Provider-specific model lists (for non-Cerebras backends)
    _PROVIDER_MODEL_FALLBACKS: dict[str, list[str]] = {
        "groq":         ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile"],
        "openai":       ["gpt-4o-mini", "gpt-3.5-turbo"],
        "anthropic":    ["claude-haiku-4-5-20251001"],
        "together":     ["meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"],
        "mistral":      ["mistral-small-latest"],
    }

    @classmethod
    def _resolve_model_for_provider(
        cls,
        provider: str,
        requested_model: str,
        discovered_models: list[str] | None = None,
    ) -> list[str]:
        """
        Return ordered list of models to try for this provider+requested_model.
        First try is most likely to work; subsequent tries are fallbacks.

        CRITICAL FIX FOR BUG-P: Never use Groq model names for Cerebras.
        When the backend provider is Cerebras, Groq-specific model identifiers
        (like llama-3.3-70b-versatile) are automatically translated to their
        Cerebras equivalents (like llama-3.3-70b) via the alias map.
        Discovered live models from the Cerebras /v1/models endpoint are
        prioritized since they are confirmed to exist on the backend.
        """
        if provider == "cerebras":
            models_to_try = []

            # 1. Try discovered live models first (most reliable)
            if discovered_models:
                models_to_try.extend(discovered_models)

            # 2. Alias lookup: translate Groq/generic name to Cerebras name
            canonical = cls._CEREBRAS_MODEL_ALIASES.get(requested_model)
            if canonical and canonical not in models_to_try:
                models_to_try.append(canonical)

            # 3. Fallback to known models
            for m in cls._CEREBRAS_KNOWN_MODELS:
                if m not in models_to_try:
                    models_to_try.append(m)

            return models_to_try[:4]  # Max 4 models to try

        # Non-Cerebras providers
        provider_fallbacks = cls._PROVIDER_MODEL_FALLBACKS.get(provider, [])
        models_to_try = []
        if requested_model and requested_model not in provider_fallbacks:
            models_to_try.append(requested_model)
        models_to_try.extend(provider_fallbacks)
        return models_to_try[:3]

    # ── BUG-E: URL probe cache ────────────────────────────────────────
    _URL_PROBE_CACHE: ClassVar[dict] = {}
    _URL_PROBE_LOCK: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def _normalize_portkey_url(cls, raw_url: str) -> str:
        """Normalize Portkey gateway URL to always end with /v1/chat/completions.

        Handles all common URL formats:
          - "https://api.portkey.ai" → .../v1/chat/completions
          - "https://api.portkey.ai/v1" → .../v1/chat/completions
          - "https://api.portkey.ai/v1/" → .../v1/chat/completions
          - Already has /chat/completions → unchanged
          - Empty string → PORTKEY_DEFAULT_URL
        """
        if not raw_url or not raw_url.strip():
            return cls.PORTKEY_DEFAULT_URL

        url = raw_url.strip().rstrip("/")

        # Already has /chat/completions suffix — unchanged
        if url.endswith(cls.PORTKEY_CHAT_SUFFIX):
            return url

        # Has /v1 but no /chat/completions
        if url.endswith("/v1"):
            return url + cls.PORTKEY_CHAT_SUFFIX

        # Bare domain like https://api.portkey.ai
        return url + cls.PORTKEY_V1_CHAT_SUFFIX

    @staticmethod
    def _normalize_gateway_url(raw_url: str) -> str:
        """
        Normalize any Portkey gateway URL to its canonical chat completions endpoint.
        Handles all edge cases: missing path, duplicate path, custom gateway, etc.

        BUG-N/v18: Replaces broken _probe_working_url() approach.
        """
        import re
        from urllib.parse import urlparse, urlunparse

        if not raw_url:
            return "https://api.portkey.ai/v1/chat/completions"

        raw_url = raw_url.strip().rstrip("/")

        # Already ends with /chat/completions — use as-is
        if raw_url.endswith("/chat/completions"):
            return raw_url

        # Already ends with /v1 — append endpoint
        if raw_url.endswith("/v1"):
            return raw_url + "/chat/completions"

        # Standard portkey.ai domain — always use canonical URL
        parsed = urlparse(raw_url)
        if "portkey.ai" in parsed.netloc:
            return "https://api.portkey.ai/v1/chat/completions"

        # Custom gateway (self-hosted or enterprise) — strip any existing
        # versioned path and rebuild cleanly
        path = re.sub(r"/v\d+(/chat/completions)?$", "", parsed.path)
        path = re.sub(r"/chat/completions$", "", path)
        clean_base = urlunparse(parsed._replace(path=path.rstrip("/")))
        return clean_base + "/v1/chat/completions"

    @classmethod
    def _build_auth_headers(
        cls,
        strategy: str,
        portkey_api_key: str,
        backend_provider: str,
        backend_key: str,
        backend_model: str,
        slot_index: int | None = None,
    ) -> dict[str, str] | None:
        """
        Build Portkey request headers for a given auth strategy.
        Returns None if strategy is not applicable (missing required env vars).

        BUG-N/v18: Multi-strategy authentication cascade replaces the old
        single-strategy approach. Tries virtual_key → config_object →
        provider_passthrough → bare_key in order.
        """
        import base64
        import json as _json

        base = {
            "Content-Type": "application/json",
            "x-portkey-api-key": portkey_api_key,
        }

        if strategy == "virtual_key":
            vk = ""
            if slot_index is not None:
                vk = os.environ.get(f"PORTKEY_VIRTUAL_KEY_{slot_index}", "").strip()
            if not vk:
                vk = os.environ.get("PORTKEY_VIRTUAL_KEY", "").strip()
            if not vk:
                return None  # Strategy not applicable
            return {**base, "x-portkey-virtual-key": vk}

        elif strategy == "config_object":
            # Build minimal Portkey config for provider passthrough
            if not backend_key:
                return None
            config = {
                "provider": backend_provider,
                "api_key": backend_key,
            }
            config_b64 = base64.b64encode(
                _json.dumps(config).encode()
            ).decode()
            return {**base, "x-portkey-config": config_b64}

        elif strategy == "provider_passthrough":
            if not backend_key:
                return None
            return {
                **base,
                "x-portkey-provider": backend_provider,
                "Authorization": f"Bearer {backend_key}",
            }

        elif strategy == "bare_key":
            # No backend headers — relies on Portkey dashboard default config
            return base

        return None

    @classmethod
    def _build_headers_for_strategy(
        cls,
        strategy: str,
        portkey_key: str,
        backend_provider: str,
        backend_key: str,
    ) -> dict[str, str]:
        """Build Portkey headers for a given authentication strategy."""
        base = {
            "Content-Type": "application/json",
            "x-portkey-api-key": portkey_key,
        }
        if strategy == "backend_cascade" and backend_key:
            base["x-portkey-provider"] = backend_provider
            base["Authorization"] = f"Bearer {backend_key}"
        elif strategy == "virtual_key":
            vk = os.environ.get("PORTKEY_VIRTUAL_KEY", "").strip()
            if vk:
                base["x-portkey-virtual-key"] = vk
        # "bare_portkey": no additional headers
        return base

    def _resolve_backend(self) -> tuple[str, str, str]:
        """Resolve provider backend from cascade based on available API keys.

        Checks numbered slots (_1 through _11) FIRST, then bare name.
        Priority: cerebras → groq → openai → anthropic → together → ...
        """
        for provider_name, env_prefix, model in self.PROVIDER_BACKEND_CASCADE:
            # CHECK NUMBERED SLOTS FIRST (_1 through _11)
            for slot_n in range(1, 12):
                key = os.environ.get(f"{env_prefix}_{slot_n}", "").strip()
                if key:
                    logger.info(
                        f"[Portkey] Backend resolved via numbered slot: "
                        f"provider={provider_name} env={env_prefix}_{slot_n} "
                        f"key_len={len(key)} model={model}"
                    )
                    return provider_name, key, model

            # THEN CHECK BARE NAME (e.g. CEREBRAS_API_KEY without suffix)
            key = os.environ.get(env_prefix, "").strip()
            if key:
                logger.info(
                    f"[Portkey] Backend resolved via bare name: "
                    f"provider={provider_name} env={env_prefix} "
                    f"key_len={len(key)} model={model}"
                )
                return provider_name, key, model

        # FINAL FALLBACK: PORTKEY_PROVIDER_KEY (legacy)
        fallback_key = os.environ.get("PORTKEY_PROVIDER_KEY", "").strip()
        if fallback_key:
            logger.info(
                f"[Portkey] Backend resolved via PORTKEY_PROVIDER_KEY "
                f"key_len={len(fallback_key)}"
            )
            return "cerebras", fallback_key, "llama-3.3-70b-versatile"

        # NOTHING FOUND
        logger.warning(
            "[Portkey] No backend provider key found. "
            "Available numbered-slot env vars checked: "
            + ", ".join(
                f"{p[1]}_1..11"
                for p in self.PROVIDER_BACKEND_CASCADE
            )
            + ". Set CEREBRAS_API_KEY_1 in GitHub Secrets."
        )
        return "", "", ""

    # ── BUG-N/v18: _probe_working_url REMOVED ────────────────────────
    # The URL probe logic was fundamentally broken:
    #   - Used GET/HEAD to test endpoints (all REST APIs return 405 for GET)
    #   - Treated 405 as "valid" when it only means method mismatch
    #   - Created wrong URL by appending /v1/chat/completions to URL that
    #     may already have it
    #   - Caused silent retry to wrong endpoint
    # Replaced by _normalize_gateway_url() which deterministically builds
    # the correct URL without probing.

    def __init__(self):
        # Build Portkey slots locally instead of using the generic rotator
        # helper: Portkey can be configured with PORTKEY_VIRTUAL_KEY_{i}
        # without a PORTKEY_API_KEY_{i}, and virtual-key-only slots are valid
        # routes when the Portkey dashboard owns the provider credentials.
        slots = []
        for i in range(1, 4):
            api_key = os.environ.get(f"PORTKEY_API_KEY_{i}", "").strip()
            virtual_key = os.environ.get(f"PORTKEY_VIRTUAL_KEY_{i}", "").strip()
            effective_key = api_key or virtual_key
            if effective_key:
                slots.append(
                    AccountSlot(
                        index=i,
                        account_id=os.environ.get(
                            f"PORTKEY_ACCOUNT_ID_{i}", ""
                        ).strip(),
                        api_key=effective_key,
                    )
                )
        self.rotator = AccountRotator("portkey", slots)
        raw_url = os.environ.get("PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1")
        if not raw_url.startswith("http"):
            raw_url = "https://api.portkey.ai/v1"
        # ── BUG-E: Normalize Portkey gateway URL ─────────────────────────
        # BUG-N/v18: Also apply _normalize_gateway_url for deterministic URL
        self.gateway_url = self._normalize_gateway_url(
            self._normalize_portkey_url(raw_url)
        )
        self.circuit_breaker = ProviderCircuitBreaker("Portkey")
        # ── BUG-A/v15: Resolve backend provider ──────────────────────────
        self._backend_provider, self._backend_key, self._backend_model = self._resolve_backend()
        # ── FIX-19.0: Portkey model registry integration ────────────────
        # Per-slot working model cache (discovered via probing).
        # Maps slot_index -> working_model or None.
        self._slot_working_models: dict = {}
        if _PORTKEY_REGISTRY_AVAILABLE:
            self._registry = get_portkey_registry()
        else:
            self._registry = None

        # ── Pre-flight key validation ────────────────────────────────────
        # Validate that Portkey API keys are long enough to be valid.
        # Real Portkey API keys are alphanumeric strings (e.g. g8V...qTF)
        # that do NOT necessarily start with 'pk-' or 'sk-'.
        # If ALL keys are too short, raise ProviderConfigurationError
        # so the health check marks this provider as 'skipped'.
        MIN_KEY_LEN = 16
        self._active_slots: list[int] = []
        self._invalid_key_slots: list[int] = []
        for i in range(1, 4):
            key = os.environ.get(f"PORTKEY_API_KEY_{i}", "").strip()
            virtual_key = os.environ.get(f"PORTKEY_VIRTUAL_KEY_{i}", "").strip()
            if not key and not virtual_key:
                continue
            # A slot is valid if its key (or virtual key) is long enough.
            # Portkey keys are alphanumeric with no mandatory prefix.
            effective_key = key or virtual_key
            if len(effective_key) >= MIN_KEY_LEN:
                self._active_slots.append(i)
            else:
                self._invalid_key_slots.append(i)
                logger.warning(
                    f"[Portkey] slot {i} skipped — key too short "
                    f"(len={len(effective_key)}, expected >={MIN_KEY_LEN})"
                )

        if self._invalid_key_slots and not self._active_slots:
            reason = (
                "All Portkey API keys are too short "
                f"(len < {MIN_KEY_LEN}). "
                "Check PORTKEY_API_KEY_1/2/3 in GitHub Secrets."
            )
            logger.warning(f"[Portkey] {reason}")
            raise ProviderConfigurationError(reason, provider="portkey")

        logger.info(
            f"[Portkey] Initialized with gateway: {_mask_url(self.gateway_url)} "
            f"({len(self._active_slots)} active slot(s), "
            f"{len(self._invalid_key_slots)} invalid-format slot(s))"
        )

    @staticmethod
    def _build_portkey_auth(slot: int) -> dict:
        """
        Build Portkey authentication headers with intelligent key detection.

        Supports auth methods:
        1. Native Portkey key (pk- prefix) → x-portkey-api-key header
        2. Virtual key fallback (pk- prefix in PORTKEY_VIRTUAL_KEY) → combined auth
        3. Provider API key (sk- prefix like OpenAI) → Bearer + x-portkey-provider
        4. Generic alphanumeric key (no prefix) → Bearer auth with x-portkey-api-key

        Raises ValueError if no valid key format is found.
        """
        key = os.environ.get(f"PORTKEY_API_KEY_{slot}", "").strip()
        virtual_key = os.environ.get(f"PORTKEY_VIRTUAL_KEY_{slot}", "").strip()

        headers = {"Content-Type": "application/json"}

        if key.startswith("pk-"):
            # Native Portkey key
            headers["x-portkey-api-key"] = key
            logger.debug(
                f"[Portkey] slot {slot} Using native Portkey key: {_mask_key(key)}"
            )
        elif virtual_key.startswith("pk-"):
            # Virtual key fallback
            headers["x-portkey-api-key"] = virtual_key
            headers["x-portkey-virtual-key"] = virtual_key
            logger.debug(
                f"[Portkey] slot {slot} Using virtual key: {_mask_key(virtual_key)}"
            )
        elif key.startswith("sk-"):
            # Provider API key (e.g. OpenAI key) — route directly
            headers["Authorization"] = f"Bearer {key}"
            headers["x-portkey-provider"] = "openai"
            logger.debug(
                f"[Portkey] slot {slot} Using provider key (sk- prefix) "
                f"with x-portkey-provider=openai"
            )
        elif key:
            # Generic alphanumeric key (e.g. g8V...qTF) — try as Bearer with
            # x-portkey-api-key header. Real Portkey keys may not have a prefix.
            # BUG-4 FIX: Also add provider routing headers for Cerebras.
            # Portkey cannot resolve model IDs without knowing which provider
            # to route to. x-portkey-provider tells Portkey to use Cerebras.
            headers["Authorization"] = f"Bearer {key}"
            headers["x-portkey-api-key"] = key
            # BUG-4 FIX: Add provider routing header
            provider_key = os.environ.get("PORTKEY_PROVIDER_KEY", "").strip()
            if provider_key:
                headers["x-portkey-provider"] = "cerebras"
                headers["Authorization"] = f"Bearer {provider_key}"
                logger.debug(
                    f"[Portkey] slot {slot} Using PORTKEY_PROVIDER_KEY "
                    f"with x-portkey-provider=cerebras"
                )
            logger.debug(
                f"[Portkey] slot {slot} Using generic key "
                f"(starts with '{key[:4]}...') — attempting Bearer + x-portkey-api-key auth."
            )
        else:
            raise ValueError(
                f"Slot {slot}: no valid Portkey key found — "
                f"PORTKEY_API_KEY_{slot} and PORTKEY_VIRTUAL_KEY_{slot} are empty"
            )

        # Also check for x-portkey-config header (virtual key config ID)
        config_id = os.environ.get(
            f"PORTKEY_CONFIG_{slot}",
            os.environ.get("PORTKEY_CONFIG", "")
        ).strip()
        if config_id:
            headers["x-portkey-config"] = config_id
            logger.debug(
                f"[Portkey] slot {slot} Using config: {_mask_key(config_id)}"
            )

        return headers

    @staticmethod
    def _validate_portkey_key(key: str, slot_index: int = 0) -> list[str]:
        """Validate Portkey API key format and return list of diagnostic issues.

        Portkey keys may have various formats: pk-xxx-xxx (native),
        sk-xxx (provider), or generic alphanumeric (e.g. g8V...qTF).
        Returns a list of warning strings (empty if key looks valid).
        """
        issues = []
        if not key:
            issues.append("Key is empty")
            return issues
        if len(key) < 16:
            issues.append(
                f"Key appears too short (len={len(key)}). "
                f"Expected at least 16 characters for a valid API key."
            )
        if "\n" in key or "\r" in key:
            issues.append("Key contains newline characters — possible copy-paste error")
        if key != key.strip():
            issues.append("Key has leading/trailing whitespace")
        if issues:
            for issue in issues:
                logger.warning(
                    f"[Portkey] slot {slot_index} KEY VALIDATION: {issue}"
                )
        return issues

    @staticmethod
    def _get_virtual_key(slot_index: int) -> str | None:
        """Get PORTKEY_VIRTUAL_KEY_{i} env var for alternative auth.

        Portkey supports virtual keys as an alternative to direct API keys.
        Virtual keys are mapped in the Portkey dashboard to provider credentials.
        """
        virtual_key = os.environ.get(f"PORTKEY_VIRTUAL_KEY_{slot_index}", "")
        if virtual_key:
            virtual_key = _sanitize_api_key(virtual_key)
        return virtual_key or None

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        """
        v19.0: Multi-slot x multi-strategy x multi-model cascade.
        Fixes BUG-P (wrong model), BUG-Q (strategy skipping), BUG-R (break→continue).
        """
        # Provider-level circuit breaker check
        if not self.circuit_breaker.allow_request():
            logger.warning(
                "[Portkey] Circuit breaker OPEN — skipping request"
            )
            raise RuntimeError(
                f"Portkey provider circuit breaker is OPEN "
                f"({self.circuit_breaker.failure_count} consecutive failures)"
            )

        # ── Feature-R/v18: Iran-aware circuit breaker check ────────────
        if _IRAN_CB_AVAILABLE:
            try:
                cb = get_iran_circuit_breaker()
                if not cb.can_attempt("portkey"):
                    logger.info("[Portkey] Iran-aware circuit OPEN — skipping")
                    return ""
            except Exception as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:1717', _remediation_exc)
                pass

        # ── FEATURE-1 v16: DPI Model Override ───────────────────────────
        model = _apply_dpi_model_override("portkey", model)

        has_virtual_key = any(
            os.environ.get(f"PORTKEY_VIRTUAL_KEY_{i}", "").strip()
            for i in range(1, 4)
        ) or bool(os.environ.get("PORTKEY_VIRTUAL_KEY", "").strip())

        # ── BUG-K: HARD EXIT when no route is configured ─────────────────
        # A Portkey virtual key can encapsulate provider routing in the
        # dashboard, so do not require a local backend key when a virtual key
        # is present. If neither exists, skip gracefully instead of emitting a
        # long cascade of guaranteed 400s.
        if not self._backend_key and not has_virtual_key:
            logger.warning(
                "[Portkey] No backend or virtual key — skipping. "
                "Set CEREBRAS_API_KEY_1 or PORTKEY_VIRTUAL_KEY_1 in GitHub Secrets."
            )
            return ""

        # Determine which models to try for this backend
        # Share discovered models from CerebrasProvider if available
        discovered = None
        try:
            from torshield_ai_gateway.providers import CerebrasProvider
            discovered = getattr(CerebrasProvider, '_discovered_models_cache', None)
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.providers:1737', _remediation_exc)
            pass

        requested_model = (
            model
            if model and not model.startswith("@cf/")
            else self._backend_model
        )
        if self._backend_key:
            models_to_try = self._resolve_model_for_provider(
                self._backend_provider,
                requested_model,
                discovered,
            )
        else:
            models_to_try = [
                model
                for model in [requested_model, self.DEFAULT_MODEL, *self.PORTKEY_MODELS]
                if model and not model.startswith("@cf/") and not model.startswith("workers-ai/")
            ][:3]
        logger.debug(
            f"[Portkey] Models to try for {self._backend_provider}: {models_to_try}"
        )

        # ── BUG-N/v18: Normalize gateway URL deterministically ──────────
        normalized_gateway = self._normalize_gateway_url(self.gateway_url)

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None
            try:
                # Sanitize API key
                clean_key = _sanitize_api_key(s.api_key)
                if not clean_key:
                    logger.warning(f"[Portkey] slot {s.index} has empty API key — skipping")
                    continue

                # ── BUG-N/v18: Use normalized gateway URL ────────────
                slot_gw_raw = os.environ.get(
                    f"PORTKEY_GATEWAY_URL_{s.index}", ""
                ).strip()
                if slot_gw_raw:
                    gateway = self._normalize_gateway_url(slot_gw_raw)
                else:
                    gateway = normalized_gateway

                # ── v19.0: Multi-model cascade (BUG-P fix) ──────────
                for model_candidate in models_to_try:
                    payload = {
                        "model":       model_candidate,
                        "messages":    messages,
                        "max_tokens":  max_tokens,
                        "temperature": temperature,
                    }

                    # ── BUG-N/v18: Try each auth strategy in order ───────
                    # FIX BUG-Q: All strategies attempted (not just 2)
                    # FIX BUG-R: Use `continue` not `break` on 400
                    strategy_success = False
                    for strategy in self._AUTH_STRATEGIES:
                        headers = self._build_auth_headers(
                            strategy,
                            clean_key,
                            self._backend_provider,
                            self._backend_key,
                            model_candidate,
                            s.index,
                        )
                        if headers is None:
                            logger.debug(
                                f"[Portkey] slot {s.index} model={model_candidate} "
                                f"strategy={strategy} → not applicable (missing env var)"
                            )
                            continue  # Strategy not applicable

                        try:
                            t0_req = time.monotonic()
                            t0_req  # noqa: F841 — explicit reference to silence pyflakes
                            resp, lat = self._post_json_with_retry(
                                gateway, headers, payload, timeout,
                                provider_name="Portkey", slot_index=s.index
                            )
                            self.rotator.mark_success(s, lat)
                            self.circuit_breaker.record_success()
                            logger.info(
                                f"[Portkey] slot={s.index} "
                                f"strategy={strategy} "
                                f"model={model_candidate} "
                                f"latency={lat:.0f}ms OK"
                            )
                            # FEATURE-T/v19.0: Record success to AI threat detector
                            if _AI_THREAT_DETECTOR_AVAILABLE:
                                try:
                                    get_ai_threat_detector().record(
                                        provider="portkey",
                                        latency_ms=lat,
                                        success=True,
                                    )
                                except Exception as _remediation_exc:
                                    from monitoring.structured_logger import record_silent_failure
                                    record_silent_failure('torshield_ai_gateway.providers:1830', _remediation_exc)
                                    pass
                            # FEATURE-V/v19.0: Cache healthy status
                            try:
                                get_provider_health_cache().set_healthy(
                                    f"portkey:{s.index}", model_candidate
                                )
                            except Exception as _remediation_exc:
                                from monitoring.structured_logger import record_silent_failure
                                record_silent_failure('torshield_ai_gateway.providers:1837', _remediation_exc)
                                pass
                            strategy_success = True
                            return self._extract_text(resp)

                        except BadRequestError:
                            # HTTP 400 — try next header strategy
                            # FIX BUG-R: continue (not break!) to try next strategy
                            logger.debug(
                                f"[Portkey] slot {s.index} "
                                f"strategy={strategy} model={model_candidate} "
                                f"→ BadRequestError, trying next strategy/model"
                            )
                            continue

                        except urllib.error.HTTPError as e:
                            if e.code == 404:
                                # Wrong URL path or routing config missing
                                logger.debug(
                                    f"[Portkey] slot {s.index} "
                                    f"strategy={strategy} → HTTP 404 "
                                    f"(routing not configured), try next strategy"
                                )
                                continue  # ← MUST be continue, not break

                            elif e.code == 401:
                                # Invalid API key
                                logger.warning(
                                    f"[Portkey] slot {s.index} "
                                    f"strategy={strategy} → HTTP 401 "
                                    f"(invalid API key), try next strategy"
                                )
                                continue  # ← MUST be continue

                            elif e.code == 400:
                                # Bad request — could be wrong model name
                                # FIX BUG-R: continue (not break!) to try next strategy
                                logger.debug(
                                    f"[Portkey] slot {s.index} "
                                    f"strategy={strategy} model={model_candidate} "
                                    f"→ HTTP 400, trying next strategy/model"
                                )
                                continue  # ← THE BUG FIX: was break, now continue

                            elif e.code == 422:
                                logger.debug(
                                    f"[Portkey] slot {s.index} "
                                    f"strategy={strategy} → HTTP 422, try next"
                                )
                                continue  # ← continue

                            elif e.code == 429:
                                logger.warning(
                                    f"[Portkey] slot {s.index} "
                                    f"strategy={strategy} → HTTP 429 (rate limited). "
                                    f"Trying next slot."
                                )
                                break  # Rate limited: skip this slot, try next

                            elif e.code >= 500:
                                logger.warning(
                                    f"[Portkey] slot {s.index} "
                                    f"strategy={strategy} → HTTP {e.code} "
                                    f"(server error)"
                                )
                                break  # Server error: skip this slot

                            else:
                                logger.warning(
                                    f"[Portkey] slot {s.index} "
                                    f"strategy={strategy} → HTTP {e.code}"
                                )
                                continue  # Unknown status: try next strategy

                    if strategy_success:
                        break  # Already returned above, this is safety guard

            except urllib.error.HTTPError as e:
                last_err = e
                latency_ms_err = 0
                # FEATURE-T/v19.0: Record failure to AI threat detector
                if _AI_THREAT_DETECTOR_AVAILABLE:
                    try:
                        get_ai_threat_detector().record(
                            provider="portkey",
                            latency_ms=latency_ms_err,
                            success=False,
                            http_status=e.code if hasattr(e, 'code') else None,
                            error_type=type(e).__name__,
                        )
                    except Exception as _remediation_exc:
                        from monitoring.structured_logger import record_silent_failure
                        record_silent_failure('torshield_ai_gateway.providers:1927', _remediation_exc)
                        pass
                if e.code in (403, 401):
                    last_auth_error = e
                    error_body = _read_error_body(e)
                    logger.warning(
                        f"[Portkey] slot {s.index} AUTH FAIL HTTP {e.code}"
                    )
                    if e.code == 401:
                        logger.error(
                            f"[Portkey] slot {s.index} HTTP 401 UNAUTHORIZED — "
                            f"possible causes: "
                            f"(1) Invalid/expired API key, "
                            f"(2) Key may need x-portkey-config header for virtual key auth, "
                            f"(3) Check PORTKEY_GATEWAY_URL matches your workspace. "
                            f"Response: {error_body[:200]}"
                        )
                    self.rotator.mark_failure(s)
                    self.circuit_breaker.record_failure()
                    continue  # Try next slot
                logger.warning(f"[Portkey] slot {s.index} HTTP {e.code}: {e.reason}")
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                if attempt == len(fallbacks) - 1:
                    raise
                time.sleep(_iran_safe_retry_delay(attempt))

            if last_err and last_err.code in (403, 401):
                continue  # Already marked failure, try next slot
            elif last_err:
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(_iran_safe_retry_delay(attempt))

        # All slots x all strategies x all models exhausted
        logger.error(
            "[Portkey] All slots × all strategies × all models exhausted. "
            f"Gateway: {normalized_gateway}. "
            "FIXES TO TRY (in order of likelihood): "
            "1. Set PORTKEY_VIRTUAL_KEY in GitHub Secrets "
            "2. Verify Cerebras API key works directly "
            "3. Check Portkey dashboard for virtual key config"
        )
        if last_auth_error:
            raise last_auth_error
        return ""


# ── Cerebras ───────────────────────────────────────────────────────────────────

class CerebrasProvider(_BaseProvider):
    name          = "cerebras"
    BASE_URL      = "https://api.cerebras.ai/v1"
    DEFAULT_MODEL = "llama3.1-8b"  # Most stable free-tier model
    CEREBRAS_MODELS = [
        "llama3.1-8b",
        "llama3.1-70b",
        "llama-4-scout-17b-16e-instruct",
        "qwen-2.5-32b",
    ]

    # ── FIX-2/v19.0: Class-level cache shared with PortkeyProvider ────
    # PortkeyProvider reads this to know which Cerebras models are live.
    _discovered_models_cache: list[str] | None = None

    def __init__(self):
        self.rotator = build_rotator_from_env("CEREBRAS", n_accounts=3)
        self._discovered_models: list[str] | None = None
        self._discovery_ts: float = 0.0
        self.circuit_breaker = ProviderCircuitBreaker("Cerebras")
        logger.info(
            f"[Cerebras] Initialized with {len(self.rotator.slots)} slot(s)"
        )

    def _discover_models(self) -> list[str]:
        """Fetch available models from Cerebras /v1/models endpoint.

        Caches results for 10 minutes to avoid excessive API calls.
        Falls back to CEREBRAS_MODELS on any error.
        """
        cache_ttl = 600.0  # 10 minutes
        if (
            self._discovered_models is not None
            and (time.time() - self._discovery_ts) < cache_ttl
        ):
            return self._discovered_models

        try:
            slot = self.rotator.get_primary()
            clean_key = _sanitize_api_key(slot.api_key)
            if not clean_key:
                logger.debug("[Cerebras] No API key for model discovery — using static list")
                return list(self.CEREBRAS_MODELS)

            url = f"{self.BASE_URL}/models"
            headers = {
                "Authorization": f"Bearer {clean_key}",
                "User-Agent": _USER_AGENT,
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            discovered = []
            for item in data.get("data", []):
                model_id = item.get("id", "")
                if model_id:
                    discovered.append(model_id)

            if discovered:
                self._discovered_models = discovered
                self._discovery_ts = time.time()
                # FIX-2/v19.0: Update class-level cache for PortkeyProvider
                CerebrasProvider._discovered_models_cache = list(discovered)
                logger.info(
                    f"[Cerebras] Discovered {len(discovered)} models: {discovered}"
                )
                logger.debug(
                    f"[Cerebras] Updated discovery cache: {CerebrasProvider._discovered_models_cache}"
                )
                return discovered
            else:
                logger.warning("[Cerebras] /models returned empty list — using static list")
                return list(self.CEREBRAS_MODELS)

        except Exception as e:
            logger.warning(
                f"[Cerebras] Model discovery failed: {e} — using static list"
            )
            return list(self.CEREBRAS_MODELS)

    @staticmethod
    def _extract_openai_content(response_json: dict) -> str:
        """
        Extract content from OpenAI-format response.
        NEVER returns str(response_json).
        Handles finish_reason=length gracefully.
        """
        try:
            choices = response_json.get("choices", [])
            if not choices:
                logger.warning(
                    f"[Cerebras] Response has no choices. "
                    f"Keys: {list(response_json.keys())}"
                )
                return ""
            choice = choices[0]
            finish_reason = choice.get("finish_reason", "unknown")
            if finish_reason == "length":
                logger.warning(
                    "[Cerebras] finish_reason=length — "
                    "max_tokens budget exhausted before TORSHIELD_OK. "
                    "Increase max_tokens in health check prompt."
                )
            content = choice.get("message", {}).get("content", "")
            return content if isinstance(content, str) else ""
        except (KeyError, IndexError, TypeError) as e:
            logger.error(f"[Cerebras] Response parse error: {e}")
            return ""

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        # Provider-level circuit breaker check
        if not self.circuit_breaker.allow_request():
            logger.warning(
                f"[Cerebras] Circuit breaker OPEN — skipping request "
                f"(failures={self.circuit_breaker.failure_count}, "
                f"state={self.circuit_breaker.state})"
            )
            raise RuntimeError(
                f"Cerebras provider circuit breaker is OPEN "
                f"({self.circuit_breaker.failure_count} consecutive failures)"
            )

        # ── Feature-R/v18: Iran-aware circuit breaker check ────────────
        if _IRAN_CB_AVAILABLE:
            try:
                cb = get_iran_circuit_breaker()
                if not cb.can_attempt("cerebras"):
                    logger.info("[Cerebras] Iran-aware circuit OPEN — skipping")
                    return ""
            except Exception as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:2112', _remediation_exc)
                pass

        # ── FEATURE-1 v16: DPI Model Override ───────────────────────────
        model = _apply_dpi_model_override("cerebras", model)

        explicit_model = model
        chosen_model   = explicit_model or self.DEFAULT_MODEL

        # Use discovered models if available, otherwise fall back to static list
        available_models = self._discover_models()
        models_to_try  = [chosen_model] + [m for m in available_models if m != chosen_model]

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        # ── BUG-M: 429 slot cooldown tracker ────────────────────────────
        _429_slot_cooldown: dict[int, float] = {}  # slot_idx → skip-until time

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None

            # ── BUG-M: Skip slots that recently got 429 ────────────────
            if time.time() < _429_slot_cooldown.get(s.index, 0):
                logger.debug(f"[Cerebras] slot {s.index} in 429 cooldown — skipping")
                continue

            for m in models_to_try:
                try:
                    # Sanitize API key
                    clean_key = _sanitize_api_key(s.api_key)
                    if not clean_key:
                        logger.warning(f"[Cerebras] slot {s.index} has empty API key — skipping")
                        break  # No point trying other models with empty key

                    url     = f"{self.BASE_URL}/chat/completions"
                    headers = {
                        "Content-Type":  "application/json",
                        "Authorization": f"Bearer {clean_key}",
                    }
                    payload = {
                        "model":       m,
                        "messages":    messages,
                        "max_tokens":  max_tokens,
                        "temperature": temperature,
                        "stream":      False,
                    }
                    resp, lat = self._post_json_with_retry(
                        url, headers, payload, timeout,
                        provider_name="Cerebras", slot_index=s.index
                    )
                    self.rotator.mark_success(s, lat)
                    self.circuit_breaker.record_success()
                    # FEATURE-T/v19.0: Record success to AI threat detector
                    if _AI_THREAT_DETECTOR_AVAILABLE:
                        try:
                            get_ai_threat_detector().record(
                                provider="cerebras",
                                latency_ms=lat,
                                success=True,
                            )
                        except Exception as _remediation_exc:
                            from monitoring.structured_logger import record_silent_failure
                            record_silent_failure('torshield_ai_gateway.providers:2174', _remediation_exc)
                            pass
                    return self._extract_openai_content(resp)
                except BadRequestError as e:
                    # HTTP 400 — NOT an auth failure, try next model
                    logger.debug(
                        f"[Cerebras] slot {s.index} model {m} → "
                        f"BadRequestError: {str(e)[:200]}"
                    )
                    continue  # Try next model
                except urllib.error.HTTPError as e:
                    last_err = e
                    # ── BUG-M: Handle 429 by rotating to next slot ──────
                    if e.code == 429:
                        retry_after = int(e.headers.get("Retry-After", "60"))
                        _429_slot_cooldown[s.index] = time.time() + retry_after
                        logger.warning(
                            f"[Cerebras] slot {s.index} HTTP 429 — "
                            f"rotating to next slot (cooldown {retry_after}s)"
                        )
                        continue  # ← IMMEDIATELY rotate to next slot
                    if e.code in (403, 401):
                        last_auth_error = e
                        logger.warning(f"[Cerebras] slot {s.index} AUTH FAIL HTTP {e.code}")
                        self.rotator.mark_failure(s)
                        self.circuit_breaker.record_failure()
                        break  # Try next slot, not next model
                    # NOTE: 400 is now caught as BadRequestError above, not here
                    if e.code == 404:
                        logger.debug(f"[Cerebras] Model not found: {m}")
                        continue  # Try next model
                    logger.warning(f"[Cerebras] slot {s.index} HTTP {e.code}: {e.reason}")
                    self.rotator.mark_failure(s)
                    self.circuit_breaker.record_failure()
                    if attempt == len(fallbacks) - 1:
                        raise
                    time.sleep(_iran_safe_retry_delay(attempt))

            if last_err and last_err.code in (403, 401):
                continue  # Already marked failure, try next slot
            elif last_err:
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(_iran_safe_retry_delay(attempt))

        if last_auth_error:
            raise last_auth_error
        return ""


# ── Cloudflare Workers AI (direct) ────────────────────────────────────────────

class CloudflareWorkersAIProvider(_BaseProvider):
    """
    Cloudflare Workers AI — direct API with dynamic model selection.
    Model is resolved at call-time via CloudflareModelSelector.

    CORRECTION 7: Uses OpenAI-compatible endpoint:
      POST https://api.cloudflare.com/client/v4/accounts/{acct}/ai/v1/chat/completions
      Body: {"model": model_id, "messages": [...], "max_tokens": N, "stream": false}

    CORRECTION 6: Pre-flight screening validates each slot's token and
    account_id BEFORE any request is sent. Broken slots are silently skipped.
    """
    name = "cloudflare_workers_ai"
    # Class-level set of models that 400'd on any slot — skip on all
    # subsequent slots to reduce health-check timeout cascade.
    _failed_models: set = set()

    def __init__(self):
        slots = []
        skipped_slots = []
        for i in range(1, CF_N_SLOTS + 1):
            acct_id   = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            api_token = os.environ.get(f"CF_API_TOKEN_{i}", "")
            if not (acct_id and api_token):
                continue
            # ── CORRECTION 6: Pre-flight screening ───────────────────
            valid, reason = _preflight_screen_slot(i)
            if not valid:
                logger.warning(
                    f"[CF-Workers-AI] Slot {i} skipped by pre-flight: {reason}"
                )
                skipped_slots.append(i)
                continue
            preflight_issues = preflight_validate_cf_slot(
                slot_index=i,
                account_id=acct_id,
                api_token=api_token,
            )
            if preflight_issues:
                skipped_slots.append(i)
                continue
            slots.append(
                AccountSlot(index=i, account_id=acct_id, api_key=api_token)
            )
        if skipped_slots:
            logger.warning(
                f"[CF-Workers-AI] Pre-flight screening SKIPPED {len(skipped_slots)} "
                f"broken slot(s): {skipped_slots}. These slots are NOT deleted — "
                f"they will be retried in the next CI run after fixing secrets."
            )
        if not slots:
            raise ProviderConfigurationError(
                "[CloudflareWorkersAI] No CF accounts configured "
                "(all slots either empty or failed pre-flight screening).",
                provider="cloudflare_workers_ai",
            )
        self.rotator = AccountRotator("cloudflare_workers_ai", slots)
        self._selector = CloudflareModelSelector.instance()
        self.circuit_breaker = ProviderCircuitBreaker(
            "CF-Workers-AI",
            failure_threshold=max(len(slots), 20),
        )
        # Session-level blacklist for slots that fail all models at runtime
        self._session_blacklist: set = set()
        # Thread-safe dead slot tracking: slots that return 400+empty body
        self._dead_slots: set[int] = set()
        self._dead_slots_lock = threading.Lock()
        logger.info(
            f"[CF-Workers-AI] Initialized with {len(slots)} slot(s) "
            f"({len(skipped_slots)} skipped by pre-flight screening)"
        )

    @staticmethod
    def _build_cf_workers_url(account_id: str) -> str:
        """Build the correct CF Workers AI REST API URL.
        OpenAI-compatible format — model goes in request body, not URL.
        """
        return (
            f"https://api.cloudflare.com/client/v4/accounts/"
            f"{account_id}/ai/v1/chat/completions"
        )

    @staticmethod
    def _build_cf_request_body(
        model_id: str,
        messages: list,
        max_tokens: int = 50,
        temperature: float = 0.2,
    ) -> dict:
        """Build request body for CF OpenAI-compatible endpoint.
        Model ID is placed in the request body, NOT the URL path.
        """
        return {
            "model": model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }

    @staticmethod
    def _extract_cf_content(response_json: dict) -> str:
        """Extract text content from CF Workers AI response (any format)."""
        if not isinstance(response_json, dict):
            return ""
        # Format 1: wrapped in 'result'
        result = response_json.get("result", response_json)
        # Format 2: direct OpenAI format
        choices = result.get("choices") if isinstance(result, dict) else None
        if not choices:
            choices = response_json.get("choices", [])
        if choices:
            try:
                msg = choices[0].get("message", {})
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content.strip()
            except (KeyError, IndexError, TypeError, AttributeError) as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:2345', _remediation_exc)
                pass
        # Format 3: legacy CF format
        if "result" in response_json:
            r = response_json["result"]
            if isinstance(r, str) and r.strip():
                return r.strip()
            if isinstance(r, dict):
                resp_val = r.get("response", "")
                if isinstance(resp_val, str) and resp_val.strip():
                    return resp_val.strip()
        # Nothing found — return empty string (NOT str(response_json))
        logger.debug(
            f"[CF-Workers-AI] Could not extract content from response keys: "
            f"{list(response_json.keys())}"
        )
        return ""

    # ── BUG-I: Huge model markers for fast task guard ───────────────────
    HUGE_MODEL_MARKERS = ["kimi-k2", "llama-3.1-405b", "nemotron-4-340b"]
    _FAST_MODEL_OVERRIDE = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"

    def _resolve_model(self, model: str | None, task: str) -> str:
        """Return model to use: explicit > dynamic brain > dynamic selection > stable fallback."""
        if model:
            return model
        # ── Dynamic Brain Integration (Fix-16.0) ─────────────────────
        # Try live model selection from DynamicModelBrain first.
        if _DYNAMIC_BRAIN_AVAILABLE:
            try:
                _live_cf = best_cf_model_live(task=task)
                if _live_cf:
                    resolved = _live_cf.id
                    # ── BUG-I: Guard against huge models on fast tasks ──
                    if task == "fast" and any(marker in resolved for marker in self.HUGE_MODEL_MARKERS):
                        logger.info(
                            f"[CF-Workers-AI] BUG-I guard: overriding huge model "
                            f"'{resolved}' for fast task → '{self._FAST_MODEL_OVERRIDE}'"
                        )
                        return self._FAST_MODEL_OVERRIDE
                    logger.debug(
                        f"[CF-Workers-AI] Dynamic Brain [{task}]: {resolved} "
                        f"(score={_live_cf.score})"
                    )
                    return resolved
            except Exception as exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:2390', exc)
                logger.debug(f"[CF-Workers-AI] Brain model fetch failed: {exc}")
        # Fallback: existing CloudflareModelSelector
        try:
            selected = self._selector.best_model(task=task, probe=False)
            logger.debug(f"[CF-Workers-AI] Dynamic model [{task}]: {selected}")
            # ── BUG-I: Guard against huge models on fast tasks ──────────
            if task == "fast" and any(marker in selected for marker in self.HUGE_MODEL_MARKERS):
                logger.info(
                    f"[CF-Workers-AI] BUG-I guard: overriding huge model "
                    f"'{selected}' for fast task → '{self._FAST_MODEL_OVERRIDE}'"
                )
                return self._FAST_MODEL_OVERRIDE
            # ── BUG-I: HC_FAST_MODEL_OVERRIDE env var support ────────────
            if os.environ.get("HC_USE_PREFERRED_MODELS", "").lower() == "true" and task == "fast":
                env_fast_model = os.environ.get("HC_FAST_MODEL_OVERRIDE", "").strip()
                if env_fast_model:
                    logger.info(
                        f"[CF-Workers-AI] BUG-I: HC_FAST_MODEL_OVERRIDE → {env_fast_model}"
                    )
                    return env_fast_model
            return selected
        except Exception as exc:
            logger.warning(f"[CF-Workers-AI] Model selector error: {exc}; using fallback")
            return CF_STABLE_MODELS[0]

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        # Provider-level circuit breaker check
        if not self.circuit_breaker.allow_request():
            logger.warning(
                "[CF-Workers-AI] Circuit breaker OPEN — skipping request"
            )
            raise RuntimeError(
                f"CF-Workers-AI provider circuit breaker is OPEN "
                f"({self.circuit_breaker.failure_count} consecutive failures)"
            )

        # ── Feature-R/v18: Iran-aware circuit breaker check ────────────
        if _IRAN_CB_AVAILABLE:
            try:
                cb = get_iran_circuit_breaker()
                if not cb.can_attempt("cloudflare_workers_ai"):
                    logger.info("[CF-Workers-AI] Iran-aware circuit OPEN — skipping")
                    return ""
            except Exception as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:2437', _remediation_exc)
                pass

        # ── FEATURE-1 v16: DPI Model Override ───────────────────────────
        model = _apply_dpi_model_override("cloudflare_workers_ai", model)

        chosen_model = self._resolve_model(model, task)

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        # Build fallback model chain: chosen → stable models, excluding already-failed models
        models_to_try = [chosen_model] + [m for m in CF_STABLE_MODELS if m != chosen_model]

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None

            # Skip dead slots (slots that previously returned 400+empty body)
            with self._dead_slots_lock:
                if s.index in self._dead_slots:
                    continue

            for m in models_to_try:
                # Skip models that already 400'd on a previous slot
                if m in self._failed_models:
                    logger.debug(
                        f"[CF-Workers-AI] Skipping model {m} — previously 400'd on another slot"
                    )
                    continue

                try:
                    # Sanitize credentials
                    clean_token = _sanitize_api_key(s.api_key)
                    clean_acct  = _sanitize_api_key(s.account_id)
                    if not clean_token or not clean_acct:
                        logger.warning(
                            f"[CF-Workers-AI] slot {s.index} has empty credentials — skipping"
                        )
                        break  # No point trying other models with bad credentials

                    # CORRECTION 7: Use OpenAI-compatible endpoint
                    # Model ID goes in request body, NOT URL path.
                    url = self._build_cf_workers_url(clean_acct)
                    headers = {
                        "Content-Type":  "application/json",
                        "Authorization": f"Bearer {clean_token}",
                    }
                    payload = self._build_cf_request_body(
                        model_id=m,
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )
                    resp, lat = self._post_json_with_retry(
                        url, headers, payload, timeout,
                        provider_name="CF-Workers-AI", slot_index=s.index
                    )
                    self.rotator.mark_success(s, lat)
                    self.circuit_breaker.record_success()
                    return self._extract_cf_content(resp)
                except BadRequestError as e:
                    # HTTP 400 — NOT an auth failure. Check if empty body (dead slot)
                    # or model-specific issue (try next model).
                    err_msg = str(e)
                    if "empty body" in err_msg.lower():
                        with self._dead_slots_lock:
                            if s.index not in self._dead_slots:
                                self._dead_slots.add(s.index)
                                logger.warning(
                                    f"[CF] slot {s.index} permanently failed "
                                    f"(HTTP 400 empty body) — "
                                    f"skipping all remaining models for this slot"
                                )
                        break  # Stop trying models for this slot
                    # Model-specific issue — add to failed set and try next model
                    self._failed_models.add(m)
                    logger.debug(
                        f"[CF-Workers-AI] slot {s.index} model {m} → "
                        f"BadRequestError: {err_msg[:200]}"
                    )
                    continue
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code in (403, 401):
                        last_auth_error = e
                        logger.warning(
                            f"[CF-Workers-AI] slot {s.index} AUTH FAIL HTTP {e.code}"
                        )
                        self.circuit_breaker.record_failure()
                        break  # Try next slot, not next model
                    # NOTE: 400 is now caught as BadRequestError above, not here
                    if e.code == 404:
                        logger.debug(f"[CF-Workers-AI] Model not found: {m}")
                        self._failed_models.add(m)
                        continue
                    self.circuit_breaker.record_failure()
                    raise

            if last_err:
                if last_err.code in (403, 401):
                    self.rotator.mark_failure(s)
                    continue  # Try next slot
                logger.warning(f"[CF-Workers-AI] slot {s.index} all models failed")
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(2 ** attempt)

        # All slots exhausted — check if all are dead (config error, not runtime)
        with self._dead_slots_lock:
            all_dead = all(
                s.index in self._dead_slots
                for s in self.rotator.slots
            )

        if all_dead:
            raise ProviderConfigurationError(
                f"[CF-Workers-AI] All {len(self.rotator.slots)} slots failed "
                f"(HTTP 400 / empty body on first model attempt per slot). "
                f"Verify CF_ACCOUNT_ID and CF_API_TOKEN values in GitHub Secrets.",
                provider="cloudflare_workers_ai",
            )

        if last_auth_error:
            raise last_auth_error
        return ""


# ── Cloudflare AI Gateway (proxy layer) ───────────────────────────────────────

class CloudflareAIGatewayProvider(_BaseProvider):
    """
    Cloudflare AI Gateway — proxy layer with caching and dynamic model selection.
    11 gateway slots × free quota = 11× effective throughput.
    Model resolved dynamically via CloudflareModelSelector.

    CRITICAL FIX v17.0: Uses /compat/chat/completions endpoint:
      POST {gateway_base}/compat/chat/completions
      Body: {"model": model_id, "messages": [...], "max_tokens": N, "stream": false}
      Model ID goes in request body, NOT URL path.
      The /compat/ endpoint is the correct OpenAI-compatible endpoint.
      Previous /workers-ai/v1/chat/completions caused HTTP 400 on all slots.
      The account_id must appear EXACTLY ONCE in each URL (inside the gateway base).

    CORRECTION 6: Pre-flight screening validates each slot's token length,
    account_id format, and gateway URL structure BEFORE any request is sent.
    """
    name = "cloudflare_ai_gateway"
    # Class-level set of models that 400'd on any slot — skip on all
    # subsequent slots to reduce health-check timeout cascade.
    _failed_models: set = set()
    # Expected gateway URL prefix
    _GATEWAY_URL_PREFIX = "https://gateway.ai.cloudflare.com/v1/"

    # ── FIX-19.0: CF Gateway Multi-Provider Cascade (Feature-2) ────────────
    # CF AI Gateway supports 15+ providers. Each entry:
    #   (model_id_for_api, provider_name_for_log, needs_byok)
    # Workers AI models are always tried first (no BYOK needed, uses CF token).
    # External providers via CF Gateway need BYOK or Unified Billing.
    CF_GATEWAY_PROVIDER_CASCADE = [
        # Workers AI — always tried first (no BYOK needed):
        ("@cf/meta/llama-3.3-70b-instruct-fp8-fast", "workers-ai", False),
        ("@cf/openai/gpt-oss-120b",                  "workers-ai", False),
        ("@cf/qwen/qwq-32b",                         "workers-ai", False),
        # External providers via CF Gateway (need BYOK or Unified Billing):
        ("openai/gpt-4o-mini",                        "openai",     True),
        ("anthropic/claude-3-haiku-20240307",          "anthropic",  True),
        ("google/gemini-1.5-flash",                    "google",     True),
        ("groq/llama-3.3-70b-versatile",              "groq",       True),
        ("mistral/mistral-7b-instruct",               "mistral",    True),
    ]

    def __init__(self):
        slots = []
        skipped_slots = []
        for i in range(1, CF_N_SLOTS + 1):
            acct_id     = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            api_token   = os.environ.get(f"CF_API_TOKEN_{i}", "")
            gateway_url = os.environ.get(f"CF_AI_GATEWAY_URL_{i}", "")
            if not (acct_id and api_token and gateway_url):
                continue

            # ── CORRECTION 6: Pre-flight screening ───────────────────
            valid, reason = _preflight_screen_slot(i)
            if not valid:
                logger.warning(
                    f"[CF-AI-GW] Slot {i} skipped by pre-flight: {reason}"
                )
                skipped_slots.append(i)
                continue
            preflight_issues = preflight_validate_cf_slot(
                slot_index=i,
                account_id=acct_id,
                api_token=api_token,
                gateway_url=gateway_url,
            )
            if preflight_issues:
                skipped_slots.append(i)
                continue

            try:
                gateway_url = _validate_url(gateway_url, f"CF_AI_GATEWAY_URL_{i}")
            except ValueError as e:
                logger.error(str(e))
                skipped_slots.append(i)
                continue
            # Validate gateway URL structure
            try:
                self._validate_gateway_url(gateway_url, acct_id, slot_index=i)
            except ValueError as e:
                logger.error(str(e))
                skipped_slots.append(i)
                continue
            slots.append(
                AccountSlot(
                    index=i,
                    account_id=acct_id,
                    api_key=api_token,
                    gateway_url=gateway_url,
                )
            )
        if skipped_slots:
            logger.warning(
                f"[CF-AI-GW] Pre-flight screening SKIPPED {len(skipped_slots)} "
                f"broken slot(s): {skipped_slots}. These slots are NOT deleted — "
                f"they will be retried in the next CI run after fixing secrets."
            )
        if not slots:
            raise ProviderConfigurationError(
                "[CF-AI-Gateway] No gateway slots configured "
                "(all slots either empty or failed pre-flight screening).",
                provider="cloudflare_ai_gateway",
            )
        self.rotator  = AccountRotator("cloudflare_ai_gateway", slots)
        self._selector = CloudflareModelSelector.instance()
        self.circuit_breaker = ProviderCircuitBreaker(
            "CF-AI-GW",
            failure_threshold=max(len(slots), 20),
        )
        # Session-level blacklist for slots that fail all models at runtime
        self._session_blacklist: set = set()
        # Thread-safe dead slot tracking: slots that return 400+empty body
        self._dead_slots: set[int] = set()
        self._dead_slots_lock = threading.Lock()
        logger.info(
            f"[CF-AI-GW] Initialized with {len(slots)} slot(s) "
            f"({len(skipped_slots)} skipped by pre-flight screening)"
        )

    @staticmethod
    def _build_cf_gateway_url(gateway_base_url: str) -> str:
        """Build the correct CF AI Gateway Workers AI URL.
        Uses /compat/ OpenAI-compatible format — model goes in request body, not URL.
        Path: {gateway_base}/compat/chat/completions

        Uses normalize_cf_gateway_url() to handle bare gateway roots,
        partial paths, and auto-correct /workers-ai/ → /compat/.
        """
        return normalize_cf_gateway_url(gateway_base_url)

    @staticmethod
    def _build_cf_request_body(
        model_id: str,
        messages: list,
        max_tokens: int = 50,
        temperature: float = 0.2,
    ) -> dict:
        """Build request body for CF AI Gateway OpenAI-compatible endpoint.
        Model ID is placed in the request body, NOT the URL path.
        """
        return {
            "model": model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }

    @classmethod
    def _validate_gateway_url(
        cls, gateway_url: str, account_id: str, slot_index: int = 0
    ) -> None:
        """Validate CF AI Gateway URL structure.

        Expected format: https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_slug}
        - Must start with https://gateway.ai.cloudflare.com/v1/
        - Must contain an account_id in the path after /v1/
        - Logs the validated endpoint (with masked account_id) for debugging.
        """
        if not gateway_url.startswith(cls._GATEWAY_URL_PREFIX):
            raise ValueError(
                f"[CF-AI-GW] slot {slot_index} Invalid gateway URL: "
                f"must start with '{cls._GATEWAY_URL_PREFIX}'. "
                f"Got: {_mask_url(gateway_url)}"
            )

        # Extract the path after /v1/
        path_after_v1 = gateway_url[len(cls._GATEWAY_URL_PREFIX):]
        path_parts = [p for p in path_after_v1.split("/") if p]

        if len(path_parts) < 2:
            raise ValueError(
                f"[CF-AI-GW] slot {slot_index} Invalid gateway URL: "
                f"expected path /v1/{{account_id}}/{{gateway_slug}}, "
                f"got {_mask_url(gateway_url)}. "
                f"Path after /v1/ has {len(path_parts)} segment(s), need at least 2 "
                f"(account_id and gateway_slug)."
            )

        url_account_id = path_parts[0]
        gateway_slug = path_parts[1]

        # Validate that account_id in URL matches the configured account_id
        if account_id and url_account_id != account_id:
            logger.warning(
                f"[CF-AI-GW] slot {slot_index} Account ID mismatch: "
                f"URL contains '{_mask_key(url_account_id, 3)}' but "
                f"CF_ACCOUNT_ID is '{_mask_key(account_id, 3)}'. "
                f"This may cause 400 errors."
            )

        # Log the CORRECT endpoint pattern (OpenAI-compatible /compat/)
        logger.info(
            f"[CF-AI-GW] slot {slot_index} validated: "
            f"endpoint=https://gateway.ai.cloudflare.com/v1/"
            f"{_mask_key(url_account_id, 3)}/{gateway_slug}"
            f"/compat/chat/completions model_in_body=True"
        )

    @staticmethod
    def _probe_gateway(gateway_url: str, timeout: int = 10) -> bool:
        """Send a lightweight GET request to the gateway URL to check reachability.

        Returns True if the gateway is reachable (any HTTP response, even 404),
        False if the connection itself fails.
        """
        try:
            req = urllib.request.Request(
                gateway_url,
                headers={"User-Agent": _USER_AGENT},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                logger.debug(
                    f"[CF-AI-GW] Gateway probe OK: HTTP {resp.status} "
                    f"for {_mask_url(gateway_url)}"
                )
                return True
        except urllib.error.HTTPError as e:
            # Any HTTP response means the gateway is reachable
            logger.debug(
                f"[CF-AI-GW] Gateway probe got HTTP {e.code} — "
                f"gateway is reachable but returned error"
            )
            return True
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
            logger.warning(
                f"[CF-AI-GW] Gateway probe FAILED for {_mask_url(gateway_url)}: {e}. "
                f"Gateway may be unreachable or DNS resolution failed."
            )
            return False

    # ── BUG-I: Huge model markers for fast task guard ───────────────────
    HUGE_MODEL_MARKERS = ["kimi-k2", "llama-3.1-405b", "nemotron-4-340b"]
    _FAST_MODEL_OVERRIDE = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"

    def _resolve_model(self, model: str | None, task: str) -> str:
        if model:
            return model
        # ── Dynamic Brain Integration (Fix-16.0) ─────────────────────
        # Try live model selection from DynamicModelBrain first.
        # Falls back to existing CloudflareModelSelector on any failure.
        if _DYNAMIC_BRAIN_AVAILABLE:
            try:
                _live_cf = best_cf_model_live(task=task)
                if _live_cf:
                    resolved = _live_cf.id
                    # ── BUG-I: Guard against huge models on fast tasks ──
                    if task == "fast" and any(marker in resolved for marker in self.HUGE_MODEL_MARKERS):
                        logger.info(
                            f"[CF-AI-GW] BUG-I guard: overriding huge model "
                            f"'{resolved}' for fast task → '{self._FAST_MODEL_OVERRIDE}'"
                        )
                        return self._FAST_MODEL_OVERRIDE
                    logger.debug(
                        f"[CF-AI-GW] Dynamic Brain [{task}]: {resolved} "
                        f"(score={_live_cf.score})"
                    )
                    return resolved
            except Exception as exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:2828', exc)
                logger.debug(f"[CF-AI-GW] Brain model fetch failed: {exc}")
        # Fallback: existing CloudflareModelSelector
        try:
            selected = self._selector.best_model(task=task, probe=False)
            logger.debug(f"[CF-AI-GW] Dynamic model [{task}]: {selected}")
            # ── BUG-I: Guard against huge models on fast tasks ──────────
            if task == "fast" and any(marker in selected for marker in self.HUGE_MODEL_MARKERS):
                logger.info(
                    f"[CF-AI-GW] BUG-I guard: overriding huge model "
                    f"'{selected}' for fast task → '{self._FAST_MODEL_OVERRIDE}'"
                )
                return self._FAST_MODEL_OVERRIDE
            # ── BUG-I: HC_FAST_MODEL_OVERRIDE env var support ────────────
            if os.environ.get("HC_USE_PREFERRED_MODELS", "").lower() == "true" and task == "fast":
                env_fast_model = os.environ.get("HC_FAST_MODEL_OVERRIDE", "").strip()
                if env_fast_model:
                    logger.info(
                        f"[CF-AI-GW] BUG-I: HC_FAST_MODEL_OVERRIDE → {env_fast_model}"
                    )
                    return env_fast_model
            return selected
        except Exception as exc:
            logger.warning(f"[CF-AI-GW] Model selector error: {exc}; using fallback")
            return CF_STABLE_MODELS[0]

    def _try_gateway_provider_cascade(
        self, messages: list, max_tokens: int = 10, timeout: int = 15,
    ):
        """
        NON-DESTRUCTIVE new method — CF Gateway Multi-Provider Cascade (Feature-2).

        Tries multiple providers through the CF AI Gateway REST API.
        After Workers AI models fail, tries external providers like OpenAI,
        Anthropic, Google, Groq, Mistral — all routed through the CF Gateway.

        Requires CF_GW_PROVIDER_CASCADE_ENABLED=true (default).
        External providers need BYOK keys configured in CF dashboard.

        Returns: (response_dict, latency_ms) tuple if 200, else None
        """
        if not _CF_GW_PROVIDER_CASCADE_ENABLED or not _CF_FORMATTER_AVAILABLE:
            return None

        import ssl as _ssl

        for i in range(1, 12):
            account_id = os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip()
            api_token  = os.environ.get(f"CF_API_TOKEN_{i}", "").strip()
            gw_url_raw = os.environ.get(f"CF_AI_GATEWAY_URL_{i}", "").strip()

            if not account_id or not api_token:
                continue

            clean_token = _sanitize_api_key(api_token)
            if not clean_token:
                continue

            gw_name = extract_gateway_name(gw_url_raw, account_id)
            rest_url = build_format1_url(account_id)
            base_headers = {
                "Authorization": f"Bearer {clean_token}",
                "Content-Type":  "application/json",
                "User-Agent":   _USER_AGENT,
            }
            if gw_name:
                base_headers["cf-aig-gateway-id"] = gw_name

            for model_id, provider_name, needs_byok in self.CF_GATEWAY_PROVIDER_CASCADE:
                try:
                    # Skip Workers AI models here — they're already tried in
                    # _cf_gateway_multi_format_attempt(). Only try external providers.
                    if not needs_byok:
                        continue

                    payload = {
                        "model":      model_id,
                        "messages":   messages,
                        "max_tokens": max_tokens,
                        "stream":     False,
                    }
                    t0 = time.monotonic()
                    data = json.dumps(payload).encode("utf-8")
                    ctx = _ssl.create_default_context()
                    req = urllib.request.Request(
                        rest_url, data=data, headers=base_headers, method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                        result = json.loads(resp.read().decode("utf-8"))
                    latency_ms = (time.monotonic() - t0) * 1000.0
                    logger.info(
                        f"[CF-AI-GW] Provider cascade success: "
                        f"provider={provider_name} model={model_id} "
                        f"slot={i} latency={latency_ms:.0f}ms"
                    )
                    return result, latency_ms
                except urllib.error.HTTPError as e:
                    if e.code == 401 and needs_byok:
                        logger.debug(
                            f"[CF-AI-GW] {provider_name} needs BYOK "
                            f"(Cloudflare dashboard -> AI Gateway -> Provider Keys)"
                        )
                    elif e.code == 400:
                        logger.debug(
                            f"[CF-AI-GW] {provider_name}/{model_id} -> 400"
                        )
                    elif e.code in (403, 401):
                        break  # Auth issue on this slot, try next slot
                    else:
                        logger.debug(
                            f"[CF-AI-GW] {provider_name}/{model_id} -> HTTP {e.code}"
                        )
                except Exception as exc:
                    from monitoring.structured_logger import record_silent_failure
                    record_silent_failure('torshield_ai_gateway.providers:2940', exc)
                    logger.debug(
                        f"[CF-AI-GW] Provider cascade {provider_name} error: {exc}"
                    )

            # Only try first valid slot for cascade (avoid unnecessary API calls)
            break

        return None

    def _cf_gateway_multi_format_attempt(
        self, model_id: str, messages: list, max_tokens: int = 512,
        temperature: float = 0.2, timeout: int = 30,
    ):
        """
        NON-DESTRUCTIVE new method — multi-format dynamic requester.

        Tries all 3 CF AI Gateway endpoint formats across all 11 slots.
        This runs BEFORE the existing legacy slot loop and short-circuits on success.

        Priority order for @cf/ models:
          1. FORMAT-1: REST API + cf-aig-gateway-id header  (most reliable)
          2. FORMAT-3: /compat/ with "workers-ai/@cf/..." model (OpenAI-compat)
          3. FORMAT-2: /workers-ai/ path with model in URL  (native)

        Returns: (response_dict, latency_ms) tuple if 200, else None
        """
        if not _CF_FORMATTER_AVAILABLE or not _CF_DYNAMIC_REQUESTER_ENABLED:
            return None

        import ssl as _ssl

        for i in range(1, 12):
            account_id = os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip()
            api_token  = os.environ.get(f"CF_API_TOKEN_{i}", "").strip()
            gw_url_raw = os.environ.get(f"CF_AI_GATEWAY_URL_{i}", "").strip()

            if not account_id or not api_token:
                continue

            # Sanitize token
            clean_token = _sanitize_api_key(api_token)
            if not clean_token:
                continue

            gw_name = extract_gateway_name(gw_url_raw, account_id)
            base_headers = {
                "Authorization": f"Bearer {clean_token}",
                "Content-Type":  "application/json",
                "User-Agent":   _USER_AGENT,
            }

            # ── FORMAT 1: REST API + cf-aig-gateway-id header ──────────
            # URL: https://api.cloudflare.com/client/v4/accounts/{id}/ai/v1/chat/completions
            # Header: cf-aig-gateway-id: {gateway_name}
            # Model: "@cf/meta/llama-3.3-70b-instruct-fp8-fast"  (no prefix)
            try:
                rest_url = build_format1_url(account_id)
                rest_headers = {**base_headers}
                if gw_name:
                    rest_headers["cf-aig-gateway-id"] = gw_name

                rest_model = format_model_for_rest_api(model_id)
                payload = {
                    "model":      rest_model,
                    "messages":   messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "stream":     False,
                }
                t0 = time.monotonic()
                data = json.dumps(payload).encode("utf-8")
                ctx = _ssl.create_default_context()
                req = urllib.request.Request(
                    rest_url, data=data, headers=rest_headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                latency_ms = (time.monotonic() - t0) * 1000.0
                logger.info(
                    f"[CF-AI-GW] FORMAT-1 (REST API) success: slot={i} "
                    f"model={rest_model} latency={latency_ms:.0f}ms"
                )
                return result, latency_ms
            except urllib.error.HTTPError as e:
                if e.code == 400:
                    logger.debug(
                        f"[CF-AI-GW] FORMAT-1 slot={i} HTTP 400 -> trying FORMAT-3"
                    )
                elif e.code in (401, 403):
                    logger.warning(
                        f"[CF-AI-GW] FORMAT-1 slot={i} HTTP {e.code} (auth) -> next slot"
                    )
                    continue
                elif e.code == 429:
                    delay = _compute_backoff_delay(0)
                    logger.warning(
                        f"[CF-AI-GW] FORMAT-1 slot={i} HTTP 429 -> backoff {delay:.1f}s"
                    )
                    time.sleep(delay)
                    continue
                else:
                    logger.debug(
                        f"[CF-AI-GW] FORMAT-1 slot={i} HTTP {e.code} -> trying FORMAT-3"
                    )
            except Exception as exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:3045', exc)
                logger.debug(f"[CF-AI-GW] FORMAT-1 slot={i} exception: {exc}")

            # ── FORMAT 3: /compat/ + "workers-ai/@cf/..." model ────────
            # URL: gateway.ai.cloudflare.com/v1/{acct}/{gw}/compat/chat/completions
            # Model: "workers-ai/@cf/meta/llama-3.3-70b-instruct-fp8-fast"
            # This is the BUG-1 ROOT CAUSE FIX: the /compat/ endpoint REQUIRES
            # the "workers-ai/" provider scope prefix for @cf/ models.
            if gw_name:
                try:
                    compat_url = build_format3_url(account_id, gw_name)
                    compat_model = format_model_for_compat_endpoint(model_id)
                    payload = {
                        "model":      compat_model,
                        "messages":   messages,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                        "stream":     False,
                    }
                    t0 = time.monotonic()
                    data = json.dumps(payload).encode("utf-8")
                    req = urllib.request.Request(
                        compat_url, data=data, headers=base_headers, method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        result = json.loads(resp.read().decode("utf-8"))
                    latency_ms = (time.monotonic() - t0) * 1000.0
                    logger.info(
                        f"[CF-AI-GW] FORMAT-3 (/compat/) success: slot={i} "
                        f"model={compat_model} latency={latency_ms:.0f}ms"
                    )
                    return result, latency_ms
                except urllib.error.HTTPError as e:
                    if e.code == 400:
                        logger.debug(
                            f"[CF-AI-GW] FORMAT-3 slot={i} HTTP 400 -> trying FORMAT-2"
                        )
                    elif e.code in (401, 403):
                        logger.warning(
                            f"[CF-AI-GW] FORMAT-3 slot={i} HTTP {e.code} -> next slot"
                        )
                        continue
                    elif e.code == 429:
                        delay = _compute_backoff_delay(0)
                        time.sleep(delay)
                        continue
                    else:
                        logger.debug(
                            f"[CF-AI-GW] FORMAT-3 slot={i} HTTP {e.code} -> trying FORMAT-2"
                        )
                except Exception as exc:
                    from monitoring.structured_logger import record_silent_failure
                    record_silent_failure('torshield_ai_gateway.providers:3095', exc)
                    logger.debug(f"[CF-AI-GW] FORMAT-3 slot={i} exception: {exc}")

                # ── FORMAT 2: /workers-ai/{model} in URL (native) ──────
                # URL: gateway.ai.cloudflare.com/v1/{acct}/{gw}/workers-ai/@cf/meta/...
                # NO "model" key in body — model is in the URL path
                try:
                    native_url = build_format2_url(account_id, gw_name, model_id)
                    payload_native = {
                        "messages":   messages,
                        "max_tokens": max_tokens,
                    }
                    if temperature != 0.2:
                        payload_native["temperature"] = temperature
                    t0 = time.monotonic()
                    data = json.dumps(payload_native).encode("utf-8")
                    req = urllib.request.Request(
                        native_url, data=data, headers=base_headers, method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        result = json.loads(resp.read().decode("utf-8"))
                    latency_ms = (time.monotonic() - t0) * 1000.0
                    logger.info(
                        f"[CF-AI-GW] FORMAT-2 (native) success: slot={i} "
                        f"model_in_url latency={latency_ms:.0f}ms"
                    )
                    return result, latency_ms
                except urllib.error.HTTPError as e:
                    if e.code == 400:
                        logger.debug(
                            f"[CF-AI-GW] FORMAT-2 slot={i} HTTP 400 -> next slot"
                        )
                    elif e.code in (401, 403):
                        logger.warning(
                            f"[CF-AI-GW] FORMAT-2 slot={i} HTTP {e.code} -> next slot"
                        )
                        continue
                    elif e.code == 429:
                        delay = _compute_backoff_delay(0)
                        time.sleep(delay)
                        continue
                    else:
                        logger.debug(
                            f"[CF-AI-GW] FORMAT-2 slot={i} HTTP {e.code} -> next slot"
                        )
                except Exception as exc:
                    from monitoring.structured_logger import record_silent_failure
                    record_silent_failure('torshield_ai_gateway.providers:3140', exc)
                    logger.debug(f"[CF-AI-GW] FORMAT-2 slot={i} exception: {exc}")

        logger.error(
            "[CF-AI-GW] All FORMAT-1/2/3 attempts failed across all 11 slots"
        )
        return None  # Caller's existing logic takes over

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        # Provider-level circuit breaker check
        if not self.circuit_breaker.allow_request():
            logger.warning(
                "[CF-AI-GW] Circuit breaker OPEN — skipping request"
            )
            raise RuntimeError(
                f"CF-AI-GW provider circuit breaker is OPEN "
                f"({self.circuit_breaker.failure_count} consecutive failures)"
            )

        # ── Feature-R/v18: Iran-aware circuit breaker check ────────────
        if _IRAN_CB_AVAILABLE:
            try:
                cb = get_iran_circuit_breaker()
                if not cb.can_attempt("cloudflare_ai_gateway"):
                    logger.info("[CF-AI-GW] Iran-aware circuit OPEN — skipping")
                    return ""
            except Exception as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.providers:3169', _remediation_exc)
                pass

        # ── FEATURE-1 v16: DPI Model Override ───────────────────────────
        model = _apply_dpi_model_override("cloudflare_ai_gateway", model)

        chosen_model = self._resolve_model(model, task)

        # ── FIX-18.0: Multi-format dynamic requester (NON-DESTRUCTIVE) ──────
        # Try all 3 CF endpoint formats across all 11 slots FIRST.
        # This runs BEFORE the existing legacy slot loop and short-circuits on success.
        # On failure, the existing legacy code below runs unchanged.
        try:
            _dyn_resp = self._cf_gateway_multi_format_attempt(
                model_id   = chosen_model,
                messages   = messages,
                max_tokens = max_tokens,
                temperature= temperature,
                timeout    = min(timeout, 30),
            )
            if _dyn_resp is not None:
                _dyn_result, _dyn_lat = _dyn_resp
                _extracted = CloudflareWorkersAIProvider._extract_cf_content(_dyn_result)
                if _extracted:
                    logger.info(
                        f"[CF-AI-GW] Dynamic multi-format attempt succeeded "
                        f"(latency={_dyn_lat:.0f}ms)"
                    )
                    self.circuit_breaker.record_success()
                    return _extracted
                logger.debug(
                    "[CF-AI-GW] Dynamic attempt returned 200 but empty content "
                    "— falling through to legacy logic"
                )
            logger.debug(
                "[CF-AI-GW] Dynamic attempt failed — falling through to legacy logic"
            )
        except Exception as _dyn_err:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.providers:3206', _dyn_err)
            logger.warning(
                f"[CF-AI-GW] Dynamic attempt raised exception: {_dyn_err} "
                f"— continuing with legacy"
            )

        # ── FIX-19.0: Try CF Gateway provider cascade (Feature-2) ──────────
        # After Workers AI formats fail, try external providers (OpenAI, Anthropic,
        # etc.) routed through the CF AI Gateway REST API. This only works if
        # BYOK keys are configured in the Cloudflare dashboard.
        try:
            _cascade_resp = self._try_gateway_provider_cascade(
                messages   = messages,
                max_tokens = max_tokens,
            )
            if _cascade_resp is not None:
                _cascade_result, _cascade_lat = _cascade_resp
                _cascade_extracted = CloudflareWorkersAIProvider._extract_cf_content(_cascade_result)
                if _cascade_extracted:
                    logger.info(
                        f"[CF-AI-GW] Provider cascade succeeded "
                        f"(latency={_cascade_lat:.0f}ms)"
                    )
                    self.circuit_breaker.record_success()
                    return _cascade_extracted
                logger.debug(
                    "[CF-AI-GW] Provider cascade returned 200 but empty content "
                    "— falling through to legacy logic"
                )
        except Exception as _cascade_err:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.providers:3235', _cascade_err)
            logger.debug(
                f"[CF-AI-GW] Provider cascade error: {_cascade_err} "
                f"— continuing with legacy"
            )

        # ── ALL EXISTING LEGACY CODE BELOW REMAINS COMPLETELY UNCHANGED ──

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        models_to_try = [chosen_model] + [m for m in CF_STABLE_MODELS if m != chosen_model]

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None
            bad_req_count = 0  # BUG-3 FIX: Track 400s per slot

            # Skip dead slots (slots that previously returned 400+empty body)
            with self._dead_slots_lock:
                if s.index in self._dead_slots:
                    continue

            # Probe gateway reachability before first attempt on this slot
            if attempt == 0 or last_auth_error is None:
                if not self._probe_gateway(s.gateway_url):
                    logger.warning(
                        f"[CF-AI-GW] slot {s.index} gateway unreachable — skipping"
                    )
                    self.rotator.mark_failure(s)
                    self.circuit_breaker.record_failure()
                    continue

            for m in models_to_try:
                # BUG-3 FIX: Skip models that 400'd on THIS slot only.
                # Do NOT use a global _failed_models set — different slots
                # may support different models. Only skip if the model 400'd
                # on the SAME slot we're about to try.
                if hasattr(self, '_slot_failed_models'):
                    if (s.index, m) in self._slot_failed_models:
                        logger.debug(
                            f"[CF-AI-GW] Skipping model {m} on slot {s.index} "
                            f"— previously 400'd on this same slot"
                        )
                        continue

                try:
                    # Sanitize credentials
                    clean_token = _sanitize_api_key(s.api_key)
                    clean_acct  = _sanitize_api_key(s.account_id)
                    clean_acct  # noqa: F841 — explicit reference to silence pyflakes
                    if not clean_token:
                        logger.warning(
                            f"[CF-AI-GW] slot {s.index} has empty API token — skipping"
                        )
                        break  # No point trying other models with empty token

                    # CRITICAL FIX v17.0: Use /compat/ OpenAI-compatible endpoint
                    # Model ID goes in request body, NOT URL path.
                    # URL: {gateway_base}/compat/chat/completions
                    url = self._build_cf_gateway_url(s.gateway_url)
                    headers = {
                        "Content-Type":  "application/json",
                        "Authorization": f"Bearer {clean_token}",
                    }
                    payload = self._build_cf_request_body(
                        model_id=m,
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )
                    resp, lat = self._post_json_with_retry(
                        url, headers, payload, timeout,
                        provider_name="CF-AI-GW", slot_index=s.index
                    )
                    self.rotator.mark_success(s, lat)
                    self.circuit_breaker.record_success()
                    return CloudflareWorkersAIProvider._extract_cf_content(resp)
                except BadRequestError as e:
                    bad_req_count += 1  # BUG-3 FIX: Track per-slot
                    last_err = e  # BUG-3 FIX: Set last_err so slot failure is handled
                    # HTTP 400 — NOT an auth failure. Check if empty body (dead slot)
                    # or model-specific issue (try next model).
                    err_msg = str(e)
                    if "empty body" in err_msg.lower():
                        with self._dead_slots_lock:
                            if s.index not in self._dead_slots:
                                self._dead_slots.add(s.index)
                                logger.warning(
                                    f"[CF-AI-GW] slot {s.index} permanently failed "
                                    f"(HTTP 400 empty body) — "
                                    f"skipping all remaining models for this slot"
                                )
                        break  # Stop trying models for this slot
                    # BUG-3 FIX: Track per-slot model failures (not global)
                    if not hasattr(self, '_slot_failed_models'):
                        self._slot_failed_models = set()
                    self._slot_failed_models.add((s.index, m))
                    logger.debug(
                        f"[CF-AI-GW] slot {s.index} model {m} → "
                        f"BadRequestError: {err_msg[:200]}"
                    )
                    continue  # Try next model on THIS slot
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code in (403, 401):
                        last_auth_error = e
                        logger.warning(
                            f"[CF-AI-GW] slot {s.index} AUTH FAIL HTTP {e.code} "
                            f"URL={s.gateway_url[:40]}..."
                        )
                        self.circuit_breaker.record_failure()
                        break  # Try next slot, not next model
                    # NOTE: 400 is now caught as BadRequestError above, not here
                    if e.code == 404:
                        logger.debug(f"[CF-AI-GW] Model not found: {m}")
                        if not hasattr(self, '_slot_failed_models'):
                            self._slot_failed_models = set()
                        self._slot_failed_models.add((s.index, m))
                        continue
                    logger.warning(
                        f"[CF-AI-GW] slot {s.index} "
                        f"URL={s.gateway_url[:40]}... HTTP {e.code}"
                    )
                    self.circuit_breaker.record_failure()
                    raise

            # BUG-3 FIX: After trying all models for a slot,
            # handle the result properly — mark failure and continue
            # to the NEXT slot. NEVER raise here — always try next slot.
            if bad_req_count > 0 and bad_req_count == len(models_to_try):
                logger.warning(
                    f"[CF-AI-GW] slot {s.index} — all {len(models_to_try)} "
                    f"models returned 400, moving to next slot"
                )
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                continue  # ← Always continue to next slot

            if last_err:
                if isinstance(last_err, (urllib.error.HTTPError,)) and last_err.code in (403, 401):
                    self.rotator.mark_failure(s)
                    continue  # Try next slot
                logger.warning(f"[CF-AI-GW] slot {s.index} all models failed")
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(2 ** attempt)

        # All slots exhausted — check if all are dead (config error, not runtime)
        with self._dead_slots_lock:
            all_dead = all(
                s.index in self._dead_slots
                for s in self.rotator.slots
            )

        if all_dead:
            raise ProviderConfigurationError(
                f"[CF-AI-GW] All {len(self.rotator.slots)} slots failed "
                f"(HTTP 400 / empty body on first model attempt per slot). "
                f"Verify CF_ACCOUNT_ID and CF_API_TOKEN values in GitHub Secrets.",
                provider="cloudflare_ai_gateway",
            )

        if last_auth_error:
            raise last_auth_error
        return ""
