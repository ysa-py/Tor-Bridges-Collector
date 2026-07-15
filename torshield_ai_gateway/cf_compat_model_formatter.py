"""
cf_compat_model_formatter.py — Correct model ID formatting per CF endpoint type
==================================================================================

NON-DESTRUCTIVE: New standalone module. Existing code untouched.
Purpose: Correctly format model IDs for each Cloudflare AI Gateway endpoint type.

ENDPOINT FORMAT REFERENCE:
  ┌─────────────────┬──────────────────────────────────────────────────────────────────────┐
  │  FORMAT         │  Details                                                             │
  ├─────────────────┼──────────────────────────────────────────────────────────────────────┤
  │  FORMAT-1       │  URL: https://api.cloudflare.com/client/v4/accounts/{ID}/ai/v1/     │
  │  (REST API)     │       chat/completions                                               │
  │  ← TRY FIRST   │  Auth: Authorization: Bearer {CF_API_TOKEN}                          │
  │                 │  Header: cf-aig-gateway-id: {GATEWAY_NAME}  (optional, for logging) │
  │                 │  Model: "@cf/meta/llama-3.3-70b-instruct-fp8-fast"  (no prefix)     │
  ├─────────────────┼──────────────────────────────────────────────────────────────────────┤
  │  FORMAT-2       │  URL: https://gateway.ai.cloudflare.com/v1/{ACCT}/{GW}/             │
  │  (Native path)  │       workers-ai/@cf/meta/llama-3.3-70b-instruct-fp8-fast           │
  │                 │  Auth: Authorization: Bearer {CF_API_TOKEN}                          │
  │                 │  Body: {"messages": [...]}  ← NO model key in body!                 │
  ├─────────────────┼──────────────────────────────────────────────────────────────────────┤
  │  FORMAT-3       │  URL: https://gateway.ai.cloudflare.com/v1/{ACCT}/{GW}/             │
  │  (/compat/)     │       compat/chat/completions                                        │
  │  ← MOST COMMON │  Auth: Authorization: Bearer {CF_API_TOKEN}                          │
  │                 │  Model: "workers-ai/@cf/meta/llama-3.3-70b-instruct-fp8-fast"       │
  │                 │  ← "workers-ai/" PREFIX IS MANDATORY HERE                            │
  ├─────────────────┼──────────────────────────────────────────────────────────────────────┤
  │  FORMAT-4       │  Same URL as FORMAT-3 (/compat/chat/completions)                    │
  │  (External)     │  Model: "openai/gpt-4o-mini" / "anthropic/claude-3-haiku" etc.      │
  │                 │  Used for BYOK (Bring Your Own Key) external models                  │
  └─────────────────┴──────────────────────────────────────────────────────────────────────┘

Version: 1.0.0 (Fix-18.0 — BUG-1 root-cause resolution)
"""

import logging
import os
import re

log = logging.getLogger("torshield.cf_formatter")


# ── Hardcoded static fallback models (used when brain returns 0 models) ──────
STATIC_FALLBACK_MODELS = [
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
    "@cf/meta/llama-3.1-8b-instruct",
    "@cf/qwen/qwq-32b",
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
    "@cf/mistral/mistral-7b-instruct-v0.1",
    "@cf/google/gemma-7b-it",
    "@cf/meta/llama-2-7b-chat-int8",
    "@cf/openai/gpt-oss-120b",
    "@cf/nvidia/nemotron-3-120b-a12b",
    "@cf/meta/llama-4-scout-17b-16e-instruct",
    "@cf/zai-org/glm-4.7-flash",
    "@cf/microsoft/phi-4",
    "@cf/mistral/mistral-large-2407",
    "@cf/google/gemma-3-27b-it",
]

# ── Portkey-compatible model names (never use @cf/ models with Portkey) ──────
PORTKEY_SAFE_MODELS = [
    "llama3.1-70b",
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "gpt-4o-mini",
    "mistral-7b-instruct",
    "meta/llama-3.1-70b-instruct",
    "meta/llama-3.1-8b-instruct",
]


def format_model_for_compat_endpoint(model_id: str) -> str:
    """
    Add 'workers-ai/' prefix to @cf/ models for /compat/chat/completions endpoint.

    Cloudflare /compat/ endpoint requires provider-scoped model IDs:
      @cf/meta/llama-3.3-70b-instruct-fp8-fast  →  workers-ai/@cf/meta/llama-3.3-70b-instruct-fp8-fast
      openai/gpt-4o-mini                         →  openai/gpt-4o-mini  (unchanged)
      anthropic/claude-3-haiku                   →  anthropic/claude-3-haiku  (unchanged)

    This is the ROOT CAUSE fix for BUG-1: the /compat/ endpoint returns HTTP 400
    when @cf/ models are sent without the "workers-ai/" provider scope prefix.
    """
    if not model_id:
        return model_id
    # Already has provider scope prefix (not @cf/) → leave unchanged
    if "/" in model_id and not model_id.startswith("@cf/"):
        return model_id
    # @cf/ model without workers-ai/ prefix → add it
    if model_id.startswith("@cf/"):
        return f"workers-ai/{model_id}"
    # Already has workers-ai/ prefix → leave unchanged
    if model_id.startswith("workers-ai/"):
        return model_id
    # Unknown format → return as-is (safe fallback)
    return model_id


def format_model_for_rest_api(model_id: str) -> str:
    """
    Format model for CF REST API endpoint (no prefix needed for @cf/ models).

    https://api.cloudflare.com/client/v4/accounts/{id}/ai/v1/chat/completions
    accepts: "@cf/meta/llama-3.3-70b-instruct-fp8-fast" directly.
    This is FORMAT-1 — the most reliable endpoint format.
    """
    # Strip workers-ai/ prefix if present (REST API doesn't need it)
    if model_id.startswith("workers-ai/@cf/"):
        return model_id[len("workers-ai/"):]
    return model_id


def format_model_for_native_path(model_id: str) -> str:
    """
    Format model for CF native Workers AI path endpoint (FORMAT-2).

    URL: https://gateway.ai.cloudflare.com/v1/{ACCT}/{GW}/workers-ai/@cf/meta/...
    The model goes in the URL path, NOT in the request body.
    The @cf/ prefix must be kept in the path.
    """
    # Strip workers-ai/ prefix if present (it goes in the URL, not the model name)
    clean = model_id
    if clean.startswith("workers-ai/"):
        clean = clean[len("workers-ai/"):]
    return clean


def is_cf_model(model_id: str) -> bool:
    """Returns True if model is a Cloudflare Workers AI model."""
    clean = model_id.replace("workers-ai/", "")
    return clean.startswith("@cf/")


def get_portkey_safe_model(preferred: str = "") -> str:
    """
    Returns a Portkey-compatible model ID, never an @cf/ model.

    BUG-4 FIX: Portkey NEVER accepts @cf/ or workers-ai/ prefixed models.
    This function ensures that any CF-specific model ID is replaced with
    a Portkey-compatible equivalent before the request is sent.
    """
    # If the preferred model is already Portkey-safe, use it
    if preferred and not is_cf_model(preferred) and not preferred.startswith("workers-ai/"):
        return preferred

    # Use env var if set and valid
    env_model = os.environ.get("PORTKEY_HEALTH_MODEL", "").strip()
    if env_model and not is_cf_model(env_model) and not env_model.startswith("workers-ai/"):
        return env_model

    # Fall back to safe Portkey models
    return PORTKEY_SAFE_MODELS[0]  # "llama3.1-70b" — always safe for Portkey


def extract_gateway_name(gateway_url: str, account_id: str = "") -> str:
    """
    Robustly extract gateway name from CF_AI_GATEWAY_URL_N env var.

    Handles all stored formats:
      https://gateway.ai.cloudflare.com/v1/{account}/{name}/compat/chat/completions
      https://gateway.ai.cloudflare.com/v1/{account}/{name}
      {name}  (bare gateway name)

    This is essential for building FORMAT-1 (REST API) and FORMAT-2 (native path)
    URLs where the gateway name is needed separately from the full URL.
    """
    if not gateway_url:
        return ""
    url = gateway_url.strip().rstrip("/")

    # Strip known suffixes to get the base gateway URL
    for suffix in [
        "/compat/chat/completions",
        "/workers-ai/v1/chat/completions",
        "/compat",
        "/workers-ai/v1",
        "/workers-ai",
    ]:
        if url.endswith(suffix):
            url = url[: -len(suffix)]
            break

    # Try to extract gateway name from the URL path
    # Pattern: gateway.ai.cloudflare.com/v1/{account_id}/{gateway_name}
    m = re.search(
        r"gateway\.ai\.cloudflare\.com/v1/[^/]+/([^/]+)/?$", url
    )
    if m:
        return m.group(1)

    # If it's just a bare name (no slashes, no dots)
    if "/" not in url and "." not in url:
        return url

    log.warning(
        f"[Formatter] Could not extract gateway name from: {gateway_url[:80]}"
    )
    return ""


def build_format1_url(account_id: str) -> str:
    """
    Build FORMAT-1 (REST API) URL.

    URL: https://api.cloudflare.com/client/v4/accounts/{ID}/ai/v1/chat/completions
    This is the most reliable endpoint — try it FIRST.
    """
    return (
        f"https://api.cloudflare.com/client/v4/accounts"
        f"/{account_id}/ai/v1/chat/completions"
    )


def build_format3_url(account_id: str, gateway_name: str) -> str:
    """
    Build FORMAT-3 (/compat/) URL.

    URL: https://gateway.ai.cloudflare.com/v1/{ACCT}/{GW}/compat/chat/completions
    Model MUST include "workers-ai/" prefix for @cf/ models.
    """
    return (
        f"https://gateway.ai.cloudflare.com/v1"
        f"/{account_id}/{gateway_name}/compat/chat/completions"
    )


def build_format2_url(account_id: str, gateway_name: str, model_id: str) -> str:
    """
    Build FORMAT-2 (native path) URL.

    URL: https://gateway.ai.cloudflare.com/v1/{ACCT}/{GW}/workers-ai/@cf/meta/...
    Model goes in the URL path, NOT in the request body.
    """
    clean_model = format_model_for_native_path(model_id)
    return (
        f"https://gateway.ai.cloudflare.com/v1"
        f"/{account_id}/{gateway_name}/workers-ai/{clean_model}"
    )
