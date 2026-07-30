# ══════════════════════════════════════════════════════════════════════════════
# TorShield-IR Environment Variables Template
# ══════════════════════════════════════════════════════════════════════════════
#
# Copy this file to .env and fill in your values:
#   cp configs/env_template.sh .env
#   source .env
#
# All values are optional unless marked [REQUIRED].
# Values can also be set as GitHub Actions Secrets.
#
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: Cerebras.ai
# ─────────────────────────────────────────────────────────────────────────────
# Fast inference provider (2100 tokens/sec). Primary provider in the waterfall.
# Get your key at: https://cloud.cerebras.ai/
CEREBRAS_API_KEY=""                    # [RECOMMENDED] Cerebras API key

# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: Cloudflare Workers AI + AI Gateway
# ─────────────────────────────────────────────────────────────────────────────
# Cloudflare provides multiple slots for redundancy and quota multiplication.
# Each slot has its own CF_ACCOUNT_ID, CF_API_TOKEN, and CF_AI_GATEWAY_URL.

# Account IDs for each Cloudflare slot (1-11)
# Each slot can have a different account_id for quota multiplication
CF_ACCOUNT_ID_1=""                      # [RECOMMENDED] Cloudflare account ID slot 1
CF_ACCOUNT_ID_2=""                      # Cloudflare account ID slot 2
CF_ACCOUNT_ID_3=""                      # Cloudflare account ID slot 3
CF_ACCOUNT_ID_4=""                      # Cloudflare account ID slot 4
CF_ACCOUNT_ID_5=""                      # Cloudflare account ID slot 5
CF_ACCOUNT_ID_6=""                      # Cloudflare account ID slot 6
CF_ACCOUNT_ID_7=""                      # Cloudflare account ID slot 7
CF_ACCOUNT_ID_8=""                      # Cloudflare account ID slot 8
CF_ACCOUNT_ID_9=""                      # Cloudflare account ID slot 9
CF_ACCOUNT_ID_10=""                     # Cloudflare account ID slot 10
CF_ACCOUNT_ID_11=""                     # Cloudflare account ID slot 11

# API tokens for each Cloudflare slot (1-11)
# At least CF_API_TOKEN_1 should be set for Workers AI access.
CF_API_TOKEN_1=""                      # [RECOMMENDED] Cloudflare API token slot 1
CF_API_TOKEN_2=""                      # Cloudflare API token slot 2
CF_API_TOKEN_3=""                      # Cloudflare API token slot 3
CF_API_TOKEN_4=""                      # Cloudflare API token slot 4
CF_API_TOKEN_5=""                      # Cloudflare API token slot 5
CF_API_TOKEN_6=""                      # Cloudflare API token slot 6
CF_API_TOKEN_7=""                      # Cloudflare API token slot 7
CF_API_TOKEN_8=""                      # Cloudflare API token slot 8
CF_API_TOKEN_9=""                      # Cloudflare API token slot 9
CF_API_TOKEN_10=""                     # Cloudflare API token slot 10
CF_API_TOKEN_11=""                     # Cloudflare API token slot 11

# CF AI Gateway URLs — full absolute URLs for cached inference
# Must start with https://gateway.ai.cloudflare.com/v1/{account_id}/
# Up to 11 gateway URLs for slot rotation
CF_AI_GATEWAY_URL_1=""                 # [RECOMMENDED] CF AI Gateway URL slot 1
CF_AI_GATEWAY_URL_2=""                 # CF AI Gateway URL slot 2
CF_AI_GATEWAY_URL_3=""                 # CF AI Gateway URL slot 3
CF_AI_GATEWAY_URL_4=""                 # CF AI Gateway URL slot 4
CF_AI_GATEWAY_URL_5=""                 # CF AI Gateway URL slot 5
CF_AI_GATEWAY_URL_6=""                 # CF AI Gateway URL slot 6
CF_AI_GATEWAY_URL_7=""                 # CF AI Gateway URL slot 7
CF_AI_GATEWAY_URL_8=""                 # CF AI Gateway URL slot 8
CF_AI_GATEWAY_URL_9=""                 # CF AI Gateway URL slot 9
CF_AI_GATEWAY_URL_10=""                # CF AI Gateway URL slot 10
CF_AI_GATEWAY_URL_11=""                # CF AI Gateway URL slot 11

# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: Portkey.ai
# ─────────────────────────────────────────────────────────────────────────────
# Meta-router provider — routes to multiple backends.
# Get your key at: https://app.portkey.ai/
PORTKEY_API_KEY=""                     # [RECOMMENDED] Portkey API key (pk- prefix)
PORTKEY_GATEWAY_URL="https://api.portkey.ai/v1"  # Portkey gateway URL

# Alternative: per-slot Portkey virtual keys
PORTKEY_VIRTUAL_KEY_1=""               # Portkey virtual key slot 1
PORTKEY_VIRTUAL_KEY_2=""               # Portkey virtual key slot 2
PORTKEY_VIRTUAL_KEY_3=""               # Portkey virtual key slot 3

# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: Groq (used by self_heal.py)
# ─────────────────────────────────────────────────────────────────────────────
# Used as a fallback AI provider in the self-healing system.
GROQ_API_KEY=""                        # Groq API key for self-heal

# ─────────────────────────────────────────────────────────────────────────────
# GITHUB ACTIONS / SELF-HEAL
# ─────────────────────────────────────────────────────────────────────────────
# Required for autonomous self-healing (committing patches back to repo)
GITHUB_TOKEN=""                        # GitHub personal access token
GITHUB_REPOSITORY=""                   # Repository in owner/repo format
GITHUB_SHA=""                          # Current commit SHA (set by GitHub Actions)
GH_PAT_AUTOFIX=""                      # [SELF-HEAL] GitHub PAT for auto-fix commits
GH_REPO_OWNER=""                       # [SELF-HEAL] Repository owner
GH_REPO_NAME=""                        # [SELF-HEAL] Repository name

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK / TESTING CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
# Bridge collection and testing parameters
MAX_WORKERS="150"                      # Maximum concurrent workers
CONNECTION_TIMEOUT="8"                 # Connection timeout in seconds
SSL_TIMEOUT="6"                        # SSL handshake timeout in seconds
MAX_RETRIES="2"                        # Maximum retry attempts
MAX_TEST_PER_TYPE="1000"               # Maximum bridges to test per transport type

# ─────────────────────────────────────────────────────────────────────────────
# TIME WINDOWS
# ─────────────────────────────────────────────────────────────────────────────
RECENT_HOURS="72"                      # Hours to consider bridges "recent"
HISTORY_RETENTION_DAYS="45"            # Days to retain bridge history

# ─────────────────────────────────────────────────────────────────────────────
# FILE PATHS
# ─────────────────────────────────────────────────────────────────────────────
BRIDGE_DIR="bridge"                    # Directory for bridge data
EXPORT_DIR="export"                    # Directory for exported bridge files

# ─────────────────────────────────────────────────────────────────────────────
# REPOSITORY URL
# ─────────────────────────────────────────────────────────────────────────────
# Used to fetch static bridge lists from GitHub
REPO_URL="https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main"

# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Optional: send bridge updates to a Telegram channel
TELEGRAM_BOT_TOKEN=""                  # Telegram bot token
TELEGRAM_CHAT_ID=""                    # Telegram chat/channel ID
TELEGRAM_UPLOAD="false"                # Enable ZIP upload to Telegram

# ─────────────────────────────────────────────────────────────────────────────
# PROXY CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
# Optional: use a proxy for all HTTP requests
HTTP_PROXY=""                          # HTTP proxy URL (e.g., socks5://127.0.0.1:1080)
HTTPS_PROXY=""                         # HTTPS proxy URL

# ─────────────────────────────────────────────────────────────────────────────
# COLLECTION SOURCES (toggle on/off)
# ─────────────────────────────────────────────────────────────────────────────
USE_TORPROJECT_SCRAPER="true"          # Enable bridges.torproject.org scraper
USE_MOAT_API="true"                    # Enable MOAT API bridge collector
USE_BRIDGEDB_API="true"               # Enable BridgeDB API collector
USE_TELEGRAM_SOURCES="false"           # Enable Telegram bridge channels
USE_STATIC_BRIDGES="true"             # Enable static bridge list

# ─────────────────────────────────────────────────────────────────────────────
# IRAN-SPECIFIC CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
# NIN mode: rescore bridges for internet-cut scenario
NIN_MODE="false"                       # Enable NIN (internet cut) scoring mode

# Deep testing: test ALL bridges (slower but more thorough)
DEEP_TEST="false"                      # Enable deep testing mode


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE FLAGS (new capabilities default to enabled)
# ─────────────────────────────────────────────────────────────────────────────
# These flags mirror config/feature_flags.py. Leave them as "true" to use the
# repaired/enhanced runtime path; set any individual flag to "false" to opt out
# without removing the capability from the codebase.
ENABLE_ENDPOINT_VALIDATION="true"      # Enable endpoint validation layer
ENABLE_CIRCUIT_BREAKER="true"          # Enable enhanced per-slot circuit breaker
ENABLE_MODEL_REGISTRY="true"           # Enable dynamic model registry discovery
ENABLE_RETRY_FAILOVER="true"           # Enable enhanced retry and failover engine
ENABLE_SELF_HEALING="true"             # Enable self-healing engine
ENABLE_STRUCTURED_LOGGING="true"       # Enable structured diagnostics logging
ENABLE_REPORT_GENERATION="true"        # Enable report generation
ENABLE_ANTI_DPI_IRAN="true"            # Enable enhanced Iran anti-DPI behavior
ENABLE_UTLS_EVASION="true"             # Enable uTLS evasion layer
ENABLE_IRST_ROUTING="true"             # Enable IRST time-based predictive routing
ENABLE_COMPAT_PATH_FIX="true"          # Enable Cloudflare AI Gateway /compat/ path fix
ENABLE_TELEMETRY="true"                # Enable telemetry watcher

# ─────────────────────────────────────────────────────────────────────────────
# v4: uTLS Evasion, Elite Registry, Circuit Breaker, Telemetry, IRST windows
# ─────────────────────────────────────────────────────────────────────────────
# REMEDIATION 2026-06-21: these 16 keys existed in the real runtime .env but
# were missing from this template, so scripts/circleci_env_bootstrap.sh never
# materialised them in CI — Iran-specific stealth timing, uTLS evasion, the
# circuit breaker, the elite registry, and telemetry would silently fall back
# to Python-side defaults (or empty string) in CI with no error and no
# warning. Values below mirror the real .env defaults exactly.

# uTLS Evasion Layer (default: enabled)
UTLS_EVASION_MODE="true"               # Enable uTLS fingerprint evasion
UTLS_PROFILE_ROTATION="30"             # Rotate uTLS profile every N requests

# Elite Registry: dynamic model discovery (default: enabled)
ELITE_REGISTRY_ENABLED="true"          # Enable elite model registry
ELITE_REGISTRY_REFRESH_HRS="6"         # Refresh interval in hours

# Circuit Breaker 11-Slot: zero-error fallback (default: enabled)
CIRCUIT_BREAKER_ENABLED="true"         # Enable the 11-slot circuit breaker
CIRCUIT_BREAKER_MAX_FAILURES="3"       # Failures before a slot opens
CIRCUIT_BREAKER_RESET_SECS="300"       # Seconds before a half-open retry
SESSION_BLACKLIST_DURATION_SECS="3600" # Session blacklist duration in seconds

# Telemetry Watcher (default: enabled)
TELEMETRY_ENABLED="true"               # Enable telemetry_watcher.py
TELEMETRY_AUTO_DEBUG_THRESHOLD="2"     # Failures before auto-debug triggers
TELEMETRY_LOG_MAX_MB="10"              # Max telemetry log size in MB

# IRST (Iran Standard Time) high-censorship / ultra-stealth hour windows,
# used for time-based predictive routing
IRST_HIGH_CENSORSHIP_START="18"        # Hour (IRST, 24h) high-censorship begins
IRST_HIGH_CENSORSHIP_END="1"           # Hour (IRST, 24h) high-censorship ends
IRST_ULTRA_STEALTH_START="20"          # Hour (IRST, 24h) ultra-stealth begins
IRST_ULTRA_STEALTH_END="23"            # Hour (IRST, 24h) ultra-stealth ends

# Database (currently not read by any module as of the 2026-06-21 audit —
# kept here for forward-compatibility rather than dropped; confirm before
# wiring real code to it)
DATABASE_URL=""                        # Optional database connection string

# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONALLY DISCOVERED (REMEDIATION 2026-06-21) — secrets-manifest cross-check
# ─────────────────────────────────────────────────────────────────────────────
# Found while building docs/SECRETS_MANIFEST.md: these keys are referenced
# by the dormant GitHub Actions workflows AND actively read by current
# provider code (12 of 14 confirmed), but existed in NEITHER .env NOR this
# template on either side of the CI migration — a second, independent
# secrets-migration gap from the original 16 in the section above.
CEREBRAS_API_KEY_1=""                  # Cerebras API key, slot 1
CEREBRAS_API_KEY_2=""                  # Cerebras API key, slot 2
CEREBRAS_API_KEY_3=""                  # Cerebras API key, slot 3
DEEPSEEK_API_KEY=""                    # DeepSeek provider API key
GEMINI_API_KEY=""                      # Google Gemini provider API key
HUGGINGFACE_API_KEY=""                 # HuggingFace inference API key
HYPERBOLIC_API_KEY=""                  # Hyperbolic provider API key
MISTRAL_API_KEY=""                     # Mistral provider API key
PORTKEY_API_KEY_1=""                   # Portkey API key, slot 1
PORTKEY_API_KEY_2=""                   # Portkey API key, slot 2
PORTKEY_API_KEY_3=""                   # Portkey API key, slot 3
PORTKEY_HEALTH_MODEL=""                # Model used for Portkey health checks
PORTKEY_PROVIDER_KEY=""                # Portkey provider routing key
RIPE_ATLAS_API_KEY=""                  # RIPE Atlas measurement API key

# ─────────────────────────────────────────────────────────────────────────────
# CI RUNTIME DETECTION
# ─────────────────────────────────────────────────────────────────────────────
# Automatically set by GitHub Actions/CircleCI; do not override manually in
# shared secrets contexts. Defaults mirror local/offline bootstrap behavior so
# verification can confirm every .env key is documented in this template.
GITHUB_ACTIONS="false"                 # Set to true automatically in GitHub Actions
CI="false"                             # Generic CI marker
CI_PROVIDER=""                         # CI provider name (for example: circleci)
CIRCLE_BUILD_URL=""                    # CircleCI build URL
CIRCLE_PROJECT_REPONAME=""             # CircleCI repository name
CIRCLE_BRANCH="main"                   # CircleCI branch name
CIRCLE_SHA1=""                         # CircleCI commit SHA

echo "✓ TorShield-IR environment template loaded."
echo "  Configure the [RECOMMENDED] variables above before running the pipeline."
