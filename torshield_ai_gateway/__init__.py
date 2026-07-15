"""
torshield_ai_gateway — v21.0 Ultra-Quantum Edition + Dynamic Brain
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v19.0 CHANGES (TorShield-IR AI Gateway v19.0 — ZERO ERROR):
  - BUG-P: Portkey wrong Cerebras model name — added _CEREBRAS_MODEL_ALIASES
    and _resolve_model_for_provider() to translate Groq model names to
    Cerebras equivalents. Multi-model cascade tries discovered models first.
  - BUG-Q: Only 2 of 4 auth strategies tried — fixed inner loop to use
    `continue` instead of `break`, ensuring all 4 strategies are attempted.
  - BUG-R: break vs continue for HTTP 400 — changed from `break` to
    `continue` so that a 400 from one strategy doesn't skip remaining ones.
  - BUG-S: Status label mismatch — _classify_portkey_status() now returns
    'gateway_config_required' instead of 'no_backend_configured' for
    routing/authentication failures.
  - FEATURE-T: AI-Powered Real-Time DPI Threat Level Detector —
    AIThreatDetector in ai_threat_detector.py uses statistical inference
    from provider response patterns to detect Iran DPI activity.
  - FEATURE-U: Adaptive Multi-Model Health Check Strategy — health check
    tries multiple models per provider when first model returns 400.
  - FEATURE-V: Smart Provider Health Cache with TTL — ProviderHealthCache
    prevents repeatedly hitting dead providers within a run.
  - FEATURE-W: Improved DPI Evasion in iran_traffic_evasion.py —
    Origin/Referer camouflage, realistic IP generation, TLS fragmentation
    marker, and human-pause simulation in retry timing.
  - FEATURE-X: Self-Healing Provider State Persistence — circuit breaker
    state can be saved/loaded across CI runs.
  - ZERO DELETIONS: All existing modules, functions, classes preserved.

v21.0 CHANGES (Fix-18.0: Zero-Error Edition):
  - BUG-N: Portkey 404 root cause fix — removed broken _probe_working_url(),
    added _normalize_gateway_url() for deterministic URL construction,
    added _build_auth_headers() with multi-strategy auth cascade
    (virtual_key → config_object → provider_passthrough → bare_key).
  - BUG-O: Portkey graceful degradation for 404 — health check classifies
    Portkey 404/routing errors as SKIP (not ERROR).
  - FEATURE-Q: DPI-Aware Provider Selection — ProviderDPIProfile and
    DPIAwareProviderSelector reorder providers by DPI safety for health checks.
  - FEATURE-R: Self-Healing Circuit Breaker with Iran Geo-Awareness —
    IranAwareCircuitBreaker opens faster for Iran-blocked providers.
  - FEATURE-S: Adaptive Iran DPI Evasion Headers — IranTrafficEvasion
    applies browser camouflage and noise headers based on threat level.
  - ZERO DELETIONS: All existing modules, functions, classes preserved.
  - NEW: dynamic_model_brain.py — Live model fetcher + intelligent scorer
    Fetches models from all 11 CF accounts + Portkey APIs concurrently.
    Scores models automatically (params, capabilities, context, recency).
    Replaces hardcoded model IDs with live, scored, dynamic ranking.
    Falls back to existing model_selector.py on any failure.
  - NEW: dynamic_brain_anti_dpi.py — AI-powered anti-DPI integration
    Detects Iran DPI threat level using multiple signal sources.
    Automatically adjusts model selection for anti-DPI stealth.
    Prefers CF-hosted models when DPI is active.
    Limits response sizes to reduce traffic analysis surface.
  - INTEGRATED: All providers now try Dynamic Brain first,
    falling back to existing model_selector on any error.
  - INTEGRATED: Health check Step 0 refreshes brain before checks.
  - INTEGRATED: CI workflow uses live model ranking step.
  - ZERO DELETIONS: All existing modules, functions, classes preserved.

v18.0 CHANGES (Correction 7: URL Path + Response Parser + Config Errors):
  - CF AI Gateway URL uses OpenAI-compatible endpoint:
    {gateway_base}/workers-ai/v1/chat/completions with model in request body
  - CF Workers AI direct URL uses OpenAI-compatible endpoint:
    https://api.cloudflare.com/client/v4/accounts/{acct}/ai/v1/chat/completions
  - _extract_text() NEVER returns str(response) — always extracts content properly
  - ProviderConfigurationError for permanent config failures (no retry)
  - _dead_slots with threading.Lock for thread-safe dead slot tracking
  - CF slot 400+empty-body → dead-listed, ONE warning per slot
  - Health check max_tokens=100, prompt tightened
  - Portkey key validation: prefix check removed, length-only check (>=16 chars)
  - BadRequestError for HTTP 400 — separated from auth failures
  - normalize_cf_gateway_url() auto-fixes bare gateway URLs
  - Circuit breaker threshold raised to max(n_slots, 20)
  - Health check max_tokens=256, prompt simplified
"""
from .exceptions import BadRequestError, ProviderConfigurationError
from .gateway import TorShieldAIGateway, get_gateway
from .iran_auto_defense import IranAutoDefense, get_auto_defense, run_defense_cycle
from .local_ai_engine import LocalAIEngine
from .polymorphic_traffic_morpher import PolymorphicTrafficMorpher
from .model_selector import (
    CloudflareModelSelector,
    best_cf_model,
    model_selector_status,
    ranked_cf_models,
)
from .smart_bypass_engine import SmartBypassEngine

# V2 modules (graceful — import errors are non-fatal)
try:
    from .iran_smart_anti_filter_v2 import IranSmartAntiFilterV2
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:92', _remediation_exc)
    IranSmartAntiFilterV2 = None  # type: ignore[misc,assignment]

try:
    from .ai_anti_dpi_iran_v2 import IranAntiDPIV2
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:97', _remediation_exc)
    IranAntiDPIV2 = None  # type: ignore[misc,assignment]

# V3 modules (graceful — import errors are non-fatal)
try:
    from .neural_anti_dpi_v3 import (
        AntiDPIV3Orchestrator,
        ECHFallbackRouter,
        JA3_JA3S_RotationEngine,
        NeuralTrafficMorphing,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:108', _remediation_exc)
    NeuralTrafficMorphing = None  # type: ignore[misc,assignment]
    JA3_JA3S_RotationEngine = None  # type: ignore[misc,assignment]
    ECHFallbackRouter = None  # type: ignore[misc,assignment]
    AntiDPIV3Orchestrator = None  # type: ignore[misc,assignment]

# V3 Anti-Filter + Anti-DPI (graceful — import errors are non-fatal)
try:
    from .iran_anti_filter_v3 import (
        EvasionStrategy,
        FilterType,
        SmartAntiFilterEngine,
        get_anti_filter_engine,
        run_anti_filter_cycle,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:123', _remediation_exc)
    SmartAntiFilterEngine = None  # type: ignore[misc,assignment]
    FilterType = None  # type: ignore[misc,assignment]
    EvasionStrategy = None  # type: ignore[misc,assignment]
    get_anti_filter_engine = None  # type: ignore[misc,assignment]
    run_anti_filter_cycle = None  # type: ignore[misc,assignment]

# Anti-Censorship Engine (graceful — import errors are non-fatal)
try:
    from .anti_censorship import (
        AntiCensorshipEngine,
        CensorshipLevel,
        DPIAction,
        IranDPIEvasionV2,
        IranDPISignatures,
        TransportType,
        get_anti_censorship_engine,
        get_dpi_evasion_v2,
        run_anti_censorship_cycle,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:143', _remediation_exc)
    AntiCensorshipEngine = None  # type: ignore[misc,assignment]
    TransportType = None  # type: ignore[misc,assignment]
    DPIAction = None  # type: ignore[misc,assignment]
    CensorshipLevel = None  # type: ignore[misc,assignment]
    IranDPISignatures = None  # type: ignore[misc,assignment]
    get_anti_censorship_engine = None  # type: ignore[misc,assignment]
    run_anti_censorship_cycle = None  # type: ignore[misc,assignment]
    IranDPIEvasionV2 = None  # type: ignore[misc,assignment]
    get_dpi_evasion_v2 = None  # type: ignore[misc,assignment]

# Auto-Debugger (graceful — import errors are non-fatal)
try:
    from .auto_debugger import (
        AutoDebugger,
        DiagnosticResult,
        FixAction,
        get_auto_debugger,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:162', _remediation_exc)
    AutoDebugger = None  # type: ignore[misc,assignment]
    FixAction = None  # type: ignore[misc,assignment]
    DiagnosticResult = None  # type: ignore[misc,assignment]
    get_auto_debugger = None  # type: ignore[misc,assignment]

# Dynamic Model Brain (Fix-16.0 — graceful, import errors are non-fatal)
try:
    from .dynamic_model_brain import (
        DynamicModelBrain,
        LiveModel,
        ModelSource,
        activate_anti_dpi_if_needed,
        best_cf_model_live,
        best_portkey_model_live,
        get_brain,
        globally_strongest_model_live,
        ranked_cf_models_live,
        refresh_brain_sync,
        score_model,
        score_model_anti_dpi,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:184', _remediation_exc)
    DynamicModelBrain = None  # type: ignore[misc,assignment]
    LiveModel = None  # type: ignore[misc,assignment]
    ModelSource = None  # type: ignore[misc,assignment]
    get_brain = None  # type: ignore[misc,assignment]
    ranked_cf_models_live = None  # type: ignore[misc,assignment]
    best_portkey_model_live = None  # type: ignore[misc,assignment]
    best_cf_model_live = None  # type: ignore[misc,assignment]
    globally_strongest_model_live = None  # type: ignore[misc,assignment]
    refresh_brain_sync = None  # type: ignore[misc,assignment]
    activate_anti_dpi_if_needed = None  # type: ignore[misc,assignment]
    score_model = None  # type: ignore[misc,assignment]
    score_model_anti_dpi = None  # type: ignore[misc,assignment]

# Dynamic Brain Anti-DPI (Fix-16.0 — graceful, import errors are non-fatal)
try:
    from .dynamic_brain_anti_dpi import (
        DPIAssessment,
        DPIPatternType,
        DPIThreatLevel,
        DynamicBrainDPIAdapter,
        IranDPIAssessor,
        get_dpi_adapter,
        run_dpi_assessment,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:209', _remediation_exc)
    DynamicBrainDPIAdapter = None  # type: ignore[misc,assignment]
    IranDPIAssessor = None  # type: ignore[misc,assignment]
    DPIAssessment = None  # type: ignore[misc,assignment]
    DPIThreatLevel = None  # type: ignore[misc,assignment]
    DPIPatternType = None  # type: ignore[misc,assignment]
    get_dpi_adapter = None  # type: ignore[misc,assignment]
    run_dpi_assessment = None  # type: ignore[misc,assignment]

# Iran Quantum Shield — Ultra-Advanced AI Anti-Filtering & Anti-DPI (graceful)
try:
    from .iran_quantum_shield import (
        BridgeScore,
        DPIPattern,
        IranQuantumShield,
        TLSProfile,
        get_quantum_shield,
        run_quantum_assessment,
        run_quantum_diagnosis,
        score_bridge_for_iran,
    )
    from .iran_quantum_shield import (
        DPIAssessment as QuantumDPIAssessment,
    )
    from .iran_quantum_shield import (
        EvasionStrategy as QuantumEvasionStrategy,
    )
    from .iran_quantum_shield import (
        ThreatLevel as QuantumThreatLevel,
    )
    from .iran_quantum_shield import (
        TransportType as QuantumTransportType,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:242', _remediation_exc)
    IranQuantumShield = None  # type: ignore[misc,assignment]
    DPIPattern = None  # type: ignore[misc,assignment]
    QuantumEvasionStrategy = None  # type: ignore[misc,assignment]
    QuantumThreatLevel = None  # type: ignore[misc,assignment]
    QuantumTransportType = None  # type: ignore[misc,assignment]
    QuantumDPIAssessment = None  # type: ignore[misc,assignment]
    TLSProfile = None  # type: ignore[misc,assignment]
    BridgeScore = None  # type: ignore[misc,assignment]
    get_quantum_shield = None  # type: ignore[misc,assignment]
    run_quantum_assessment = None  # type: ignore[misc,assignment]
    run_quantum_diagnosis = None  # type: ignore[misc,assignment]
    score_bridge_for_iran = None  # type: ignore[misc,assignment]

# v4 NEW: uTLS Evasion, Elite Registry, Circuit Breaker, Telemetry
# (graceful — import errors are non-fatal)
try:
    from uTLS_evasion_layer import (
        TLSFingerprint,
        UTLSManager,
        get_evasion_headers,
        get_randomized_profile,
        get_utls_manager,
        is_ultra_stealth_mode,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:267', _remediation_exc)
    UTLSManager = None  # type: ignore[misc,assignment]
    TLSFingerprint = None  # type: ignore[misc,assignment]
    get_utls_manager = None  # type: ignore[misc,assignment]
    get_evasion_headers = None  # type: ignore[misc,assignment]
    get_randomized_profile = None  # type: ignore[misc,assignment]
    is_ultra_stealth_mode = None  # type: ignore[misc,assignment]

try:
    from elite_registry import (
        EliteRegistry,
        ModelEntry,
        get_registry,
    )
    from elite_registry import (
        get_best_model as registry_get_best_model,
    )
    from elite_registry import (
        get_ranked_models as registry_get_ranked_models,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:287', _remediation_exc)
    EliteRegistry = None  # type: ignore[misc,assignment]
    ModelEntry = None  # type: ignore[misc,assignment]
    get_registry = None  # type: ignore[misc,assignment]
    registry_get_best_model = None  # type: ignore[misc,assignment]
    registry_get_ranked_models = None  # type: ignore[misc,assignment]

try:
    from circuit_breaker_11slot import (
        CircuitBreaker11Slot,
        SlotState,
        get_circuit_breaker,
        get_next_slot,
        mark_slot_failed,
        mark_slot_success,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:303', _remediation_exc)
    CircuitBreaker11Slot = None  # type: ignore[misc,assignment]
    SlotState = None  # type: ignore[misc,assignment]
    get_circuit_breaker = None  # type: ignore[misc,assignment]
    get_next_slot = None  # type: ignore[misc,assignment]
    mark_slot_failed = None  # type: ignore[misc,assignment]
    mark_slot_success = None  # type: ignore[misc,assignment]

try:
    from telemetry_watcher import (
        DailyAggregation,
        TelemetryWatcher,
        generate_daily_report,
        get_telemetry,
        log_dpi_event,
        log_self_heal,
        log_slot_failure,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:321', _remediation_exc)
    TelemetryWatcher = None  # type: ignore[misc,assignment]
    DailyAggregation = None  # type: ignore[misc,assignment]
    get_telemetry = None  # type: ignore[misc,assignment]
    log_dpi_event = None  # type: ignore[misc,assignment]
    log_slot_failure = None  # type: ignore[misc,assignment]
    log_self_heal = None  # type: ignore[misc,assignment]
    generate_daily_report = None  # type: ignore[misc,assignment]

# v5 NEW: CF Compat Model Formatter (Fix-18.0 — BUG-1 root-cause)
# Graceful — import errors are non-fatal
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
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:346', _remediation_exc)
    format_model_for_compat_endpoint = None  # type: ignore[misc,assignment]
    format_model_for_rest_api = None  # type: ignore[misc,assignment]
    format_model_for_native_path = None  # type: ignore[misc,assignment]
    extract_gateway_name = None  # type: ignore[misc,assignment]
    build_format1_url = None  # type: ignore[misc,assignment]
    build_format3_url = None  # type: ignore[misc,assignment]
    build_format2_url = None  # type: ignore[misc,assignment]
    is_cf_model = None  # type: ignore[misc,assignment]
    get_portkey_safe_model = None  # type: ignore[misc,assignment]
    STATIC_FALLBACK_MODELS = None  # type: ignore[misc,assignment]
    PORTKEY_SAFE_MODELS = None  # type: ignore[misc,assignment]

# v6 NEW: Dynamic CF Catalog (Fix-19.0 — Feature-1)
# Graceful — import errors are non-fatal
try:
    from .dynamic_cf_catalog import (
        STATIC_CATALOG,
        CatalogModel,
        CloudflareCatalogFetcher,
        get_cf_catalog,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:368', _remediation_exc)
    CloudflareCatalogFetcher = None  # type: ignore[misc,assignment]
    get_cf_catalog = None  # type: ignore[misc,assignment]
    CatalogModel = None  # type: ignore[misc,assignment]
    STATIC_CATALOG = None  # type: ignore[misc,assignment]

# v6 NEW: Portkey Model Registry (Fix-19.0 — Feature-3)
# Graceful — import errors are non-fatal
try:
    from .portkey_model_registry import (
        PORTKEY_MODEL_PROBE_LIST,
        PORTKEY_SAFE_FALLBACKS,
        PortkeyModelRegistry,
        get_portkey_registry,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:383', _remediation_exc)
    PortkeyModelRegistry = None  # type: ignore[misc,assignment]
    get_portkey_registry = None  # type: ignore[misc,assignment]
    PORTKEY_MODEL_PROBE_LIST = None  # type: ignore[misc,assignment]
    PORTKEY_SAFE_FALLBACKS = None  # type: ignore[misc,assignment]

# v7 NEW: Iran DPI Model Selector (Feature-1 v16.0)
# Graceful — import errors are non-fatal
try:
    from .iran_dpi_model_selector import (
        DPI_PROFILES,
        DPIModelProfile,
        IranDPIModelSelector,
        IranDPIThreatLevel,
        get_dpi_selector,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:399', _remediation_exc)
    IranDPIModelSelector = None  # type: ignore[misc,assignment]
    IranDPIThreatLevel = None  # type: ignore[misc,assignment]
    DPIModelProfile = None  # type: ignore[misc,assignment]
    DPI_PROFILES = None  # type: ignore[misc,assignment]
    get_dpi_selector = None  # type: ignore[misc,assignment]

# v7 NEW: Iran Gateway DPI Shaper (Feature-2 v16.0)
# Graceful — import errors are non-fatal
try:
    from .iran_gateway_dpi_shaper import (
        CF_FRONTING_DOMAINS,
        ISP_SLOT_MAPPING,
        GatewayDPIShaper,
        get_gateway_dpi_shaper,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:415', _remediation_exc)
    GatewayDPIShaper = None  # type: ignore[misc,assignment]
    CF_FRONTING_DOMAINS = None  # type: ignore[misc,assignment]
    ISP_SLOT_MAPPING = None  # type: ignore[misc,assignment]
    get_gateway_dpi_shaper = None  # type: ignore[misc,assignment]

# v8 NEW: Iran-Aware Circuit Breaker (Feature-R v18.0)
# Graceful — import errors are non-fatal
try:
    from .circuit_breaker import (
        CircuitState,
        CircuitStats,
        IranAwareCircuitBreaker,
        get_circuit_breaker,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:430', _remediation_exc)
    CircuitState = None  # type: ignore[misc,assignment]
    CircuitStats = None  # type: ignore[misc,assignment]
    IranAwareCircuitBreaker = None  # type: ignore[misc,assignment]
    get_circuit_breaker = None  # type: ignore[misc,assignment]

# v8 NEW: Iran Traffic Evasion (Feature-S v18.0)
# Graceful — import errors are non-fatal
try:
    from .iran_traffic_evasion import (
        IranTrafficEvasion,
        get_iran_evasion,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:443', _remediation_exc)
    IranTrafficEvasion = None  # type: ignore[misc,assignment]
    get_iran_evasion = None  # type: ignore[misc,assignment]

# v9 NEW: AI Threat Detector (Feature-T v19.0)
# Graceful — import errors are non-fatal
try:
    from .ai_threat_detector import (
        AIThreatDetector,
        get_ai_threat_detector,
    )
    from .ai_threat_detector import (
        ThreatLevel as AIThreatLevel,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:457', _remediation_exc)
    AIThreatDetector = None  # type: ignore[misc,assignment]
    AIThreatLevel = None  # type: ignore[misc,assignment]
    get_ai_threat_detector = None  # type: ignore[misc,assignment]

# v8 NEW: DPI-Aware Provider Selector (Feature-Q v18.0)
# Graceful — import errors are non-fatal
try:
    from .dynamic_brain_anti_dpi import (
        PROVIDER_DPI_PROFILES,
        DPIAwareProviderSelector,
        ProviderDPIProfile,
    )
except ImportError as _remediation_exc:
    from monitoring.structured_logger import record_silent_failure
    record_silent_failure('torshield_ai_gateway.__init__:470', _remediation_exc)
    ProviderDPIProfile = None  # type: ignore[misc,assignment]
    PROVIDER_DPI_PROFILES = None  # type: ignore[misc,assignment]
    DPIAwareProviderSelector = None  # type: ignore[misc,assignment]

__all__ = [
    "TorShieldAIGateway",
    "get_gateway",
    "CloudflareModelSelector",
    "best_cf_model",
    "ranked_cf_models",
    "model_selector_status",
    "LocalAIEngine",
    "SmartBypassEngine",
    "IranAutoDefense",
    "get_auto_defense",
    "run_defense_cycle",
    "IranSmartAntiFilterV2",
    "IranAntiDPIV2",
    "NeuralTrafficMorphing",
    "JA3_JA3S_RotationEngine",
    "ECHFallbackRouter",
    "AntiDPIV3Orchestrator",
    "SmartAntiFilterEngine",
    "FilterType",
    "EvasionStrategy",
    "get_anti_filter_engine",
    "run_anti_filter_cycle",
    "AntiCensorshipEngine",
    "TransportType",
    "DPIAction",
    "CensorshipLevel",
    "IranDPISignatures",
    "get_anti_censorship_engine",
    "run_anti_censorship_cycle",
    "IranDPIEvasionV2",
    "get_dpi_evasion_v2",
    "AutoDebugger",
    "FixAction",
    "DiagnosticResult",
    "get_auto_debugger",
    "ProviderConfigurationError",
    "BadRequestError",
    # Dynamic Brain (Fix-16.0)
    "DynamicModelBrain",
    "LiveModel",
    "ModelSource",
    "get_brain",
    "ranked_cf_models_live",
    "best_portkey_model_live",
    "best_cf_model_live",
    "globally_strongest_model_live",
    "refresh_brain_sync",
    "activate_anti_dpi_if_needed",
    "score_model",
    "score_model_anti_dpi",
    # Dynamic Brain Anti-DPI (Fix-16.0)
    "DynamicBrainDPIAdapter",
    "IranDPIAssessor",
    "DPIAssessment",
    "DPIThreatLevel",
    "DPIPatternType",
    "get_dpi_adapter",
    "run_dpi_assessment",
    # Iran Quantum Shield (v1.0)
    "IranQuantumShield",
    "DPIPattern",
    "QuantumEvasionStrategy",
    "QuantumThreatLevel",
    "QuantumTransportType",
    "QuantumDPIAssessment",
    "TLSProfile",
    "BridgeScore",
    "get_quantum_shield",
    "run_quantum_assessment",
    "run_quantum_diagnosis",
    "score_bridge_for_iran",
    # v4 NEW: uTLS Evasion Layer
    "UTLSManager",
    "TLSFingerprint",
    "get_utls_manager",
    "get_evasion_headers",
    "get_randomized_profile",
    "is_ultra_stealth_mode",
    # v4 NEW: Elite Registry
    "EliteRegistry",
    "ModelEntry",
    "get_registry",
    "registry_get_best_model",
    "registry_get_ranked_models",
    # v4 NEW: Circuit Breaker 11-Slot
    "CircuitBreaker11Slot",
    "SlotState",
    "get_circuit_breaker",
    "get_next_slot",
    "mark_slot_failed",
    "mark_slot_success",
    # v4 NEW: Telemetry Watcher
    "TelemetryWatcher",
    "DailyAggregation",
    "get_telemetry",
    "log_dpi_event",
    "log_slot_failure",
    "log_self_heal",
    "generate_daily_report",
    # v5 NEW: CF Compat Model Formatter (Fix-18.0)
    "format_model_for_compat_endpoint",
    "format_model_for_rest_api",
    "format_model_for_native_path",
    "extract_gateway_name",
    "build_format1_url",
    "build_format3_url",
    "build_format2_url",
    "is_cf_model",
    "get_portkey_safe_model",
    "STATIC_FALLBACK_MODELS",
    "PORTKEY_SAFE_MODELS",
    # v6 NEW: Dynamic CF Catalog (Fix-19.0)
    "CloudflareCatalogFetcher",
    "get_cf_catalog",
    "CatalogModel",
    "STATIC_CATALOG",
    # v6 NEW: Portkey Model Registry (Fix-19.0)
    "PortkeyModelRegistry",
    "get_portkey_registry",
    "PORTKEY_MODEL_PROBE_LIST",
    "PORTKEY_SAFE_FALLBACKS",
    # v7 NEW: Iran DPI Model Selector (Feature-1 v16.0)
    "IranDPIModelSelector",
    "IranDPIThreatLevel",
    "DPIModelProfile",
    "DPI_PROFILES",
    "get_dpi_selector",
    # v7 NEW: Iran Gateway DPI Shaper (Feature-2 v16.0)
    "GatewayDPIShaper",
    "CF_FRONTING_DOMAINS",
    "ISP_SLOT_MAPPING",
    "get_gateway_dpi_shaper",
    # v8 NEW: Iran-Aware Circuit Breaker (Feature-R v18.0)
    "CircuitState",
    "CircuitStats",
    "IranAwareCircuitBreaker",
    "get_circuit_breaker",
    # v8 NEW: Iran Traffic Evasion (Feature-S v18.0)
    "IranTrafficEvasion",
    "get_iran_evasion",
    # v9 NEW: AI Threat Detector (Feature-T v19.0)
    "AIThreatDetector",
    "AIThreatLevel",
    "get_ai_threat_detector",
    # v8 NEW: DPI-Aware Provider Selector (Feature-Q v18.0)
    "ProviderDPIProfile",
    "PROVIDER_DPI_PROFILES",
    "DPIAwareProviderSelector",
    "PolymorphicTrafficMorpher",
]
