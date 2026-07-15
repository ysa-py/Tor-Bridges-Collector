from __future__ import annotations

"""
iran_dpi_model_selector.py — Iran DPI-Aware AI Model Selector
==============================================================

Selects the optimal AI model for the current Iran DPI threat level.
Iran's SIAM/NGFW deep packet inspection operates on multiple layers:

  1. TIMING ANALYSIS: NGFW tracks inter-packet timing. Regular, fast bursts
     from small models are easier to fingerprint than irregular timing from
     larger models.
  2. PAYLOAD SIZE ANALYSIS: Responses from large models have larger, more
     varied payload sizes — harder to fingerprint than consistent small payloads.
  3. TLS FINGERPRINTING: JA3/JA3S hashes. CF Gateway uses TLS 1.3 which
     evades most basic fingerprinting, but response timing still reveals
     model size signatures.
  4. CONNECTION PERSISTENCE: Long TTFB (time-to-first-byte) from large models
     resembles normal HTTPS browsing better than instant responses from 3B models.

DPI Evasion Strategy by threat level:
  NONE     → Use fastest model (@cf/llama-3.2-3b, ~200ms TTFB)
  LOW      → Use medium model (@cf/llama-3.1-8b, ~500ms TTFB)
  MEDIUM   → Use large model (@cf/llama-3.3-70b-fp8-fast, ~800ms TTFB)
  HIGH     → Use XL model with jitter (@cf/deepseek-r1-distill-32b, ~2s TTFB)
  CRITICAL → Use multi-hop with random delays + largest available model

NON-DESTRUCTIVE: New standalone module. Existing code untouched.
Version: 1.0.0 (Feature-1 v16.0)
"""


import asyncio
import logging
import random
import threading
import time
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("torshield.ai.iran_dpi_selector")


# ── Threat Level Enum ─────────────────────────────────────────────────────────

class IranDPIThreatLevel(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── DPI Model Profile ─────────────────────────────────────────────────────────

@dataclass
class DPIModelProfile:
    """Model selection profile optimized for a DPI threat level."""
    threat_level: IranDPIThreatLevel

    # Primary model choice per provider
    cf_workers_ai_model: str
    cf_gateway_model: str
    cerebras_model: str
    portkey_model: str

    # Traffic shaping parameters (milliseconds)
    min_pre_request_delay_ms: int = 0       # Random delay before sending request
    max_pre_request_delay_ms: int = 0
    min_response_jitter_ms: int = 0         # Delay after receiving response
    max_response_jitter_ms: int = 0

    # Request fragmentation
    stream_chunks: bool = False              # Use streaming to vary chunk timing
    chunk_delay_ms_range: tuple = (0, 0)    # Delay between stream chunks

    # Evasion notes for logging
    evasion_rationale: str = ""


# ── DPI Profile Table ─────────────────────────────────────────────────────────

DPI_PROFILES: dict[IranDPIThreatLevel, DPIModelProfile] = {
    IranDPIThreatLevel.NONE: DPIModelProfile(
        threat_level=IranDPIThreatLevel.NONE,
        cf_workers_ai_model="@cf/meta/llama-3.2-3b-instruct",
        cf_gateway_model="@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        cerebras_model="llama-3.3-70b-versatile",
        portkey_model="llama-3.3-70b-versatile",
        min_pre_request_delay_ms=0,
        max_pre_request_delay_ms=0,
        evasion_rationale="No DPI detected — optimize for speed",
    ),
    IranDPIThreatLevel.LOW: DPIModelProfile(
        threat_level=IranDPIThreatLevel.LOW,
        cf_workers_ai_model="@cf/meta/llama-3.1-8b-instruct",
        cf_gateway_model="@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        cerebras_model="llama-3.3-70b-versatile",
        portkey_model="llama-3.3-70b-versatile",
        min_pre_request_delay_ms=50,
        max_pre_request_delay_ms=200,
        evasion_rationale="Low DPI: mild timing jitter, medium model TTFB",
    ),
    IranDPIThreatLevel.MEDIUM: DPIModelProfile(
        threat_level=IranDPIThreatLevel.MEDIUM,
        cf_workers_ai_model="@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        cf_gateway_model="@cf/openai/gpt-oss-120b",
        cerebras_model="gpt-oss-120b",
        portkey_model="llama-3.3-70b-versatile",
        min_pre_request_delay_ms=100,
        max_pre_request_delay_ms=500,
        stream_chunks=True,
        chunk_delay_ms_range=(50, 200),
        evasion_rationale="Medium DPI: larger models, streaming chunks, timing variance",
    ),
    IranDPIThreatLevel.HIGH: DPIModelProfile(
        threat_level=IranDPIThreatLevel.HIGH,
        cf_workers_ai_model="@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
        cf_gateway_model="@cf/moonshotai/kimi-k2.5",
        cerebras_model="gpt-oss-120b",
        portkey_model="llama-3.3-70b-versatile",
        min_pre_request_delay_ms=200,
        max_pre_request_delay_ms=1500,
        stream_chunks=True,
        chunk_delay_ms_range=(100, 600),
        evasion_rationale="High DPI: XL models mimic browsing TTFB, high timing variance",
    ),
    IranDPIThreatLevel.CRITICAL: DPIModelProfile(
        threat_level=IranDPIThreatLevel.CRITICAL,
        cf_workers_ai_model="@cf/moonshotai/kimi-k2.6",
        cf_gateway_model="@cf/moonshotai/kimi-k2.6",
        cerebras_model="gpt-oss-120b",
        portkey_model="llama-3.3-70b-versatile",
        min_pre_request_delay_ms=500,
        max_pre_request_delay_ms=3000,
        stream_chunks=True,
        chunk_delay_ms_range=(200, 1000),
        evasion_rationale="Critical DPI: maximum timing obfuscation, gigantic models",
    ),
}


# ── Iran DPI Model Selector ───────────────────────────────────────────────────

class IranDPIModelSelector:
    """
    Selects the optimal AI model for the current Iran DPI threat level.
    Integrates with existing DynamicModelBrain and anti-DPI assessment.
    """

    def __init__(self):
        self._current_threat_level = IranDPIThreatLevel.NONE
        self._last_assessment_time = 0.0
        self._assessment_ttl = 300  # 5 minutes
        self._lock = threading.RLock()

    def _get_current_threat_level(self) -> IranDPIThreatLevel:
        """Get current Iran DPI threat level from anti-DPI engine."""
        with self._lock:
            now = time.time()
            if now - self._last_assessment_time < self._assessment_ttl:
                return self._current_threat_level

        try:
            from torshield_ai_gateway.dynamic_brain_anti_dpi import run_dpi_assessment
            assessment = run_dpi_assessment()
            threat_str = assessment.threat_level.value.lower()
            level = IranDPIThreatLevel(threat_str)
        except Exception as e:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.iran_dpi_model_selector:169', e)
            logger.debug(f"[DPISelector] Assessment failed: {e} — using NONE")
            level = IranDPIThreatLevel.NONE

        with self._lock:
            self._current_threat_level = level
            self._last_assessment_time = time.time()

        logger.info(
            f"[DPISelector] Threat level: {level.value} "
            f"(TTL: {self._assessment_ttl}s)"
        )
        return level

    def get_profile(self) -> DPIModelProfile:
        """Get the DPI evasion profile for current threat level."""
        threat = self._get_current_threat_level()
        profile = DPI_PROFILES[threat]
        logger.debug(
            f"[DPISelector] Profile: {threat.value} — "
            f"CF={profile.cf_workers_ai_model} "
            f"delay={profile.min_pre_request_delay_ms}-"
            f"{profile.max_pre_request_delay_ms}ms"
        )
        return profile

    def get_model_for_provider(self, provider_name: str) -> str | None:
        """
        Get the optimal model for a specific provider at current threat level.
        Returns None if no DPI-specific override needed (use default selection).
        Only returns a model when DPI threat > NONE.
        """
        threat = self._get_current_threat_level()
        if threat == IranDPIThreatLevel.NONE:
            return None  # No override needed

        profile = DPI_PROFILES[threat]
        model_map = {
            "cloudflare_workers_ai": profile.cf_workers_ai_model,
            "cloudflare_ai_gateway": profile.cf_gateway_model,
            "cerebras": profile.cerebras_model,
            "portkey": profile.portkey_model,
        }
        return model_map.get(provider_name)

    async def apply_pre_request_delay(self, profile: DPIModelProfile) -> None:
        """Apply randomized pre-request delay for DPI timing obfuscation."""
        if profile.max_pre_request_delay_ms > 0:
            delay_ms = random.randint(
                profile.min_pre_request_delay_ms,
                profile.max_pre_request_delay_ms,
            )
            if delay_ms > 0:
                logger.debug(f"[DPISelector] Pre-request delay: {delay_ms}ms")
                await asyncio.sleep(delay_ms / 1000.0)


# ── Singleton ─────────────────────────────────────────────────────────────────

_dpi_selector: IranDPIModelSelector | None = None
_dpi_selector_lock = threading.Lock()


def get_dpi_selector() -> IranDPIModelSelector:
    """Get or create the singleton IranDPIModelSelector instance."""
    global _dpi_selector
    with _dpi_selector_lock:
        if _dpi_selector is None:
            _dpi_selector = IranDPIModelSelector()
        return _dpi_selector
