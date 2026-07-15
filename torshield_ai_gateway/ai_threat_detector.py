"""
ai_threat_detector.py — AI-Powered Real-Time DPI Threat Level Detector
========================================================================

Uses statistical analysis of provider response patterns to infer
Iran DPI threat level WITHOUT requiring external network calls.

Iran's SIAM/NAPI systems cause these measurable side-effects:
  - Increased latency variance (timing attacks)
  - Selective packet loss (RST injection)
  - DNS NXDOMAIN for blocked domains
  - Asymmetric failure patterns (some providers fail, others don't)

FEATURE-T (v19.0): AI-Powered Real-Time DPI Threat Level Detector

NON-DESTRUCTIVE: Additive only — does not replace or remove any existing
anti-DPI or threat detection module logic.
"""

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("torshield.ai.ai_threat_detector")


class ThreatLevel(Enum):
    """AI-inferred DPI threat level based on provider response patterns."""
    NONE     = "none"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass
class ProviderObservation:
    """Single observation of a provider's response behavior."""
    provider: str
    timestamp: float
    latency_ms: float
    success: bool
    http_status: int | None
    error_type: str | None


class AIThreatDetector:
    """
    Machine-learning-inspired threat detector using statistical inference.
    No external API calls needed — works from provider response patterns alone.

    Iran's SIAM/NAPI DPI systems produce measurable side-effects in provider
    response patterns. This detector uses four statistical signals to infer
    the current DPI threat level:

    1. Asymmetric failures — Cloudflare providers succeed while Cerebras/Portkey
       fail, indicating Iran-specific blocking of non-CDN providers.
    2. Latency spikes — Sudden increase in latency (>3x baseline) suggests
       DPI inspection overhead adding processing delay.
    3. Selective timeouts — Timeouts on specific providers but not others
       indicate RST injection or packet dropping by DPI systems.
    4. DNS failures — ClientConnectorError with DNS failure signatures
       indicate DNS poisoning of blocked domains.

    Each signal contributes a weighted score. The combined score maps to a
    threat level classification. The detector uses an exponential moving
    average for baseline latency tracking and a sliding window of recent
    observations to maintain responsiveness.
    """

    # Iran DPI pattern signatures (empirically observed)
    IRAN_DPI_SIGNATURES = {
        "asymmetric_failures": {
            # Cloudflare works but Cerebras fails → Iran-specific blocking
            "description": "CF providers succeed, non-CF providers fail",
            "weight": 0.4,
        },
        "latency_spike": {
            # Sudden latency increase → DPI inspection overhead
            "description": "Latency > 3x baseline",
            "weight": 0.25,
        },
        "selective_timeout": {
            # Timeouts on specific providers → RST injection
            "description": "Timeout rate > 30% on Iran-blocked providers",
            "weight": 0.25,
        },
        "dns_failure": {
            # Connection errors → DNS poisoning
            "description": "ClientConnectorError with DNS failure",
            "weight": 0.1,
        },
    }

    def __init__(self, window_size: int = 20):
        self._observations: deque[ProviderObservation] = deque(maxlen=window_size)
        self._lock = threading.Lock()
        self._baseline_latency: dict[str, float] = {}
        self._threat_level = ThreatLevel.NONE
        self._confidence = 0.0
        self._last_assessment = 0.0
        self._assessment_ttl = 300  # 5 minutes

    def record(
        self,
        provider: str,
        latency_ms: float,
        success: bool,
        http_status: int | None = None,
        error_type: str | None = None,
    ) -> None:
        """
        Record a provider response observation for threat analysis.

        Each observation contributes to the statistical model that infers
        DPI threat level. Successful responses update the baseline latency
        using exponential moving average (alpha=0.2) for stable tracking.
        Failed responses contribute to the asymmetric failure and timeout
        signals.

        The detector automatically re-assesses threat level when at least
        3 observations have been collected, ensuring rapid detection of
        DPI state changes while avoiding false positives from sparse data.
        """
        with self._lock:
            obs = ProviderObservation(
                provider=provider,
                timestamp=time.time(),
                latency_ms=latency_ms,
                success=success,
                http_status=http_status,
                error_type=error_type,
            )
            self._observations.append(obs)

            # Update baseline (exponential moving average)
            if success and latency_ms > 0:
                current = self._baseline_latency.get(provider, latency_ms)
                self._baseline_latency[provider] = current * 0.8 + latency_ms * 0.2

            # Trigger re-assessment if enough new data
            if len(self._observations) >= 3:
                self._assess_threat_level()

    def _assess_threat_level(self) -> None:
        """Statistical inference of DPI threat level from observations.

        Computes a composite threat score from four signals:
        1. Asymmetric failures: Compares success rates between Cloudflare
           providers (DPI-resistant) and non-Cloudflare providers (Iran-blocked).
           A large gap indicates Iran-specific blocking.
        2. Latency spikes: Counts observations where latency exceeds 3x
           the baseline for that provider, indicating DPI inspection overhead.
        3. Selective timeouts: Measures timeout rate specifically on
           Iran-blocked providers (cerebras, portkey), which indicates
           RST injection by DPI systems.
        4. DNS failures: Counts observations with DNS-related error types,
           indicating DNS poisoning by Iran's filtering infrastructure.

        The combined score maps to threat levels:
          <0.15 → NONE, <0.30 → LOW, <0.50 → MEDIUM, <0.75 → HIGH, >=0.75 → CRITICAL
        """
        obs_list = list(self._observations)
        if not obs_list:
            return

        score = 0.0

        # Signal 1: Asymmetric failures (CF works, non-CF fails)
        cf_obs = [o for o in obs_list if "cloudflare" in o.provider]
        non_cf_obs = [o for o in obs_list
                      if o.provider in ("cerebras", "portkey")]

        if cf_obs and non_cf_obs:
            cf_success_rate = sum(1 for o in cf_obs if o.success) / len(cf_obs)
            non_cf_success_rate = (
                sum(1 for o in non_cf_obs if o.success) / len(non_cf_obs)
            )
            asymmetry = cf_success_rate - non_cf_success_rate
            if asymmetry > 0.5:
                score += self.IRAN_DPI_SIGNATURES["asymmetric_failures"]["weight"] * asymmetry * 2

        # Signal 2: Latency spikes
        latency_spikes = 0
        for obs in obs_list:
            baseline = self._baseline_latency.get(obs.provider, 1000)
            if baseline > 0 and obs.latency_ms > baseline * 3:
                latency_spikes += 1
        if obs_list:
            spike_rate = latency_spikes / len(obs_list)
            score += self.IRAN_DPI_SIGNATURES["latency_spike"]["weight"] * spike_rate

        # Signal 3: Selective timeouts
        timeout_obs = [
            o for o in obs_list
            if o.error_type and "timeout" in o.error_type.lower()
            and o.provider in ("cerebras", "portkey")
        ]
        if non_cf_obs:
            timeout_rate = len(timeout_obs) / max(len(non_cf_obs), 1)
            if timeout_rate > 0.3:
                score += self.IRAN_DPI_SIGNATURES["selective_timeout"]["weight"] * timeout_rate

        # Signal 4: DNS failures
        dns_failures = [
            o for o in obs_list
            if o.error_type and "dns" in o.error_type.lower()
        ]
        if obs_list:
            dns_rate = len(dns_failures) / len(obs_list)
            score += self.IRAN_DPI_SIGNATURES["dns_failure"]["weight"] * dns_rate

        # Map score to threat level
        self._confidence = min(score, 1.0)
        if score < 0.15:
            self._threat_level = ThreatLevel.NONE
        elif score < 0.30:
            self._threat_level = ThreatLevel.LOW
        elif score < 0.50:
            self._threat_level = ThreatLevel.MEDIUM
        elif score < 0.75:
            self._threat_level = ThreatLevel.HIGH
        else:
            self._threat_level = ThreatLevel.CRITICAL

        self._last_assessment = time.time()

    @property
    def threat_level(self) -> ThreatLevel:
        """Current inferred DPI threat level."""
        with self._lock:
            return self._threat_level

    @property
    def confidence(self) -> float:
        """Confidence score (0.0-1.0) of the current threat assessment."""
        with self._lock:
            return self._confidence

    def get_assessment(self) -> dict:
        """Return a comprehensive assessment dict for logging/monitoring.

        Includes the current threat level, confidence score, observation
        count, per-provider baseline latencies, and the age of the last
        assessment. This is used by the health check to report DPI
        threat status after all provider checks complete.
        """
        with self._lock:
            return {
                "threat_level": self._threat_level.value,
                "confidence": round(self._confidence, 3),
                "observation_count": len(self._observations),
                "baseline_latencies": dict(self._baseline_latency),
                "last_assessment_age_s": round(
                    time.time() - self._last_assessment, 1
                ),
            }


# Singleton
_AI_THREAT_DETECTOR = AIThreatDetector()


def get_ai_threat_detector() -> AIThreatDetector:
    """Get the singleton AI threat detector instance."""
    return _AI_THREAT_DETECTOR
