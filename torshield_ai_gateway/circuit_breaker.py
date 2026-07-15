"""
circuit_breaker.py — Iran-Aware Circuit Breaker for TorShield AI Gateway
==========================================================================

Self-healing circuit breaker that understands Iran's DPI/censorship patterns.
Automatically detects when a provider is blocked/throttled in Iran and switches
to an alternative without manual intervention.

FEATURE-R (v18.0): Iran Geo-Aware Circuit Breaker

OPEN thresholds are more aggressive for Iran-blocked providers to prevent
wasting time on provably blocked endpoints.

Iran-blocked providers (cerebras, portkey) open after 2 failures.
DPI-resistant providers (cloudflare) open after 5 failures.

FEATURE-X (v19.0): Self-Healing Provider State Persistence

Circuit breaker state can now be persisted to disk and restored across
CI runs, allowing the breaker to remember which providers were previously
failing and start in a more informed state instead of resetting to CLOSED
every run.

NON-DESTRUCTIVE: Additive only — does not replace or remove any existing
circuit breaker or provider logic.
"""

import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("torshield.ai.circuit_breaker")


class CircuitState(Enum):
    """Circuit breaker state machine."""
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Provider failed — blocking requests
    HALF_OPEN = "half_open" # Testing if provider recovered


@dataclass
class CircuitStats:
    """Statistics for a provider's circuit breaker."""
    failures: int = 0
    successes: int = 0
    last_failure_time: float = 0.0
    last_success_time: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    iran_block_suspected: bool = False
    total_latency_ms: float = 0.0
    request_count: int = 0

    @property
    def avg_latency_ms(self) -> float:
        """Average latency across all tracked requests."""
        return (
            self.total_latency_ms / self.request_count
            if self.request_count > 0 else 0.0
        )


class IranAwareCircuitBreaker:
    """
    Circuit breaker that understands Iran's DPI/censorship patterns.

    OPEN thresholds are more aggressive for Iran-blocked providers
    to prevent wasting time on provably blocked endpoints.

    Iran-blocked providers (cerebras, portkey) open after 2 failures.
    DPI-resistant providers (cloudflare) open after 5 failures.
    """

    # Failure thresholds before opening circuit
    IRAN_BLOCKED_THRESHOLD = 2    # Open fast for Iran-blocked providers
    STANDARD_THRESHOLD = 5        # Standard providers

    # Seconds to wait before trying again (half-open)
    RECOVERY_TIMEOUT: dict[str, int] = {
        "none":     30,    # No DPI: retry quickly
        "low":      60,
        "medium":   120,
        "high":     300,
        "critical": 600,
    }

    # Providers suspected blocked in Iran
    IRAN_BLOCKED_PROVIDERS = {"cerebras", "portkey"}

    def __init__(self):
        self._circuits: dict[str, CircuitState] = {}
        self._stats: dict[str, CircuitStats] = {}
        self._opened_at: dict[str, float] = {}
        self._lock = threading.Lock()
        self._threat_level = "none"
        # FEATURE-X v19.0: Load persisted state from previous run
        self.load_state()

    def set_threat_level(self, level: str) -> None:
        """Set the current DPI threat level (affects recovery timeout)."""
        self._threat_level = level

    def _get_threshold(self, provider: str) -> int:
        """Get failure threshold for a provider based on Iran accessibility."""
        if provider in self.IRAN_BLOCKED_PROVIDERS:
            return self.IRAN_BLOCKED_THRESHOLD
        return self.STANDARD_THRESHOLD

    def _get_recovery_timeout(self) -> int:
        """Get recovery timeout based on current threat level."""
        return self.RECOVERY_TIMEOUT.get(self._threat_level, 30)

    def can_attempt(self, provider: str) -> bool:
        """Check if a request can be attempted for the given provider."""
        with self._lock:
            state = self._circuits.get(provider, CircuitState.CLOSED)

            if state == CircuitState.CLOSED:
                return True

            if state == CircuitState.OPEN:
                opened = self._opened_at.get(provider, 0)
                if time.time() - opened > self._get_recovery_timeout():
                    self._circuits[provider] = CircuitState.HALF_OPEN
                    logger.info(
                        f"[CircuitBreaker] {provider}: OPEN -> HALF_OPEN "
                        f"(testing recovery)"
                    )
                    return True
                return False

            # HALF_OPEN: allow one attempt
            return True

    def record_success(self, provider: str, latency_ms: float) -> None:
        """Record a successful request, potentially closing the circuit."""
        with self._lock:
            stats = self._stats.setdefault(provider, CircuitStats())
            stats.successes += 1
            stats.consecutive_successes += 1
            stats.consecutive_failures = 0
            stats.last_success_time = time.time()
            stats.total_latency_ms += latency_ms
            stats.request_count += 1

            state = self._circuits.get(provider, CircuitState.CLOSED)
            if state == CircuitState.HALF_OPEN:
                self._circuits[provider] = CircuitState.CLOSED
                logger.info(
                    f"[CircuitBreaker] {provider}: HALF_OPEN -> CLOSED "
                    f"(recovered, latency={latency_ms:.0f}ms)"
                )

    def record_failure(
        self,
        provider: str,
        error: str,
        http_status: int | None = None,
    ) -> None:
        """Record a failed request, potentially opening the circuit."""
        with self._lock:
            stats = self._stats.setdefault(provider, CircuitStats())
            stats.failures += 1
            stats.consecutive_failures += 1
            stats.consecutive_successes = 0
            stats.last_failure_time = time.time()

            # Detect Iran block patterns
            iran_block_signals = [
                http_status in (403, 0),  # 403 = CF blocks, 0 = no connection
                "connection refused" in error.lower(),
                "timed out" in error.lower() and provider in self.IRAN_BLOCKED_PROVIDERS,
                "dns" in error.lower(),   # DNS poisoning
            ]
            if any(iran_block_signals):
                stats.iran_block_suspected = True
                logger.warning(
                    f"[CircuitBreaker] {provider}: Iran block suspected "
                    f"(http={http_status}, error={error[:100]})"
                )

            threshold = self._get_threshold(provider)
            if stats.consecutive_failures >= threshold:
                current_state = self._circuits.get(provider, CircuitState.CLOSED)
                if current_state != CircuitState.OPEN:
                    self._circuits[provider] = CircuitState.OPEN
                    self._opened_at[provider] = time.time()
                    logger.warning(
                        f"[CircuitBreaker] {provider}: -> OPEN "
                        f"({stats.consecutive_failures} consecutive failures, "
                        f"iran_block={stats.iran_block_suspected})"
                    )

    def get_status(self) -> dict:
        """Return status dict for all tracked providers."""
        with self._lock:
            return {
                p: {
                    "state": self._circuits.get(p, CircuitState.CLOSED).value,
                    "stats": vars(self._stats.get(p, CircuitStats())),
                }
                for p in set(list(self._circuits.keys()) + list(self._stats.keys()))
            }

    # ── FEATURE-X v19.0: State Persistence ────────────────────────────

    def save_state(self, path: str = "/tmp/torshield_cb_state.json") -> None:
        """Save circuit breaker state for next run.

        Persists the circuit state (CLOSED/OPEN/HALF_OPEN), opened_at
        timestamp, consecutive failure count, and Iran block suspicion flag
        for each tracked provider. This allows subsequent CI runs to start
        with informed circuit breaker state instead of resetting everything
        to CLOSED.

        Non-critical: errors during save are silently ignored since circuit
        breaker state persistence is a best-effort optimization, not a
        correctness requirement.
        """
        import json
        with self._lock:
            state = {}
            for provider in set(
                list(self._circuits.keys()) + list(self._stats.keys())
            ):
                state[provider] = {
                    "circuit": self._circuits.get(
                        provider, CircuitState.CLOSED
                    ).value,
                    "opened_at": self._opened_at.get(provider, 0),
                    "consecutive_failures": self._stats.get(
                        provider, CircuitStats()
                    ).consecutive_failures,
                    "iran_block_suspected": self._stats.get(
                        provider, CircuitStats()
                    ).iran_block_suspected,
                }
            try:
                with open(path, "w") as f:
                    json.dump(state, f)
                logger.debug(
                    f"[CircuitBreaker] State saved to {path} "
                    f"({len(state)} providers)"
                )
            except Exception as _remediation_exc:
                from monitoring.structured_logger import record_silent_failure
                record_silent_failure('torshield_ai_gateway.circuit_breaker:248', _remediation_exc)
                pass  # Non-critical

    def load_state(self, path: str = "/tmp/torshield_cb_state.json") -> None:
        """Load persisted circuit breaker state.

        Restores circuit breaker state from a previous run's save file.
        This allows the circuit breaker to remember which providers were
        previously failing and start in a more informed state. If the
        state file does not exist or is corrupt, the breaker starts fresh
        with all circuits CLOSED — this is always safe since a missing
        state file means no prior evidence of failure.

        Note: Only consecutive_failures and iran_block_suspected are
        restored. The circuit state itself is NOT restored to OPEN to
        prevent a single bad run from permanently blocking a provider.
        Instead, the failure count is restored so the breaker will open
        quickly if the provider fails again.
        """
        import json
        try:
            with open(path) as f:
                state = json.load(f)
            with self._lock:
                for provider, data in state.items():
                    # Restore stats but start CLOSED (give providers a chance)
                    stats = CircuitStats()
                    stats.consecutive_failures = data.get("consecutive_failures", 0)
                    stats.iran_block_suspected = data.get("iran_block_suspected", False)
                    self._stats[provider] = stats
                    # Always start CLOSED — previous OPEN state may be stale
                    self._circuits[provider] = CircuitState.CLOSED
                    self._opened_at[provider] = 0
            logger.debug(
                f"[CircuitBreaker] State loaded from {path} "
                f"({len(state)} providers)"
            )
        except FileNotFoundError:
            # First run or clean CI workspaces normally have no persisted state.
            # Treat that as a healthy cold start instead of recording an error.
            logger.debug(f"[CircuitBreaker] No state file at {path}; starting fresh")
            pass  # No state file yet, start fresh
        except json.JSONDecodeError as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.circuit_breaker:285', _remediation_exc)
            pass  # No state file yet, start fresh
        except Exception as _remediation_exc:
            from monitoring.structured_logger import record_silent_failure
            record_silent_failure('torshield_ai_gateway.circuit_breaker:287', _remediation_exc)
            pass  # Non-critical


# Singleton circuit breaker (shared across providers)
_CIRCUIT_BREAKER = IranAwareCircuitBreaker()


def get_circuit_breaker() -> IranAwareCircuitBreaker:
    """Get the singleton Iran-aware circuit breaker instance."""
    return _CIRCUIT_BREAKER
