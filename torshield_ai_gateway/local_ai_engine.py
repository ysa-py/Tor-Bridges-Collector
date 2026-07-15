from __future__ import annotations

"""
local_ai_engine.py — TorShield Local AI Fallback Engine v1.0
═══════════════════════════════════════════════════════════════════════════

Provides a zero-dependency local AI fallback when ALL external AI providers
(Cerebras, Portkey, Cloudflare) are unavailable (403/400 errors).

This engine uses rule-based intelligence with pre-built knowledge bases
specifically optimized for Iran's DPI infrastructure, censorship patterns,
and bridge survival analysis. It requires NO external API calls.

CAPABILITIES:
  - Bridge scoring for Iran reachability (rule-based scoring)
  - Censorship level detection (Level 1-5)
  - DPI evasion strategy recommendation
  - NIN survival prediction
  - Transport stack recommendation
  - ISP-specific blocking predictions
  - Workflow failure pattern matching and fix suggestion
  - obfs4 parameter mutation hints

USAGE:
  from torshield_ai_gateway.local_ai_engine import LocalAIEngine
  engine = LocalAIEngine()
  result = engine.score_bridge("obfs4 1.2.3.4:443 ...")
"""


import hashlib
import json
import logging
import random
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
UTC = timezone.utc

log = logging.getLogger("torshield.ai.local")

# ════════════════════════════════════════════════════════════════════════════
# IRAN DPI KNOWLEDGE BASE (updated June 2026)
# ════════════════════════════════════════════════════════════════════════════

# Iran DPI infrastructure components
_IRAN_DPI_SYSTEMS = {
    "arvan_dpi": {
        "name": "Arvan Cloud DPI",
        "detection_methods": ["SNI inspection", "TLS fingerprinting (JA3)", "HTTP header analysis"],
        "blocks": ["Direct Tor", "obfs4 (non-443 ports)", "vanilla Tor", "OpenVPN"],
        "bypasses": ["obfs4 port 443 with iat-mode=2", "WebTunnel CDN-fronted", "Snowflake", "meek-lite"],
        "active_since": "2023-Q3",
    },
    "siam": {
        "name": "SIAM (Smart Integrated Access Management)",
        "detection_methods": ["ML traffic classification", "Statistical packet analysis", "Flow duration patterns"],
        "blocks": ["obfs4 (some)", "Shadowsocks (some)", "WireGuard"],
        "bypasses": ["WebTunnel via CDN", "Snowflake with AMP cache", "VLESS-Reality"],
        "active_since": "2024-Q1",
    },
    "nin": {
        "name": "National Internet Network (NIN) shutdown",
        "detection_methods": ["Complete international cut", "DNS hijacking", "BGP route withdrawal"],
        "blocks": ["ALL international traffic", "Direct VPN", "obfs4 non-CDN", "Snowflake (partial)"],
        "bypasses": ["CDN-fronted WebTunnel", "Arvan/Cloudflare CDN tunnels", "Domestic bridge relays"],
        "active_since": "2019 (intermittent)",
    },
    "kowsar": {
        "name": "Kowsar National Firewall",
        "detection_methods": ["Deep packet inspection", "Protocol fingerprinting", "Entropy analysis"],
        "blocks": ["Tor directory authorities", "obfs4 with known cert patterns", "SSH tunneling"],
        "bypasses": ["obfs4 with iat-mode=2", "WebTunnel HTTPS", "XTLS-Reality"],
        "active_since": "2024-Q2",
    },
    "ngfw": {
        "name": "NGFW (Next-Generation Firewall)",
        "detection_methods": ["Application-layer analysis", "Behavioral analysis", "Certificate pinning bypass detection"],
        "blocks": ["Some obfs4 bridges", "Unusual TLS patterns", "Known bridge IPs"],
        "bypasses": ["Snowflake (short-lived)", "meek-lite via Azure/Amazon", "WebTunnel"],
        "active_since": "2025-Q1",
    },
}

# ISP-specific blocking data (updated June 2026)
_IRAN_ISP_DATA = {
    "MCI": {
        "full_name": "Hamrah Aval (Mobile Communication Company of Iran)",
        "type": "mobile",
        "dpi_level": 4,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "degraded",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "degraded",
        },
        "notes": "Heaviest DPI on mobile networks; obfs4 on port 443 sometimes works",
    },
    "IRANCELL": {
        "full_name": "Irancell (MTN Irancell)",
        "type": "mobile",
        "dpi_level": 4,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "degraded",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "works",
        },
        "notes": "Slightly less aggressive than MCI; meek-lite often works",
    },
    "Rightel": {
        "full_name": "Rightel",
        "type": "mobile",
        "dpi_level": 3,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "works",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "works",
        },
        "notes": "Lighter DPI than MCI/IRANCELL; obfs4 generally works",
    },
    "Shatel": {
        "full_name": "Shatel (Aftabeh Pars)",
        "type": "fixed",
        "dpi_level": 3,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "works",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "works",
        },
        "notes": "Fixed-line ISP; generally less aggressive filtering",
    },
    "Asiatech": {
        "full_name": "Asiatech Data Transfer",
        "type": "fixed",
        "dpi_level": 3,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "degraded",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "works",
        },
        "notes": "Some obfs4 bridges blocked; WebTunnel preferred",
    },
}

# Transport scoring weights for Iran (higher = better for Iran)
_IRAN_TRANSPORT_SCORES = {
    "snowflake":     {"base": 0.92, "nin_survival": 0.30, "dpi_resist": 0.95, "reason": "Short-lived proxies, hard to block"},
    "webtunnel":     {"base": 0.88, "nin_survival": 0.75, "dpi_resist": 0.90, "reason": "CDN-fronted HTTPS, survives NIN"},
    "meek_lite":     {"base": 0.82, "nin_survival": 0.55, "dpi_resist": 0.85, "reason": "Domain fronting via cloud CDNs"},
    "obfs4":         {"base": 0.72, "nin_survival": 0.20, "dpi_resist": 0.60, "reason": "Effective but DPI can detect patterns"},
    "obfs4_443":     {"base": 0.80, "nin_survival": 0.25, "dpi_resist": 0.75, "reason": "obfs4 on port 443 reduces detection"},
    "vanilla":       {"base": 0.10, "nin_survival": 0.05, "dpi_resist": 0.05, "reason": "Immediately detected and blocked"},
    "vless_reality": {"base": 0.90, "nin_survival": 0.70, "dpi_resist": 0.92, "reason": "XTLS Reality, strong DPI resistance"},
}

# Port scoring for Iran
_IRAN_PORT_SCORES = {
    443:   1.0,   # HTTPS — best, allowed by DPI
    80:    0.7,   # HTTP — allowed but inspected
    8080:  0.6,   # HTTP alt — sometimes allowed
    8443:  0.8,   # HTTPS alt — usually allowed
    2083:  0.75,  # cPanel HTTPS — often allowed
    2087:  0.75,  # cPanel HTTPS — often allowed
    2096:  0.70,  # cPanel HTTPS — often allowed
    9001:  0.3,   # Tor default — usually blocked
    993:   0.5,   # IMAPS — sometimes allowed
    995:   0.5,   # POP3S — sometimes allowed
}

# Temporal blocking patterns (Iran Standard Time = UTC+3:30)
_TEMPORAL_PATTERNS = {
    "peak_block_hours": [20, 21, 22, 23],     # Evening heavy DPI
    "low_block_hours":  [3, 4, 5, 6],          # Early morning light
    "weekend_modifier": "lighter",              # Weekends less aggressive
    "event_sensitivity": "high",                # Political events = heavy
    "best_window": "03:00-06:00 IRST",
}

# Known workflow failure patterns and fixes
_WORKFLOW_FIXES = {
    "ModuleNotFoundError": {
        "root_cause": "missing_python_dependency",
        "fix_type": "yaml_patch",
        "fix": "Add 'pip install -r requirements.txt' step before the failing step",
        "confidence": 0.95,
    },
    "SyntaxError": {
        "root_cause": "python_syntax_error",
        "fix_type": "python_patch",
        "fix": "Fix the syntax error in the reported file and line",
        "confidence": 0.90,
    },
    "HTTP Error 403": {
        "root_cause": "api_key_invalid_or_expired",
        "fix_type": "env_fix",
        "fix": "Rotate or update the API key in GitHub Secrets",
        "confidence": 0.85,
    },
    "HTTP Error 400": {
        "root_cause": "invalid_request_format",
        "fix_type": "python_patch",
        "fix": "Check request payload format; model ID may be deprecated",
        "confidence": 0.80,
    },
    "HTTP Error 429": {
        "root_cause": "rate_limit_exceeded",
        "fix_type": "yaml_patch",
        "fix": "Add rate limiting or use account rotation",
        "confidence": 0.90,
    },
    "cargo build failed": {
        "root_cause": "rust_compilation_error",
        "fix_type": "shell_fix",
        "fix": "Check Cargo.toml dependencies and Rust toolchain version",
        "confidence": 0.75,
    },
    "zipfile.BadZipFile": {
        "root_cause": "corrupted_artifact",
        "fix_type": "yaml_patch",
        "fix": "Add artifact integrity check and retry logic",
        "confidence": 0.70,
    },
    "Connection refused": {
        "root_cause": "service_unreachable",
        "fix_type": "env_fix",
        "fix": "Check network connectivity; may need proxy configuration",
        "confidence": 0.65,
    },
}




_DEFAULT_STATE_PATH = Path("data/local_ai_censorship_state.json")


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _stable_unit_interval(*parts: object) -> float:
    digest = hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).hexdigest()
    return int(digest[:12], 16) / float(0xFFFFFFFFFFFF)

# ════════════════════════════════════════════════════════════════════════════
# LOCAL AI ENGINE
# ════════════════════════════════════════════════════════════════════════════

class LocalAIEngine:
    """
    Zero-dependency local AI engine for Iran bridge intelligence.
    Activated automatically when ALL external AI providers fail.
    Provides rule-based scoring, censorship detection, and fix suggestions.
    """

    def __init__(self, state_path: str | Path | None = None):
        self._cache: dict[str, Any] = {}
        self.state_path = Path(state_path) if state_path is not None else _DEFAULT_STATE_PATH
        self.state_matrix = self._load_state_matrix()
        log.info("[LocalAI] Initialized — zero external dependencies with adaptive RL state")

    def _default_state_matrix(self) -> dict[str, Any]:
        transports = list(_IRAN_TRANSPORT_SCORES)
        isps = list(_IRAN_ISP_DATA) + ["unknown"]
        return {
            "version": 1,
            "updated_at": datetime.now(UTC).isoformat(),
            "learning_rate": 0.18,
            "discount_factor": 0.72,
            "epsilon_floor": 0.05,
            "patterns": {
                isp: {
                    t: {
                        "q_value": float(_IRAN_TRANSPORT_SCORES[t]["base"]),
                        "successes": 0,
                        "failures": 0,
                        "handshake_failures": 0,
                        "dpi_triggers": 0,
                        "last_reward": 0.0,
                    }
                    for t in transports
                }
                for isp in isps
            },
        }

    def _load_state_matrix(self) -> dict[str, Any]:
        default = self._default_state_matrix()
        try:
            if self.state_path.exists():
                loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("patterns"), dict):
                    for isp, transports in default["patterns"].items():
                        loaded.setdefault("patterns", {}).setdefault(isp, {})
                        for transport, cell in transports.items():
                            loaded["patterns"][isp].setdefault(transport, cell)
                    loaded.setdefault("learning_rate", default["learning_rate"])
                    loaded.setdefault("discount_factor", default["discount_factor"])
                    loaded.setdefault("epsilon_floor", default["epsilon_floor"])
                    return loaded
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            log.warning("[LocalAI] State matrix load failed; using defaults: %s", exc)
        return default

    def persist_state_matrix(self) -> bool:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_matrix["updated_at"] = datetime.now(UTC).isoformat()
            self.state_path.write_text(json.dumps(self.state_matrix, indent=2, sort_keys=True), encoding="utf-8")
            return True
        except OSError as exc:
            log.warning("[LocalAI] State matrix persistence failed: %s", exc)
            return False

    def observe_feedback(self, isp: str, transport: str, outcome: str, latency_ms: float | None = None, persist: bool = True) -> dict[str, Any]:
        isp_key = isp if isp in self.state_matrix["patterns"] else "unknown"
        transport_key = transport if transport in _IRAN_TRANSPORT_SCORES else "vanilla"
        cell = self.state_matrix["patterns"][isp_key][transport_key]
        outcome_l = outcome.lower()
        reward = 0.6
        if outcome_l in {"success", "ok", "reachable"}:
            cell["successes"] += 1; reward = 1.0
        elif "handshake" in outcome_l or "tls" in outcome_l or "tcp" in outcome_l:
            cell["failures"] += 1; cell["handshake_failures"] += 1; reward = -0.45
        elif "dpi" in outcome_l or "fingerprint" in outcome_l or "blocked" in outcome_l:
            cell["failures"] += 1; cell["dpi_triggers"] += 1; reward = -0.85
        else:
            cell["failures"] += 1; reward = -0.25
        if latency_ms is not None and latency_ms > 0:
            reward -= min(0.25, latency_ms / 10000.0)
        lr = float(self.state_matrix.get("learning_rate", 0.18))
        gamma = float(self.state_matrix.get("discount_factor", 0.72))
        old_q = float(cell.get("q_value", 0.5))
        cell["q_value"] = round(_clamp(old_q + lr * (reward + gamma * old_q - old_q)), 4)
        cell["last_reward"] = round(reward, 4)
        if persist:
            self.persist_state_matrix()
        return {"isp": isp_key, "transport": transport_key, "q_value": cell["q_value"], "reward": cell["last_reward"], "source": "local_ai_engine_rl"}

    def choose_dynamic_transport(self, isp: str = "unknown", censorship_level: int = 4) -> dict[str, Any]:
        isp_key = isp if isp in self.state_matrix["patterns"] else "unknown"
        pressure = _clamp((censorship_level - 1) / 4.0)
        epsilon = max(float(self.state_matrix.get("epsilon_floor", 0.05)), 0.22 - pressure * 0.14)
        rows = []
        for transport, cell in self.state_matrix["patterns"][isp_key].items():
            base = _IRAN_TRANSPORT_SCORES.get(transport, _IRAN_TRANSPORT_SCORES["vanilla"])
            score = _clamp(float(cell.get("q_value", base["base"])) * 0.65 + base["dpi_resist"] * 0.25 + base["nin_survival"] * pressure * 0.10)
            rows.append({"transport": transport, "score": round(score, 4), "q_value": cell.get("q_value", 0.0)})
        rows.sort(key=lambda r: r["score"], reverse=True)
        explore = _stable_unit_interval(isp_key, censorship_level, self.state_matrix.get("updated_at")) < epsilon
        choice = rows[min(1, len(rows)-1)] if explore and len(rows) > 1 else rows[0]
        return {"isp": isp_key, "selected_transport": choice["transport"], "score": choice["score"], "exploration": explore, "candidates": rows[:5], "source": "local_ai_engine_rl"}

    # ── Bridge Parsing ────────────────────────────────────────────────────

    @staticmethod
    def _parse_bridge_line(bridge_line: str) -> dict[str, Any]:
        """Extract transport type, address, port, and parameters from a bridge line."""
        parts = bridge_line.strip().split()
        transport = "vanilla"
        addr = ""
        port = 0
        params: dict[str, str] = {}

        if not parts:
            return {"transport": transport, "addr": addr, "port": port, "params": params}

        # First part could be transport name or IP
        if parts[0] in ("obfs4", "webtunnel", "snowflake", "meek_lite",
                         "meek-azure", "vanilla", "vless", "shadowsocks"):
            transport = parts[0]
            if len(parts) > 1:
                addr_part = parts[1]
            else:
                addr_part = ""
        else:
            addr_part = parts[0]

        # Parse address:port
        if addr_part:
            if ":" in addr_part:
                addr, port_str = addr_part.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError as _remediation_exc:
                    from monitoring.structured_logger import record_silent_failure
                    record_silent_failure('torshield_ai_gateway.local_ai_engine:284', _remediation_exc)
                    port = 0
            else:
                addr = addr_part

        # Parse key=value parameters
        for p in parts[2:]:
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v

        # Adjust transport for obfs4 on port 443
        if transport == "obfs4" and port == 443:
            transport = "obfs4_443"

        # Detect iat-mode
        iat_mode = params.get("iat-mode", "")
        if iat_mode == "2" and transport == "obfs4":
            transport = "obfs4_443"  # iat-mode=2 is best for Iran

        return {
            "transport": transport,
            "addr": addr,
            "port": port,
            "params": params,
        }

    # ── Bridge Scoring ────────────────────────────────────────────────────

    def score_bridge(self, bridge_line: str, censorship_level: int = 4) -> dict[str, Any]:
        """
        Score a single bridge for Iran reachability using rule-based analysis.

        Args:
            bridge_line: Tor bridge line (e.g., "obfs4 1.2.3.4:443 cert=... iat-mode=2")
            censorship_level: Current Iran censorship level (1-5)

        Returns:
            {score, transport_ok, dpi_bypass_rating, nin_survival,
             isp_block_risk, recommendation, mutation_hint}
        """
        parsed = self._parse_bridge_line(bridge_line)
        transport = parsed["transport"]
        port = parsed["port"]

        # Get base transport scores
        t_scores = _IRAN_TRANSPORT_SCORES.get(transport, _IRAN_TRANSPORT_SCORES["vanilla"])

        # Port bonus
        port_bonus = _IRAN_PORT_SCORES.get(port, 0.3)

        # Iran pressure modifier: harsh censorship should penalize weak
        # transports, but it should not unfairly demote transports designed for
        # DPI evasion (Snowflake/WebTunnel/meek).  The previous whole-score
        # multiplier made excellent local scores impossible at level >= 3, so
        # external-provider outages produced only mediocre tiers.
        pressure = max(0.0, min(1.0, (censorship_level - 1) / 4.0))

        # Compute composite score; fold in the local RL state for unknown/aggregate ISP.
        rl_cell = self.state_matrix.get("patterns", {}).get("unknown", {}).get(transport, {})
        rl_q = float(rl_cell.get("q_value", t_scores["base"]))
        base_score = rl_q * 0.2 + t_scores["base"] * 0.35 + port_bonus * 0.2 + t_scores["dpi_resist"] * 0.25
        dpi_bonus = pressure * t_scores["dpi_resist"] * 0.12
        weak_transport_penalty = pressure * (1.0 - t_scores["dpi_resist"]) * 0.35
        nin_bonus = pressure * t_scores["nin_survival"] * 0.08
        score = min(1.0, max(0.0, base_score + dpi_bonus + nin_bonus - weak_transport_penalty))

        # Determine recommendation
        if score >= 0.75:
            recommendation = "use"
        elif score >= 0.45:
            recommendation = "test"
        else:
            recommendation = "avoid"

        # ISP block risk
        if t_scores["dpi_resist"] >= 0.85:
            isp_risk = "low"
        elif t_scores["dpi_resist"] >= 0.60:
            isp_risk = "medium"
        else:
            isp_risk = "high"

        # Mutation hint
        mutation_hint = ""
        if transport == "obfs4":
            iat_mode = parsed["params"].get("iat-mode", "0")
            if iat_mode != "2":
                mutation_hint = "Set iat-mode=2 for better DPI evasion"
            if port != 443:
                mutation_hint += "; move to port 443 if possible"
        elif transport == "vanilla":
            mutation_hint = "Switch to obfs4, WebTunnel, or Snowflake"

        return {
            "score": round(score, 3),
            "transport_ok": score > 0.4,
            "dpi_bypass_rating": round(t_scores["dpi_resist"], 3),
            "nin_survival": round(t_scores["nin_survival"], 3),
            "isp_block_risk": isp_risk,
            "recommendation": recommendation,
            "mutation_hint": mutation_hint,
            "rl_q_value": round(rl_q, 3),
            "source": "local_ai_engine",
        }

    def build_polymorphic_morphing_profile(
        self,
        transport: str = "obfs4",
        isp: str = "unknown",
        censorship_level: int = 4,
        handshake_failure: bool = False,
        dpi_trigger: bool = False,
    ) -> dict[str, Any]:
        """Return a local-only traffic morphing profile for runners/clients.

        The method emits configuration hints rather than touching packets itself, so
        callers can apply them in their own transport layer with a non-blocking
        fallback path. It adapts padding, header rotation, and fragmentation timing
        from the RL state plus TCP/TLS/DPI feedback.
        """
        if handshake_failure:
            self.observe_feedback(isp, transport, "handshake_failure", persist=False)
        if dpi_trigger:
            self.observe_feedback(isp, transport, "dpi_trigger", persist=False)
        decision = self.choose_dynamic_transport(isp=isp, censorship_level=censorship_level)
        selected = decision["selected_transport"]
        pressure = _clamp((censorship_level - 1) / 4.0)
        seed = int(_stable_unit_interval(selected, isp, censorship_level) * 10_000)
        rng = random.Random(seed)
        padding_min = int(16 + pressure * 96)
        padding_max = int(128 + pressure * 640)
        if dpi_trigger:
            padding_max += 256
        if handshake_failure:
            padding_min = 0
            padding_max = min(padding_max, 256)
        return {
            "selected_transport": selected,
            "fallback_transport": self.recommend_transport_stack(censorship_level, isp).get("fallback_transport"),
            "packet_headers": {
                "rotate_user_agent": True,
                "accept_language": rng.choice(["fa-IR,fa;q=0.9,en;q=0.7", "en-US,en;q=0.9", "fa,en;q=0.8"]),
                "tls_profile": rng.choice(["chrome_stable", "firefox_esr", "android_webview"]),
            },
            "padding": {"mode": "polymorphic", "min_bytes": padding_min, "max_bytes": padding_max},
            "fragmentation_timing": {
                "enabled": censorship_level >= 3 and not handshake_failure,
                "min_delay_ms": int(5 + pressure * 20),
                "max_delay_ms": int(35 + pressure * 120),
                "burst_jitter_ms": rng.randint(8, 48),
            },
            "retry_reconfigure_loop": {
                "tcp_tls_handshake_failure": "reduce padding, disable fragmentation for one attempt, switch TLS profile",
                "dpi_fingerprint_trigger": "increase polymorphic padding, rotate transport, widen timing jitter",
                "max_attempts": 3,
                "non_blocking_fallback": "LocalAIEngine.choose_dynamic_transport",
            },
            "decision": decision,
            "source": "local_ai_engine_rl",
        }

    def rank_bridges(self, bridge_lines: list[str], censorship_level: int = 4) -> list[dict[str, Any]]:
        """Rank bridges from best to worst for Iran."""
        scored = []
        for line in bridge_lines:
            result = self.score_bridge(line, censorship_level)
            result["bridge_line"] = line
            scored.append(result)
        scored.sort(key=lambda x: x["score"], reverse=True)
        for i, s in enumerate(scored):
            s["rank"] = i + 1
        return scored

    # ── Censorship Detection ──────────────────────────────────────────────

    def detect_censorship_level(
        self,
        probe_results: dict[str, str] | None = None,
        nin_active: bool | None = None,
    ) -> dict[str, Any]:
        """
        Detect Iran censorship level (1-5) based on probe results.

        Args:
            probe_results: Dict of probe_category -> "ok"/"fail"
            nin_active: Whether NIN is detected as active

        Returns:
            {level, confidence, label, best_transports, pack_file, urgency, reasoning}
        """
        if nin_active:
            level = 5
            label = "NIN/Shutdown"
            best_transports = ["webtunnel", "vless_reality"]
            pack_file = "export/iran_cut_pack.txt"
            urgency = "critical"
            reasoning = "NIN detected: international internet cut. Only CDN-fronted tunnels viable."
        elif probe_results:
            fails = sum(1 for v in probe_results.values() if v == "fail")
            total = len(probe_results)

            if fails == 0:
                level = 1
                label = "Minimal"
                best_transports = ["obfs4", "snowflake", "webtunnel"]
                pack_file = "export/iran_pack.txt"
                urgency = "low"
                reasoning = "No blocking detected. All transports viable."
            elif fails <= total * 0.3:
                level = 2
                label = "Standard"
                best_transports = ["obfs4_443", "snowflake", "webtunnel"]
                pack_file = "export/iran_pack.txt"
                urgency = "low"
                reasoning = "Light blocking detected. obfs4 on port 443 recommended."
            elif fails <= total * 0.6:
                level = 3
                label = "Elevated"
                best_transports = ["snowflake", "webtunnel", "meek_lite"]
                pack_file = "export/iran_pack.txt"
                urgency = "medium"
                reasoning = "Elevated blocking. Direct Tor and some obfs4 blocked."
            elif fails <= total * 0.8:
                level = 4
                label = "DPI Active"
                best_transports = ["snowflake", "webtunnel", "meek_lite"]
                pack_file = "export/iran_pack.txt"
                urgency = "high"
                reasoning = "Active DPI with AI/ML analysis. obfs4 degraded."
            else:
                level = 5
                label = "NIN/Shutdown"
                best_transports = ["webtunnel", "vless_reality"]
                pack_file = "export/iran_cut_pack.txt"
                urgency = "critical"
                reasoning = "Near-total blocking. Only CDN-fronted tunnels viable."
        else:
            # Default assumption for Iran: DPI Level 4
            level = 4
            label = "DPI Active (assumed)"
            best_transports = ["snowflake", "webtunnel", "meek_lite"]
            pack_file = "export/iran_pack.txt"
            urgency = "high"
            reasoning = "No probe data. Assuming DPI Level 4 for Iran (conservative)."

        return {
            "level": level,
            "confidence": 0.85 if probe_results else 0.60,
            "label": label,
            "best_transports": best_transports,
            "pack_file": pack_file,
            "urgency": urgency,
            "reasoning": reasoning,
            "isp_notes": "MCI/IRANCELL have heaviest DPI; Rightel/Shatel lighter",
            "source": "local_ai_engine",
        }

    # ── ISP Block Matrix ──────────────────────────────────────────────────

    def isp_block_matrix(
        self, transport_types: list[str] | None = None
    ) -> dict[str, Any]:
        """Return per-ISP blocking predictions for each transport type."""
        transports = transport_types or ["vanilla", "obfs4", "webtunnel", "snowflake", "meek_lite"]
        result = {}
        for isp, data in _IRAN_ISP_DATA.items():
            result[isp] = {t: data["blocks"].get(t, "unknown") for t in transports}
        result["updated_hint"] = "Based on OONI/Censored Planet data June 2026 (local KB)"
        result["source"] = "local_ai_engine"
        return result

    # ── Transport Recommendation ──────────────────────────────────────────

    def recommend_transport_stack(
        self,
        censorship_level: int = 4,
        isp: str = "unknown",
        nin_active: bool = False,
    ) -> dict[str, Any]:
        """Recommend optimal transport chain for current Iran conditions."""

        if nin_active or censorship_level >= 5:
            return {
                "primary_transport": "webtunnel",
                "fallback_transport": "vless_reality",
                "last_resort": "meek_lite",
                "avoid": ["vanilla", "obfs4", "snowflake"],
                "bridge_selection_hint": "Prefer CDN-fronted WebTunnel bridges (Arvan/Cloudflare)",
                "config_hints": {
                    "webtunnel": {"cdn_front": "arvancloud.ir", "verify": True},
                    "obfs4": {"iat-mode": 2, "prefer_port": 443},
                },
                "confidence": 0.80,
                "reasoning": "NIN active: only CDN-fronted tunnels survive international cut",
                "source": "local_ai_engine",
            }

        if censorship_level >= 4:
            return {
                "primary_transport": "snowflake",
                "fallback_transport": "webtunnel",
                "last_resort": "obfs4_443",
                "avoid": ["vanilla"],
                "bridge_selection_hint": "Snowflake short-lived + WebTunnel CDN-fronted for fallback",
                "config_hints": {
                    "obfs4": {"iat-mode": 2, "prefer_port": 443},
                    "snowflake": {"broker": "cdn", "ampcache": True},
                    "webtunnel": {"cdn_front": True},
                },
                "confidence": 0.78,
                "reasoning": "DPI Level 4: AI/ML traffic analysis active. Snowflake and WebTunnel best.",
                "source": "local_ai_engine",
            }

        if censorship_level >= 3:
            return {
                "primary_transport": "webtunnel",
                "fallback_transport": "snowflake",
                "last_resort": "obfs4_443",
                "avoid": ["vanilla"],
                "bridge_selection_hint": "WebTunnel primary; obfs4 on 443 as backup",
                "config_hints": {
                    "obfs4": {"iat-mode": 2, "prefer_port": 443},
                },
                "confidence": 0.75,
                "reasoning": "Elevated blocking: WebTunnel + obfs4 port 443 viable",
                "source": "local_ai_engine",
            }

        return {
            "primary_transport": "obfs4_443",
            "fallback_transport": "snowflake",
            "last_resort": "webtunnel",
            "avoid": ["vanilla"],
            "bridge_selection_hint": "obfs4 on port 443 with iat-mode=2 recommended",
            "config_hints": {
                "obfs4": {"iat-mode": 2, "prefer_port": 443},
            },
            "confidence": 0.82,
            "reasoning": "Standard/Light blocking: most transports work; prefer obfs4 port 443",
            "source": "local_ai_engine",
        }

    # ── NIN Survival ──────────────────────────────────────────────────────

    def predict_nin_survival(self, bridge_type: str, transport: str) -> dict[str, Any]:
        """Predict bridge survival during NIN internet-cut events."""
        t_scores = _IRAN_TRANSPORT_SCORES.get(transport, _IRAN_TRANSPORT_SCORES["vanilla"])
        nin_surv = t_scores["nin_survival"]

        survives = nin_surv > 0.4
        reason = (
            f"{transport} has NIN survival rating {nin_surv:.0%}. "
            f"{'CDN-fronted tunnels may survive NIN.' if survives else 'NIN cuts international connectivity; only CDN-fronted tunnels survive.'}"
        )

        return {
            "survives": survives,
            "confidence": 0.75,
            "reason": reason,
            "source": "local_ai_engine",
        }

    # ── obfs4 Mutation ────────────────────────────────────────────────────

    def generate_obfs4_mutation(
        self, existing_cert: str, existing_iat_mode: int
    ) -> dict[str, Any]:
        """Generate obfs4 parameter mutation hints for DPI evasion."""
        hints = []

        if existing_iat_mode != 2:
            hints.append("Change iat-mode to 2 (spreads timing to defeat DPI statistical analysis)")
        else:
            hints.append("iat-mode=2 is already optimal for Iran DPI evasion")

        if existing_cert:
            # Analyze cert length (longer = more entropy = harder to fingerprint)
            cert_len = len(existing_cert)
            if cert_len < 30:
                hints.append("Consider regenerating cert — shorter certs are easier to fingerprint")
            else:
                hints.append("Cert length looks adequate")

        return {
            "cert": existing_cert,
            "iat_mode": 2,
            "fingerprint_delta": "high" if existing_iat_mode != 2 else "none",
            "hints": hints,
            "source": "local_ai_engine",
        }

    # ── Temporal Pattern ──────────────────────────────────────────────────

    def temporal_block_pattern(
        self, transport: str = "obfs4", isp: str = "MCI"
    ) -> dict[str, Any]:
        """Predict time-of-day blocking intensity for Iran."""
        now = datetime.now(UTC)
        iran_offset_hours = 3.5
        iran_hour = (now.hour + iran_offset_hours) % 24

        peak_hours = _TEMPORAL_PATTERNS["peak_block_hours"]
        low_hours = _TEMPORAL_PATTERNS["low_block_hours"]

        if int(iran_hour) in peak_hours:
            current = "heavy"
        elif int(iran_hour) in low_hours:
            current = "light"
        else:
            current = "normal"

        return {
            "peak_block_hours": peak_hours,
            "low_block_hours": low_hours,
            "weekend_modifier": _TEMPORAL_PATTERNS["weekend_modifier"],
            "event_sensitivity": _TEMPORAL_PATTERNS["event_sensitivity"],
            "current_estimate": current,
            "best_connection_window": _TEMPORAL_PATTERNS["best_window"],
            "current_iran_hour": int(iran_hour),
            "confidence": 0.70,
            "source": "local_ai_engine",
        }

    # ── Workflow Failure Analysis ─────────────────────────────────────────

    def analyze_workflow_failure(
        self, workflow_name: str, error_log: str
    ) -> dict[str, Any]:
        """Analyze a GitHub Actions workflow failure using pattern matching."""
        best_match = None
        best_confidence = 0.0

        for pattern, fix_info in _WORKFLOW_FIXES.items():
            if pattern.lower() in error_log.lower():
                if fix_info["confidence"] > best_confidence:
                    best_match = fix_info
                    best_confidence = fix_info["confidence"]

        if best_match:
            return {
                "root_cause": best_match["root_cause"],
                "fix_type": best_match["fix_type"],
                "patch": best_match["fix"],
                "confidence": best_match["confidence"],
                "additive_only": True,
                "source": "local_ai_engine",
            }

        # Default analysis for unknown patterns
        return {
            "root_cause": "unknown",
            "fix_type": "manual",
            "patch": "",
            "confidence": 0.3,
            "additive_only": True,
            "reasoning": "No pattern match found in local knowledge base",
            "source": "local_ai_engine",
        }

    # ── Batch Scoring ─────────────────────────────────────────────────────

    def batch_ai_score(
        self,
        bridge_lines: list[str],
        censorship_level: int = 4,
    ) -> list[dict[str, Any]]:
        """Score multiple bridges for Iran reachability."""
        results = []
        for line in bridge_lines:
            parsed = self._parse_bridge_line(line)
            score_result = self.score_bridge(line, censorship_level)
            results.append({
                "bridge_line": line,
                "score": score_result["score"],
                "transport": parsed["transport"],
                "port": parsed["port"],
                "recommendation": score_result["recommendation"],
                "tier": "excellent" if score_result["score"] >= 0.80
                        else "good" if score_result["score"] >= 0.60
                        else "capable" if score_result["score"] >= 0.40
                        else "poor",
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    # ── Chat Completion (gateway-compatible interface) ─────────────────────

    def chat_complete(
        self,
        messages: list[dict[str, str]],
        task: str = "general",
        **kwargs,
    ) -> str:
        """
        Gateway-compatible chat completion interface.
        Analyzes the user message and returns structured JSON response.

        IMPORTANT: For health check probes ("Reply with exactly: TORSHIELD_OK"),
        this engine honestly responds that it is a LOCAL fallback — NOT a primary
        provider. This allows the health check to correctly identify that no
        primary provider is available.
        """
        user_msg = ""
        for m in messages:
            if m.get("role") == "user":
                user_msg += m.get("content", "")

        # ── Health check probe detection ──────────────────────────────────
        # If this is a health check probe asking for TORSHIELD_OK,
        # respond honestly that this is the local engine (DEGRADED mode).
        # The health check script uses this to distinguish primary_ok from
        # degraded_local responses.
        if "TORSHIELD_OK" in user_msg.upper():
            return json.dumps({
                "status": "degraded_local",
                "message": "LOCAL_AI_ENGINE: No primary AI provider available. "
                           "This is a rule-based fallback, not a cloud AI provider.",
                "source": "local_ai_engine",
                "primary_available": False,
            })

        # Route to appropriate method based on message content
        lowered_msg = user_msg.lower()
        if "score" in lowered_msg and "bridge" in lowered_msg:
            level_match = re.search(r"level\s+(\d+)", lowered_msg)
            censorship_level = int(level_match.group(1)) if level_match else 4

            # Batch prompts include a JSON array after "Bridges:".  Prefer a
            # complete local batch response so callers receive one result per
            # bridge even when every external provider is rate-limited.
            batch_match = re.search(r"Bridges:\s*(\[.*\])", user_msg, re.DOTALL)
            if batch_match:
                try:
                    bridge_lines = json.loads(batch_match.group(1))
                    if isinstance(bridge_lines, list):
                        return json.dumps(
                            self.batch_ai_score(
                                [str(line) for line in bridge_lines],
                                censorship_level=censorship_level,
                            )
                        )
                except json.JSONDecodeError:
                    log.debug("[LocalAI] Could not parse batch bridge JSON", exc_info=True)

            # Try to extract a single bridge line from message
            bridge_match = re.search(r'(obfs4|webtunnel|snowflake|meek_lite|vanilla)\s+\S+:\d+', user_msg)
            if bridge_match:
                result = self.score_bridge(bridge_match.group(0), censorship_level=censorship_level)
                return json.dumps(result)

        if "censorship" in user_msg.lower() or "level" in user_msg.lower():
            result = self.detect_censorship_level()
            return json.dumps(result)

        if "isp" in user_msg.lower() and "block" in user_msg.lower():
            result = self.isp_block_matrix()
            return json.dumps(result)

        if "transport" in user_msg.lower() and "recommend" in user_msg.lower():
            result = self.recommend_transport_stack()
            return json.dumps(result)

        if "nin" in user_msg.lower() and "survival" in user_msg.lower():
            result = self.predict_nin_survival("tor", "obfs4")
            return json.dumps(result)

        if "workflow" in user_msg.lower() or "failure" in user_msg.lower():
            result = self.analyze_workflow_failure("unknown", user_msg)
            return json.dumps(result)

        # Default: return general Iran intelligence
        return json.dumps({
            "status": "local_ai_engine_active",
            "message": "External AI providers unavailable. Using local rule-based engine.",
            "iran_dpi_systems": list(_IRAN_DPI_SYSTEMS.keys()),
            "available_methods": [
                "score_bridge", "detect_censorship_level", "isp_block_matrix",
                "recommend_transport_stack", "predict_nin_survival",
                "analyze_workflow_failure", "batch_ai_score",
                "observe_feedback", "choose_dynamic_transport", "build_polymorphic_morphing_profile",
            ],
        })
