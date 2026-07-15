from __future__ import annotations

"""
Ultra VIP Edition — additive tests for the new Phase 3/4 modules.

These tests are MARKED `iran` so they are skipped in pure-CI mode
(SKIP_NETWORK_TESTS=true) per the project's conftest.py convention.
However, none of them require network access — they are pure unit tests
over the new modules' deterministic logic. They will run normally in
local development.
"""

import json
import os
import unittest
from unittest.mock import patch


class TestAntiDPIV4QuantumNoise(unittest.TestCase):
    """Unit tests for AntiDPIV4 + its four subsystems."""

    def test_quantum_noise_injector(self):
        from torshield_ai_gateway.anti_dpi_v4_quantum_noise import QuantumNoiseInjector
        inj = QuantumNoiseInjector(budget_pct=0.10)
        padded, n = inj.inject(b"hello world")
        self.assertGreaterEqual(n, 16)
        self.assertGreaterEqual(len(padded), len(b"hello world") + n)

    def test_adaptive_iat_shaper(self):
        from torshield_ai_gateway.anti_dpi_v4_quantum_noise import AdaptiveIATShaper
        shaper = AdaptiveIATShaper(profile="google")
        delay = shaper.shape(0)
        self.assertIsInstance(delay, float)
        self.assertGreaterEqual(delay, 0.0)
        self.assertTrue(shaper.switch_profile("video"))
        self.assertFalse(shaper.switch_profile("nonexistent"))

    def test_tls_record_splitter(self):
        from torshield_ai_gateway.anti_dpi_v4_quantum_noise import TLSRecordSplitter
        sp = TLSRecordSplitter(max_fragment=100)
        fragments = sp.split(b"x" * 1000)
        self.assertGreater(len(fragments), 1)
        self.assertEqual(b"".join(fragments), b"x" * 1000)

    def test_sni_encryption_fallback_ech(self):
        from torshield_ai_gateway.anti_dpi_v4_quantum_noise import SNIEncryptionFallback
        sni = SNIEncryptionFallback(prefer_ech=True)
        result = sni.negotiate("example.com", ech_supported=True)
        self.assertEqual(result["tier"], "ech")

    def test_sni_encryption_fallback_padding(self):
        from torshield_ai_gateway.anti_dpi_v4_quantum_noise import SNIEncryptionFallback
        sni = SNIEncryptionFallback(prefer_ech=True)
        result = sni.negotiate("example.com", ech_supported=False)
        self.assertEqual(result["tier"], "sni_padding")

    def test_anti_dpi_v4_prepare_request(self):
        from torshield_ai_gateway.anti_dpi_v4_quantum_noise import AntiDPIV4
        v4 = AntiDPIV4()
        headers, config = v4.prepare_request("https://example.com/", "HIGH")
        self.assertIn("User-Agent", headers)
        self.assertEqual(config["version"], "v4")
        self.assertEqual(config["threat_level"], "HIGH")

    def test_anti_dpi_v4_get_status(self):
        from torshield_ai_gateway.anti_dpi_v4_quantum_noise import AntiDPIV4
        v4 = AntiDPIV4()
        status = v4.get_status()
        self.assertEqual(status["engine"], "AntiDPIV4")
        self.assertIn("noise", status)
        self.assertIn("iat", status)
        self.assertIn("splitter", status)
        self.assertIn("sni", status)


class TestNINSurvivalPack(unittest.TestCase):
    """Unit tests for the NIN Survival Pack."""

    def test_generate_pack_ranks_by_priority(self):
        from core.nin_survival_pack import NINSurvivalPack
        pack = NINSurvivalPack()
        bridges = [
            {"transport": "vanilla", "address": "1.1.1.1", "port": 9001, "iran_score": 0.9},
            {"transport": "obfs4", "address": "2.2.2.2", "port": 443, "iran_score": 0.5},
            {"transport": "snowflake", "address": "3.3.3.3", "port": 443, "iran_score": 0.6},
            {"transport": "webtunnel", "address": "4.4.4.4", "port": 443, "iran_score": 0.7},
        ]
        ranked = pack.generate_pack(bridges)
        # vanilla must NOT appear (not NIN-capable)
        transports = [b["transport"] for b in ranked]
        self.assertNotIn("vanilla", transports)
        # snowflake + webtunnel + obfs4 should all be present
        self.assertIn("snowflake", transports)
        self.assertIn("webtunnel", transports)
        self.assertIn("obfs4", transports)

    def test_export_pack_writes_file(self):
        from core.nin_survival_pack import NINSurvivalPack
        pack = NINSurvivalPack(export_path="/tmp/test_nin_pack.txt")
        pack.generate_pack([
            {"transport": "snowflake", "address": "1.2.3.4", "port": 443,
             "fingerprint": "A" * 40, "iran_score": 0.9},
        ])
        pack.export_pack()
        with open("/tmp/test_nin_pack.txt") as fh:
            content = fh.read()
        self.assertIn("NIN Survival Pack", content)
        self.assertIn("snowflake", content)

    def test_get_status(self):
        from core.nin_survival_pack import NINSurvivalPack
        pack = NINSurvivalPack()
        status = pack.get_status()
        self.assertEqual(status["engine"], "NINSurvivalPack")
        self.assertIn("transport_priorities", status)


class TestAIBridgeRerankerV2(unittest.TestCase):
    """Unit tests for the V2 multi-signal re-ranker."""

    def test_score_bridge_v2_high_for_snowflake_443(self):
        from scripts.ai_bridge_reranker_v2 import score_bridge_v2
        bridge = {"transport": "snowflake", "address": "1.2.3.4", "port": 443}
        result = score_bridge_v2(bridge, threat_level="LOW")
        self.assertGreater(result["v2_score"], 0.85)
        self.assertEqual(result["breakdown"]["port_443_bonus"], 1.0)

    def test_score_bridge_v2_low_for_vanilla_high_threat(self):
        from scripts.ai_bridge_reranker_v2 import score_bridge_v2
        bridge = {"transport": "vanilla", "address": "1.2.3.4", "port": 9001}
        result = score_bridge_v2(bridge, threat_level="CRITICAL")
        self.assertLess(result["v2_score"], 0.20)

    def test_rerank_bridges_v2_preserves_count(self):
        from scripts.ai_bridge_reranker_v2 import rerank_bridges_v2
        bridges = [
            {"transport": "obfs4", "address": "1.1.1.1", "port": 443},
            {"transport": "snowflake", "address": "2.2.2.2", "port": 443},
        ]
        ranked = rerank_bridges_v2(bridges)
        self.assertEqual(len(ranked), 2)
        # Snowflake should rank first
        self.assertEqual(ranked[0]["transport"], "snowflake")

    def test_top_k_truncates(self):
        from scripts.ai_bridge_reranker_v2 import rerank_bridges_v2
        bridges = [
            {"transport": "obfs4", "address": f"1.1.1.{i}", "port": 443}
            for i in range(10)
        ]
        ranked = rerank_bridges_v2(bridges, top_k=3)
        self.assertEqual(len(ranked), 3)

    def test_export_writes_json(self):
        from scripts.ai_bridge_reranker_v2 import AIBridgeRerankerV2
        v2 = AIBridgeRerankerV2(threat_level="MEDIUM")
        ranked = v2.rerank([
            {"transport": "snowflake", "address": "1.2.3.4", "port": 443},
        ])
        out = "/tmp/test_reranker_v2.json"
        v2.export(ranked, out)
        with open(out) as fh:
            data = json.load(fh)
        self.assertEqual(data["version"], "v2")
        self.assertEqual(len(data["bridges"]), 1)


class TestSelfHealingEngineV2(unittest.TestCase):
    """Unit tests for the V2 self-healing engine."""

    def test_run_full_diagnosis_returns_dict(self):
        from recovery.self_healing_engine_v2 import SelfHealingEngineV2
        engine = SelfHealingEngineV2(log_path="/tmp/test_self_heal.json")
        diag = engine.run_full_diagnosis(trigger="test")
        self.assertIn("diagnoses_run", diag)
        self.assertEqual(len(diag["diagnoses_run"]), 6)  # DIAG-1..6
        self.assertIn("actions_taken", diag)

    def test_get_status(self):
        from recovery.self_healing_engine_v2 import SelfHealingEngineV2
        engine = SelfHealingEngineV2()
        status = engine.get_status()
        self.assertEqual(status["engine"], "SelfHealingEngineV2")
        self.assertEqual(len(status["diagnoses_available"]), 6)


class TestTelemetryDashboard(unittest.TestCase):
    """Unit tests for the telemetry dashboard."""

    def test_generate_writes_json(self):
        from monitoring.telemetry_dashboard import TelemetryDashboard
        dash = TelemetryDashboard(output_path="/tmp/test_dashboard.json")
        snapshot = dash.generate()
        data = json.loads(snapshot)
        self.assertIn("timestamp", data)
        self.assertIn("bridges", data)
        self.assertIn("dpi", data)
        self.assertIn("gateway", data)
        self.assertIn("pipeline", data)
        self.assertTrue(os.path.exists("/tmp/test_dashboard.json"))

    def test_get_status(self):
        from monitoring.telemetry_dashboard import TelemetryDashboard
        dash = TelemetryDashboard()
        status = dash.get_status()
        self.assertEqual(status["engine"], "TelemetryDashboard")


class TestTemporalAnalyzer(unittest.TestCase):
    """Unit tests for the Iran temporal analyzer."""

    def test_current_threat_level_returns_known_value(self):
        from core.temporal_analyzer import IranTemporalAnalyzer
        analyzer = IranTemporalAnalyzer()
        level = analyzer.current_threat_level()
        self.assertIn(level, ("LOW", "MEDIUM", "HIGH", "VARIABLE"))

    def test_best_connection_windows(self):
        from core.temporal_analyzer import IranTemporalAnalyzer
        analyzer = IranTemporalAnalyzer()
        windows = analyzer.best_connection_windows(limit=3)
        self.assertLessEqual(len(windows), 3)
        for w in windows:
            self.assertEqual(w["level"], "LOW")

    def test_export_schedule(self):
        from core.temporal_analyzer import IranTemporalAnalyzer
        analyzer = IranTemporalAnalyzer()
        out = "/tmp/test_temporal_schedule.json"
        analyzer.export_schedule(out)
        with open(out) as fh:
            data = json.load(fh)
        self.assertIn("schedule", data)
        self.assertIn("current_threat_level", data)


class TestNINDetector(unittest.TestCase):
    """Unit tests for the additive NINDetector class."""

    def test_nin_detector_instantiable(self):
        from core.iran_detector import NINDetector
        d = NINDetector()
        self.assertEqual(d.export_path, "export/iran_cut_pack.txt")

    def test_record_event_appends_to_log(self):
        from core.iran_detector import NINDetector
        d = NINDetector(events_path="/tmp/test_nin_events.json")
        # Start clean
        if os.path.exists("/tmp/test_nin_events.json"):
            os.remove("/tmp/test_nin_events.json")
        d.record_event("test_event", {"foo": "bar"})
        d.record_event("test_event_2", {"baz": "qux"})
        with open("/tmp/test_nin_events.json") as fh:
            events = json.load(fh)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["kind"], "test_event")
        self.assertEqual(events[1]["kind"], "test_event_2")


class TestPort443Filter(unittest.TestCase):
    """Unit tests for the additive prioritize_port_443 filter."""

    def test_port_443_floats_to_front(self):
        from core.collector import prioritize_port_443
        bridges = [
            {"port": 9001, "addr": "a"},
            {"port": 443, "addr": "b"},
            {"port": 443, "addr": "c"},
            {"port": 8080, "addr": "d"},
        ]
        ranked = prioritize_port_443(bridges)
        self.assertEqual([b["addr"] for b in ranked], ["b", "c", "a", "d"])

    def test_no_443_keeps_order(self):
        from core.collector import prioritize_port_443
        bridges = [
            {"port": 9001, "addr": "a"},
            {"port": 8080, "addr": "b"},
        ]
        ranked = prioritize_port_443(bridges)
        self.assertEqual([b["addr"] for b in ranked], ["a", "b"])



__all__ = [
    'patch',
]
if __name__ == "__main__":
    unittest.main()
