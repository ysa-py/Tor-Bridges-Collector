"""
tests/test_anti_censorship.py
================================
Comprehensive unit tests for the anti_censorship package.

All tests are fully offline (no real network required).
Uses unittest.mock to patch asyncio connections.

Run with:
    pytest -q tests/test_anti_censorship.py
"""

from __future__ import annotations

import asyncio
import struct
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so we can import autonomous.*
# ---------------------------------------------------------------------------
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
#  TrafficObfuscator
# ---------------------------------------------------------------------------
class TestTrafficObfuscator(unittest.TestCase):
    """Test obfuscation roundtrip, TLS mimicry, and padding."""

    def setUp(self) -> None:
        from autonomous.anti_censorship.obfuscator import TrafficObfuscator
        self.obf = TrafficObfuscator()

    def test_roundtrip_empty(self) -> None:
        """Empty bytes should survive obfuscate → deobfuscate."""
        data   = b""
        result = self.obf.deobfuscate(self.obf.obfuscate(data))
        self.assertEqual(result, data)

    def test_roundtrip_short(self) -> None:
        data   = b"hello iran"
        result = self.obf.deobfuscate(self.obf.obfuscate(data))
        self.assertEqual(result, data)

    def test_roundtrip_large(self) -> None:
        data   = os.urandom(8_192)
        result = self.obf.deobfuscate(self.obf.obfuscate(data))
        self.assertEqual(result, data)

    def test_obfuscated_looks_like_http(self) -> None:
        data      = b"secret payload"
        obfuscated = self.obf.obfuscate(data)
        self.assertIn(b"HTTP/1.1", obfuscated)
        self.assertIn(b"Host:", obfuscated)

    def test_obfuscated_hides_plaintext(self) -> None:
        data      = b"very secret data"
        obfuscated = self.obf.obfuscate(data)
        # The plaintext must NOT appear verbatim in the obfuscated blob
        self.assertNotIn(data, obfuscated)

    def test_tls_hello_starts_with_correct_record_type(self) -> None:
        hello = self.obf.mimic_tls_client_hello()
        # Content type 0x16 = Handshake
        self.assertEqual(hello[0], 0x16)
        # Legacy version TLS 1.0 = 03 01
        self.assertEqual(hello[1:3], b"\x03\x01")

    def test_tls_hello_contains_sni(self) -> None:
        sni   = b"cdn.cloudflare.com"
        hello = self.obf.mimic_tls_client_hello(sni=sni)
        self.assertIn(sni, hello)

    def test_different_keys_produce_different_ciphertexts(self) -> None:
        from autonomous.anti_censorship.obfuscator import TrafficObfuscator
        obf1 = TrafficObfuscator(key=b"A" * 32)
        obf2 = TrafficObfuscator(key=b"B" * 32)
        data = b"same plaintext"
        self.assertNotEqual(obf1.obfuscate(data), obf2.obfuscate(data))


import os  # noqa: E402 (already imported above, needed for test body)


# ---------------------------------------------------------------------------
#  BridgeConfig / TorBridgeManager
# ---------------------------------------------------------------------------
class TestBridgeConfig(unittest.TestCase):
    """Test bridge line generation for various protocols."""

    def _make(self, **kw):
        from autonomous.anti_censorship.bridges import BridgeConfig
        from autonomous.anti_censorship.obfuscator import ObfuscationProtocol
        defaults = {
            "address": "1.2.3.4",
            "port": 443,
            "protocol": ObfuscationProtocol.OBFS4,
            "fingerprint": "DEADBEEF",
        }
        defaults.update(kw)
        return BridgeConfig(**defaults)

    def test_obfs4_line_contains_cert(self) -> None:
        b = self._make(extra_params={"cert": "abc123", "iat-mode": "0"})
        line = b.to_bridge_line()
        self.assertIn("obfs4", line)
        self.assertIn("cert=abc123", line)

    def test_plain_line(self) -> None:
        from autonomous.anti_censorship.obfuscator import ObfuscationProtocol
        b = self._make(protocol=ObfuscationProtocol.PLAIN, fingerprint="AABBCC")
        line = b.to_bridge_line()
        self.assertIn("1.2.3.4:443", line)
        self.assertIn("AABBCC", line)

    def test_snowflake_line(self) -> None:
        from autonomous.anti_censorship.obfuscator import ObfuscationProtocol
        b = self._make(protocol=ObfuscationProtocol.SNOWFLAKE, fingerprint=None)
        self.assertIn("snowflake", b.to_bridge_line())

    def test_meek_azure_has_url(self) -> None:
        from autonomous.anti_censorship.obfuscator import ObfuscationProtocol
        b = self._make(
            protocol=ObfuscationProtocol.MEEK_AZURE,
            extra_params={"url": "https://meek.azurefd.net/"},
        )
        self.assertIn("url=https://meek.azurefd.net/", b.to_bridge_line())


class TestTorBridgeManager(unittest.IsolatedAsyncioTestCase):
    """Test bridge probing logic (mocked TCP)."""

    async def test_finds_working_bridge(self) -> None:
        from autonomous.anti_censorship.bridges import BridgeConfig, TorBridgeManager
        from autonomous.anti_censorship.obfuscator import ObfuscationProtocol

        good_bridge = BridgeConfig("1.2.3.4", 443, ObfuscationProtocol.MEEK_AZURE)
        mgr = TorBridgeManager(bridges=[good_bridge])

        # Patch open_connection to succeed
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock,
                   return_value=(None, mock_writer)):
            result = await mgr.find_working_bridge()

        self.assertIsNotNone(result)
        self.assertEqual(result.address, "1.2.3.4")

    async def test_skips_unreachable_bridge(self) -> None:
        from autonomous.anti_censorship.bridges import BridgeConfig, TorBridgeManager
        from autonomous.anti_censorship.obfuscator import ObfuscationProtocol

        dead_bridge = BridgeConfig("9.9.9.9", 9999, ObfuscationProtocol.OBFS4)
        mgr = TorBridgeManager(bridges=[dead_bridge])

        with patch("asyncio.open_connection",
                   side_effect=ConnectionRefusedError("refused")):
            result = await mgr.find_working_bridge()

        self.assertIsNone(result)

    def test_generate_torrc_contains_usebridges(self) -> None:
        from autonomous.anti_censorship.bridges import TorBridgeManager
        mgr = TorBridgeManager()
        torrc = mgr.generate_torrc()
        self.assertIn("UseBridges 1", torrc)
        self.assertIn("ClientTransportPlugin obfs4", torrc)

    def test_add_bridge_clears_backoff(self) -> None:
        from autonomous.anti_censorship.bridges import BridgeConfig, TorBridgeManager
        from autonomous.anti_censorship.obfuscator import ObfuscationProtocol
        import time

        mgr = TorBridgeManager(bridges=[])
        b   = BridgeConfig("1.2.3.4", 443, ObfuscationProtocol.PLAIN)
        k   = "1.2.3.4:443"
        mgr._backoff_until[k] = time.monotonic() + 9999   # simulate back-off
        mgr.add_bridge(b)
        self.assertFalse(mgr._in_backoff(b))


# ---------------------------------------------------------------------------
#  DPIDetector
# ---------------------------------------------------------------------------
class TestDPIDetector(unittest.IsolatedAsyncioTestCase):
    """Test DPI detection logic (mocked network)."""

    async def test_probe_reachable(self) -> None:
        from autonomous.anti_censorship.detector import DPIDetector

        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock,
                   return_value=(None, mock_writer)):
            probe = await DPIDetector().probe_tcp("8.8.8.8", 53)

        self.assertTrue(probe.reachable)
        self.assertGreaterEqual(probe.latency_ms, 0)

    async def test_probe_timeout(self) -> None:
        from autonomous.anti_censorship.detector import DPIDetector

        # Patch wait_for directly to raise TimeoutError without creating a coroutine
        async def _fake_wait_for(coro, timeout):
            # Cancel the coroutine to avoid "never awaited" warning
            coro.close()
            raise asyncio.TimeoutError()

        with patch("asyncio.wait_for", side_effect=_fake_wait_for):
            probe = await DPIDetector(probe_timeout=0.001).probe_tcp("0.0.0.0", 1)

        self.assertFalse(probe.reachable)
        self.assertTrue(probe.dpi_detected)

    async def test_dns_poisoning_detected(self) -> None:
        from autonomous.anti_censorship.detector import DPIDetector

        loop = asyncio.get_event_loop()
        with patch.object(
            loop, "getaddrinfo",
            new_callable=AsyncMock,
            return_value=[(None, None, None, None, ("10.10.34.34", 0))],
        ):
            result = await DPIDetector().probe_dns("www.google.com")

        self.assertTrue(result)

    async def test_no_poisoning_when_ip_is_legit(self) -> None:
        from autonomous.anti_censorship.detector import DPIDetector

        loop = asyncio.get_event_loop()
        with patch.object(
            loop, "getaddrinfo",
            new_callable=AsyncMock,
            return_value=[(None, None, None, None, ("142.250.64.46", 0))],
        ):
            result = await DPIDetector().probe_dns("www.google.com")

        self.assertFalse(result)


# ---------------------------------------------------------------------------
#  IranBypassConfig
# ---------------------------------------------------------------------------
class TestIranBypassConfig(unittest.TestCase):

    def setUp(self) -> None:
        from autonomous.anti_censorship.iran import IranBypassConfig
        self.cfg = IranBypassConfig.recommended()

    def test_recommended_has_bridges(self) -> None:
        self.assertGreater(len(self.cfg.bridges), 0)

    def test_known_blocked_domains(self) -> None:
        self.assertTrue(self.cfg.is_likely_blocked("github.com"))
        self.assertTrue(self.cfg.is_likely_blocked("twitter.com"))
        self.assertTrue(self.cfg.is_likely_blocked("api.github.com"))

    def test_non_blocked_domain(self) -> None:
        self.assertFalse(self.cfg.is_likely_blocked("example.internal"))

    def test_dns_poisoning_check(self) -> None:
        self.assertTrue(self.cfg.is_dns_poisoned("10.10.34.34"))
        self.assertFalse(self.cfg.is_dns_poisoned("142.250.64.46"))

    def test_torrc_contains_exclude_iran(self) -> None:
        torrc = self.cfg.build_torrc()
        self.assertIn("ExcludeNodes {ir}", torrc)
        self.assertIn("UseBridges 1", torrc)

    def test_suffix_blocking(self) -> None:
        """Sub-domains of blocked domains should also be flagged."""
        self.assertTrue(self.cfg.is_likely_blocked("raw.githubusercontent.com"))


# ---------------------------------------------------------------------------
#  AntiCensorshipNetworkHealth
# ---------------------------------------------------------------------------
class TestAntiCensorshipNetworkHealth(unittest.TestCase):

    def test_direct_constructor(self) -> None:
        from autonomous.anti_censorship.network_health import AntiCensorshipNetworkHealth
        h = AntiCensorshipNetworkHealth.direct(latency_ms=50.0)
        self.assertFalse(h.bypass_active)
        self.assertTrue(h.online)

    def test_bypassed_constructor(self) -> None:
        from autonomous.anti_censorship.network_health import AntiCensorshipNetworkHealth
        h = AntiCensorshipNetworkHealth.bypassed("meek-azure", latency_ms=250.0)
        self.assertTrue(h.bypass_active)
        self.assertEqual(h.bypass_protocol, "meek-azure")

    def test_str_representation(self) -> None:
        from autonomous.anti_censorship.network_health import AntiCensorshipNetworkHealth
        h = AntiCensorshipNetworkHealth.bypassed("snowflake", latency_ms=300.0)
        s = str(h)
        self.assertIn("snowflake", s)
        self.assertIn("300ms", s)


# ---------------------------------------------------------------------------
#  SmartAntiCensorshipRouter — integration smoke test
# ---------------------------------------------------------------------------
class TestSmartAntiCensorshipRouter(unittest.IsolatedAsyncioTestCase):

    async def test_initialize_no_network(self) -> None:
        """Router should initialize even when all probes fail (offline mode)."""
        from autonomous.anti_censorship.router import SmartAntiCensorshipRouter

        with patch("asyncio.open_connection",
                   side_effect=OSError("no network")):
            router = SmartAntiCensorshipRouter()
            # Should not raise
            await router.initialize()

        status = router.get_status()
        self.assertTrue(status["initialized"])
        self.assertIsNotNone(status["current_strategy"])

    async def test_get_status_keys(self) -> None:
        from autonomous.anti_censorship.router import SmartAntiCensorshipRouter

        with patch("asyncio.open_connection",
                   side_effect=OSError("no network")):
            router = SmartAntiCensorshipRouter()
            await router.initialize()

        status = router.get_status()
        for key in ("initialized", "filtering_level", "current_strategy",
                    "active_bridge", "bridge_pool", "last_probe_ago_s"):
            self.assertIn(key, status, f"Missing key: {key}")

    async def test_escalation_order_starts_at_current(self) -> None:
        from autonomous.anti_censorship.obfuscator import ObfuscationProtocol
        from autonomous.anti_censorship.router import SmartAntiCensorshipRouter

        with patch("asyncio.open_connection",
                   side_effect=OSError("no network")):
            router = SmartAntiCensorshipRouter()
            await router.initialize()

        router._strategy = ObfuscationProtocol.HTTP_MIMIC
        order = router._escalation_order()
        self.assertEqual(order[0], ObfuscationProtocol.HTTP_MIMIC)
        # Snowflake must appear after HTTP_MIMIC
        self.assertIn(ObfuscationProtocol.SNOWFLAKE, order)
        self.assertGreater(order.index(ObfuscationProtocol.SNOWFLAKE),
                           order.index(ObfuscationProtocol.HTTP_MIMIC))


# ---------------------------------------------------------------------------
#  Shell script syntax check
# ---------------------------------------------------------------------------
class TestBootstrapScriptSyntax(unittest.TestCase):

    def test_bash_syntax(self) -> None:
        """Ensure the bootstrap script has valid bash syntax."""
        import subprocess
        script = os.path.join(
            os.path.dirname(__file__),
            "..", "scripts", "bootstrap_autonomous_orchestrator.sh"
        )
        script = os.path.abspath(script)
        if not os.path.exists(script):
            self.skipTest(f"Script not found: {script}")

        result = subprocess.run(
            ["bash", "-n", script],
            capture_output=True, text=True
        )
        self.assertEqual(
            result.returncode, 0,
            f"Bash syntax error:\n{result.stderr}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
