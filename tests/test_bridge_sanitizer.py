"""Unit tests for scripts/bridge_sanitizer.py (run: python3 -m unittest tests/test_bridge_sanitizer.py)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import bridge_sanitizer as bs  # noqa: E402

CERT = "A" * 70
FP = "ab" * 20


class SanitizerTests(unittest.TestCase):
    def test_prefix_and_case(self):
        self.assertEqual(bs.normalize(f"Bridge 8.8.4.4:443 {FP}")[0], f"8.8.4.4:443 {FP.upper()}")

    def test_obfs4_is_orbot_valid(self):
        n = bs.normalize(f"Bridge obfs4 8.8.4.4:443 {FP} cert={CERT} iat-mode=1 extra=1")
        self.assertTrue(bs.orbot_valid(n[0]))

    def test_reserved_obfs4_rejected(self):
        self.assertIsNone(bs.normalize(f"obfs4 192.0.2.1:443 {FP} cert={CERT} iat-mode=0"))
        self.assertIsNone(bs.normalize(f"obfs4 10.0.0.1:443 {FP} cert={CERT} iat-mode=0"))

    def test_webtunnel_placeholder_ok_and_extra_params_dropped(self):
        n = bs.normalize(f"webtunnel [2001:db8::1]:443 {FP} url=https://x.example/p sni-imitation=a.b ver=0.0.3")
        self.assertTrue(bs.orbot_valid(n[0]))
        self.assertNotIn("sni-imitation", n[0])

    def test_empty_file_refilled(self):
        with tempfile.TemporaryDirectory() as d:
            b = os.path.join(d, "bridge")
            os.makedirs(b)
            open(os.path.join(b, "obfs4.txt"), "w").write(f"obfs4 8.8.4.4:443 {FP} cert={CERT} iat-mode=0\n")
            open(os.path.join(b, "obfs4_tested.txt"), "w").write("")
            self.assertEqual(bs.main(["--root", d, "--bridge-dir", b]), 0)
            self.assertTrue(open(os.path.join(b, "obfs4_tested.txt")).read().strip())
            self.assertTrue(os.path.isfile(os.path.join(d, "export", "orbot", "orbot_top.txt")))


if __name__ == "__main__":
    unittest.main()
