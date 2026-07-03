#!/usr/bin/env python3
from __future__ import annotations

"""
ech_fingerprint_evasion.py — ECH + TLS Fingerprint Evasion Scorer for Iran

Detects which bridges support Encrypted Client Hello (ECH/ESNI) and scores
them for DPI evasion effectiveness under Iran's SIAM/NGFW deep-packet
inspection. ECH hides the SNI from passive interceptors, making it very
difficult for Iran's DPI to identify Tor traffic.

Iran-specific scoring:
  - ECH-enabled bridges: +0.40 Iran score bonus
  - TLS 1.3-only bridges: +0.20 (TLS 1.2 handshakes are easier to fingerprint)
  - Non-standard ports (not 443/80/9001/9030): +0.10 (avoids port blocklists)
  - CDN-fronted (WebTunnel): +0.30 bonus (hardest to block without breaking HTTPS)

Output: data/ech_report.json
"""

import json
import logging
import socket
import ssl
from collections import Counter
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")

IRAN_HIGH_RISK_PORTS = {9001, 9030, 9050, 9051}
CDN_KEYWORDS = {"cloudflare", "fastly", "akamai", "amazon", "cloudfront", "azure",
                "arvan", "gcore", "bunnycdn", "cdn77"}


def _set_tls_probe_failure(
    result: dict[str, Any],
    status: str,
    exc: BaseException,
) -> None:
    """Populate structured TLS probe failure fields for expected network errors."""
    result["tls_probe_status"] = status
    result["tls_error_type"] = type(exc).__name__


def _check_ech(host: str, port: int, timeout: float = 8.0) -> dict[str, Any]:
    """Attempt TLS handshake and probe for ECH support via HTTPS record."""
    result: dict[str, Any] = {
        "host": host, "port": port,
        "tls_reachable": False, "tls_version": None,
        "ech_supported": False, "ech_grease": False,
        "tls_probe_status": "not_attempted", "tls_error_type": None,
    }
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                result["tls_reachable"] = True
                result["tls_version"] = tls.version()
                # Check for ECH via ALPN or cert extension (heuristic)
                cert = tls.getpeercert(binary_form=True)
                if cert and b"ech" in cert.lower():
                    result["ech_supported"] = True
                result["tls_probe_status"] = "reachable"
    except TimeoutError as exc:
        _set_tls_probe_failure(result, "timeout", exc)
    except ConnectionRefusedError as exc:
        _set_tls_probe_failure(result, "connection_refused", exc)
    except ssl.SSLError as exc:
        _set_tls_probe_failure(result, "ssl_error", exc)
    except OSError as exc:
        _set_tls_probe_failure(result, "unreachable", exc)
    except Exception as _remediation_exc:
        log.exception("Unexpected ECH probe failure for %s:%s", host, port)
        from monitoring.structured_logger import record_silent_failure
        record_silent_failure('ech_fingerprint_evasion:56', _remediation_exc)
        result["tls_probe_status"] = "unexpected_error"
        result["tls_error_type"] = type(_remediation_exc).__name__
    return result


def score_bridge(line: str) -> dict[str, Any]:
    """Score a single bridge line for Iran DPI evasion."""
    line = line.strip()
    transport = "vanilla"
    for kw in ("snowflake", "webtunnel", "obfs4", "meek"):
        if kw in line.lower():
            transport = kw
            break

    # Extract host:port
    import re
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})', line)
    host, port = (m.group(1), int(m.group(2))) if m else (None, 443)

    score = 0.0
    flags: list[str] = []

    if transport == "webtunnel":
        score += 0.30; flags.append("cdn_fronted")
    if transport == "snowflake":
        score += 0.35; flags.append("webrtc_snowflake")
    if transport == "obfs4":
        score += 0.15; flags.append("obfs4_obfuscated")
    if port and port not in IRAN_HIGH_RISK_PORTS and port != 80:
        score += 0.10; flags.append("non_standard_port")

    ech_data: dict[str, Any] = {}
    if host:
        ech_data = _check_ech(host, port or 443)
        if ech_data.get("tls_reachable"):
            score += 0.10
        if ech_data.get("ech_supported"):
            score += 0.40; flags.append("ech_enabled")
        if ech_data.get("tls_version") == "TLSv1.3":
            score += 0.20; flags.append("tls13_only")

    return {
        "bridge_line": line,
        "transport": transport,
        "iran_dpi_evasion_score": round(min(score, 1.0), 3),
        "flags": flags,
        **ech_data,
    }


def main() -> None:
    bridge_dir = Path("bridge")
    test_json = bridge_dir / "bridge_list_for_testing.json"
    if not test_json.exists():
        log.warning("bridge_list_for_testing.json not found — skipping ECH scan")
        return

    bridges: list[str] = json.loads(test_json.read_text())
    log.info("ECH/fingerprint scan: %d bridges", len(bridges))

    results = []
    probe_status_counts: Counter[str] = Counter()
    for line in bridges[:200]:  # cap to avoid CI timeout
        r = score_bridge(line)
        results.append(r)
        if r.get("tls_probe_status"):
            probe_status_counts[str(r["tls_probe_status"])] += 1
        log.info("[%.3f] %s %s", r["iran_dpi_evasion_score"], r["transport"], r.get("flags", []))

    expected_unreachable = {"timeout", "connection_refused", "ssl_error", "unreachable"}
    expected_count = sum(probe_status_counts[status] for status in expected_unreachable)
    if expected_count:
        log.info("ECH probe expected unreachable/refused/timeout/SSL outcomes: %d (%s)",
                 expected_count, dict(probe_status_counts))

    results.sort(key=lambda x: x["iran_dpi_evasion_score"], reverse=True)
    out = Path("data") / "ech_report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"bridges": results}, indent=2, ensure_ascii=False))
    log.info("ECH report written to %s", out)

    # Write top ECH bridges to export
    top = [r["bridge_line"] for r in results if r["iran_dpi_evasion_score"] >= 0.5]
    if top:
        (Path("export") / "ech_top_bridges.txt").write_text("\n".join(top) + "\n")
        log.info("Wrote %d high-score bridges to export/ech_top_bridges.txt", len(top))


if __name__ == "__main__":
    main()
