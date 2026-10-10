#!/usr/bin/env python3
"""Independent golden vectors for RFC 6455 Accept and observation freshness.

These checks are intentionally stdlib-only so they can run when cargo/go are
absent. They encode the same constants and acceptance rules the Rust/Worker
probes use; they are not live reachability evidence.
"""
from __future__ import annotations

import base64
import hashlib
import sys
from datetime import datetime, timedelta, timezone

RFC6455_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
RFC6455_SAMPLE_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
RFC6455_SAMPLE_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
OBSERVATION_MAX_AGE = timedelta(minutes=10)
OBSERVATION_FUTURE_SKEW = timedelta(seconds=120)

FAILURES: list[str] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(f"{name}: {detail or 'failed'}")


def expected_accept(key: str) -> str:
    digest = hashlib.sha1((key + RFC6455_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def unique_header(head_text: str, name: str) -> str | None:
    prefix = f"{name.lower()}:"
    values = []
    for line in head_text.split("\r\n")[1:]:
        if line.lower().startswith(prefix):
            values.append(line.split(":", 1)[1].strip())
    return values[0] if len(values) == 1 else None


def has_valid_upgrade_signature(response: str, key: str) -> bool:
    if "\r\n\r\n" not in response:
        return False
    head, _ = response.split("\r\n\r\n", 1)
    status_line = head.split("\r\n", 1)[0]
    parts = status_line.split()
    if len(parts) < 2 or parts[0] != "HTTP/1.1" or parts[1] != "101":
        return False
    upgrade = unique_header(head, "upgrade")
    connection = unique_header(head, "connection")
    accept = unique_header(head, "sec-websocket-accept")
    if upgrade is None or connection is None or accept is None:
        return False
    tokens = [token.strip().lower() for token in connection.split(",")]
    return (
        upgrade.lower() == "websocket"
        and "upgrade" in tokens
        and accept == expected_accept(key)
    )


def parse_rfc3339(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def observation_is_fresh(timestamp: str, now: datetime) -> bool:
    try:
        observed = parse_rfc3339(timestamp)
    except ValueError:
        return False
    age = now - observed
    return -OBSERVATION_FUTURE_SKEW <= age <= OBSERVATION_MAX_AGE


def main() -> int:
    print("═══ Golden vectors (RFC 6455 + freshness) ═══")
    record(
        "RFC6455 sample Accept",
        expected_accept(RFC6455_SAMPLE_KEY) == RFC6455_SAMPLE_ACCEPT,
        RFC6455_SAMPLE_ACCEPT,
    )

    valid = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: keep-alive, Upgrade\r\n"
        f"Sec-WebSocket-Accept: {RFC6455_SAMPLE_ACCEPT}\r\n"
        "\r\n"
    )
    record("valid handshake accepted", has_valid_upgrade_signature(valid, RFC6455_SAMPLE_KEY))
    record(
        "generic 101 rejected",
        not has_valid_upgrade_signature(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            RFC6455_SAMPLE_KEY,
        ),
    )
    record(
        "wrong Accept rejected",
        not has_valid_upgrade_signature(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
            RFC6455_SAMPLE_KEY,
        ),
    )
    duplicate = (
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {RFC6455_SAMPLE_ACCEPT}\r\n"
        f"Sec-WebSocket-Accept: {RFC6455_SAMPLE_ACCEPT}\r\n\r\n"
    )
    record("duplicate Accept rejected", not has_valid_upgrade_signature(duplicate, RFC6455_SAMPLE_KEY))
    http10 = valid.replace("HTTP/1.1 101", "HTTP/1.0 101")
    record("HTTP/1.0 101 rejected", not has_valid_upgrade_signature(http10, RFC6455_SAMPLE_KEY))

    now = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    record(
        "JS Date.toISOString fractional seconds accepted",
        observation_is_fresh("2026-10-10T12:00:00.125Z", now + timedelta(seconds=1)),
    )
    record(
        "exactly 10 minutes old accepted",
        observation_is_fresh("2026-10-10T11:50:00Z", now),
    )
    record(
        "10 minutes 1 second old rejected",
        not observation_is_fresh("2026-10-10T11:49:59Z", now),
    )
    record(
        "120 seconds in the future accepted",
        observation_is_fresh("2026-10-10T12:02:00Z", now),
    )
    record(
        "121 seconds in the future rejected",
        not observation_is_fresh("2026-10-10T12:02:01Z", now),
    )
    record("unparseable timestamp rejected", not observation_is_fresh("not-a-timestamp", now))

    if FAILURES:
        print("═══ Golden vectors: FAILED ═══")
        for failure in FAILURES:
            print(f"::error::{failure}")
        return 1
    print("═══ Golden vectors: PASSED ═══")
    return 0


if __name__ == "__main__":
    sys.exit(main())
