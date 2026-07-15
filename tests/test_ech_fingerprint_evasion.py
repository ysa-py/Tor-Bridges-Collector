import socket
import ssl
import sys
import types
from unittest.mock import Mock, patch

import pytest

import ech_fingerprint_evasion as efe


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (TimeoutError("timed out"), "timeout"),
        (TimeoutError("timed out"), "timeout"),
        (ConnectionRefusedError("refused"), "connection_refused"),
        (OSError("network unreachable"), "unreachable"),
        (ssl.SSLError("tls handshake failed"), "ssl_error"),
    ],
)
def test_check_ech_records_expected_probe_failures_without_global_telemetry(exc, status):
    recorder = Mock()
    log_exception = Mock()
    fake_logger = types.ModuleType("monitoring.structured_logger")
    fake_logger.record_silent_failure = recorder

    with patch.dict(sys.modules, {"monitoring.structured_logger": fake_logger}):
        with patch("ech_fingerprint_evasion.log.exception", log_exception):
            with patch("ech_fingerprint_evasion.socket.create_connection", side_effect=exc):
                result = efe._check_ech("198.51.100.7", 443)

    assert result["tls_reachable"] is False
    assert result["tls_probe_status"] == status
    assert result["tls_error_type"] == type(exc).__name__
    recorder.assert_not_called()
    log_exception.assert_not_called()


def test_check_ech_records_ssl_wrap_failure_without_global_telemetry():
    recorder = Mock()
    log_exception = Mock()
    fake_logger = types.ModuleType("monitoring.structured_logger")
    fake_logger.record_silent_failure = recorder
    exc = ssl.SSLError("tls handshake failed")

    class FakeRawSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    fake_context = Mock()
    fake_context.wrap_socket.side_effect = exc

    with patch.dict(sys.modules, {"monitoring.structured_logger": fake_logger}):
        with patch("ech_fingerprint_evasion.log.exception", log_exception):
            with patch("ech_fingerprint_evasion.ssl.SSLContext", return_value=fake_context):
                with patch("ech_fingerprint_evasion.socket.create_connection", return_value=FakeRawSocket()):
                    result = efe._check_ech("198.51.100.7", 443)

    assert result["tls_reachable"] is False
    assert result["tls_probe_status"] == "ssl_error"
    assert result["tls_error_type"] == "SSLError"
    recorder.assert_not_called()
    log_exception.assert_not_called()


def test_check_ech_records_oserror_wrap_failure_without_global_telemetry():
    recorder = Mock()
    log_exception = Mock()
    fake_logger = types.ModuleType("monitoring.structured_logger")
    fake_logger.record_silent_failure = recorder
    exc = OSError("network reset")

    class FakeRawSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    fake_context = Mock()
    fake_context.wrap_socket.side_effect = exc

    with patch.dict(sys.modules, {"monitoring.structured_logger": fake_logger}):
        with patch("ech_fingerprint_evasion.log.exception", log_exception):
            with patch("ech_fingerprint_evasion.ssl.SSLContext", return_value=fake_context):
                with patch("ech_fingerprint_evasion.socket.create_connection", return_value=FakeRawSocket()):
                    result = efe._check_ech("198.51.100.7", 443)

    assert result["tls_reachable"] is False
    assert result["tls_probe_status"] == "unreachable"
    assert result["tls_error_type"] == "OSError"
    recorder.assert_not_called()
    log_exception.assert_not_called()


def test_check_ech_keeps_unexpected_probe_failures_visible_and_telemetered():
    recorder = Mock()
    fake_logger = types.ModuleType("monitoring.structured_logger")
    fake_logger.record_silent_failure = recorder
    exc = RuntimeError("parser bug")

    with patch.dict(sys.modules, {"monitoring.structured_logger": fake_logger}):
        with patch("ech_fingerprint_evasion.socket.create_connection", side_effect=exc):
            result = efe._check_ech("198.51.100.7", 443)

    assert result["tls_probe_status"] == "unexpected_error"
    assert result["tls_error_type"] == "RuntimeError"
    recorder.assert_called_once_with("ech_fingerprint_evasion:56", exc)
