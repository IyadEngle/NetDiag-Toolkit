# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import socket
import ssl
import threading
from unittest.mock import MagicMock, patch

import pytest

from netdiag.security.tls import (
    CertificateInfo,
    TLSProtocolStatus,
    _classify_ssl_error_for_protocol,
    _classify_verification_error,
    _test_tls_version,
    check_certificate_expiry,
    check_certificate_hostname,
)
from netdiag.utils.models import SecurityStatus, Severity


@pytest.fixture
def self_signed_server(tmp_path):
    """TLS server on 127.0.0.1 presenting a freshly generated self-signed cert for 'localhost'."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    server.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    thread.join(timeout=2)
    server.close()


class TestTLSProtocolClassification:
    @pytest.mark.parametrize("error_msg", [
        "wrong version number",
        "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1007)",
        "certificate verify failed",
        "no cipher match",
        "handshake failure",
        "no protocols available",
    ])
    def test_all_ssl_errors_are_inconclusive(self, error_msg):
        err = ssl.SSLError(1, error_msg)
        assert _classify_ssl_error_for_protocol(err) == TLSProtocolStatus.INCONCLUSIVE


class TestCertificateExpiry:
    @patch('netdiag.security.tls._retrieve_certificate')
    def test_connection_failed_is_skip(self, mock_retrieve):
        mock_retrieve.return_value = (None, None, "CONNECTION_FAILED", "refused")
        findings = check_certificate_expiry("test.com")
        assert findings[0].status == SecurityStatus.SKIP
        assert findings[0].severity == Severity.INFO

    @patch('netdiag.security.tls._retrieve_certificate')
    def test_expired_is_fail_high(self, mock_retrieve):
        cert = CertificateInfo(days_until_expiry=-5, not_after="2024-01-01")
        mock_retrieve.return_value = (cert, "TLSv1.3", "OK", None)
        findings = check_certificate_expiry("test.com")
        assert findings[0].status == SecurityStatus.FAIL
        assert findings[0].severity == Severity.HIGH

    @patch('netdiag.security.tls._retrieve_certificate')
    def test_valid_is_pass(self, mock_retrieve):
        cert = CertificateInfo(days_until_expiry=90, not_after="2025-04-15")
        mock_retrieve.return_value = (cert, "TLSv1.3", "OK", None)
        findings = check_certificate_expiry("test.com")
        assert findings[0].status == SecurityStatus.PASS


def _verify_error(message: str, code: int | None) -> ssl.SSLCertVerificationError:
    err = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message}")
    if code is not None:
        err.verify_code = code
        err.verify_message = message
    return err


class TestVerificationErrorClassification:
    @pytest.mark.parametrize("message,code,expected", [
        ("self-signed certificate", 18, "self_signed"),                      # OpenSSL 3
        ("self signed certificate", 18, "self_signed"),                      # OpenSSL 1.1
        ("self-signed certificate in certificate chain", 19, "self_signed"),
        ("Hostname mismatch, certificate is not valid for 'x'.", 62, "hostname_mismatch"),
        ("certificate has expired", 10, "expired"),
        ("unable to get local issuer certificate", 20, "other"),
        # No verify_code attribute: fall back to message text.
        ("self-signed certificate", None, "self_signed"),
        ("Hostname mismatch, certificate is not valid for 'x'.", None, "hostname_mismatch"),
    ])
    def test_classification(self, message, code, expected):
        assert _classify_verification_error(_verify_error(message, code)) == expected


class TestSelfSignedDetection:
    @patch("netdiag.security.tls._retrieve_certificate")
    @patch("netdiag.security.tls.socket.create_connection")
    def test_openssl3_self_signed_is_reported_as_self_signed(self, mock_conn, mock_retrieve):
        mock_conn.side_effect = _verify_error("self-signed certificate", 18)
        mock_retrieve.return_value = (CertificateInfo(is_self_signed=True), "TLSv1.3", "OK", None)
        findings = check_certificate_hostname("selfsigned.test")
        assert findings[0].status == SecurityStatus.FAIL
        assert findings[0].title == "Self-Signed TLS Certificate (Cryptographically Verified)"

    def test_real_self_signed_server_on_loopback(self, self_signed_server):
        port = self_signed_server
        findings = check_certificate_hostname("localhost", port, timeout=5)
        assert findings[0].status == SecurityStatus.FAIL
        assert "Self-Signed" in findings[0].title


class TestTLSSocketCleanup:
    @patch("netdiag.security.tls.ssl.SSLContext")
    @patch("netdiag.security.tls.socket.create_connection")
    def test_socket_closed_when_handshake_fails(self, mock_conn, mock_ctx_cls):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        mock_conn.return_value = sock
        mock_ctx_cls.return_value.wrap_socket.side_effect = ssl.SSLError(1, "handshake failure")
        status, _ = _test_tls_version("x.test", 443, "TLSv1.2", ssl.TLSVersion.TLSv1_2, timeout=1)
        assert status == TLSProtocolStatus.INCONCLUSIVE
        sock.__exit__.assert_called_once()
