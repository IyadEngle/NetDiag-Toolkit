# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""DNS resolution and TLS handshake reuse within a scan.

Inside a scan (an ExecutionScope with a shared ScanCache):
- the DNS step records the resolved address, and socket-based checks connect
  to it, while every label, TLS SNI and certificate hostname check keeps the
  original hostname
- one certificate handshake is shared by the certificate checks, the TLS
  service probe and the matching protocol-version test
Outside a scan nothing is reused: each call resolves and handshakes itself.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import threading
from unittest.mock import MagicMock, patch

import pytest

from netdiag.utils.execution import ExecutionScope, ScanCache, activate, cached, cached_value, connect_host
from netdiag.utils.models import SecurityStatus, Status

UNRESOLVABLE = "reuse-target.invalid"   # RFC 2606: guaranteed never to resolve


def in_scan(cache: ScanCache, func, *args, **kwargs):
    """Run one 'step' the way the runner will: its own scope, the scan's shared cache."""
    with activate(ExecutionScope(cache=cache)):
        return func(*args, **kwargs)


def scan_with(host: str, address: str) -> ScanCache:
    """A scan cache in which `host` was already resolved to `address` by the DNS step."""
    from netdiag.utils.execution import remember_resolution
    cache = ScanCache()
    in_scan(cache, remember_resolution, host, address)
    return cache


# ---------------------------------------------------------------------------
# Loopback TLS servers
# ---------------------------------------------------------------------------

class TLSServer:
    """TLS server on 127.0.0.1 that counts TCP connections and records SNI names."""

    def __init__(self, cert_pem: bytes, key_pem: bytes, tmp_path) -> None:
        cert_path, key_path = tmp_path / "server.pem", tmp_path / "server.key"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.sni_names: list[str | None] = []
        self.ctx.sni_callback = lambda sslobj, name, ctx: self.sni_names.append(name)
        self.connections = 0
        self._lock = threading.Lock()
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            with self._lock:
                self.connections += 1
            try:
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                conn.close()

    def reset_counts(self) -> None:
        with self._lock:
            self.connections = 0
        self.sni_names.clear()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(2)
        self._sock.close()


def _pem(obj) -> bytes:
    from cryptography.hazmat.primitives import serialization
    if hasattr(obj, "public_bytes"):
        return obj.public_bytes(serialization.Encoding.PEM)
    return obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _make_certs(self_signed: bool):
    """Leaf certificate for 'localhost' (+ CA cert when not self-signed)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
    )
    if self_signed:
        leaf = builder.issuer_name(leaf_name).sign(leaf_key, hashes.SHA256())
        return _pem(leaf), _pem(leaf_key), None

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NetDiag Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        builder.issuer_name(ca_name)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return _pem(leaf), _pem(leaf_key), _pem(ca)


@pytest.fixture
def ca_signed_server(tmp_path):
    """Server for 'localhost' whose CA is trusted by create_default_context during the test."""
    cert, key, ca = _make_certs(self_signed=False)
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca)
    server = TLSServer(cert, key, tmp_path)
    original = ssl.create_default_context

    def trusting_test_ca(*args, **kwargs):
        return original(cafile=str(ca_path))

    with patch("netdiag.security.tls.ssl.create_default_context", side_effect=trusting_test_ca):
        yield server
    server.close()


@pytest.fixture
def self_signed_server(tmp_path):
    cert, key, _ = _make_certs(self_signed=True)
    server = TLSServer(cert, key, tmp_path)
    yield server
    server.close()


def _comparable(findings) -> list[dict]:
    rows = []
    for finding in findings:
        row = finding.to_dict()
        row.pop("timestamp")
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

class TestCacheHelpers:
    def test_cache_if_false_is_not_stored(self):
        cache = ScanCache()
        calls = []
        compute = lambda: calls.append(1) or "failed"   # noqa: E731
        for _ in range(2):
            assert cache.get_or_compute("k", compute, cache_if=lambda v: v == "ok") == "failed"
        assert len(calls) == 2
        assert "k" not in cache

    def test_cache_if_true_is_stored(self):
        cache = ScanCache()
        calls = []
        compute = lambda: calls.append(1) or "ok"   # noqa: E731
        for _ in range(2):
            cache.get_or_compute("k", compute, cache_if=lambda v: v == "ok")
        assert len(calls) == 1

    def test_cached_value_peeks_without_computing(self):
        assert cached_value("k", "default") == "default"          # outside a scan
        cache = ScanCache()
        assert in_scan(cache, cached_value, "k") is None
        in_scan(cache, cached, "k", lambda: 7)
        assert in_scan(cache, cached_value, "k") == 7

    def test_cached_passes_cache_if(self):
        cache = ScanCache()
        in_scan(cache, cached, "k", lambda: "bad", cache_if=lambda v: False)
        assert "k" not in cache


# ---------------------------------------------------------------------------
# DNS resolution reuse
# ---------------------------------------------------------------------------

GAI = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0)),
       (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
       (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("10.0.0.2", 0))]


class TestResolutionIsRecorded:
    @patch("netdiag.core.dns.socket.getaddrinfo", return_value=GAI)
    def test_dns_step_records_the_os_preferred_address(self, _gai):
        from netdiag.core.dns import resolve_hostname
        cache = ScanCache()
        result = in_scan(cache, resolve_hostname, "example.com")
        # Result is unchanged: sorted unique addresses.
        assert result.status == Status.PASS
        assert result.evidence == "Resolved to: 10.0.0.1, 10.0.0.2"
        # The first getaddrinfo answer (OS preference), not the sorted minimum, is reused.
        assert in_scan(cache, connect_host, "example.com") == "10.0.0.2"

    @patch("netdiag.core.dns.socket.getaddrinfo", return_value=GAI)
    def test_outside_a_scan_nothing_is_recorded(self, _gai):
        from netdiag.core.dns import resolve_hostname
        resolve_hostname("example.com")
        assert connect_host("example.com") == "example.com"

    @patch("netdiag.core.dns.socket.getaddrinfo", side_effect=socket.gaierror("no such host"))
    def test_failed_resolution_records_nothing(self, _gai):
        from netdiag.core.dns import resolve_hostname
        cache = ScanCache()
        assert in_scan(cache, resolve_hostname, "nope.invalid").status == Status.FAIL
        assert in_scan(cache, connect_host, "nope.invalid") == "nope.invalid"


# ---------------------------------------------------------------------------
# Socket checks connect to the resolved address; labels keep the hostname
# ---------------------------------------------------------------------------

@pytest.fixture
def listening_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    yield server.getsockname()[1]
    server.close()


class TestSocketChecksReuseResolution:
    def test_tcp_connect_uses_resolved_address_and_keeps_label(self, listening_port):
        from netdiag.core.tcp import tcp_connect
        cache = scan_with(UNRESOLVABLE, "127.0.0.1")
        result = in_scan(cache, tcp_connect, UNRESOLVABLE, listening_port, timeout_seconds=2)
        assert result.status == Status.PASS
        assert result.target == f"{UNRESOLVABLE}:{listening_port}"
        assert "127.0.0.1" not in result.evidence

    def test_tcp_connect_outside_a_scan_still_resolves_the_name(self, listening_port):
        from netdiag.core.tcp import tcp_connect
        result = tcp_connect(UNRESOLVABLE, listening_port, timeout_seconds=2)
        assert result.status == Status.ERROR
        assert result.error == "socket.gaierror"

    def test_tcp_multi_port_pool_threads_see_the_scan(self, listening_port):
        from netdiag.core.tcp import tcp_multi_port
        cache = scan_with(UNRESOLVABLE, "127.0.0.1")
        results = in_scan(cache, tcp_multi_port, UNRESOLVABLE, [listening_port, listening_port],
                          timeout_seconds=2)
        assert [r.status for r in results] == [Status.PASS, Status.PASS]
        assert {r.target for r in results} == {f"{UNRESOLVABLE}:{listening_port}"}

    def test_port_scan_pool_threads_see_the_scan(self, listening_port):
        from netdiag.network.discovery import port_scan
        cache = scan_with(UNRESOLVABLE, "127.0.0.1")
        result = in_scan(cache, port_scan, UNRESOLVABLE, ports=[listening_port], timeout_seconds=2)
        assert result.target == UNRESOLVABLE
        assert result.details["open_ports"] == [{"port": listening_port, "service": "unknown"}]

    def test_exposure_pool_threads_see_the_scan(self, listening_port):
        from netdiag.security.exposure import check_tcp_exposure
        cache = scan_with(UNRESOLVABLE, "127.0.0.1")
        findings = in_scan(cache, check_tcp_exposure, UNRESOLVABLE, ports=[listening_port], timeout_seconds=2)
        assert findings[0].status == SecurityStatus.OBSERVATION
        assert f"{UNRESOLVABLE}:{listening_port}" in findings[0].evidence
        assert "127.0.0.1" not in findings[0].evidence + findings[0].description

    def test_port_scan_and_exposure_unchanged_outside_a_scan(self, listening_port):
        from netdiag.network.discovery import port_scan
        from netdiag.security.exposure import check_tcp_exposure
        assert port_scan(UNRESOLVABLE, ports=[listening_port], timeout_seconds=2).details["open_ports"] == []
        assert check_tcp_exposure(UNRESOLVABLE, ports=[listening_port], timeout_seconds=2)[0].status \
            == SecurityStatus.PASS


# ---------------------------------------------------------------------------
# TLS: resolved address for the connection, hostname for SNI and verification
# ---------------------------------------------------------------------------

class TestTLSHostnameSemantics:
    def test_verification_uses_hostname_while_connecting_to_resolved_ip(self, ca_signed_server):
        from netdiag.security.tls import check_certificate_hostname
        cache = scan_with("localhost", "127.0.0.1")
        findings = in_scan(cache, check_certificate_hostname, "localhost", ca_signed_server.port, timeout=5)
        assert findings[0].status == SecurityStatus.PASS
        assert ca_signed_server.sni_names == ["localhost"]

    def test_mismatch_is_judged_against_the_hostname_not_the_ip(self, ca_signed_server):
        """The cert is for 'localhost'. Connecting to 127.0.0.1 for another name must be a mismatch."""
        from netdiag.security.tls import check_certificate_hostname
        cache = scan_with(UNRESOLVABLE, "127.0.0.1")
        findings = in_scan(cache, check_certificate_hostname, UNRESOLVABLE, ca_signed_server.port, timeout=5)
        assert findings[0].status == SecurityStatus.FAIL
        assert findings[0].title == "TLS Certificate Hostname Mismatch"
        assert ca_signed_server.sni_names == [UNRESOLVABLE]   # SNI carried the hostname

    def test_every_tls_connection_sends_the_hostname_as_sni(self, ca_signed_server):
        from netdiag.security.tls import check_certificate_expiry, check_tls_protocol_versions
        cache = scan_with(UNRESOLVABLE, "127.0.0.1")
        in_scan(cache, check_certificate_expiry, UNRESOLVABLE, ca_signed_server.port, timeout=5)
        in_scan(cache, check_tls_protocol_versions, UNRESOLVABLE, ca_signed_server.port, timeout=5)
        assert ca_signed_server.sni_names
        assert set(ca_signed_server.sni_names) == {UNRESOLVABLE}

    def test_messages_keep_the_hostname(self, ca_signed_server):
        from netdiag.security.tls import check_certificate_expiry, check_tls_protocol_versions
        cache = scan_with(UNRESOLVABLE, "127.0.0.1")
        findings = in_scan(cache, check_certificate_expiry, UNRESOLVABLE, ca_signed_server.port, timeout=5)
        findings += in_scan(cache, check_tls_protocol_versions, UNRESOLVABLE, ca_signed_server.port, timeout=5)
        text = " ".join(f.title + f.description + f.evidence + f.recommendation for f in findings)
        assert "127.0.0.1" not in text
        assert findings[0].status == SecurityStatus.PASS   # certificate retrieved via the resolved IP

    def test_outside_a_scan_tls_connects_to_the_hostname(self):
        from netdiag.security import tls
        with patch.object(tls.socket, "create_connection", side_effect=OSError("refused")) as mock_conn:
            tls.check_certificate_expiry("example.com", 443, timeout=1)
            tls.check_certificate_hostname("example.com", 443, timeout=1)
            tls._test_tls_version("example.com", 443, "TLSv1.2", ssl.TLSVersion.TLSv1_2, timeout=1)
            tls._probe_tls_service("example.com", 443, timeout=1)
        assert mock_conn.call_args_list
        assert {c.args[0] for c in mock_conn.call_args_list} == {("example.com", 443)}


# ---------------------------------------------------------------------------
# TLS: one certificate handshake per scan, identical findings
# ---------------------------------------------------------------------------

def _audit(port: int, host: str = "localhost"):
    from netdiag.security.tls import (
        check_certificate_expiry,
        check_certificate_hostname,
        check_tls_protocol_versions,
    )
    return [
        (check_certificate_expiry, (host, port), {"timeout": 5}),
        (check_tls_protocol_versions, (host, port), {"timeout": 5}),
        (check_certificate_hostname, (host, port), {"timeout": 5}),
    ]


def _run_audit(server, cache: ScanCache | None):
    # 127.0.0.1 rather than "localhost": on Windows "localhost" tries ::1 first and each
    # refused IPv6 attempt costs ~2 s. Counts and parity do not depend on the name.
    server.reset_counts()
    findings = []
    for func, args, kwargs in _audit(server.port, host="127.0.0.1"):
        findings += func(*args, **kwargs) if cache is None else in_scan(cache, func, *args, **kwargs)
    return findings, server.connections


class TestTLSHandshakeReuse:
    def test_scan_saves_two_handshakes_with_identical_findings(self, ca_signed_server):
        direct, direct_connections = _run_audit(ca_signed_server, cache=None)
        scanned, scan_connections = _run_audit(ca_signed_server, cache=ScanCache())
        assert _comparable(scanned) == _comparable(direct)
        # The TLS-service probe and the TLSv1.3 version test reuse the certificate handshake.
        assert scan_connections == direct_connections - 2

    def test_self_signed_branch_reuses_the_certificate(self, self_signed_server):
        direct, direct_connections = _run_audit(self_signed_server, cache=None)
        scanned, scan_connections = _run_audit(self_signed_server, cache=ScanCache())
        assert _comparable(scanned) == _comparable(direct)
        hostname = [f for f in scanned if f.test_name == "tls_cert_hostname"][0]
        assert hostname.title == "Self-Signed TLS Certificate (Cryptographically Verified)"
        # Probe + TLSv1.3 test + the self-signed branch's second certificate handshake.
        assert scan_connections == direct_connections - 3

    def test_certificate_fetched_once_per_scan(self):
        from netdiag.security import tls
        ok = (MagicMock(days_until_expiry=90, not_after="x"), "TLSv1.3", "OK", None)
        with patch.object(tls, "_fetch_certificate", return_value=ok) as fetch:
            cache = ScanCache()
            for _ in range(3):
                in_scan(cache, tls._retrieve_certificate, "Example.com", 443)
            in_scan(cache, tls._retrieve_certificate, "example.com", 8443)   # different port
        assert fetch.call_count == 2

    def test_connection_failures_are_retried_not_cached(self):
        from netdiag.security import tls
        failed = (None, None, "CONNECTION_FAILED", "refused")
        with patch.object(tls, "_fetch_certificate", return_value=failed) as fetch:
            cache = ScanCache()
            in_scan(cache, tls._retrieve_certificate, "example.com", 443)
            in_scan(cache, tls._retrieve_certificate, "example.com", 443)
        assert fetch.call_count == 2

    def test_outside_a_scan_every_call_performs_a_handshake(self):
        from netdiag.security import tls
        ok = (MagicMock(), "TLSv1.3", "OK", None)
        with patch.object(tls, "_fetch_certificate", return_value=ok) as fetch:
            tls._retrieve_certificate("example.com", 443)
            tls._retrieve_certificate("example.com", 443)
        assert fetch.call_count == 2

    @pytest.mark.parametrize("negotiated", ["TLSv1", "TLSv1.1", None])
    def test_probe_reuses_only_tls12_or_tls13(self, negotiated):
        from netdiag.security import tls
        cache = ScanCache()
        cache.set(tls._handshake_cache_key("example.com", 443), (MagicMock(), negotiated, "OK", None))
        with patch.object(tls.socket, "create_connection", side_effect=OSError("refused")) as mock_conn:
            is_tls, _ = in_scan(cache, tls._probe_tls_service, "example.com", 443, timeout=1)
        assert is_tls is False
        assert mock_conn.called   # probed the network itself

    def test_version_test_reuses_only_the_negotiated_version(self):
        from netdiag.security import tls
        cache = ScanCache()
        cache.set(tls._handshake_cache_key("example.com", 443), (MagicMock(), "TLSv1.3", "OK", None))
        with patch.object(tls.socket, "create_connection", side_effect=OSError("refused")) as mock_conn:
            v13 = in_scan(cache, tls._test_tls_version, "example.com", 443, "TLSv1.3",
                          ssl.TLSVersion.TLSv1_3, timeout=1)
            assert not mock_conn.called
            v12 = in_scan(cache, tls._test_tls_version, "example.com", 443, "TLSv1.2",
                          ssl.TLSVersion.TLSv1_2, timeout=1)
        assert v13 == (tls.TLSProtocolStatus.SUPPORTED, "Negotiated TLSv1.3 with example.com:443")
        assert v12[0] == tls.TLSProtocolStatus.UNAVAILABLE
        assert mock_conn.call_count == 1


# ---------------------------------------------------------------------------
# HTTPS checks keep hostname-based behavior (urllib is not pinned)
# ---------------------------------------------------------------------------

class TestHTTPSUnchanged:
    def _capture_urls(self, func, *args):
        seen = []

        def fake_urlopen(req, *a, **kw):
            seen.append(req.full_url)
            raise OSError("stop here")

        cache = scan_with("example.com", "93.184.216.34")
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            in_scan(cache, func, *args)
        return seen

    def test_https_connectivity_uses_the_hostname_url(self):
        from netdiag.core.https import https_connectivity
        assert self._capture_urls(https_connectivity, "example.com") == ["https://example.com:443/"]

    def test_http_security_headers_use_the_hostname_url(self):
        from netdiag.security.http_security import check_http_security_headers
        assert self._capture_urls(check_http_security_headers, "example.com") == ["https://example.com:443/"]
