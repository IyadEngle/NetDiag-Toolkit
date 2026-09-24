# Copyright (c) 2026 Iyad Engle. All rights reserved.

import socket
from unittest.mock import patch

from netdiag.security.dns_security import (
    _find_zone_apex,
    _open_resolver_check_dnspython,
    _resolve_server_ip,
    check_dnssec,
    check_open_resolver,
)
from netdiag.utils.models import SecurityStatus, Severity


class TestDNSSEC:
    @patch('netdiag.security.dns_security._dnssec_check_dnspython')
    def test_not_detected_is_observation(self, mock_check):
        mock_check.return_value = ("NOT_DETECTED", "No DNSKEY")
        findings = check_dnssec("example.com")
        assert findings[0].status == SecurityStatus.OBSERVATION
        assert findings[0].severity == Severity.INFO

    @patch('netdiag.security.dns_security._dnssec_check_dnspython')
    def test_keys_detected_no_finding(self, mock_check):
        mock_check.return_value = ("KEYS_DETECTED", "Found 2 DNSKEY")
        assert len(check_dnssec("example.com")) == 0

    @patch('netdiag.security.dns_security._dnssec_check_dnspython')
    def test_inconclusive(self, mock_check):
        mock_check.return_value = ("INCONCLUSIVE", "SERVFAIL")
        findings = check_dnssec("example.com")
        assert findings[0].status == SecurityStatus.INCONCLUSIVE


class TestOpenResolver:
    @patch('netdiag.security.dns_security._open_resolver_check_dnspython')
    def test_recursive_accepted_is_fail(self, mock_check):
        mock_check.return_value = (True, "resolved")
        findings = check_open_resolver("8.8.8.8")
        assert findings[0].status == SecurityStatus.FAIL
        assert "from This Network Position" in findings[0].title

    @patch('netdiag.security.dns_security._open_resolver_check_dnspython')
    def test_not_open_no_finding(self, mock_check):
        mock_check.return_value = (False, "no response")
        assert len(check_open_resolver("8.8.8.8")) == 0


def _dnskey_by_name(results: dict):
    calls: list[str] = []

    def query(name, timeout=10):
        calls.append(name)
        return results[name]

    return query, calls


class TestDNSSECZoneApex:
    @patch("netdiag.security.dns_security._find_zone_apex", return_value="example.com")
    def test_subdomain_of_signed_zone_has_no_finding(self, _apex):
        query, calls = _dnskey_by_name({
            "www.example.com": ("NOT_DETECTED", "no DNSKEY for www.example.com"),
            "example.com": ("KEYS_DETECTED", "Found 2 DNSKEY record(s) for example.com"),
        })
        with patch("netdiag.security.dns_security._dnskey_query", side_effect=query):
            assert check_dnssec("www.example.com") == []
        assert calls == ["www.example.com", "example.com"]

    @patch("netdiag.security.dns_security._find_zone_apex", return_value="example.org")
    def test_subdomain_of_unsigned_zone_is_observation_naming_zone(self, _apex):
        query, _ = _dnskey_by_name({
            "api.example.org": ("NOT_DETECTED", "no DNSKEY"),
            "example.org": ("NOT_DETECTED", "NOERROR but no DNSKEY records for example.org"),
        })
        with patch("netdiag.security.dns_security._dnskey_query", side_effect=query):
            findings = check_dnssec("api.example.org")
        assert findings[0].status == SecurityStatus.OBSERVATION
        assert "zone example.org" in findings[0].evidence

    @patch("netdiag.security.dns_security._find_zone_apex", return_value="example.org")
    def test_apex_target_is_queried_once(self, _apex):
        query, calls = _dnskey_by_name({"example.org": ("NOT_DETECTED", "no DNSKEY")})
        with patch("netdiag.security.dns_security._dnskey_query", side_effect=query):
            findings = check_dnssec("example.org")
        assert calls == ["example.org"]
        assert findings[0].status == SecurityStatus.OBSERVATION

    @patch("netdiag.security.dns_security._find_zone_apex", return_value=None)
    def test_unknown_apex_is_inconclusive_not_observation(self, _apex):
        query, _ = _dnskey_by_name({"www.example.com": ("NOT_DETECTED", "no DNSKEY")})
        with patch("netdiag.security.dns_security._dnskey_query", side_effect=query):
            findings = check_dnssec("www.example.com")
        assert findings[0].status == SecurityStatus.INCONCLUSIVE

    @patch("netdiag.security.dns_security._find_zone_apex")
    def test_nxdomain_skips_apex_lookup(self, mock_apex):
        query, _ = _dnskey_by_name({"nope.invalid": ("INCONCLUSIVE", "NXDOMAIN")})
        with patch("netdiag.security.dns_security._dnskey_query", side_effect=query):
            findings = check_dnssec("nope.invalid")
        assert findings[0].status == SecurityStatus.INCONCLUSIVE
        mock_apex.assert_not_called()

    def test_find_zone_apex_ignores_root(self):
        import dns.name
        with patch("dns.resolver.zone_for_name", return_value=dns.name.root):
            assert _find_zone_apex("1.1.1.1") is None

    def test_find_zone_apex_returns_zone_text(self):
        import dns.name
        with patch("dns.resolver.zone_for_name", return_value=dns.name.from_text("example.com")):
            assert _find_zone_apex("www.example.com") == "example.com"


class TestOpenResolverHostname:
    def test_ip_is_used_directly(self):
        assert _resolve_server_ip("192.0.2.53") == "192.0.2.53"

    @patch("netdiag.security.dns_security.socket.getaddrinfo")
    def test_hostname_is_resolved(self, mock_gai):
        mock_gai.return_value = [(2, 2, 17, "", ("192.0.2.53", 53))]
        assert _resolve_server_ip("ns.example.test") == "192.0.2.53"

    @patch("netdiag.security.dns_security.socket.getaddrinfo", side_effect=socket.gaierror("nope"))
    def test_unresolvable_hostname(self, _gai):
        assert _resolve_server_ip("nope.invalid") is None
        accepted, evidence = _open_resolver_check_dnspython("nope.invalid")
        assert accepted is None
        assert "Could not resolve" in evidence

    @patch("netdiag.security.dns_security._resolve_server_ip", return_value="192.0.2.53")
    def test_hostname_target_queries_resolved_ip(self, _resolve):
        with patch("dns.resolver.Resolver") as mock_resolver_cls:
            resolver = mock_resolver_cls.return_value
            resolver.resolve.return_value = ["93.184.216.34"]
            accepted, evidence = _open_resolver_check_dnspython("ns.example.test")
        assert resolver.nameservers == ["192.0.2.53"]
        assert accepted is True
        assert "ns.example.test (192.0.2.53)" in evidence
