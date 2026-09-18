# Copyright (c) 2026 Iyad Engle. All rights reserved.

from unittest.mock import patch

from netdiag.security.dns_security import check_dnssec, check_open_resolver
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
