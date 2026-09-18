# Copyright (c) 2026 Iyad Engle. All rights reserved.

import ssl
from unittest.mock import patch

import pytest

from netdiag.security.tls import (
    TLSProtocolStatus,
    _classify_ssl_error_for_protocol,
    check_certificate_expiry,
    CertificateInfo,
)
from netdiag.utils.models import SecurityStatus, Severity, Confidence


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
