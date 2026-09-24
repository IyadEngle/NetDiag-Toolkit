# Copyright (c) 2026 Iyad Engle. All rights reserved.

from unittest.mock import MagicMock, patch

from netdiag.security.http_security import check_http_security_headers
from netdiag.utils.models import SecurityStatus, Severity


class TestHTTPSecurityHeaders:
    @patch('netdiag.security.http_security.urllib.request.urlopen')
    def test_missing_headers_are_observation(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        findings = check_http_security_headers("example.com")
        for f in findings:
            assert f.status == SecurityStatus.OBSERVATION
            assert f.severity in (Severity.INFO, Severity.LOW)

    @patch('netdiag.security.http_security.urllib.request.urlopen')
    def test_connection_failure_is_skip(self, mock_urlopen):
        mock_urlopen.side_effect = ConnectionRefusedError("refused")
        findings = check_http_security_headers("example.com")
        assert findings[0].status == SecurityStatus.SKIP

    @patch('netdiag.security.http_security.urllib.request.urlopen')
    def test_server_version_is_observation(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Server": "Apache/2.4.41",
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
        }
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        findings = check_http_security_headers("example.com")
        version_f = [f for f in findings if "Version" in f.title]
        assert version_f[0].status == SecurityStatus.OBSERVATION
