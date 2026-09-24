# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import MagicMock, patch

from netdiag.security.exposure import check_tcp_exposure
from netdiag.utils.models import SecurityStatus, Severity


class TestTCPExposure:
    @patch('netdiag.security.exposure.socket.socket')
    def test_open_ports_are_observation(self, mock_cls):
        mock_cls.return_value = MagicMock()
        mock_cls.return_value.connect_ex.return_value = 0
        findings = check_tcp_exposure("192.168.1.1", ports=[22, 80, 6379, 27017])
        for f in findings:
            assert f.status == SecurityStatus.OBSERVATION
            assert f.severity == Severity.INFO

    @patch('netdiag.security.exposure.socket.socket')
    def test_no_open_ports_is_pass(self, mock_cls):
        mock_cls.return_value = MagicMock()
        mock_cls.return_value.connect_ex.return_value = 10061
        findings = check_tcp_exposure("192.168.1.1", ports=[80, 443])
        assert findings[0].status == SecurityStatus.PASS
