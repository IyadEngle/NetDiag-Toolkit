# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

import ipaddress
from unittest.mock import MagicMock, patch

import pytest

from netdiag.core.gateway import gateway_diagnostics, get_default_gateway
from netdiag.utils.models import Status


class TestGatewayUnit:
    @patch('netdiag.core.gateway.platform.system', return_value="Windows")
    @patch('netdiag.core.gateway.process.run')
    def test_windows_gateway(self, mock_run, mock_os):
        mock_run.return_value = MagicMock(
            stdout="Network Destination        Netmask          Gateway\n          0.0.0.0          0.0.0.0     192.168.1.1"
        )
        gateway = get_default_gateway()
        assert gateway == "192.168.1.1"
        assert ipaddress.ip_address(gateway).version == 4

    @patch('netdiag.core.gateway.get_default_gateway', return_value=None)
    def test_no_gateway_returns_fail(self, mock_gw):
        results = gateway_diagnostics()
        assert results[0].status == Status.FAIL


@pytest.mark.integration
class TestGatewayIntegration:
    def test_gateway_detection(self):
        gateway = get_default_gateway()
        if gateway is not None:
            addr = ipaddress.ip_address(gateway)
            assert addr.version == 4
            assert not addr.is_loopback
