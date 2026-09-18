# Copyright (c) 2026 Iyad Engle. All rights reserved.

from unittest.mock import patch

from netdiag.network.wifi import wifi_info
from netdiag.utils.models import Status


class TestWiFi:
    @patch('netdiag.network.wifi.platform.system', return_value="Linux")
    def test_linux_returns_skip(self, mock_os):
        assert wifi_info().status == Status.SKIP

    @patch('netdiag.network.wifi.platform.system', return_value="Darwin")
    def test_macos_returns_skip(self, mock_os):
        assert wifi_info().status == Status.SKIP
