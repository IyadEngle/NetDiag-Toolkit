# Copyright (c) 2026 Iyad Engle. All rights reserved.

from unittest.mock import MagicMock, patch

import pytest

from netdiag.network.wifi import wifi_info
from netdiag.utils.models import Status


class TestWiFi:
    @patch('netdiag.network.wifi.platform.system', return_value="Linux")
    def test_linux_returns_skip(self, mock_os):
        assert wifi_info().status == Status.SKIP

    @patch('netdiag.network.wifi.platform.system', return_value="Darwin")
    def test_macos_returns_skip(self, mock_os):
        assert wifi_info().status == Status.SKIP


CONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Channel                : 36
    Signal                 : 87%
"""
DISCONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : disconnected
    Radio status           : Hardware On
                             Software Off
"""
ASSOCIATING = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : associating
    SSID                   : HomeNet
"""
NO_INTERFACE = "There is no wireless interface on the system.\n"
WLANSVC_STOPPED = "The Wireless AutoConfig Service (wlansvc) is not running.\n"


def _wifi(stdout: str, returncode: int = 0, stderr: str = ""):
    proc = MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)
    with patch("netdiag.network.wifi.platform.system", return_value="Windows"), \
         patch("netdiag.network.wifi.process.run", return_value=proc):
        return wifi_info()


class TestWindowsWiFiStatus:
    def test_connected_is_pass(self):
        result = _wifi(CONNECTED)
        assert result.status == Status.PASS
        assert result.details["ssid"] == "HomeNet"
        assert result.details["availability"] == "connected"

    @pytest.mark.parametrize("stdout,returncode", [(NO_INTERFACE, 1), (NO_INTERFACE, 0), (WLANSVC_STOPPED, 1)])
    def test_no_wireless_subsystem_is_not_applicable(self, stdout, returncode):
        result = _wifi(stdout, returncode)
        assert result.status == Status.SKIP
        assert result.details["availability"] == "no_wireless_interface"

    def test_adapter_present_but_disconnected_is_not_applicable(self):
        # e.g. a laptop on Ethernet with Wi-Fi switched off
        result = _wifi(DISCONNECTED)
        assert result.status == Status.SKIP
        assert result.details["availability"] == "not_connected"

    def test_transitional_state_is_warn(self):
        result = _wifi(ASSOCIATING)
        assert result.status == Status.WARN
        assert result.details["availability"] == "transitional"

    def test_unreadable_output_is_warn_not_fail(self):
        # e.g. localized netsh output the parser does not understand
        result = _wifi("Es gibt 1 Schnittstelle auf dem System:\n    Status : Verbunden\n")
        assert result.status == Status.WARN

    def test_unknown_netsh_failure_is_skip(self):
        assert _wifi("", returncode=1).status == Status.SKIP

    def test_netsh_missing_is_skip(self):
        with patch("netdiag.network.wifi.platform.system", return_value="Windows"), \
             patch("netdiag.network.wifi.process.run", side_effect=FileNotFoundError):
            assert wifi_info().status == Status.SKIP

    def test_unexpected_error_is_error(self):
        with patch("netdiag.network.wifi.platform.system", return_value="Windows"), \
             patch("netdiag.network.wifi.process.run", side_effect=PermissionError("denied")):
            result = wifi_info()
        assert result.status == Status.ERROR

    def test_never_fail(self):
        for stdout in (CONNECTED, DISCONNECTED, ASSOCIATING, NO_INTERFACE, WLANSVC_STOPPED, ""):
            for code in (0, 1):
                assert _wifi(stdout, code).status != Status.FAIL
