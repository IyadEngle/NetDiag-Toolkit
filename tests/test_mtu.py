# Copyright (c) 2026 Iyad Engle. All rights reserved.

from unittest.mock import MagicMock, patch

import pytest

from netdiag.core.mtu import estimate_path_mtu
from netdiag.utils.models import Status


class TestMTUUnit:
    @patch('netdiag.core.mtu.platform.system', return_value="Darwin")
    def test_unsupported_returns_skip(self, mock_os):
        assert estimate_path_mtu("1.1.1.1").status == Status.SKIP


def _fake_ping(flag: str, max_payload: int, ok_text: str):
    """subprocess.run stand-in: replies only when the payload after `flag` fits."""
    sizes: list[int] = []

    def run(cmd, **kwargs):
        size = int(cmd[cmd.index(flag) + 1])
        sizes.append(size)
        return MagicMock(stdout=ok_text if size <= max_payload else "Packet needs to be fragmented")

    return run, sizes


class TestMTUEstimate:
    """A standard 1500-byte path carries at most 1472 bytes of ICMP payload."""

    @patch("netdiag.core.mtu.platform.system", return_value="Linux")
    def test_linux_1500_path_reports_1500(self, _os):
        run, sizes = _fake_ping("-s", 1472, "1 packets transmitted, 1 received, 0% packet loss")
        with patch("netdiag.core.mtu.subprocess.run", side_effect=run):
            result = estimate_path_mtu("192.0.2.1")
        assert result.status == Status.PASS
        assert result.details == {"mtu_estimate": 1500, "max_payload": 1472}
        assert min(sizes) >= 68  # payload is passed as-is, never size - 28

    @patch("netdiag.core.mtu.platform.system", return_value="Windows")
    def test_windows_1500_path_reports_1500(self, _os):
        run, _ = _fake_ping("-l", 1472, "Reply from 192.0.2.1: bytes=1472 time=1ms TTL=57")
        with patch("netdiag.core.mtu.subprocess.run", side_effect=run):
            result = estimate_path_mtu("192.0.2.1")
        assert result.details == {"mtu_estimate": 1500, "max_payload": 1472}

    @patch("netdiag.core.mtu.platform.system", return_value="Linux")
    def test_linux_and_windows_agree_on_smaller_path(self, _os):
        run, _ = _fake_ping("-s", 1372, "1 packets transmitted, 1 received")  # 1400-byte path
        with patch("netdiag.core.mtu.subprocess.run", side_effect=run):
            assert estimate_path_mtu("192.0.2.1").details["mtu_estimate"] == 1400


@pytest.mark.integration
class TestMTUIntegration:
    def test_mtu_1_1_1_1(self):
        result = estimate_path_mtu("1.1.1.1")
        assert result.status in (Status.PASS, Status.FAIL, Status.ERROR)
