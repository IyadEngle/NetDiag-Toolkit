# Copyright (c) 2026 Iyad Engle. All rights reserved.

from unittest.mock import MagicMock, patch

import pytest

from netdiag.core.connectivity import _parse_linux_ping, _parse_windows_ping, ping
from netdiag.utils.models import Status


class TestPingParsing:
    def test_windows_success(self):
        output = "Reply from 1.1.1.1: bytes=32 time=10ms TTL=57\nReply from 1.1.1.1: bytes=32 time=12ms TTL=57\n\nPackets: Sent = 2, Received = 2, Lost = 0 (0% loss)"
        r = _parse_windows_ping(output)
        assert r.sent == 2 and r.received == 2 and r.loss_percent == 0.0

    def test_windows_partial_loss(self):
        output = "Reply from 1.1.1.1: bytes=32 time=10ms TTL=57\nRequest timed out.\n\nPackets: Sent = 2, Received = 1, Lost = 1 (50% loss)"
        r = _parse_windows_ping(output)
        assert r.sent == 2 and r.received == 1 and r.loss_percent == 50.0

    def test_linux_success(self):
        output = "2 packets transmitted, 2 received, 0% packet loss\nrtt min/avg/max/mdev = 10.200/10.350/10.500/0.150 ms"
        r = _parse_linux_ping(output)
        assert r.sent == 2 and r.received == 2 and r.avg_ms == 10.35


def _linux_ping_output(sent: int, received: int) -> str:
    loss = round((sent - received) / sent * 100)
    out = f"{sent} packets transmitted, {received} received, {loss}% packet loss\n"
    if received:
        out += "rtt min/avg/max/mdev = 10.0/11.0/12.0/0.5 ms\n"
    return out


class TestWindowsUnreachable:
    UNREACHABLE = (
        "Pinging 192.168.1.50 with 32 bytes of data:\n"
        "Reply from 192.168.1.10: Destination host unreachable.\n"
        "Reply from 192.168.1.10: Destination host unreachable.\n"
        "Reply from 192.168.1.10: Destination host unreachable.\n"
        "Reply from 192.168.1.10: Destination host unreachable.\n\n"
        "Ping statistics for 192.168.1.50:\n"
        "    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n"
    )

    def test_unreachable_replies_are_not_received(self):
        r = _parse_windows_ping(self.UNREACHABLE)
        assert r.sent == 4 and r.received == 0 and r.lost == 4 and r.loss_percent == 100.0

    def test_mixed_echo_and_unreachable(self):
        output = (
            "Reply from 192.168.1.50: bytes=32 time=3ms TTL=64\n"
            "Reply from 192.168.1.10: Destination host unreachable.\n"
            "Request timed out.\n"
            "Reply from 192.168.1.50: bytes=32 time<1ms TTL=64\n\n"
            "    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),\n"
        )
        r = _parse_windows_ping(output)
        assert r.received == 2 and r.lost == 2 and r.loss_percent == 50.0

    def test_ttl_expired_is_not_a_reply(self):
        output = (
            "Reply from 10.0.0.1: TTL expired in transit.\n\n"
            "    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\n"
        )
        assert _parse_windows_ping(output).received == 0

    @patch("netdiag.core.connectivity.platform.system", return_value="Windows")
    def test_ping_status_is_fail(self, _os):
        with patch("netdiag.core.connectivity.subprocess.run",
                   return_value=MagicMock(stdout=self.UNREACHABLE, stderr="")):
            assert ping("192.168.1.50").status == Status.FAIL


@patch("netdiag.core.connectivity.platform.system", return_value="Linux")
class TestPingStatus:
    def _ping(self, output: str):
        with patch("netdiag.core.connectivity.subprocess.run",
                   return_value=MagicMock(stdout=output, stderr="")):
            return ping("192.0.2.1", count=4)

    def test_no_loss_is_pass(self, _os):
        assert self._ping(_linux_ping_output(4, 4)).status == Status.PASS

    def test_partial_loss_is_warn(self, _os):
        result = self._ping(_linux_ping_output(4, 1))
        assert result.status == Status.WARN
        assert result.details["loss_percent"] == 75.0

    def test_total_loss_is_fail(self, _os):
        assert self._ping(_linux_ping_output(4, 0)).status == Status.FAIL


@pytest.mark.integration
class TestPingIntegration:
    def test_ping_localhost(self):
        result = ping("127.0.0.1", count=2, timeout_seconds=3)
        assert result.status.value in ("PASS", "WARN", "FAIL")
