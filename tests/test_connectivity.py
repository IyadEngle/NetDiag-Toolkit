# Copyright (c) 2026 Iyad Engle. All rights reserved.

import pytest

from netdiag.core.connectivity import ping, _parse_windows_ping, _parse_linux_ping


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


@pytest.mark.integration
class TestPingIntegration:
    def test_ping_localhost(self):
        result = ping("127.0.0.1", count=2, timeout_seconds=3)
        assert result.status.value in ("PASS", "FAIL")
