# Copyright (c) 2026 Iyad Engle. All rights reserved.

import pytest
from netdiag.core.tcp import tcp_connect
from netdiag.utils.models import Status


class TestTCPUnit:
    def test_closed_port_fails(self):
        result = tcp_connect("127.0.0.1", 1, timeout_seconds=2)
        assert result.status in (Status.FAIL, Status.ERROR)


@pytest.mark.integration
class TestTCPIntegration:
    def test_connect_dns_google(self):
        result = tcp_connect("dns.google", 443, timeout_seconds=5)
        assert result.status == Status.PASS
