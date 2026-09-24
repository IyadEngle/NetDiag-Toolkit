# Copyright (c) 2026 Iyad Engle. All rights reserved.

import socket
from unittest.mock import patch

import pytest

from netdiag.core.tcp import tcp_connect
from netdiag.network.discovery import port_scan
from netdiag.security.exposure import check_tcp_exposure
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


class TestSocketCleanup:
    """Sockets must be closed even when connect_ex raises."""

    @patch("netdiag.core.tcp.socket.socket")
    def test_tcp_connect_closes_on_dns_failure(self, mock_cls):
        mock_cls.return_value.connect_ex.side_effect = socket.gaierror("no such host")
        result = tcp_connect("nope.invalid", 443)
        assert result.status == Status.ERROR
        mock_cls.return_value.close.assert_called_once()

    @patch("netdiag.network.discovery.socket.socket")
    def test_port_scan_closes_on_error(self, mock_cls):
        mock_cls.return_value.connect_ex.side_effect = OSError("boom")
        port_scan("192.0.2.1", ports=[22, 80])
        assert mock_cls.return_value.close.call_count == 2

    @patch("netdiag.security.exposure.socket.socket")
    def test_exposure_closes_on_error(self, mock_cls):
        mock_cls.return_value.connect_ex.side_effect = OSError("boom")
        check_tcp_exposure("192.0.2.1", ports=[22, 80, 443])
        assert mock_cls.return_value.close.call_count == 3
