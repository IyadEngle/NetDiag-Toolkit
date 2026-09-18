# Copyright (c) 2026 Iyad Engle. All rights reserved.

from unittest.mock import patch, MagicMock

from netdiag.network.discovery import port_scan
from netdiag.utils.models import Status


class TestPortScan:
    @patch('netdiag.network.discovery.socket.socket')
    def test_port_states(self, mock_cls):
        responses = {80: 0, 443: 10061, 22: 10060}

        def side_effect(addr):
            return responses.get(addr[1], 10061)

        mock_cls.return_value = MagicMock()
        mock_cls.return_value.connect_ex.side_effect = side_effect

        result = port_scan("127.0.0.1", ports=[22, 80, 443])
        assert result.status == Status.PASS
        assert len(result.details["open_ports"]) == 1
