# Copyright (c) 2026 Iyad Engle. All rights reserved.

import pytest
from unittest.mock import patch

from netdiag.core.mtu import estimate_path_mtu
from netdiag.utils.models import Status


class TestMTUUnit:
    @patch('netdiag.core.mtu.platform.system', return_value="Darwin")
    def test_unsupported_returns_skip(self, mock_os):
        assert estimate_path_mtu("1.1.1.1").status == Status.SKIP


@pytest.mark.integration
class TestMTUIntegration:
    def test_mtu_1_1_1_1(self):
        result = estimate_path_mtu("1.1.1.1")
        assert result.status in (Status.PASS, Status.FAIL, Status.ERROR)
