# Copyright (c) 2026 Iyad Engle. All rights reserved.

import pytest

from netdiag.network.adapters import adapter_info
from netdiag.utils.models import Status


@pytest.mark.integration
class TestAdaptersIntegration:
    def test_adapter_info(self):
        result = adapter_info()
        assert result.status in (Status.PASS, Status.FAIL)
