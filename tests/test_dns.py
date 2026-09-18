# Copyright (c) 2026 Iyad Engle. All rights reserved.

from netdiag.core.dns import resolve_hostname


class TestDNSResolution:
    def test_resolve_localhost(self):
        assert resolve_hostname("localhost").status.value == "PASS"

    def test_resolve_invalid(self):
        assert resolve_hostname("this-does-not-exist-12345.invalid").status.value == "FAIL"
