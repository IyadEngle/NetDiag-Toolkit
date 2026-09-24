# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared target validation (netdiag.utils.validation), used by both CLI and GUI."""

import pytest

from netdiag.utils import validation
from netdiag.utils.validation import Target, TargetError, parse_target, validate_target


class TestSharedValidation:
    @pytest.mark.parametrize("target", ["-f", "-oProxyCommand=x", "--help", "-1.1.1.1", "  -evil.com"])
    def test_leading_dash_rejected(self, target):
        ok, message = validate_target(target)
        assert not ok
        assert "'-'" in message

    @pytest.mark.parametrize("target", ["example.com", "1.1.1.1", "my-host.example.com", "localhost"])
    def test_ordinary_targets_accepted(self, target):
        assert validate_target(target) == (True, target)

    def test_gui_module_reexports_shared_validator(self):
        from netdiag.gui import validation as gui_validation
        assert gui_validation.validate_target is validate_target

    def test_cli_uses_shared_validator(self):
        import importlib
        cli_main = importlib.import_module("netdiag.cli.main")  # the package re-exports main()
        assert cli_main.validate_target is validate_target


class TestInvalidIPv4:
    @pytest.mark.parametrize("target", ["1.2.3.999", "256.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1234"])
    def test_numeric_non_addresses_rejected(self, target):
        ok, message = validate_target(target)
        assert not ok
        assert "Invalid IPv4 address" in message

    def test_all_numeric_last_label_rejected(self):
        ok, message = validate_target("host.123")
        assert not ok
        assert "last label" in message

    @pytest.mark.parametrize("target", ["123.example.com", "1e100.net", "0.0.0.0", "255.255.255.255"])
    def test_numeric_leading_labels_and_edge_ips_accepted(self, target):
        assert validate_target(target) == (True, target)


class TestIPv6ReadyValidation:
    """IPv6 is recognised by the parser and rejected only by the current policy."""

    @pytest.mark.parametrize("raw,expected", [
        ("::1", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1%eth0"),
    ])
    def test_parser_classifies_ipv6(self, raw, expected):
        assert parse_target(raw) == Target(value=expected, kind="ipv6")

    def test_parser_classifies_ipv4_and_hostname(self):
        assert parse_target(" 1.1.1.1 ").kind == "ipv4"
        assert parse_target("example.com").kind == "hostname"

    def test_policy_rejects_ipv6_by_default(self):
        ok, message = validate_target("2001:db8::1")
        assert not ok
        assert "not supported yet" in message

    def test_ipv6_can_be_enabled_per_call(self):
        assert validate_target("[2001:db8::1]", allow_ipv6=True) == (True, "2001:db8::1")

    def test_ipv6_can_be_enabled_by_policy_flag(self, monkeypatch):
        monkeypatch.setattr(validation, "IPV6_TARGETS_SUPPORTED", True)
        assert validate_target("::1") == (True, "::1")

    @pytest.mark.parametrize("target", ["example.com:443", "1.2.3.4:80", "[example.com]", "::g"])
    def test_invalid_colon_and_bracket_forms_rejected_even_with_ipv6(self, target):
        assert not validate_target(target, allow_ipv6=True)[0]

    def test_parse_error_is_value_error(self):
        with pytest.raises(TargetError):
            parse_target("1.2.3.999")
        assert issubclass(TargetError, ValueError)
