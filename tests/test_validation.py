# Copyright (c) 2026 Iyad Engle. All rights reserved.

"""Shared target validation (netdiag.utils.validation), used by both CLI and GUI."""

import pytest

from netdiag.utils.validation import validate_target


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
