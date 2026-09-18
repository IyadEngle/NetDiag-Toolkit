# Copyright (c) 2026 Iyad Engle. All rights reserved.

import netdiag
from click.testing import CliRunner
from netdiag.cli.main import cli


class TestCLI:
    def test_help(self):
        assert CliRunner().invoke(cli, ["--help"]).exit_code == 0

    def test_version(self):
        result = CliRunner().invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert netdiag.__version__ in result.output

    def test_diagnose_requires_target(self):
        assert CliRunner().invoke(cli, ["diagnose"]).exit_code != 0

    def test_security_requires_target(self):
        assert CliRunner().invoke(cli, ["security"]).exit_code != 0

    def test_cli_does_not_import_gui(self):
        """The CLI must work without PySide6: its module must not reference netdiag.gui."""
        import inspect
        from netdiag.cli import main as cli_main
        source = inspect.getsource(cli_main)
        assert "netdiag.gui" not in source
