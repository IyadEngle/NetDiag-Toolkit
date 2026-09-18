# Copyright (c) 2026 Iyad Engle. All rights reserved.

from click.testing import CliRunner
from netdiag.cli.main import cli


class TestCLI:
    def test_help(self):
        assert CliRunner().invoke(cli, ["--help"]).exit_code == 0

    def test_version(self):
        result = CliRunner().invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.3.0" in result.output

    def test_diagnose_requires_target(self):
        assert CliRunner().invoke(cli, ["diagnose"]).exit_code != 0

    def test_security_requires_target(self):
        assert CliRunner().invoke(cli, ["security"]).exit_code != 0
