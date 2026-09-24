# Copyright (c) 2026 Iyad Engle. All rights reserved.

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest
from click.testing import CliRunner

import netdiag
from netdiag.cli.main import cli, exit_code_for
from netdiag.utils.models import (
    Confidence,
    DiagnosticResult,
    ScanReport,
    SecurityFinding,
    SecurityStatus,
    Severity,
    Status,
)

# `netdiag.cli` re-exports the `main` function, which shadows the `netdiag.cli.main`
# module for attribute lookups (and for patch("netdiag.cli.main.x") on Python 3.10).
cli_module = importlib.import_module("netdiag.cli.main")


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
        import importlib
        import inspect

        cli_main = importlib.import_module("netdiag.cli.main")  # the package re-exports main()
        source = inspect.getsource(cli_main)
        assert "netdiag.gui" not in source


def _report(diag: Status | None = None, security: SecurityStatus | None = None) -> ScanReport:
    report = ScanReport(target="example.com")
    if diag is not None:
        report.results.append(DiagnosticResult(
            test_name="icmp_ping", target="example.com", status=diag, evidence="e", duration_ms=1))
    if security is not None:
        report.findings.append(SecurityFinding(
            test_name="tls_cert_expiry", status=security, severity=Severity.HIGH, title="t",
            description="d", evidence="e", recommendation="r", confidence=Confidence.CONFIRMED))
    return report


class TestTargetValidation:
    @pytest.mark.parametrize("command", ["diagnose", "security", "full", "dns", "mtu", "tcp",
                                         "trace", "scan", "report"])
    def test_leading_dash_target_rejected(self, command):
        result = CliRunner().invoke(cli, [command, "--target=-oEvil"])
        assert result.exit_code == 2
        assert "must not begin with '-'" in result.output

    def test_url_target_rejected(self):
        result = CliRunner().invoke(cli, ["tcp", "--target", "https://example.com"])
        assert result.exit_code == 2

    def test_target_is_normalized(self):
        with patch("netdiag.core.tcp.tcp_multi_port", return_value=[]) as mock_tcp:
            CliRunner().invoke(cli, ["tcp", "--target", " example.com "])
        assert mock_tcp.call_args.args[0] == "example.com"


class TestExitCodes:
    @pytest.mark.parametrize("report,expected", [
        (_report(), 0),
        (_report(Status.PASS, SecurityStatus.PASS), 0),
        (_report(Status.WARN, SecurityStatus.OBSERVATION), 0),
        (_report(Status.SKIP, SecurityStatus.INCONCLUSIVE), 0),
        (_report(Status.FAIL), 1),
        (_report(Status.ERROR), 1),
        (_report(security=SecurityStatus.FAIL), 4),
        (_report(Status.FAIL, SecurityStatus.FAIL), 5),
    ])
    def test_exit_code_for(self, report, expected):
        assert exit_code_for(report) == expected

    @pytest.mark.parametrize("diag,expected", [(Status.PASS, 0), (Status.WARN, 0), (Status.FAIL, 1)])
    def test_diagnose_command_exit_code(self, diag, expected):
        with patch.object(cli_module, "_run_diagnostics", return_value=_report(diag)):
            result = CliRunner().invoke(cli, ["diagnose", "-t", "example.com"])
        assert result.exit_code == expected

    def test_full_command_combines_flags(self):
        with patch.object(cli_module, "_run_diagnostics", return_value=_report(Status.ERROR)), \
             patch.object(cli_module, "_run_security_audit", return_value=_report(security=SecurityStatus.FAIL)):
            result = CliRunner().invoke(cli, ["full", "-t", "example.com", "-r", "json"])
        assert result.exit_code == 5

    def test_json_output_still_printed_on_failure(self):
        with patch.object(cli_module, "_run_diagnostics", return_value=_report(Status.FAIL)):
            result = CliRunner().invoke(cli, ["diagnose", "-t", "example.com", "-r", "json"])
        assert result.exit_code == 1
        assert '"target": "example.com"' in result.output
