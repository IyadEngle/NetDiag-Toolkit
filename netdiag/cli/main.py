# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""NetDiag-Toolkit CLI."""

from __future__ import annotations

import re
import sys
import time

import click

from netdiag import __version__
from netdiag.cli.progress import ProgressLine, stream_is_interactive
from netdiag.runner import ScanPlan, ScanRunner, StepState
from netdiag.runner import plans as scan_plans
from netdiag.utils.logging import setup_logging
from netdiag.utils.models import ScanReport
from netdiag.utils.validation import validate_target

logger = setup_logging()

# Exit codes are bit flags so scripts can test each condition independently.
# 2 is left to Click, which uses it for usage errors (missing/invalid options).
EXIT_OK = 0
EXIT_DIAGNOSTIC_FAILURE = 1   # at least one diagnostic returned FAIL or ERROR
EXIT_SECURITY_FAILURE = 4     # at least one security finding has status FAIL
EXIT_INTERRUPTED = 130        # Ctrl+C: the partial report is still printed

# ctx.meta key under which _execute records an interrupted (Ctrl+C) scan
_INTERRUPTED_RESULT = "netdiag.interrupted_result"


def exit_code_for(report: ScanReport) -> int:
    """Map a finished report to the process exit code (see EXIT_* constants)."""
    code = EXIT_OK
    if report.failed or report.errors:
        code |= EXIT_DIAGNOSTIC_FAILURE
    if report.security_failures:
        code |= EXIT_SECURITY_FAILURE
    return code


def _validate_target_option(ctx: click.Context, param: click.Parameter, value: str) -> str:
    ok, normalized_or_error = validate_target(value)
    if not ok:
        raise click.BadParameter(normalized_or_error)
    return normalized_or_error


def parse_ports(value: str) -> list[int]:
    """Parse a comma-separated port list ("80,443"). Raises ValueError with a user-facing message."""
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if not re.fullmatch(r"[0-9]+", item):
            raise ValueError(f"'{item}' is not a port number (expected e.g. 80,443).")
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"Port {port} is out of range (1-65535).")
        if port not in ports:
            ports.append(port)
    if not ports:
        raise ValueError("Specify at least one port (e.g. 80,443).")
    return ports


def _validate_ports_option(ctx: click.Context, param: click.Parameter, value: str) -> list[int]:
    try:
        return parse_ports(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from None


def _target_option(*decls: str, **kwargs):
    return click.option(*decls, required=True, callback=_validate_target_option, **kwargs)


def _execute(plan: ScanPlan) -> ScanReport:
    """Run `plan` on the shared runner and return its report (in plan order).

    A single progress line is shown on stderr only when stderr is an interactive
    terminal, so piped/redirected output is unchanged. Ctrl+C cancels the scan
    cleanly; the partial report is returned and _output_report exits with 130.
    """
    progress = ProgressLine(sys.stderr) if stream_is_interactive(sys.stderr) else None
    result = ScanRunner().run(plan, on_event=progress)
    if result.interrupted:
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            ctx.meta[_INTERRUPTED_RESULT] = result
    return result.report


def _run_diagnostics(target: str, full: bool = False, include_wifi: bool = False) -> ScanReport:
    click.echo(f"Running diagnostics against {target}...", err=True)
    return _execute(scan_plans.cli_diagnose_plan(target, full=full, wifi=include_wifi))


def _run_security_audit(target: str) -> ScanReport:
    click.echo(f"Running security audit against {target}...", err=True)
    return _execute(scan_plans.cli_security_plan(target))


def _run_full_scan(target: str, include_wifi: bool) -> ScanReport:
    """Diagnostics and security audit as one plan, so both run in parallel and the
    security checks reuse the DNS step's resolution. Both start lines go to stderr."""
    click.echo(f"Running diagnostics against {target}...", err=True)
    click.echo(f"Running security audit against {target}...", err=True)
    plan = scan_plans.cli_full_plan(target) if include_wifi else scan_plans.cli_report_plan(target)
    return _execute(plan)


def _output_report(report: ScanReport, reporter: str, output: str | None):
    if reporter == "console":
        from netdiag.reports.console import format_console_report
        click.echo(format_console_report(report))
    elif reporter == "json":
        from netdiag.reports.json_report import export_json
        result = export_json(report, output)
        if not output:
            click.echo(result)
        else:
            click.echo(f"Report saved to {output}", err=True)
    elif reporter == "csv":
        from netdiag.reports.csv_report import export_csv
        result = export_csv(report, output)
        if not output:
            click.echo(result)
        else:
            click.echo(f"Report saved to {output}", err=True)
    elif reporter == "html":
        from netdiag.reports.html_report import export_html
        filepath = output or f"netdiag_report_{int(time.time())}.html"
        export_html(report, filepath)
        click.echo(f"Report saved to {filepath}", err=True)

    ctx = click.get_current_context()
    interrupted = ctx.meta.get(_INTERRUPTED_RESULT)
    if interrupted is not None:
        finished = sum(1 for state in interrupted.states.values()
                       if state not in (StepState.CANCELLED, StepState.NOT_STARTED))
        click.echo(f"Interrupted: partial results ({finished} of {len(interrupted.states)} "
                   "steps completed).", err=True)
        ctx.exit(EXIT_INTERRUPTED)
    ctx.exit(exit_code_for(report))


@click.group()
@click.version_option(version=__version__, prog_name="NetDiag-Toolkit")
def cli():
    """NetDiag-Toolkit: Advanced Network Diagnostics & Security Audit. Copyright (c) 2026 Iyad Engle.

    \b
    Exit codes (bit flags):
      0  no diagnostic failures and no security FAIL findings
      1  one or more diagnostics returned FAIL or ERROR
      2  usage error (invalid or missing options)
      4  one or more security findings with status FAIL
      5  both 1 and 4
    130  interrupted with Ctrl+C (the partial report is still printed)
    """


@cli.command()
@_target_option("--target", "-t", help="Target hostname or IP")
@click.option("--full", is_flag=True, help="Include MTU and traceroute")
@click.option("--wifi", is_flag=True, help="Include Wi-Fi info (Windows only)")
@click.option("--reporter", "-r", type=click.Choice(["console", "json", "csv", "html"]), default="console")
@click.option("--output", "-o", default=None)
def diagnose(target, full, wifi, reporter, output):
    """Run core network diagnostics against a target."""
    report = _run_diagnostics(target, full=full, include_wifi=wifi)
    _output_report(report, reporter, output)


@cli.command()
@_target_option("--target", "-t")
@click.option("--reporter", "-r", type=click.Choice(["console", "json", "csv", "html"]), default="console")
@click.option("--output", "-o", default=None)
def security(target, reporter, output):
    """Run security audit (TLS, HTTP headers, DNSSEC, open resolver, TCP exposure)."""
    report = _run_security_audit(target)
    _output_report(report, reporter, output)


@cli.command()
@_target_option("--target", "-t")
@click.option("--reporter", "-r", type=click.Choice(["console", "json", "csv", "html"]), default="console")
@click.option("--output", "-o", default=None)
def full(target, reporter, output):
    """Run all diagnostics AND security audit."""
    report = _run_full_scan(target, include_wifi=True)
    _output_report(report, reporter, output)


@cli.command()
@_target_option("--target", "-t")
@click.option("--compare", is_flag=True)
def dns(target, compare):
    """DNS resolution and comparison diagnostics."""
    report = _execute(scan_plans.dns_plan(target, compare=compare))
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--min-size", default=68, type=int)
@click.option("--max-size", default=1500, type=int)
def mtu(target, min_size, max_size):
    """Estimate Path MTU to a target."""
    report = _execute(scan_plans.mtu_plan(target, min_size=min_size, max_size=max_size))
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--ports", "-p", default="80,443", callback=_validate_ports_option,
              help="Comma-separated TCP ports, e.g. 80,443")
@click.option("--timeout", default=3.0, type=float)
def tcp(target, ports, timeout):
    """TCP connectivity test to specified ports."""
    report = _execute(scan_plans.tcp_plan(target, ports, timeout))
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--max-hops", default=30, type=int)
def trace(target, max_hops):
    """Traceroute to a target."""
    report = _execute(scan_plans.traceroute_plan(target, max_hops=max_hops))
    _output_report(report, "console", None)


@cli.command()
@click.option("--subnet", "-s", required=True)
def discover(subnet):
    """Discover active hosts on a subnet (authorized networks only)."""
    report = _execute(scan_plans.discover_plan(subnet))
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--ports", "-p", default="21,22,80,443,3306,3389,8080", callback=_validate_ports_option,
              help="Comma-separated TCP ports, e.g. 22,80,443")
def scan(target, ports):
    """TCP port scan a target (authorized systems only)."""
    report = _execute(scan_plans.scan_plan(target, ports))
    _output_report(report, "console", None)


@cli.command()
def network():
    """Show local network information (adapters, Wi-Fi, gateway)."""
    report = _execute(scan_plans.network_plan())
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--reporter", "-r", type=click.Choice(["console", "json", "csv", "html"]), default="console")
@click.option("--output", "-o", default=None)
def report(target, reporter, output):
    """Run diagnostics + security and export a report."""
    report = _run_full_scan(target, include_wifi=False)
    _output_report(report, reporter, output)


def main():
    cli()


if __name__ == "__main__":
    main()
