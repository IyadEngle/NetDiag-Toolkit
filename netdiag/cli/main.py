# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""NetDiag-Toolkit CLI."""

from __future__ import annotations

import re
import time

import click

from netdiag import __version__
from netdiag.utils.logging import setup_logging
from netdiag.utils.models import ScanReport
from netdiag.utils.validation import validate_target

logger = setup_logging()

# Exit codes are bit flags so scripts can test each condition independently.
# 2 is left to Click, which uses it for usage errors (missing/invalid options).
EXIT_OK = 0
EXIT_DIAGNOSTIC_FAILURE = 1   # at least one diagnostic returned FAIL or ERROR
EXIT_SECURITY_FAILURE = 4     # at least one security finding has status FAIL


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


def _run_diagnostics(target: str, full: bool = False, include_wifi: bool = False) -> ScanReport:
    from netdiag.core.connectivity import ping
    from netdiag.core.dns import resolve_hostname
    from netdiag.core.https import https_connectivity
    from netdiag.core.tcp import tcp_multi_port

    report = ScanReport(target=target)
    click.echo(f"Running diagnostics against {target}...", err=True)

    report.results.append(resolve_hostname(target))
    report.results.append(ping(target, count=4))
    report.results.append(https_connectivity(target))
    report.results.extend(tcp_multi_port(target, ports=[80, 443]))

    if full:
        from netdiag.core.mtu import estimate_path_mtu
        report.results.append(estimate_path_mtu(target))
        from netdiag.core.traceroute import traceroute
        report.results.append(traceroute(target))

    from netdiag.core.gateway import gateway_diagnostics
    for r in gateway_diagnostics():
        r.target = f"gateway({target})"
        report.results.append(r)

    if include_wifi:
        from netdiag.network.wifi import wifi_info
        result = wifi_info()
        result.target = f"wifi({target})"
        report.results.append(result)

    return report


def _run_security_audit(target: str) -> ScanReport:
    from netdiag.security.dns_security import check_dnssec, check_open_resolver
    from netdiag.security.exposure import check_tcp_exposure
    from netdiag.security.http_security import check_http_security_headers
    from netdiag.security.tls import (
        check_certificate_expiry,
        check_certificate_hostname,
        check_tls_protocol_versions,
    )

    report = ScanReport(target=target)
    click.echo(f"Running security audit against {target}...", err=True)

    report.findings.extend(check_certificate_expiry(target))
    report.findings.extend(check_tls_protocol_versions(target))
    report.findings.extend(check_certificate_hostname(target))
    report.findings.extend(check_http_security_headers(target))
    report.findings.extend(check_dnssec(target))
    report.findings.extend(check_open_resolver(target))
    report.findings.extend(check_tcp_exposure(target))

    return report


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

    click.get_current_context().exit(exit_code_for(report))


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
    report = _run_diagnostics(target, full=True, include_wifi=True)
    security_report = _run_security_audit(target)
    report.findings = security_report.findings
    _output_report(report, reporter, output)


@cli.command()
@_target_option("--target", "-t")
@click.option("--compare", is_flag=True)
def dns(target, compare):
    """DNS resolution and comparison diagnostics."""
    from netdiag.core.dns import compare_dns_servers, resolve_hostname
    report = ScanReport(target=target)
    if compare:
        report.results = compare_dns_servers(target)
    else:
        report.results = [resolve_hostname(target)]
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--min-size", default=68, type=int)
@click.option("--max-size", default=1500, type=int)
def mtu(target, min_size, max_size):
    """Estimate Path MTU to a target."""
    from netdiag.core.mtu import estimate_path_mtu
    report = ScanReport(target=target)
    report.results = [estimate_path_mtu(target, min_size=min_size, max_size=max_size)]
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--ports", "-p", default="80,443", callback=_validate_ports_option,
              help="Comma-separated TCP ports, e.g. 80,443")
@click.option("--timeout", default=3.0, type=float)
def tcp(target, ports, timeout):
    """TCP connectivity test to specified ports."""
    from netdiag.core.tcp import tcp_multi_port
    report = ScanReport(target=target)
    report.results = tcp_multi_port(target, ports=ports, timeout_seconds=timeout)
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--max-hops", default=30, type=int)
def trace(target, max_hops):
    """Traceroute to a target."""
    from netdiag.core.traceroute import traceroute
    report = ScanReport(target=target)
    report.results = [traceroute(target, max_hops=max_hops)]
    _output_report(report, "console", None)


@cli.command()
@click.option("--subnet", "-s", required=True)
def discover(subnet):
    """Discover active hosts on a subnet (authorized networks only)."""
    from netdiag.network.discovery import host_discovery
    report = ScanReport(target=subnet)
    report.results = [host_discovery(subnet)]
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--ports", "-p", default="21,22,80,443,3306,3389,8080", callback=_validate_ports_option,
              help="Comma-separated TCP ports, e.g. 22,80,443")
def scan(target, ports):
    """TCP port scan a target (authorized systems only)."""
    from netdiag.network.discovery import port_scan
    report = ScanReport(target=target)
    report.results = [port_scan(target, ports=ports)]
    _output_report(report, "console", None)


@cli.command()
def network():
    """Show local network information (adapters, Wi-Fi, gateway)."""
    from netdiag.core.gateway import gateway_diagnostics
    from netdiag.network.adapters import adapter_info
    from netdiag.network.wifi import wifi_info

    report = ScanReport(target="localhost")
    report.results.append(adapter_info())
    report.results.append(wifi_info())
    for r in gateway_diagnostics():
        r.target = "gateway"
        report.results.append(r)
    _output_report(report, "console", None)


@cli.command()
@_target_option("--target", "-t")
@click.option("--reporter", "-r", type=click.Choice(["console", "json", "csv", "html"]), default="console")
@click.option("--output", "-o", default=None)
def report(target, reporter, output):
    """Run diagnostics + security and export a report."""
    report = _run_diagnostics(target, full=True)
    security_report = _run_security_audit(target)
    report.findings = security_report.findings
    _output_report(report, reporter, output)


def main():
    cli()


if __name__ == "__main__":
    main()
