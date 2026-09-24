# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""The single definition of every scan step, shared by the CLI and GUI.

`build_plan` assembles the multi-step scans; the `*_plan` functions build the
one-step plans used by the CLI's single-purpose commands. Each step calls an
existing diagnostic or security function with the same arguments the CLI or
GUI passed before, so results and statuses are unchanged.

Two presentation profiles reproduce the existing front ends exactly:

- "cli": MTU/traceroute are reported before the gateway; gateway and Wi-Fi
  targets are relabeled "gateway(<target>)" / "wifi(<target>)"; each function
  keeps its default timeouts (TCP: 3 s, as tcp_multi_port used).
- "gui": the gateway is reported before MTU/traceroute; targets are not
  relabeled; ping/HTTPS/TCP use the GUI's probe-timeout preference.

Scheduling (only visible as ordering constraints, never in the report):
- "dns" runs first for everything that benefits from the resolved address
  (ping, TCP, MTU, traceroute, TLS, TCP exposure); see Phase 3 reuse
- ping, MTU and traceroute share the ICMP lane (never concurrent, so MTU
  probes and traceroute cannot distort ping loss/latency)
- the three TLS checks share a TLS lane and run after the certificate-expiry
  check, which fills the per-scan certificate cache
- ping, MTU and traceroute are given the resolved IP (when the DNS step
  resolved one); their results keep the hostname as target
"""

from __future__ import annotations

import importlib
import ipaddress
from collections.abc import Callable
from typing import Any, Literal

from netdiag.runner.budgets import (
    DEFAULT_BUDGETS_S,
    host_discovery_budget,
    mtu_worst_case,
    ping_worst_case,
    port_scan_budget,
    scaled_budget,
)
from netdiag.runner.plan import Result, ScanPlan, Step, StepOutput
from netdiag.utils.execution import connect_host

Profile = Literal["cli", "gui"]
GuiMode = Literal["diagnose", "security", "full"]

# Values the CLI/GUI used before the runner existed.
PING_COUNT = 4
DIAGNOSE_TCP_PORTS = (80, 443)
CLI_TCP_TIMEOUT_S = 3.0          # tcp_multi_port's default, used by `diagnose`
SCAN_TIMEOUT_S = 2.0             # port_scan default
SCAN_CONCURRENCY = 20            # port_scan default
TCP_MULTI_CONCURRENCY = 10       # tcp_multi_port default
DISCOVERY_TIMEOUT_S = 2          # host_discovery default
DISCOVERY_CONCURRENCY = 50       # host_discovery default


def _call(module: str, function: str, *args: Any, **kwargs: Any) -> Any:
    # Resolved at call time (like the CLI's local imports) so tests can patch the
    # module attribute; importlib avoids package re-exports that shadow module
    # names (netdiag.core.traceroute).
    return getattr(importlib.import_module(module), function)(*args, **kwargs)


def _bound(module: str, function: str, *args: Any, **kwargs: Any) -> Callable[[], StepOutput]:
    return lambda: _call(module, function, *args, **kwargs)


def _set_target(value: str) -> Callable[[Result], Result]:
    def relabel(item: Result) -> Result:
        if hasattr(item, "target"):
            item.target = value   # type: ignore[union-attr]
        return item
    return relabel


def _pinned(module: str, function: str, target: str, **kwargs: Any) -> Callable[[], StepOutput]:
    """Run an ICMP tool against the address the DNS step resolved (if any)."""
    return lambda: _call(module, function, connect_host(target), **kwargs)


# ---------------------------------------------------------------------------
# step definitions
# ---------------------------------------------------------------------------

def _dns_step(target: str) -> Step:
    return Step("dns", "DNS resolution", "diagnostic",
                _bound("netdiag.core.dns", "resolve_hostname", target),
                budget_s=DEFAULT_BUDGETS_S["dns"], test_name="dns_resolution")


def _ping_step(target: str, probe_timeout: float | None, after: tuple[str, ...]) -> Step:
    kwargs: dict[str, Any] = {"count": PING_COUNT}
    timeout = 10
    if probe_timeout is not None:
        timeout = max(1, int(probe_timeout))
        kwargs["timeout_seconds"] = timeout
    return Step("ping", "ICMP ping", "diagnostic",
                _pinned("netdiag.core.connectivity", "ping", target, **kwargs),
                budget_s=scaled_budget("ping", ping_worst_case(PING_COUNT, timeout)),
                after=after, lanes=(f"icmp:{target}",), relabel=_set_target(target),
                test_name="icmp_ping")


def _https_step(target: str, probe_timeout: float | None) -> Step:
    kwargs: dict[str, Any] = {}
    timeout = 10
    if probe_timeout is not None:
        timeout = max(1, int(probe_timeout))
        kwargs["timeout_seconds"] = timeout
    # Not pinned: urllib keeps hostname-based connection, Host header and SNI.
    return Step("https", "HTTPS connectivity", "diagnostic",
                _bound("netdiag.core.https", "https_connectivity", target, **kwargs),
                budget_s=scaled_budget("https", timeout), test_name="https_connectivity")


def _tcp_step(target: str, port: int, timeout: float, after: tuple[str, ...]) -> Step:
    return Step(f"tcp:{port}", f"TCP port {port}", "diagnostic",
                _bound("netdiag.core.tcp", "tcp_connect", target, port, timeout_seconds=timeout),
                budget_s=scaled_budget("tcp", timeout), after=after,
                relabel=_set_target(f"{target}:{port}"), test_name="tcp_connect")


def _gateway_step(target: str, profile: Profile) -> Step:
    return Step("gateway", "Default gateway", "diagnostic",
                _bound("netdiag.core.gateway", "gateway_diagnostics"),
                budget_s=DEFAULT_BUDGETS_S["gateway"],
                relabel=_set_target(f"gateway({target})") if profile == "cli" else None,
                test_name="gateway_detection")


def _mtu_step(target: str, after: tuple[str, ...], pin: bool,
              sizes: tuple[int, int] | None = None) -> Step:
    """sizes=None calls estimate_path_mtu with its defaults (68..1500), as `diagnose --full`
    and the GUI did; the `mtu` command always passed its --min-size/--max-size."""
    kwargs: dict[str, Any] = {} if sizes is None else {"min_size": sizes[0], "max_size": sizes[1]}
    min_size, max_size = sizes if sizes is not None else (68, 1500)
    run = (_pinned("netdiag.core.mtu", "estimate_path_mtu", target, **kwargs) if pin
           else _bound("netdiag.core.mtu", "estimate_path_mtu", target, **kwargs))
    return Step("mtu", "Path MTU", "diagnostic", run,
                budget_s=scaled_budget("mtu", mtu_worst_case(min_size, max_size)),
                after=after, lanes=(f"icmp:{target}",),
                relabel=_set_target(target) if pin else None, test_name="path_mtu")


def _traceroute_step(target: str, after: tuple[str, ...], pin: bool, max_hops: int | None = None) -> Step:
    kwargs: dict[str, Any] = {} if max_hops is None else {"max_hops": max_hops}
    run = (_pinned("netdiag.core.traceroute", "traceroute", target, **kwargs) if pin
           else _bound("netdiag.core.traceroute", "traceroute", target, **kwargs))
    return Step("traceroute", "Traceroute", "diagnostic", run,
                budget_s=DEFAULT_BUDGETS_S["traceroute"], after=after, lanes=(f"icmp:{target}",),
                relabel=_set_target(target) if pin else None, test_name="traceroute")


def _wifi_step(relabel_to: str | None) -> Step:
    return Step("wifi", "Wi-Fi", "diagnostic", _bound("netdiag.network.wifi", "wifi_info"),
                budget_s=DEFAULT_BUDGETS_S["wifi"],
                relabel=_set_target(relabel_to) if relabel_to else None, test_name="wifi_info")


def _security_steps(target: str, after: tuple[str, ...]) -> list[Step]:
    tls_lane = (f"tls:{target}:443",)
    tls_after = after + ("tls.expiry",)
    return [
        Step("tls.expiry", "TLS certificate expiry", "security",
             _bound("netdiag.security.tls", "check_certificate_expiry", target),
             budget_s=DEFAULT_BUDGETS_S["tls.expiry"], after=after, lanes=tls_lane,
             test_name="tls_cert_expiry"),
        Step("tls.versions", "TLS protocol versions", "security",
             _bound("netdiag.security.tls", "check_tls_protocol_versions", target),
             budget_s=DEFAULT_BUDGETS_S["tls.versions"], after=tls_after, lanes=tls_lane,
             test_name="tls_protocol_versions"),
        Step("tls.hostname", "Certificate hostname", "security",
             _bound("netdiag.security.tls", "check_certificate_hostname", target),
             budget_s=DEFAULT_BUDGETS_S["tls.hostname"], after=tls_after, lanes=tls_lane,
             test_name="tls_cert_hostname"),
        Step("http_headers", "HTTP security headers", "security",
             _bound("netdiag.security.http_security", "check_http_security_headers", target),
             budget_s=DEFAULT_BUDGETS_S["http_headers"], test_name="http_security_headers"),
        Step("dnssec", "DNSSEC status", "security",
             _bound("netdiag.security.dns_security", "check_dnssec", target),
             budget_s=DEFAULT_BUDGETS_S["dnssec"], test_name="dns_dnssec"),
        Step("open_resolver", "Open resolver", "security",
             _bound("netdiag.security.dns_security", "check_open_resolver", target),
             budget_s=DEFAULT_BUDGETS_S["open_resolver"], test_name="dns_open_resolver"),
        Step("tcp_exposure", "TCP exposure", "security",
             _bound("netdiag.security.exposure", "check_tcp_exposure", target),
             budget_s=DEFAULT_BUDGETS_S["tcp_exposure"], after=after, test_name="tcp_exposure"),
    ]


# ---------------------------------------------------------------------------
# multi-step scans
# ---------------------------------------------------------------------------

def build_plan(
    target: str,
    *,
    diagnostics: bool = True,
    extended: bool = False,
    security: bool = False,
    include_wifi: bool = False,
    probe_timeout: float | None = None,
    profile: Profile = "cli",
) -> ScanPlan:
    """The shared scan plan.

    diagnostics   -- DNS, ping, HTTPS, TCP 80/443, default gateway
    extended      -- also path MTU and traceroute (CLI --full, GUI "full")
    security      -- the seven security checks
    include_wifi  -- Wi-Fi information (CLI --wifi / `full`)
    probe_timeout -- per-probe timeout for ping/HTTPS/TCP (GUI preference);
                     None keeps each function's default
    profile       -- "cli" or "gui" presentation (see module docstring)
    """
    if profile not in ("cli", "gui"):
        raise ValueError(f"Unknown profile: {profile!r}")
    steps: list[Step] = []
    has_dns = diagnostics
    after_dns: tuple[str, ...] = ("dns",) if has_dns else ()

    if diagnostics:
        tcp_timeout = CLI_TCP_TIMEOUT_S if probe_timeout is None else float(probe_timeout)
        steps += [
            _dns_step(target),
            _ping_step(target, probe_timeout, after_dns),
            _https_step(target, probe_timeout),
            *(_tcp_step(target, port, tcp_timeout, after_dns) for port in DIAGNOSE_TCP_PORTS),
        ]
        extended_steps = ([_mtu_step(target, after_dns, pin=True),
                           _traceroute_step(target, after_dns, pin=True)] if extended else [])
        gateway = _gateway_step(target, profile)
        if profile == "cli":
            steps += [*extended_steps, gateway]
        else:
            steps += [gateway, *extended_steps]
        if include_wifi:
            steps.append(_wifi_step(f"wifi({target})" if profile == "cli" else None))

    if security:
        steps += _security_steps(target, after_dns)

    return ScanPlan(target, tuple(steps))


def cli_diagnose_plan(target: str, full: bool = False, wifi: bool = False) -> ScanPlan:
    """`netdiag diagnose [--full] [--wifi]`."""
    return build_plan(target, extended=full, include_wifi=wifi)


def cli_security_plan(target: str) -> ScanPlan:
    """`netdiag security`."""
    return build_plan(target, diagnostics=False, security=True)


def cli_full_plan(target: str) -> ScanPlan:
    """`netdiag full`: all diagnostics (including Wi-Fi) and the security audit."""
    return build_plan(target, extended=True, security=True, include_wifi=True)


def cli_report_plan(target: str) -> ScanPlan:
    """`netdiag report`: like `full` but without Wi-Fi (as before)."""
    return build_plan(target, extended=True, security=True)


def gui_plan(target: str, mode: GuiMode, timeout: float) -> ScanPlan:
    """GUI "Run Diagnostics" / "Security Audit" / "Full Scan"."""
    if mode not in ("diagnose", "security", "full"):
        raise ValueError(f"Unknown scan mode: {mode}")
    return build_plan(
        target, diagnostics=mode in ("diagnose", "full"), extended=mode == "full",
        security=mode in ("security", "full"), probe_timeout=timeout, profile="gui",
    )


# ---------------------------------------------------------------------------
# one-step plans for single-purpose CLI commands
# ---------------------------------------------------------------------------

def dns_plan(target: str, compare: bool = False) -> ScanPlan:
    """`netdiag dns [--compare]`."""
    if compare:
        step = Step("dns_compare", "DNS server comparison", "diagnostic",
                    _bound("netdiag.core.dns", "compare_dns_servers", target),
                    budget_s=DEFAULT_BUDGETS_S["dns_compare"], test_name="dns_comparison")
    else:
        step = _dns_step(target)
    return ScanPlan(target, (step,))


def mtu_plan(target: str, min_size: int = 68, max_size: int = 1500) -> ScanPlan:
    """`netdiag mtu`. No DNS step, so the tool resolves the name itself (as before)."""
    return ScanPlan(target, (_mtu_step(target, (), pin=False, sizes=(min_size, max_size)),))


def tcp_plan(target: str, ports: list[int], timeout: float = 3.0) -> ScanPlan:
    """`netdiag tcp`: one step, tcp_multi_port as before (results sorted by port)."""
    step = Step("tcp", "TCP connectivity", "diagnostic",
                _bound("netdiag.core.tcp", "tcp_multi_port", target, ports=list(ports), timeout_seconds=timeout),
                budget_s=port_scan_budget(len(ports), timeout, TCP_MULTI_CONCURRENCY), test_name="tcp_connect")
    return ScanPlan(target, (step,))


def traceroute_plan(target: str, max_hops: int = 30) -> ScanPlan:
    """`netdiag trace`."""
    step = _traceroute_step(target, (), pin=False, max_hops=max_hops)
    return ScanPlan(target, (step,))


def discover_plan(subnet: str) -> ScanPlan:
    """`netdiag discover`."""
    try:
        host_count = ipaddress.ip_network(subnet, strict=False).num_addresses
    except ValueError:
        host_count = 0   # host_discovery reports the invalid subnet itself
    step = Step("discover", "Host discovery", "diagnostic",
                _bound("netdiag.network.discovery", "host_discovery", subnet),
                budget_s=host_discovery_budget(host_count, DISCOVERY_TIMEOUT_S, DISCOVERY_CONCURRENCY),
                test_name="host_discovery")
    return ScanPlan(subnet, (step,))


def scan_plan(target: str, ports: list[int]) -> ScanPlan:
    """`netdiag scan`."""
    step = Step("scan", "TCP port scan", "diagnostic",
                _bound("netdiag.network.discovery", "port_scan", target, ports=list(ports)),
                budget_s=port_scan_budget(len(ports), SCAN_TIMEOUT_S, SCAN_CONCURRENCY),
                test_name="tcp_port_scan")
    return ScanPlan(target, (step,))


def network_plan() -> ScanPlan:
    """`netdiag network`: adapters, Wi-Fi, gateway (gateway targets relabeled "gateway")."""
    return ScanPlan("localhost", (
        Step("adapters", "Network adapters", "diagnostic", _bound("netdiag.network.adapters", "adapter_info"),
             budget_s=DEFAULT_BUDGETS_S["adapters"], test_name="adapter_info"),
        _wifi_step(None),
        Step("gateway", "Default gateway", "diagnostic", _bound("netdiag.core.gateway", "gateway_diagnostics"),
             budget_s=DEFAULT_BUDGETS_S["gateway"], relabel=_set_target("gateway"),
             test_name="gateway_detection"),
    ))
