# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""The shared scan plans reproduce the CLI and GUI exactly.

Every diagnostic/security function is replaced by a fake that records its
call and returns results whose evidence encodes all of its arguments (after
applying the real signature's defaults). Each CLI command is run through the
CLI code and each GUI mode through ScanWorker (both on the runner since
0.5; these checks were first run against the pre-runner code); the
resulting reports must equal the report produced by running the equivalent
plan through the runner, in parallel and sequentially.
"""

from __future__ import annotations

import importlib
import inspect
import os
import threading
import time
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from netdiag.runner import ScanRunner
from netdiag.runner.budgets import DEFAULT_BUDGETS_S, WORST_CASE_S, ping_worst_case
from netdiag.runner.plans import (
    build_plan,
    cli_diagnose_plan,
    cli_full_plan,
    cli_report_plan,
    cli_security_plan,
    discover_plan,
    dns_plan,
    gui_plan,
    mtu_plan,
    network_plan,
    scan_plan,
    tcp_plan,
    traceroute_plan,
)
from netdiag.utils.execution import current_scope, remember_resolution
from netdiag.utils.models import (
    Confidence,
    DiagnosticResult,
    SecurityFinding,
    SecurityStatus,
    Severity,
    Status,
)

TARGET = "example.com"
cli_module = importlib.import_module("netdiag.cli.main")


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------

def _diag(test_name: str, target: str, args: dict) -> DiagnosticResult:
    return DiagnosticResult(test_name=test_name, target=target, status=Status.PASS,
                            evidence=repr(sorted(args.items())), duration_ms=1)


def _finding(test_name: str, args: dict) -> list[SecurityFinding]:
    return [SecurityFinding(test_name=test_name, status=SecurityStatus.OBSERVATION, severity=Severity.INFO,
                            title=test_name, description="d", evidence=repr(sorted(args.items())),
                            recommendation="r", confidence=Confidence.CONFIRMED)]


BUILDERS: dict[tuple[str, str], Any] = {
    ("netdiag.core.dns", "resolve_hostname"): lambda a: _diag("dns_resolution", a["target"], a),
    ("netdiag.core.dns", "compare_dns_servers"): lambda a: [_diag("dns_comparison_system", a["target"], a),
                                                            _diag("dns_comparison_google", a["target"], a)],
    ("netdiag.core.connectivity", "ping"): lambda a: _diag("icmp_ping", a["target"], a),
    ("netdiag.core.https", "https_connectivity"): lambda a: _diag("https_connectivity", a["target"], a),
    ("netdiag.core.tcp", "tcp_connect"): lambda a: _diag("tcp_connect", f"{a['host']}:{a['port']}", a),
    ("netdiag.core.mtu", "estimate_path_mtu"): lambda a: _diag("path_mtu", a["target"], a),
    ("netdiag.core.traceroute", "traceroute"): lambda a: _diag("traceroute", a["target"], a),
    ("netdiag.core.gateway", "gateway_diagnostics"): lambda a: [_diag("gateway_detection", "default_gateway", a),
                                                                _diag("gateway_ping", "192.0.2.254", a)],
    ("netdiag.network.wifi", "wifi_info"): lambda a: _diag("wifi_info", "localhost", a),
    ("netdiag.network.adapters", "adapter_info"): lambda a: _diag("adapter_info", "localhost", a),
    ("netdiag.network.discovery", "host_discovery"): lambda a: _diag("host_discovery", a["subnet"], a),
    ("netdiag.network.discovery", "port_scan"): lambda a: _diag("tcp_port_scan", a["target"], a),
    ("netdiag.security.tls", "check_certificate_expiry"): lambda a: _finding("tls_cert_expiry", a),
    ("netdiag.security.tls", "check_tls_protocol_versions"): lambda a: _finding("tls_protocol_versions", a),
    ("netdiag.security.tls", "check_certificate_hostname"): lambda a: _finding("tls_cert_hostname", a),
    ("netdiag.security.http_security", "check_http_security_headers"): lambda a: _finding("http_headers", a),
    ("netdiag.security.dns_security", "check_dnssec"): lambda a: _finding("dns_dnssec", a),
    ("netdiag.security.dns_security", "check_open_resolver"): lambda a: _finding("dns_open_resolver", a),
    ("netdiag.security.exposure", "check_tcp_exposure"): lambda a: _finding("tcp_exposure", a),
}


class Fakes:
    """Installs fakes for every diagnostic/security function and records calls."""

    def __init__(self, delay: float = 0.0, resolve_to: str | None = None) -> None:
        self.delay = delay
        self.resolve_to = resolve_to
        self.lock = threading.Lock()
        self.calls: list[tuple[str, dict]] = []
        self.intervals: dict[str, list[tuple[float, float]]] = {}
        self.active = 0
        self.peak = 0

    def install(self, monkeypatch) -> Fakes:
        for (module_name, function), builder in BUILDERS.items():
            module = importlib.import_module(module_name)
            monkeypatch.setattr(module, function, self._fake(function, getattr(module, function), builder))
        return self

    def _fake(self, function: str, real, builder):
        signature = inspect.signature(real)

        def fake(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            began = time.monotonic()
            with self.lock:
                self.calls.append((function, arguments))
                self.active += 1
                self.peak = max(self.peak, self.active)
            try:
                if self.delay:
                    time.sleep(self.delay)
                if function == "resolve_hostname" and self.resolve_to:
                    remember_resolution(arguments["target"], self.resolve_to)
                return builder(arguments)
            finally:
                with self.lock:
                    self.active -= 1
                    self.intervals.setdefault(function, []).append((began, time.monotonic()))
        return fake

    def call_multiset(self) -> list[str]:
        return sorted(f"{name}{sorted(args.items())!r}" for name, args in self.calls)

    def reset(self) -> None:
        self.calls.clear()
        self.intervals.clear()
        self.peak = 0


def normalized(report) -> dict:
    data = report.to_dict()
    data.pop("started_at")
    for section in ("diagnostics", "security_findings"):
        for item in data[section]:
            item.pop("timestamp")
    return data


def run_cli(args: list[str]):
    captured: dict = {}

    def capture(report, *_args, **_kwargs):
        captured["report"] = report

    with patch.object(cli_module, "_output_report", side_effect=capture):
        result = CliRunner().invoke(cli_module.cli, args)
    assert result.exception is None, result.output
    return captured["report"]


def run_plan(plan, workers: int):
    return ScanRunner(max_workers=workers).run(plan).report


# ---------------------------------------------------------------------------
# CLI parity: every command
# ---------------------------------------------------------------------------

CLI_CASES = [
    (["diagnose", "-t", TARGET], lambda: cli_diagnose_plan(TARGET)),
    (["diagnose", "-t", TARGET, "--full"], lambda: cli_diagnose_plan(TARGET, full=True)),
    (["diagnose", "-t", TARGET, "--wifi"], lambda: cli_diagnose_plan(TARGET, wifi=True)),
    (["diagnose", "-t", TARGET, "--full", "--wifi"], lambda: cli_diagnose_plan(TARGET, full=True, wifi=True)),
    (["security", "-t", TARGET], lambda: cli_security_plan(TARGET)),
    (["full", "-t", TARGET], lambda: cli_full_plan(TARGET)),
    (["report", "-t", TARGET], lambda: cli_report_plan(TARGET)),
    (["dns", "-t", TARGET], lambda: dns_plan(TARGET)),
    (["dns", "-t", TARGET, "--compare"], lambda: dns_plan(TARGET, compare=True)),
    (["mtu", "-t", TARGET], lambda: mtu_plan(TARGET)),
    (["mtu", "-t", TARGET, "--min-size", "576", "--max-size", "1400"], lambda: mtu_plan(TARGET, 576, 1400)),
    (["tcp", "-t", TARGET], lambda: tcp_plan(TARGET, [80, 443])),
    (["tcp", "-t", TARGET, "-p", "443,22,8080", "--timeout", "1.5"], lambda: tcp_plan(TARGET, [443, 22, 8080], 1.5)),
    (["trace", "-t", TARGET], lambda: traceroute_plan(TARGET)),
    (["trace", "-t", TARGET, "--max-hops", "12"], lambda: traceroute_plan(TARGET, max_hops=12)),
    (["discover", "-s", "192.0.2.0/29"], lambda: discover_plan("192.0.2.0/29")),
    (["scan", "-t", TARGET], lambda: scan_plan(TARGET, [21, 22, 80, 443, 3306, 3389, 8080])),
    (["scan", "-t", TARGET, "-p", "22,80"], lambda: scan_plan(TARGET, [22, 80])),
    (["network"], network_plan),
]


def test_every_cli_command_is_covered():
    commands = {args[0] for args, _ in CLI_CASES}
    assert commands == set(cli_module.cli.commands)


@pytest.mark.parametrize("args,make_plan", CLI_CASES, ids=[" ".join(c[0]) for c in CLI_CASES])
@pytest.mark.parametrize("workers", [4, 1])
def test_cli_command_parity(args, make_plan, workers, monkeypatch):
    fakes = Fakes().install(monkeypatch)
    expected = normalized(run_cli(args))
    expected_calls = fakes.call_multiset()
    fakes.reset()
    actual = normalized(run_plan(make_plan(), workers))
    assert actual == expected                       # same items, same order, same arguments
    assert fakes.call_multiset() == expected_calls  # same calls, none extra, none missing


# ---------------------------------------------------------------------------
# GUI parity: every mode, several probe timeouts
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def qt():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    qt_core = pytest.importorskip("PySide6.QtCore", reason="PySide6 not installed")
    app = qt_core.QCoreApplication.instance() or qt_core.QCoreApplication([])
    yield app


def run_gui_worker(mode: str, timeout: float):
    from netdiag.gui.workers import ScanWorker
    worker = ScanWorker(TARGET, mode=mode, timeout=timeout)
    worker.run()          # synchronously, on this thread
    return worker


@pytest.mark.parametrize("mode", ["diagnose", "security", "full"])
@pytest.mark.parametrize("timeout", [5, 60, 2.5])
@pytest.mark.parametrize("workers", [4, 1])
def test_gui_mode_parity(qt, mode, timeout, workers, monkeypatch):
    fakes = Fakes().install(monkeypatch)
    worker = run_gui_worker(mode, timeout)
    expected = normalized(worker.report)
    expected_calls = fakes.call_multiset()
    fakes.reset()
    actual = normalized(run_plan(gui_plan(TARGET, mode, timeout), workers))
    assert actual == expected
    assert fakes.call_multiset() == expected_calls


# Progress labels the GUI worker showed before it moved onto the runner (0.4.x).
_GUI_DIAGNOSE_LABELS = ["DNS resolution", "ICMP ping", "HTTPS connectivity", "TCP port 80", "TCP port 443",
                        "Default gateway"]
_GUI_SECURITY_LABELS = ["TLS certificate expiry", "TLS protocol versions", "Certificate hostname",
                        "HTTP security headers", "DNSSEC status", "Open resolver", "TCP exposure"]
_GUI_LABELS = {
    "diagnose": _GUI_DIAGNOSE_LABELS,
    "security": _GUI_SECURITY_LABELS,
    "full": _GUI_DIAGNOSE_LABELS + ["Path MTU", "Traceroute"] + _GUI_SECURITY_LABELS,
}


@pytest.mark.parametrize("mode", ["diagnose", "security", "full"])
def test_gui_step_labels_and_counts_match(qt, mode):
    from netdiag.gui.workers import ScanWorker
    worker = ScanWorker(TARGET, mode=mode, timeout=5)
    assert [s.label for s in worker.plan.steps] == _GUI_LABELS[mode]
    assert worker.plan.step_ids == gui_plan(TARGET, mode, 5).step_ids
    assert worker.total_steps == len(_GUI_LABELS[mode])


# ---------------------------------------------------------------------------
# resolved-IP pinning
# ---------------------------------------------------------------------------

class TestResolvedIpPinning:
    def test_icmp_tools_get_the_resolved_ip_and_keep_the_hostname_label(self, monkeypatch):
        fakes = Fakes(resolve_to="203.0.113.7").install(monkeypatch)
        report = run_plan(cli_full_plan(TARGET), 4)
        called_with = {name: args for name, args in fakes.calls}
        for tool in ("ping", "estimate_path_mtu", "traceroute"):
            assert called_with[tool]["target"] == "203.0.113.7", tool
        by_name = {r.test_name: r for r in report.results}
        for test_name in ("icmp_ping", "path_mtu", "traceroute"):
            assert by_name[test_name].target == TARGET      # user-facing target unchanged

    def test_hostname_based_checks_are_not_pinned(self, monkeypatch):
        fakes = Fakes(resolve_to="203.0.113.7").install(monkeypatch)
        run_plan(cli_full_plan(TARGET), 4)
        for name, args in fakes.calls:
            if name in ("https_connectivity", "tcp_connect", "check_certificate_expiry",
                        "check_tls_protocol_versions", "check_certificate_hostname",
                        "check_http_security_headers", "check_dnssec", "check_open_resolver",
                        "check_tcp_exposure", "resolve_hostname"):
                assert "203.0.113.7" not in repr(args), name   # these receive the hostname

    def test_unresolved_target_is_passed_through(self, monkeypatch):
        fakes = Fakes(resolve_to=None).install(monkeypatch)
        run_plan(cli_diagnose_plan(TARGET, full=True), 4)
        assert {args["target"] for name, args in fakes.calls
                if name in ("ping", "estimate_path_mtu", "traceroute")} == {TARGET}

    def test_single_purpose_commands_are_not_pinned(self, monkeypatch):
        fakes = Fakes(resolve_to="203.0.113.7").install(monkeypatch)
        run_plan(mtu_plan(TARGET), 1)
        run_plan(traceroute_plan(TARGET), 1)
        assert [args["target"] for _, args in fakes.calls] == [TARGET, TARGET]


# ---------------------------------------------------------------------------
# plan structure: dependencies, lanes, budgets
# ---------------------------------------------------------------------------

class TestPlanStructure:
    def test_cli_full_plan_steps(self):
        plan = cli_full_plan(TARGET)
        assert plan.step_ids == ("dns", "ping", "https", "tcp:80", "tcp:443", "mtu", "traceroute", "gateway",
                                 "wifi", "tls.expiry", "tls.versions", "tls.hostname", "http_headers",
                                 "dnssec", "open_resolver", "tcp_exposure")

    def test_gui_full_plan_steps(self):
        assert gui_plan(TARGET, "full", 5).step_ids == (
            "dns", "ping", "https", "tcp:80", "tcp:443", "gateway", "mtu", "traceroute",
            "tls.expiry", "tls.versions", "tls.hostname", "http_headers", "dnssec", "open_resolver",
            "tcp_exposure")

    def test_dependencies(self):
        steps = {s.id: s for s in cli_full_plan(TARGET).steps}
        for step_id in ("ping", "tcp:80", "tcp:443", "mtu", "traceroute", "tls.expiry", "tcp_exposure"):
            assert "dns" in steps[step_id].after, step_id
        for step_id in ("dns", "https", "gateway", "wifi", "http_headers", "dnssec", "open_resolver"):
            assert steps[step_id].after == (), step_id
        assert steps["tls.versions"].after == ("dns", "tls.expiry")
        assert steps["tls.hostname"].after == ("dns", "tls.expiry")

    def test_security_only_plan_has_no_dns_dependency(self):
        steps = {s.id: s for s in cli_security_plan(TARGET).steps}
        assert "dns" not in steps
        assert steps["tls.versions"].after == ("tls.expiry",)

    def test_lanes(self):
        steps = {s.id: s for s in cli_full_plan(TARGET).steps}
        icmp = {sid for sid, s in steps.items() if f"icmp:{TARGET}" in s.lanes}
        tls = {sid for sid, s in steps.items() if f"tls:{TARGET}:443" in s.lanes}
        assert icmp == {"ping", "mtu", "traceroute"}
        assert tls == {"tls.expiry", "tls.versions", "tls.hostname"}
        assert all(not s.lanes for sid, s in steps.items() if sid not in icmp | tls)

    @pytest.mark.parametrize("plan", [cli_full_plan(TARGET), gui_plan(TARGET, "full", 5)])
    def test_default_budgets(self, plan):
        for step in plan.steps:
            base = step.id.split(":")[0]
            assert step.budget_s == DEFAULT_BUDGETS_S[base], step.id
            assert step.budget_s > WORST_CASE_S[base]

    def test_budgets_grow_with_the_gui_probe_timeout(self):
        steps = {s.id: s for s in gui_plan(TARGET, "full", 60).steps}
        assert steps["ping"].budget_s > ping_worst_case(4, 60)       # 69 s worst case
        assert steps["https"].budget_s > 60
        assert steps["tcp:443"].budget_s > 60
        assert steps["dns"].budget_s == DEFAULT_BUDGETS_S["dns"]    # unaffected by the probe timeout

    def test_size_based_budgets(self):
        assert discover_plan("10.0.0.0/22").steps[0].budget_s > discover_plan("10.0.0.0/29").steps[0].budget_s
        assert discover_plan("not-a-subnet").steps[0].budget_s > 0
        assert scan_plan(TARGET, list(range(1, 101))).steps[0].budget_s > scan_plan(TARGET, [22]).steps[0].budget_s
        assert tcp_plan(TARGET, [80], 30).steps[0].budget_s > 30
        assert mtu_plan(TARGET, 68, 9000).steps[0].budget_s > mtu_plan(TARGET, 1400, 1500).steps[0].budget_s

    def test_every_step_has_a_budget_label_and_test_name(self):
        plans = [cli_full_plan(TARGET), gui_plan(TARGET, "full", 5), dns_plan(TARGET, True), mtu_plan(TARGET),
                 tcp_plan(TARGET, [80]), traceroute_plan(TARGET), discover_plan("192.0.2.0/30"),
                 scan_plan(TARGET, [22]), network_plan()]
        for plan in plans:
            for step in plan.steps:
                assert step.budget_s and step.label and step.test_name, step.id

    def test_invalid_profile_and_mode(self):
        with pytest.raises(ValueError):
            build_plan(TARGET, profile="tui")   # type: ignore[arg-type]
        with pytest.raises(ValueError):
            gui_plan(TARGET, "pentest", 5)       # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# scheduling of the real plans (fakes with a delay)
# ---------------------------------------------------------------------------

def _overlap(a, b) -> bool:
    return a[0] < b[1] and b[0] < a[1]


class TestPlanScheduling:
    def test_full_plan_runs_in_parallel_within_the_rules(self, monkeypatch):
        fakes = Fakes(delay=0.1).install(monkeypatch)
        began = time.monotonic()
        result = ScanRunner().run(cli_full_plan(TARGET))
        elapsed = time.monotonic() - began
        assert result.outcome.value == "completed"
        assert fakes.peak <= 4
        assert elapsed < 16 * 0.1 * 0.8          # meaningfully faster than sequential (1.6 s)

        iv = {name: spans[0] for name, spans in fakes.intervals.items()}
        dns_end = iv["resolve_hostname"][1]
        for name in ("ping", "estimate_path_mtu", "traceroute", "check_certificate_expiry",
                     "check_tcp_exposure"):
            assert iv[name][0] >= dns_end, name
        assert all(span[0] >= dns_end for span in fakes.intervals["tcp_connect"])
        icmp = [iv["ping"], iv["estimate_path_mtu"], iv["traceroute"]]
        assert not any(_overlap(a, b) for i, a in enumerate(icmp) for b in icmp[i + 1:])
        tls = [iv["check_certificate_expiry"], iv["check_tls_protocol_versions"], iv["check_certificate_hostname"]]
        assert not any(_overlap(a, b) for i, a in enumerate(tls) for b in tls[i + 1:])
        assert tls[1][0] >= tls[0][1] and tls[2][0] >= tls[0][1]   # certificate fetched first

    def test_plans_leave_direct_calls_untouched(self, monkeypatch):
        Fakes().install(monkeypatch)
        run_plan(cli_full_plan(TARGET), 4)
        assert current_scope() is None
