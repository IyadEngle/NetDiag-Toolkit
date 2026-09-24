# Copyright (c) 2026 Iyad Engle. All rights reserved.

"""Phase 6: the CLI runs every command through the shared runner.

- each command executes exactly one plan (full/report: one combined plan)
- output, ordering and exit codes are unchanged; progress appears only when
  stderr is an interactive terminal and never touches stdout
- Ctrl+C cancels cleanly: running subprocesses are killed, the partial
  report is printed with the requested reporter, and the exit code is 130
"""

from __future__ import annotations

import importlib
import io
import json
import os
import platform
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest
from click.testing import CliRunner

from netdiag.cli.progress import ProgressLine, stream_is_interactive
from netdiag.runner import (
    ResultProduced,
    ScanFinished,
    ScanOutcome,
    ScanResult,
    ScanRunner,
    ScanStarted,
    StepFinished,
    StepStarted,
    StepState,
)
from netdiag.runner import plans as scan_plans
from netdiag.utils import process
from netdiag.utils.models import DiagnosticResult, ScanReport, Status
from tests.test_plans import Fakes

cli_module = importlib.import_module("netdiag.cli.main")
cli = cli_module.cli
TARGET = "example.com"
POSIX = pytest.mark.skipif(os.name == "nt", reason="POSIX signals")


def invoke(args):
    return CliRunner().invoke(cli, args)


# ---------------------------------------------------------------------------
# every command goes through the runner, one plan per invocation
# ---------------------------------------------------------------------------

PLAN_CASES = [
    (["diagnose", "-t", TARGET], scan_plans.cli_diagnose_plan(TARGET)),
    (["diagnose", "-t", TARGET, "--full", "--wifi"], scan_plans.cli_diagnose_plan(TARGET, True, True)),
    (["security", "-t", TARGET], scan_plans.cli_security_plan(TARGET)),
    (["full", "-t", TARGET], scan_plans.cli_full_plan(TARGET)),
    (["report", "-t", TARGET], scan_plans.cli_report_plan(TARGET)),
    (["dns", "-t", TARGET, "--compare"], scan_plans.dns_plan(TARGET, True)),
    (["mtu", "-t", TARGET], scan_plans.mtu_plan(TARGET)),
    (["tcp", "-t", TARGET, "-p", "22,443"], scan_plans.tcp_plan(TARGET, [22, 443])),
    (["trace", "-t", TARGET], scan_plans.traceroute_plan(TARGET)),
    (["discover", "-s", "192.0.2.0/30"], scan_plans.discover_plan("192.0.2.0/30")),
    (["scan", "-t", TARGET], scan_plans.scan_plan(TARGET, [21, 22, 80, 443, 3306, 3389, 8080])),
    (["network"], scan_plans.network_plan()),
]


@pytest.mark.parametrize("args,expected_plan", PLAN_CASES, ids=[" ".join(c[0]) for c in PLAN_CASES])
def test_command_runs_one_plan_on_the_shared_runner(args, expected_plan, monkeypatch):
    Fakes().install(monkeypatch)
    plans = []
    real_run = ScanRunner.run

    def spy(self, plan, on_event=None, cancel_token=None):
        plans.append((plan, self.max_workers))
        return real_run(self, plan, on_event, cancel_token)

    with patch.object(ScanRunner, "run", spy):
        result = invoke(args)
    assert result.exception is None, result.output
    assert len(plans) == 1
    plan, workers = plans[0]
    assert plan.target == expected_plan.target
    assert plan.step_ids == expected_plan.step_ids
    assert workers == 4


def test_every_command_is_covered():
    assert {args[0] for args, _ in PLAN_CASES} == set(cli.commands)


def test_full_and_report_run_diagnostics_and_security_in_one_parallel_plan(monkeypatch):
    fakes = Fakes(delay=0.1).install(monkeypatch)
    result = invoke(["full", "-t", TARGET, "-r", "json"])
    data = json.loads(result.stdout)
    assert data["diagnostics"] and data["security_findings"]
    assert fakes.peak > 1                       # diagnostics and security overlap
    assert result.stderr.splitlines()[:2] == [f"Running diagnostics against {TARGET}...",
                                             f"Running security audit against {TARGET}..."]


def test_report_order_is_plan_order_despite_parallel_completion(monkeypatch):
    Fakes(delay=0.05).install(monkeypatch)
    data = json.loads(invoke(["full", "-t", TARGET, "-r", "json"]).stdout)
    assert [d["test_name"] for d in data["diagnostics"]] == [
        "dns_resolution", "icmp_ping", "https_connectivity", "tcp_connect", "tcp_connect", "path_mtu",
        "traceroute", "gateway_detection", "gateway_ping", "wifi_info"]
    assert [d["target"] for d in data["diagnostics"]][3:5] == [f"{TARGET}:80", f"{TARGET}:443"]
    assert [f["test_name"] for f in data["security_findings"]] == [
        "tls_cert_expiry", "tls_protocol_versions", "tls_cert_hostname", "http_headers", "dns_dnssec",
        "dns_open_resolver", "tcp_exposure"]


def test_helpers_keep_their_names_and_return_reports(monkeypatch):
    Fakes().install(monkeypatch)
    report = cli_module._run_diagnostics(TARGET, full=True)
    assert isinstance(report, ScanReport) and report.target == TARGET
    assert isinstance(cli_module._run_security_audit(TARGET), ScanReport)


# ---------------------------------------------------------------------------
# progress line
# ---------------------------------------------------------------------------

class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class TestProgressLine:
    def _events(self):
        dummy = DiagnosticResult(test_name="x", target=TARGET, status=Status.PASS, evidence="", duration_ms=0)
        return [
            ScanStarted(TARGET, ("dns", "ping"), 2),
            StepStarted("dns", "DNS resolution", 1, 2),
            ResultProduced("dns", dummy),
            StepFinished("dns", "DNS resolution", StepState.COMPLETED, 1.0),
            StepStarted("ping", "ICMP ping", 2, 2),
            StepFinished("ping", "ICMP ping", StepState.COMPLETED, 1.0),
        ]

    def test_renders_in_place_and_clears_at_the_end(self):
        stream = TTY()
        progress = ProgressLine(stream, width=80)
        for event in self._events():
            progress(event)
        out = stream.getvalue()
        assert "\r[0/2] DNS resolution…" in out
        assert "\r[1/2] ICMP ping…" in out
        assert "\n" not in out and "\x1b" not in out     # one line, no ANSI escapes
        progress(ScanFinished(ScanResult(ScanReport(target=TARGET), ScanOutcome.COMPLETED)))
        final = stream.getvalue()
        assert final.endswith("\r")                      # erased before the report is printed

    def test_shorter_text_overwrites_longer_text(self):
        stream = TTY()
        progress = ProgressLine(stream, width=80)
        progress(ScanStarted(TARGET, ("a",), 1))
        progress(StepStarted("a", "A very long step label", 1, 1))
        progress(StepFinished("a", "A very long step label", StepState.COMPLETED, 1.0))
        last = stream.getvalue().split("\r")[-1]
        assert last.startswith("[1/1]") and len(last) == len("[0/1] A very long step label…")

    def test_never_wider_than_the_terminal(self):
        stream = TTY()
        progress = ProgressLine(stream, width=20)
        progress(ScanStarted(TARGET, ("a",), 1))
        progress(StepStarted("a", "An extremely long label that would wrap", 1, 1))
        assert all(len(chunk) <= 19 for chunk in stream.getvalue().split("\r"))

    def test_broken_stream_is_ignored(self):
        class Broken(TTY):
            def write(self, text):
                raise BrokenPipeError

        progress = ProgressLine(Broken(), width=80)
        progress(ScanStarted(TARGET, ("a",), 1))
        progress(StepStarted("a", "A", 1, 1))   # must not raise

    def test_stream_is_interactive(self):
        assert stream_is_interactive(TTY())
        assert not stream_is_interactive(io.StringIO())
        assert not stream_is_interactive(object())

        closed = open(os.devnull)   # a real closed stream: isatty() raises ValueError
        closed.close()
        assert not stream_is_interactive(closed)


class TestProgressInTheCli:
    def test_no_progress_when_stderr_is_not_a_terminal(self, monkeypatch):
        Fakes().install(monkeypatch)
        result = invoke(["diagnose", "-t", TARGET, "--full"])
        assert "\r" not in result.stderr
        assert result.stderr == f"Running diagnostics against {TARGET}...\n"

    def test_progress_on_a_terminal_leaves_stdout_unchanged(self, monkeypatch):
        Fakes(delay=0.02).install(monkeypatch)
        plain = invoke(["diagnose", "-t", TARGET, "--full", "-r", "json"])
        monkeypatch.setattr(cli_module, "stream_is_interactive", lambda stream: True)
        with_progress = invoke(["diagnose", "-t", TARGET, "--full", "-r", "json"])
        strip = lambda text: [line for line in text.splitlines() if '"timestamp"' not in line  # noqa: E731
                              and '"started_at"' not in line]
        assert strip(with_progress.stdout) == strip(plain.stdout)
        assert "\r[" in with_progress.stderr and "Traceroute…" in with_progress.stderr
        assert with_progress.stderr.endswith("\r")   # line erased before exit
        assert with_progress.exit_code == plain.exit_code


# ---------------------------------------------------------------------------
# exit codes through the real runner
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("args,expected", [
    (["dns", "-t", TARGET], 0),
    (["diagnose", "-t", TARGET], 0),
    (["network"], 0),
])
def test_exit_codes_with_passing_fakes(args, expected, monkeypatch):
    Fakes().install(monkeypatch)
    assert invoke(args).exit_code == expected


def test_crashing_step_is_an_error_result_and_exit_1(monkeypatch):
    Fakes().install(monkeypatch)
    connectivity = importlib.import_module("netdiag.core.connectivity")

    def boom(*args, **kwargs):
        raise RuntimeError("parser bug")

    monkeypatch.setattr(connectivity, "ping", boom)
    result = invoke(["diagnose", "-t", TARGET, "-r", "json"])
    data = json.loads(result.stdout)
    ping = [d for d in data["diagnostics"] if d["test_name"] == "icmp_ping"][0]
    assert (ping["status"], ping["error"], ping["target"]) == ("ERROR", "RuntimeError", TARGET)
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Ctrl+C
# ---------------------------------------------------------------------------

def _interrupted_result(report: ScanReport) -> ScanResult:
    return ScanResult(report=report, outcome=ScanOutcome.CANCELLED, interrupted=True,
                      states={"dns": StepState.COMPLETED, "ping": StepState.CANCELLED,
                              "https": StepState.NOT_STARTED})


class TestInterruptedOutput:
    @pytest.mark.parametrize("reporter", ["console", "json", "csv"])
    def test_partial_report_is_printed_and_exit_is_130(self, reporter):
        partial = ScanReport(target=TARGET)
        partial.results.append(DiagnosticResult(test_name="dns_resolution", target=TARGET,
                                                status=Status.PASS, evidence="Resolved", duration_ms=1))
        with patch.object(ScanRunner, "run", return_value=_interrupted_result(partial)):
            result = invoke(["diagnose", "-t", TARGET, "-r", reporter])
        assert result.exit_code == 130
        assert "dns_resolution" in result.stdout
        assert "Interrupted: partial results (1 of 3 steps completed)." in result.stderr

    def test_partial_report_file_is_written(self, tmp_path):
        partial = ScanReport(target=TARGET)
        out = tmp_path / "partial.json"
        with patch.object(ScanRunner, "run", return_value=_interrupted_result(partial)):
            result = invoke(["security", "-t", TARGET, "-r", "json", "-o", str(out)])
        assert result.exit_code == 130
        assert json.loads(out.read_text())["target"] == TARGET

    def test_interrupt_overrides_failure_exit_codes(self):
        partial = ScanReport(target=TARGET)
        partial.results.append(DiagnosticResult(test_name="icmp_ping", target=TARGET, status=Status.FAIL,
                                                evidence="no replies", duration_ms=1))
        with patch.object(ScanRunner, "run", return_value=_interrupted_result(partial)):
            assert invoke(["diagnose", "-t", TARGET]).exit_code == 130


def _sleeper(pid_file: Path) -> list[str]:
    code = f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    return [sys.executable, "-c", code]


def _gone(pid: int, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        except psutil.NoSuchProcess:
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def default_sigint_handler():
    """Give SIGINT the disposition an interactive terminal provides.

    Shells start background jobs (`cmd &` in scripts) with SIGINT ignored, and
    Python then never installs its KeyboardInterrupt handler; these tests must
    not depend on how the test run itself was launched.
    """
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    yield
    signal.signal(signal.SIGINT, previous)


def _reset_sigint_in_child() -> None:
    signal.signal(signal.SIGINT, signal.SIG_DFL)   # like a process started from a terminal


@POSIX
class TestRealSigint:
    def test_sigint_in_process_cancels_and_prints_the_partial_report(self, monkeypatch, tmp_path,
                                                                     default_sigint_handler):
        """A real SIGINT (Python raises KeyboardInterrupt in the main thread) during a scan."""
        Fakes().install(monkeypatch)
        connectivity = importlib.import_module("netdiag.core.connectivity")
        pid_file = tmp_path / "ping.pid"

        def slow_ping(*args, **kwargs):
            threading.Timer(0.3, os.kill, (os.getpid(), signal.SIGINT)).start()
            process.run(_sleeper(pid_file), capture_output=True, timeout=60)   # killed on cancel
            return DiagnosticResult(test_name="icmp_ping", target=TARGET, status=Status.PASS,
                                    evidence="never", duration_ms=0)

        monkeypatch.setattr(connectivity, "ping", slow_ping)
        began = time.monotonic()
        result = invoke(["diagnose", "-t", TARGET, "-r", "json"])
        assert time.monotonic() - began < 10
        assert result.exit_code == 130
        data = json.loads(result.stdout)
        names = [d["test_name"] for d in data["diagnostics"]]
        assert "dns_resolution" in names and "icmp_ping" not in names    # partial, in plan order
        assert "Interrupted: partial results" in result.stderr
        assert _gone(int(pid_file.read_text()))


@pytest.mark.skipif(os.name == "nt" or platform.system() != "Linux",
                    reason="fake `ping` executable on PATH and POSIX signals")
def test_ctrl_c_end_to_end_in_a_separate_netdiag_process(tmp_path):
    """Real `netdiag` process, real diagnostics, fake hanging `ping`, real SIGINT."""
    pid_dir = tmp_path / "pids"
    pid_dir.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_ping = bin_dir / "ping"
    fake_ping.write_text(f"#!/bin/sh\necho $$ > {pid_dir}/$$\nexec {sys.executable} -c 'import time; time.sleep(60)'\n")
    fake_ping.chmod(fake_ping.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    repo_root = Path(__file__).resolve().parents[1]   # test this checkout, not an installed copy
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": os.pathsep.join(filter(None, [str(repo_root), os.environ.get("PYTHONPATH")]))}

    proc = subprocess.Popen([sys.executable, "-m", "netdiag", "diagnose", "-t", "127.0.0.1", "-r", "json"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=tmp_path,
                            preexec_fn=_reset_sigint_in_child)
    try:
        end = time.monotonic() + 20
        while not list(pid_dir.iterdir()) and time.monotonic() < end:
            time.sleep(0.05)
        pids = [int(f.read_text()) for f in pid_dir.iterdir() if f.read_text().strip()]
        assert pids, "fake ping never started"
        time.sleep(0.2)
        proc.send_signal(signal.SIGINT)   # what the terminal sends on Ctrl+C
        stdout, stderr = proc.communicate(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 130, stderr.decode()
    data = json.loads(stdout)
    names = [d["test_name"] for d in data["diagnostics"]]
    assert names[0] == "dns_resolution"
    assert "icmp_ping" not in names
    assert b"Interrupted: partial results" in stderr
    assert all(_gone(pid) for pid in pids + [int(f.read_text()) for f in pid_dir.iterdir()])
