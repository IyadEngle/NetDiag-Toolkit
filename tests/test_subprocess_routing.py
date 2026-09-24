# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Every diagnostic subprocess goes through netdiag.utils.process.run.

- A guard test forbids direct `subprocess` calls outside utils/process.py.
- Parity tests: direct calls (no scan) reach subprocess.run with exactly the
  arguments the original direct subprocess calls used (recorded below).
- End-to-end tests (POSIX): real diagnostic code running fake, slow `ping`
  executables inside a scan scope is cancelled / time-limited correctly.
"""

from __future__ import annotations

import ast
import importlib
import os
import platform
import stat
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest

from netdiag.utils.execution import CancelToken, ExecutionScope, ScanCancelled, activate
from netdiag.utils.models import Status

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "netdiag"
FORBIDDEN_CALLS = {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}


class TestNoDirectSubprocessCalls:
    def test_only_utils_process_calls_subprocess(self):
        offenders = []
        for path in PACKAGE_ROOT.rglob("*.py"):
            if path == PACKAGE_ROOT / "utils" / "process.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
                        and node.func.attr in FORBIDDEN_CALLS):
                    offenders.append(f"{path.relative_to(PACKAGE_ROOT.parent)}:{node.lineno}")
                if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                    names = {alias.name for alias in node.names}
                    if names & FORBIDDEN_CALLS:
                        offenders.append(f"{path.relative_to(PACKAGE_ROOT.parent)}:{node.lineno} (import)")
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"
                        and node.func.attr in {"system", "popen"}):
                    offenders.append(f"{path.relative_to(PACKAGE_ROOT.parent)}:{node.lineno} (os)")
        assert offenders == [], "use netdiag.utils.process.run instead: " + ", ".join(offenders)


# ---------------------------------------------------------------------------
# Parity: outside a scan, each call site hands subprocess.run the same arguments
# as the original direct subprocess calls (recorded from that source).
# ---------------------------------------------------------------------------

def _mod(name: str):
    # importlib avoids package re-exports that shadow module names (netdiag.core.traceroute)
    return importlib.import_module(name)


def _call_ping():
    _mod("netdiag.core.connectivity").ping("192.0.2.1", count=4, timeout_seconds=10)


def _call_dns_compare():
    dns = _mod("netdiag.core.dns")
    with patch.object(dns, "resolve_hostname", return_value=MagicMock(test_name="")):
        dns.compare_dns_servers("example.com")


def _call_gateway():
    _mod("netdiag.core.gateway").get_default_gateway()


def _call_mtu():
    _mod("netdiag.core.mtu").estimate_path_mtu("192.0.2.1", min_size=1000, max_size=1000)


def _call_traceroute():
    _mod("netdiag.core.traceroute").traceroute("192.0.2.1", max_hops=30, timeout_seconds=60)


def _call_adapters():
    _mod("netdiag.network.adapters")._fallback_adapters()


def _call_wifi():
    _mod("netdiag.network.wifi").wifi_info()


def _call_discovery():
    _mod("netdiag.network.discovery").host_discovery("192.0.2.1/32", timeout_seconds=2)


def _call_dnssec_dig():
    _mod("netdiag.security.dns_security")._dnssec_check_dig("example.com", timeout=10)


def _call_open_resolver_dig():
    _mod("netdiag.security.dns_security")._open_resolver_check_dig("192.0.2.53", timeout=5)


CT = {"capture_output": True, "text": True}
PARITY_CASES = [
    ("Linux", _call_ping, ["ping", "-c", "4", "-W", "10", "192.0.2.1"], {**CT, "timeout": 19}),
    ("Windows", _call_ping, ["ping", "-n", "4", "-w", "10000", "192.0.2.1"], {**CT, "timeout": 19}),
    ("Linux", _call_dns_compare, ["dig", "@8.8.8.8", "example.com", "+short"], {**CT, "timeout": 5}),
    ("Windows", _call_dns_compare, ["nslookup", "example.com", "8.8.8.8"], {**CT, "timeout": 5}),
    ("Linux", _call_gateway, ["ip", "route", "show", "default"], {**CT, "timeout": 5}),
    ("Windows", _call_gateway, ["route", "print", "0.0.0.0"], {**CT, "timeout": 5}),
    ("Linux", _call_mtu, ["ping", "-c", "1", "-M", "do", "-s", "1000", "-W", "3", "192.0.2.1"],
     {**CT, "timeout": 5}),
    ("Windows", _call_mtu, ["ping", "-n", "1", "-f", "-l", "1000", "-w", "3000", "192.0.2.1"],
     {**CT, "timeout": 5}),
    ("Linux", _call_traceroute, ["traceroute", "-n", "-m", "30", "-w", "1", "192.0.2.1"],
     {**CT, "timeout": 60}),
    ("Windows", _call_traceroute, ["tracert", "-d", "-h", "30", "-w", "1000", "192.0.2.1"],
     {**CT, "timeout": 60}),
    ("Linux", _call_adapters, ["ip", "-o", "addr", "show"], {**CT, "timeout": 10}),
    ("Windows", _call_adapters, ["ipconfig", "/all"],
     {**CT, "timeout": 10, "encoding": "utf-8", "errors": "replace"}),
    ("Windows", _call_wifi, ["netsh", "wlan", "show", "interfaces"],
     {**CT, "timeout": 10, "encoding": "utf-8", "errors": "replace"}),
    ("Linux", _call_discovery, ["ping", "-c", "1", "-W", "2", "192.0.2.1"], {**CT, "timeout": 4}),
    ("Windows", _call_discovery, ["ping", "-n", "1", "-w", "2000", "192.0.2.1"], {**CT, "timeout": 4}),
    ("Linux", _call_dnssec_dig, ["dig", "DNSKEY", "example.com", "+short"], {**CT, "timeout": 10}),
    ("Linux", _call_open_resolver_dig, ["dig", "@192.0.2.53", "example.com", "+time=3", "+tries=1"],
     {**CT, "timeout": 5}),
]


@pytest.mark.parametrize("os_name,call,expected_cmd,expected_kwargs", PARITY_CASES,
                         ids=[f"{c[1].__name__[6:]}-{c[0]}" for c in PARITY_CASES])
def test_direct_calls_reach_subprocess_run_unchanged(os_name, call, expected_cmd, expected_kwargs):
    completed = MagicMock(stdout="", stderr="", returncode=1)
    with patch("platform.system", return_value=os_name), \
         patch("netdiag.utils.process.subprocess.run", return_value=completed) as mock_run:
        call()
    assert mock_run.call_args_list, "subprocess.run was not reached"
    args, kwargs = mock_run.call_args_list[0]
    assert args == (expected_cmd,)
    # process.run forwards subprocess.run's defaults explicitly; they are equivalent to omitting them.
    defaults = {"input": None, "check": False}
    passed = {k: v for k, v in kwargs.items() if not (k in defaults and v == defaults[k])}
    assert passed == expected_kwargs


def test_parity_cases_cover_all_twelve_call_sites():
    # Functions with one process.run call (the OS only changes its command line) ...
    sites = {
        "_call_ping", "_call_dns_compare", "_call_mtu", "_call_traceroute", "_call_wifi",
        "_call_discovery", "_call_dnssec_dig", "_call_open_resolver_dig",
    }
    # ... and functions with separate Windows and Linux process.run calls.
    two_site_functions = {"_call_gateway", "_call_adapters"}
    covered = {case[1].__name__ for case in PARITY_CASES}
    assert covered == sites | two_site_functions
    assert len(sites) + 2 * len(two_site_functions) == 12


# ---------------------------------------------------------------------------
# End to end: real diagnostic functions + fake slow `ping` executables.
# ---------------------------------------------------------------------------

POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt" or platform.system() != "Linux",
    reason="fake executables on PATH and Linux ping flags",
)


@pytest.fixture
def fake_slow_ping(tmp_path, monkeypatch):
    """Put a `ping` on PATH that records its PID and sleeps for 30 s."""
    pid_dir = tmp_path / "pids"
    pid_dir.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "ping"
    script.write_text(
        "#!/bin/sh\n"
        f"echo $$ > {pid_dir}/$$\n"
        f"exec {sys.executable} -c 'import time; time.sleep(30)'\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return pid_dir


def _started_pids(pid_dir: Path, count: int, timeout: float = 10.0) -> list[int]:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        files = list(pid_dir.iterdir())
        if len(files) >= count and all(f.read_text().strip() for f in files):
            return [int(f.read_text()) for f in files]
        time.sleep(0.02)
    raise AssertionError(f"expected {count} fake pings to start")


def _all_gone(pids: list[int], timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        alive = []
        for pid in pids:
            try:
                if psutil.Process(pid).status() != psutil.STATUS_ZOMBIE:
                    alive.append(pid)
            except psutil.NoSuchProcess:
                pass
        if not alive:
            return True
        time.sleep(0.05)
    return False


def _run_cancelled(func, pid_dir: Path, expected_processes: int):
    """Run `func` in a scan scope on a thread, cancel once its pings started."""
    token = CancelToken()
    outcome: list = []

    def step():
        with activate(ExecutionScope(cancel_token=token)):
            try:
                outcome.append(("returned", func()))
            except ScanCancelled:
                outcome.append(("cancelled", None))

    thread = threading.Thread(target=step)
    thread.start()
    pids = _started_pids(pid_dir, expected_processes)
    began = time.monotonic()
    token.cancel()
    thread.join(10)
    assert not thread.is_alive()
    return outcome, pids, time.monotonic() - began


@POSIX_ONLY
class TestCancellationThroughDiagnostics:
    def test_ping_cancellation_is_not_reported_as_an_error_result(self, fake_slow_ping):
        from netdiag.core.connectivity import ping
        outcome, pids, elapsed = _run_cancelled(lambda: ping("192.0.2.1"), fake_slow_ping, 1)
        assert outcome == [("cancelled", None)]   # not swallowed by ping's `except Exception`
        assert elapsed < 5
        assert _all_gone(pids)

    def test_mtu_binary_search_stops_on_cancel(self, fake_slow_ping):
        from netdiag.core.mtu import estimate_path_mtu
        outcome, pids, elapsed = _run_cancelled(lambda: estimate_path_mtu("192.0.2.1"), fake_slow_ping, 1)
        assert outcome == [("cancelled", None)]   # not treated as "probe failed" by _try_size
        assert len(list(fake_slow_ping.iterdir())) == 1   # no further probes after cancel
        assert _all_gone(pids)

    def test_host_discovery_cancels_pings_in_pool_threads(self, fake_slow_ping):
        from netdiag.network.discovery import host_discovery
        func = lambda: host_discovery("192.0.2.0/29", timeout_seconds=30, max_concurrent=6)  # noqa: E731
        outcome, pids, elapsed = _run_cancelled(func, fake_slow_ping, 6)
        assert outcome == [("cancelled", None)]
        assert elapsed < 5
        assert _all_gone(pids)


@POSIX_ONLY
class TestBudgetThroughDiagnostics:
    def test_ping_budget_produces_its_normal_timeout_result(self, fake_slow_ping):
        from netdiag.core.connectivity import ping
        began = time.monotonic()
        with activate(ExecutionScope.with_budget(0.5)):
            result = ping("192.0.2.1", count=4, timeout_seconds=10)
        assert time.monotonic() - began < 5
        assert result.status == Status.ERROR
        assert result.error == "TimeoutExpired"
        assert result.evidence == "Ping command timed out"
        assert _all_gone([int(f.read_text()) for f in fake_slow_ping.iterdir()])
