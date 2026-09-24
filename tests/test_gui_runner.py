# Copyright (c) 2026 Iyad Engle. All rights reserved.

"""The GUI runs its scans on the shared runner.

ScanWorker is a thin adapter over ScanRunner + gui_plan: results are shown in
plan order even though steps run in parallel, cancellation stops running
commands at once (no orphans), and the main window keeps its behavior.
"""

from __future__ import annotations

import importlib
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets", reason="PySide6 not installed")
pytestmark = pytest.mark.gui

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from netdiag.runner import ScanPlan, Step  # noqa: E402
from netdiag.runner.plans import gui_plan  # noqa: E402
from netdiag.utils import process  # noqa: E402
from netdiag.utils.execution import current_scope  # noqa: E402
from netdiag.utils.models import (  # noqa: E402
    Confidence,
    DiagnosticResult,
    SecurityFinding,
    SecurityStatus,
    Severity,
    Status,
)
from tests.test_plans import Fakes  # noqa: E402

TARGET = "example.com"


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def wait_until(app, predicate, timeout: float = 15.0) -> bool:
    """Spin the Qt event loop (queued worker signals) until `predicate()` is true."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    app.processEvents()
    return predicate()


def diag(name: str, status: Status = Status.PASS) -> DiagnosticResult:
    return DiagnosticResult(test_name=name, target=TARGET, status=status, evidence=name, duration_ms=1)


def finding(name: str) -> SecurityFinding:
    return SecurityFinding(test_name=name, status=SecurityStatus.PASS, severity=Severity.INFO, title=name,
                           description="d", evidence="e", recommendation="r", confidence=Confidence.CONFIRMED)


def sleeper(pid_file: Path) -> list[str]:
    code = f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    return [sys.executable, "-c", code]


def wait_for_pid(path: Path, timeout: float = 10.0) -> int:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if path.exists() and path.read_text().strip():
            return int(path.read_text())
        time.sleep(0.02)
    raise AssertionError(f"{path} was not written")


def gone(pid: int, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        except psutil.NoSuchProcess:
            return True
        time.sleep(0.05)
    return False


def slow_ping_fake(pid_file: Path):
    """A ping that runs a real 30 s subprocess through process.run (cancellable)."""
    def ping(*args, **kwargs):
        process.run(sleeper(pid_file), capture_output=True, timeout=60)
        return diag("icmp_ping")
    return ping


# ---------------------------------------------------------------------------
# the worker
# ---------------------------------------------------------------------------

class TestWorkerOnRunner:
    def test_uses_the_shared_gui_plan(self, qapp):
        from netdiag.gui.workers import ScanWorker
        for mode in ("diagnose", "security", "full"):
            worker = ScanWorker(TARGET, mode=mode, timeout=7)
            assert worker.plan.step_ids == gui_plan(TARGET, mode, 7).step_ids
            assert worker.total_steps == len(worker.plan)

    def test_invalid_mode_still_rejected(self, qapp):
        from netdiag.gui.workers import ScanWorker
        with pytest.raises(ValueError, match="Unknown scan mode"):
            ScanWorker(TARGET, mode="pentest")

    def test_signals_progress_and_ordered_results(self, qapp, monkeypatch):
        from netdiag.gui.workers import ORDER_STRIDE, ScanWorker
        Fakes(delay=0.02).install(monkeypatch)
        worker = ScanWorker(TARGET, mode="full", timeout=5)
        progress, diags, findings, done = [], [], [], []
        worker.progress.connect(progress.append)
        worker.diagnostic_result.connect(lambda item, order: diags.append((order, item)))
        worker.security_finding.connect(lambda item, order: findings.append((order, item)))
        worker.completed.connect(done.append)
        worker.start()
        assert wait_until(qapp, lambda: bool(done) and not worker.isRunning())

        labels = [s.label for s in worker.plan.steps]
        starts = [m for m in progress if m.startswith("[")]
        assert sorted(m.split("] ", 1)[1] for m in starts) == sorted(f"{label}…" for label in labels)
        assert [m.split("]")[0] for m in starts] == [f"[{i}/15" for i in range(1, 16)]
        assert progress[-1] == "Scan complete."

        report = done[0]
        assert report is worker.report
        # order keys sort the live results into the report's (plan) order
        assert [item.test_name for _, item in sorted(diags, key=lambda x: x[0])] == \
               [r.test_name for r in report.results]
        assert [item.test_name for _, item in sorted(findings, key=lambda x: x[0])] == \
               [f.test_name for f in report.findings]
        gateway_keys = sorted(o for o, item in diags if item.test_name.startswith("gateway"))
        assert gateway_keys[1] - gateway_keys[0] == 1               # items of one step stay adjacent
        assert all(o // ORDER_STRIDE < len(labels) for o, _ in diags + findings)

    def test_runs_with_hidden_console_windows(self, qapp, monkeypatch):
        from netdiag.gui import workers
        seen = []

        def step():
            seen.append(current_scope().hide_console_windows)
            return diag("x")

        plan = ScanPlan(TARGET, [Step("x", "X", "diagnostic", step)])
        with patch.object(workers, "gui_plan", return_value=plan):
            worker = workers.ScanWorker(TARGET, mode="diagnose")
        worker.run()
        assert seen == [True]

    def test_crash_result_uses_the_real_test_name(self, qapp, monkeypatch):
        from netdiag.gui.workers import ScanWorker
        Fakes().install(monkeypatch)
        connectivity = importlib.import_module("netdiag.core.connectivity")

        def boom(*args, **kwargs):
            raise RuntimeError("parser bug")

        monkeypatch.setattr(connectivity, "ping", boom)
        worker = ScanWorker(TARGET, mode="diagnose", timeout=5)
        worker.run()
        ping = [r for r in worker.report.results if r.test_name == "icmp_ping"][0]
        assert (ping.status, ping.error) == (Status.ERROR, "RuntimeError")

    def test_cancel_kills_the_running_command_and_delivers_partial_results(self, qapp, monkeypatch, tmp_path):
        from netdiag.gui.workers import ScanWorker
        Fakes().install(monkeypatch)
        pid_file = tmp_path / "ping.pid"
        monkeypatch.setattr(importlib.import_module("netdiag.core.connectivity"), "ping", slow_ping_fake(pid_file))
        worker = ScanWorker(TARGET, mode="full", timeout=5)
        aborted, completed, progress = [], [], []
        worker.aborted.connect(lambda message, report: aborted.append((message, report)))
        worker.completed.connect(completed.append)
        worker.progress.connect(progress.append)
        worker.start()
        pid = wait_for_pid(pid_file)
        began = time.monotonic()
        worker.cancel()
        assert wait_until(qapp, lambda: bool(aborted) and not worker.isRunning(), timeout=10)
        assert time.monotonic() - began < 5
        assert completed == []
        message, report = aborted[0]
        assert message == "Scan cancelled by user." and progress[-1] == "Scan cancelled."
        names = [r.test_name for r in report.results]
        assert "dns_resolution" in names and "icmp_ping" not in names
        assert gone(pid)


# ---------------------------------------------------------------------------
# panels keep plan order for out-of-order arrivals
# ---------------------------------------------------------------------------

class TestOrderedPanels:
    def test_diagnostic_rows_follow_plan_order(self, qapp):
        from netdiag.gui.widgets.diagnostic_panel import DiagnosticPanel
        panel = DiagnosticPanel()
        for order, name in ((2000, "c"), (0, "a"), (3000, "d"), (1000, "b"), (1001, "b2")):
            panel.add_diagnostic(diag(name), order)
        assert [panel.table.item(r, 1).text() for r in range(5)] == ["a", "b", "b2", "c", "d"]

    def test_diagnostic_rows_without_order_append(self, qapp):
        from netdiag.gui.widgets.diagnostic_panel import DiagnosticPanel
        panel = DiagnosticPanel()
        panel.add_diagnostic(diag("first"))
        panel.add_diagnostic(diag("second"))
        assert [panel.table.item(r, 1).text() for r in range(2)] == ["first", "second"]

    def test_finding_cards_follow_plan_order_and_survive_theme_change(self, qapp):
        from netdiag.gui.widgets.security_panel import SecurityPanel
        panel = SecurityPanel()
        for order, name in ((3000, "d"), (1000, "b"), (0, "a"), (2000, "c")):
            panel.add_finding(finding(name), order)
        assert [f.title for f in panel._findings] == ["a", "b", "c", "d"]
        panel.set_theme("light")
        assert [f.title for f in panel._findings] == ["a", "b", "c", "d"]
        panel.add_finding(finding("b2"), 1001)
        assert [f.title for f in panel._findings] == ["a", "b", "b2", "c", "d"]
        cards = [panel._list_layout.itemAt(i).widget() for i in range(panel._list_layout.count() - 1)]
        assert len(cards) == 5   # every card sits before the trailing stretch


# ---------------------------------------------------------------------------
# the main window
# ---------------------------------------------------------------------------

class TestMainWindowOnRunner:
    def _window(self):
        from netdiag.gui.main_window import MainWindow
        window = MainWindow()
        window.show()
        return window

    def test_full_scan_fills_the_ui_in_plan_order(self, qapp, monkeypatch):
        Fakes(delay=0.02).install(monkeypatch)
        window = self._window()
        window._on_run_requested(TARGET, "full")
        assert wait_until(qapp, lambda: window._worker is None and window._report is not None
                          and window.report_panel.btn_json.isEnabled())
        table = window.diag_panel.table
        assert [table.item(r, 1).text() for r in range(table.rowCount())] == [
            "dns_resolution", "icmp_ping", "https_connectivity", "tcp_connect", "tcp_connect",
            "gateway_detection", "gateway_ping", "path_mtu", "traceroute"]
        assert [f.test_name for f in window.sec_panel._findings] == [
            "tls_cert_expiry", "tls_protocol_versions", "tls_cert_hostname", "http_headers",
            "dns_dnssec", "dns_open_resolver", "tcp_exposure"]
        assert "9 passed" in window.summary_label.text()
        assert "Scan complete." in window.log_view.toPlainText()
        assert window._status_dot.text() == "● Ready"
        window.close()

    def test_cancel_button_stops_running_commands_and_keeps_partial_results(self, qapp, monkeypatch, tmp_path):
        Fakes().install(monkeypatch)
        pid_file = tmp_path / "ping.pid"
        monkeypatch.setattr(importlib.import_module("netdiag.core.connectivity"), "ping", slow_ping_fake(pid_file))
        window = self._window()
        window._on_run_requested(TARGET, "diagnose")
        pid = wait_for_pid(pid_file)
        window._on_cancel()
        assert "stopping the running tests" in window.log_view.toPlainText()
        assert wait_until(qapp, lambda: window._worker is None, timeout=10)
        assert gone(pid)
        assert "partial results" in window.summary_label.text().lower()
        assert window.report_panel.btn_json.isEnabled()
        assert "icmp_ping" not in [r.test_name for r in window._report.results]
        assert window._status_dot.text() == "● Ready"
        window.close()

    @patch("netdiag.gui.main_window.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes)
    def test_closing_during_a_scan_stops_it_without_orphans(self, _ask, qapp, monkeypatch, tmp_path):
        Fakes().install(monkeypatch)
        pid_file = tmp_path / "ping.pid"
        monkeypatch.setattr(importlib.import_module("netdiag.core.connectivity"), "ping", slow_ping_fake(pid_file))
        window = self._window()
        window._on_run_requested(TARGET, "diagnose")
        pid = wait_for_pid(pid_file)
        worker = window._worker
        began = time.monotonic()
        window.close()                      # runner cancels; worker stops within closeEvent's wait
        assert wait_until(qapp, lambda: not window.isVisible() and not worker.isRunning(), timeout=10)
        assert time.monotonic() - began < 5
        assert gone(pid)
