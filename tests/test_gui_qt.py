# Copyright (c) 2026 Iyad Engle. All rights reserved.

"""GUI tests that require PySide6. Run headless in CI via QT_QPA_PLATFORM=offscreen."""

import os

import pytest

# Must be set before QApplication is created
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

qt_widgets = pytest.importorskip("PySide6.QtWidgets", reason="PySide6 not installed")
pytestmark = pytest.mark.gui

from unittest.mock import patch  # noqa: E402

from PySide6.QtCore import QObject, Signal  # noqa: E402
from PySide6.QtGui import QCloseEvent  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


class TestGuiStartup:
    def test_main_window_constructs(self, qapp):
        from netdiag.gui.main_window import MainWindow
        window = MainWindow()
        assert window.windowTitle() == "NetDiag-Toolkit"
        assert not window.windowIcon().isNull()
        assert window.diag_panel.table.columnCount() == 5
        assert len(window.diag_panel._cards) == 7
        window.close()

    def test_preferences_dialog_constructs(self, qapp):
        from netdiag.gui.main_window import PreferencesDialog
        from netdiag.gui.settings import GuiSettings
        dialog = PreferencesDialog(GuiSettings())
        assert dialog.windowTitle() == "Preferences"
        dialog.close()


class TestResultRendering:
    def test_result_card_status_update(self, qapp):
        from netdiag.gui.widgets.result_card import ResultCard
        card = ResultCard("Ping", theme="dark")
        card.set_status("PASS", "4/4 received")
        assert card._pill.text() == "PASS"
        card.set_status("PENDING", "")
        assert card._pill.text() == "—"

    def test_diagnostic_panel_adds_rows_and_updates_card(self, qapp, sample_result):
        import dataclasses

        from netdiag.gui.widgets.diagnostic_panel import DiagnosticPanel
        panel = DiagnosticPanel(theme="dark")
        # The Ping card is keyed on the real ping test name, "icmp_ping".
        panel.add_diagnostic(dataclasses.replace(sample_result, test_name="icmp_ping"))
        assert panel.table.rowCount() == 1
        assert panel._cards["ping"]._pill.text() == "PASS"

    def test_diagnostic_panel_tcp_443_updates_tcp_card(self, qapp):
        from netdiag.gui.widgets.diagnostic_panel import DiagnosticPanel
        from netdiag.utils.models import DiagnosticResult, Status
        panel = DiagnosticPanel(theme="dark")
        result = DiagnosticResult(
            test_name="tcp_connect", target="example.com:443",
            status=Status.FAIL, evidence="refused", duration_ms=12,
        )
        panel.add_diagnostic(result)
        assert panel._cards["tcp"]._pill.text() == "FAIL"

    def test_security_panel_adds_finding_and_counts(self, qapp, sample_security_failure):
        from netdiag.gui.widgets.security_panel import SecurityPanel
        panel = SecurityPanel(theme="dark")
        panel.add_finding(sample_security_failure)
        assert len(panel._findings) == 1
        assert "1 failure(s)" in panel.count_label.text()

    def test_security_panel_clear(self, qapp, sample_security_failure):
        from netdiag.gui.widgets.security_panel import SecurityPanel
        panel = SecurityPanel(theme="dark")
        panel.add_finding(sample_security_failure)
        panel.clear()
        assert len(panel._findings) == 0
        assert panel.count_label.text() == "No security results yet."


class TestTargetBar:
    def test_valid_target_emits_signal(self, qapp):
        from netdiag.gui.widgets.target_bar import TargetBar
        bar = TargetBar()
        received = []
        bar.run_requested.connect(lambda t, m: received.append((t, m)))
        bar.input.setText("example.com")
        bar._request("diagnose")
        assert received == [("example.com", "diagnose")]

    def test_invalid_target_does_not_emit(self, qapp):
        from netdiag.gui.widgets.target_bar import TargetBar
        bar = TargetBar()
        received = []
        bar.run_requested.connect(lambda t, m: received.append((t, m)))
        bar.input.setText("https://example.com")
        bar._request("diagnose")
        assert received == []
        assert bar.error_label.text() != ""

    def test_set_busy_disables_buttons(self, qapp):
        from netdiag.gui.widgets.target_bar import TargetBar
        bar = TargetBar()
        bar.set_busy(True)
        assert not bar.btn_diagnose.isEnabled()
        assert not bar.input.isEnabled()
        bar.set_busy(False)
        assert bar.btn_diagnose.isEnabled()


class TestWorker:
    def test_cancel_sets_flag(self, qapp):
        from netdiag.gui.workers import ScanWorker
        worker = ScanWorker("127.0.0.1", mode="diagnose", timeout=2)
        assert not worker.cancelled
        worker.cancel()
        assert worker.cancelled

    def test_plan_sizes(self, qapp):
        from netdiag.gui.workers import ScanWorker
        diagnose_worker = ScanWorker("127.0.0.1", mode="diagnose", timeout=2)
        security_worker = ScanWorker("127.0.0.1", mode="security", timeout=2)
        full_worker = ScanWorker("127.0.0.1", mode="full", timeout=2)
        # 6 diagnostic steps, 7 security steps, full = 6 + 2 (MTU/trace) + 7
        assert diagnose_worker.total_steps == 6
        assert security_worker.total_steps == 7
        assert full_worker.total_steps == 15

    def test_invalid_mode_rejected(self, qapp):
        from netdiag.gui.workers import ScanWorker
        with pytest.raises(ValueError):
            ScanWorker("127.0.0.1", mode="pentest", timeout=2)

    def test_report_target_binding(self, qapp):
        from netdiag.gui.workers import ScanWorker
        worker = ScanWorker("example.com", mode="diagnose", timeout=2)
        assert worker.report.target == "example.com"


class TestErrorHandling:
    def test_settings_defaults_on_garbage(self, qapp):
        from netdiag.gui.settings import GuiSettings
        settings = GuiSettings()
        # These read whatever is persisted; the accessors must not raise and
        # must return values within the documented ranges.
        assert 1 <= settings.timeout() <= 60
        assert settings.theme() in ("dark", "light")
        assert settings.log_level() in ("DEBUG", "INFO", "WARNING", "ERROR")

    def test_report_panel_disabled_without_report(self, qapp):
        from netdiag.gui.settings import GuiSettings
        from netdiag.gui.widgets.report_panel import ReportPanel
        panel = ReportPanel(GuiSettings(), lambda: None)
        assert not panel.btn_json.isEnabled()

    def test_report_panel_enabled_with_report(self, qapp, sample_report):
        from netdiag.gui.settings import GuiSettings
        from netdiag.gui.widgets.report_panel import ReportPanel
        panel = ReportPanel(GuiSettings(), lambda: sample_report)
        panel.set_has_report(True)
        assert panel.btn_json.isEnabled()


class _FakeWorker(QObject):
    """Stands in for ScanWorker: stays 'running' until finish() is called."""

    finished = Signal()

    def __init__(self, stops_within_wait: bool) -> None:
        super().__init__()
        self._running = True
        self._stops_within_wait = stops_within_wait
        self.cancel_requested = False

    def isRunning(self) -> bool:  # noqa: N802 — mirrors QThread API
        return self._running

    def cancel(self) -> None:
        self.cancel_requested = True

    def wait(self, _ms: int) -> bool:
        if self._stops_within_wait:
            self._running = False
        return not self._running

    def finish(self) -> None:
        self._running = False
        self.finished.emit()


def _window_with_worker(worker):
    from netdiag.gui.main_window import MainWindow
    window = MainWindow()
    window.show()
    window._worker = worker
    worker.finished.connect(window._on_thread_finished)  # same order as _on_run_requested
    return window


class TestSafeShutdown:
    @patch("netdiag.gui.main_window.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes)
    def test_close_is_deferred_while_worker_still_running(self, _ask, qapp):
        worker = _FakeWorker(stops_within_wait=False)
        window = _window_with_worker(worker)

        event = QCloseEvent()
        window.closeEvent(event)
        assert worker.cancel_requested
        assert not event.isAccepted()           # thread still running: must not be destroyed
        assert window.isVisible()
        assert "Closing" in window._status_dot.text()

        second = QCloseEvent()
        window.closeEvent(second)               # repeated close while waiting: no second prompt
        assert not second.isAccepted()
        assert _ask.call_count == 1

        worker.finish()                         # current step returns -> window closes itself
        assert window._worker is None
        assert not window.isVisible()
        assert window._log_handler not in window._logger.handlers

    @patch("netdiag.gui.main_window.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes)
    def test_close_accepted_when_worker_stops_in_time(self, _ask, qapp):
        window = _window_with_worker(_FakeWorker(stops_within_wait=True))
        event = QCloseEvent()
        window.closeEvent(event)
        assert event.isAccepted()

    @patch("netdiag.gui.main_window.QMessageBox.question", return_value=QMessageBox.StandardButton.No)
    def test_close_declined_keeps_scan_running(self, _ask, qapp):
        worker = _FakeWorker(stops_within_wait=False)
        window = _window_with_worker(worker)
        event = QCloseEvent()
        window.closeEvent(event)
        assert not event.isAccepted()
        assert not worker.cancel_requested
        window._worker = None
        window.close()


class TestPartialResultsOnCancel:
    def test_worker_emits_partial_report_on_cancel(self, qapp, sample_result):
        from netdiag.gui.workers import ScanWorker
        worker = ScanWorker("example.com", mode="diagnose", timeout=1)

        def second_step():
            worker.cancel()  # user presses Cancel while step 2 runs
            return sample_result

        steps = [("one", lambda: sample_result), ("two", second_step), ("three", lambda: sample_result)]
        aborted, completed = [], []
        worker.aborted.connect(lambda msg, report: aborted.append((msg, report)))
        worker.completed.connect(completed.append)
        with patch.object(ScanWorker, "_steps", return_value=steps):
            worker.run()  # run synchronously in this thread

        assert completed == []
        assert len(aborted) == 1
        message, report = aborted[0]
        assert "cancelled" in message.lower()
        assert report is worker.report
        assert len(report.results) == 2        # step 3 never ran

    def test_main_window_keeps_partial_report_for_export(self, qapp, sample_result, sample_observation):
        from netdiag.gui.main_window import MainWindow
        from netdiag.utils.models import ScanReport
        window = MainWindow()
        partial = ScanReport(target="example.com")
        partial.results.append(sample_result)
        partial.findings.append(sample_observation)

        window._on_aborted("Scan cancelled by user.", partial)
        assert window._report is partial
        assert window.report_panel.btn_json.isEnabled()
        assert "partial" in window.summary_label.text().lower()
        window.close()

    def test_empty_partial_report_does_not_enable_export(self, qapp):
        from netdiag.gui.main_window import MainWindow
        from netdiag.utils.models import ScanReport
        window = MainWindow()
        window._on_aborted("Scan cancelled by user.", ScanReport(target="example.com"))
        assert not window.report_panel.btn_json.isEnabled()
        window.close()
