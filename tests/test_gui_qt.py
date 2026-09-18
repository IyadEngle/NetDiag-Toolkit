# Copyright (c) 2026 Iyad Engle. All rights reserved.

"""GUI tests that require PySide6. Run headless in CI via QT_QPA_PLATFORM=offscreen."""

import os

import pytest

# Must be set before QApplication is created
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

qt_widgets = pytest.importorskip("PySide6.QtWidgets", reason="PySide6 not installed")
pytestmark = pytest.mark.gui

from PySide6.QtWidgets import QApplication  # noqa: E402


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
        from netdiag.gui.widgets.diagnostic_panel import DiagnosticPanel
        panel = DiagnosticPanel(theme="dark")
        panel.add_diagnostic(sample_result)
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
        from netdiag.gui.widgets.report_panel import ReportPanel
        from netdiag.gui.settings import GuiSettings
        panel = ReportPanel(GuiSettings(), lambda: None)
        assert not panel.btn_json.isEnabled()

    def test_report_panel_enabled_with_report(self, qapp, sample_report):
        from netdiag.gui.widgets.report_panel import ReportPanel
        from netdiag.gui.settings import GuiSettings
        panel = ReportPanel(GuiSettings(), lambda: sample_report)
        panel.set_has_report(True)
        assert panel.btn_json.isEnabled()
