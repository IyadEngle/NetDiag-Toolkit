# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Main application window: header, target bar, panels, reports, log, settings."""

from __future__ import annotations

import logging

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from netdiag import __version__
from netdiag.gui import GUI_VERSION
from netdiag.gui.app import resource_path
from netdiag.gui.settings import GuiSettings
from netdiag.gui.styles import build_stylesheet
from netdiag.gui.widgets.diagnostic_panel import DiagnosticPanel
from netdiag.gui.widgets.report_panel import ReportPanel
from netdiag.gui.widgets.security_panel import SecurityPanel
from netdiag.gui.widgets.target_bar import TargetBar
from netdiag.gui.workers import ScanWorker
from netdiag.utils.logging import setup_logging
from netdiag.utils.models import ScanReport


class QtLogHandler(logging.Handler):
    """logging.Handler that re-emits formatted records as a Qt signal.

    Safe across threads: Signal.emit from a worker thread is delivered to
    GUI slots via a queued connection."""

    class _Emitter(QObject):
        message = Signal(str)

    def __init__(self) -> None:
        logging.Handler.__init__(self)
        self._emitter = QtLogHandler._Emitter()
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    @property
    def message(self):  # convenience passthrough
        return self._emitter.message

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._emitter.message.emit(self.format(record))
        except Exception:
            self.handleError(record)


class PreferencesDialog(QDialog):
    """Settings: timeout, default target, theme, log level, report directory."""

    def __init__(self, settings: GuiSettings, parent=None) -> None:
        super().__init__(parent)
        self._settings = settings
        self.setWindowTitle("Preferences")
        self.setMinimumWidth(420)

        form = QFormLayout(self)
        form.setSpacing(10)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(settings.timeout())
        self.timeout_spin.setSuffix(" s")
        form.addRow("Test timeout", self.timeout_spin)

        self.target_edit = QLineEdit(settings.default_target())
        self.target_edit.setPlaceholderText("e.g. example.com")
        form.addRow("Default target", self.target_edit)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["dark", "light"])
        self.theme_combo.setCurrentText(settings.theme())
        form.addRow("Theme", self.theme_combo)

        self.log_combo = QComboBox()
        self.log_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_combo.setCurrentText(settings.log_level())
        form.addRow("Logging level", self.log_combo)

        dir_row = QHBoxLayout()
        self.dir_edit = QLineEdit(settings.report_dir())
        dir_row.addWidget(self.dir_edit, stretch=1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        dir_row.addWidget(browse)
        form.addRow("Report folder", dir_row)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Report folder", self.dir_edit.text())
        if path:
            self.dir_edit.setText(path)

    def apply(self) -> None:
        self._settings.set_timeout(self.timeout_spin.value())
        self._settings.set_default_target(self.target_edit.text())
        self._settings.set_theme(self.theme_combo.currentText())
        self._settings.set_log_level(self.log_combo.currentText())
        self._settings.set_report_dir(self.dir_edit.text())


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NetDiag-Toolkit")
        self.setWindowIcon(QIcon(str(resource_path("app.ico"))))
        self.resize(980, 680)
        self.setMinimumSize(820, 560)

        self._settings = GuiSettings()
        self._theme = self._settings.theme()
        self._report: ScanReport | None = None
        self._worker: ScanWorker | None = None
        self._close_pending = False

        self._log_handler = QtLogHandler()
        self._logger = setup_logging()
        self._apply_log_level(self._settings.log_level())

        self._build_menu()
        self._build_ui()
        self._connect_log()
        self.apply_theme(self._theme)

        default_target = self._settings.default_target()
        if default_target:
            self.target_bar.set_target(default_target)

    # ─── UI construction ─────────────────────────────────────────────────
    def _build_menu(self) -> None:
        menu_file = self.menuBar().addMenu("&File")
        act_exit = QAction("E&xit", self)
        act_exit.triggered.connect(self.close)
        menu_file.addAction(act_exit)

        menu_settings = self.menuBar().addMenu("&Settings")
        act_prefs = QAction("&Preferences…", self)
        act_prefs.triggered.connect(self._open_preferences)
        menu_settings.addAction(act_prefs)

        menu_help = self.menuBar().addMenu("&Help")
        act_about = QAction("&About", self)
        act_about.triggered.connect(self._show_about)
        menu_help.addAction(act_about)

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 10, 14, 10)
        root.setSpacing(10)

        # -- header --------------------------------------------------------
        header_frame = QFrame()
        header_frame.setObjectName("HeaderFrame")
        header = QHBoxLayout(header_frame)
        header.setContentsMargins(14, 10, 14, 10)

        title = QLabel("🛡️ NetDiag-Toolkit")
        title.setObjectName("HeaderTitle")
        header.addWidget(title)

        version = QLabel(f"v{GUI_VERSION} · core {__version__}")
        version.setObjectName("HeaderVersion")
        header.addWidget(version)
        header.addStretch(1)

        self._status_dot = QLabel("● Ready")
        self._status_dot.setObjectName("Muted")
        header.addWidget(self._status_dot)

        root.addWidget(header_frame)

        # -- target bar ------------------------------------------------------
        self.target_bar = TargetBar(default_target=self._settings.default_target())
        self.target_bar.run_requested.connect(self._on_run_requested)
        root.addWidget(self.target_bar)

        # -- progress row ------------------------------------------------------
        progress_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # indeterminate
        self.progress.setVisible(False)
        self.progress.setMaximumHeight(14)
        progress_row.addWidget(self.progress, stretch=1)

        self.progress_label = QLabel("")
        self.progress_label.setObjectName("Muted")
        progress_row.addWidget(self.progress_label)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setVisible(False)
        self.btn_cancel.clicked.connect(self._on_cancel)
        progress_row.addWidget(self.btn_cancel)

        self.summary_label = QLabel("")
        self.summary_label.setObjectName("Muted")
        progress_row.addWidget(self.summary_label)
        root.addLayout(progress_row)

        # -- tabs: diagnostics / security -------------------------------------
        self.diag_panel = DiagnosticPanel(theme=self._theme)
        self.sec_panel = SecurityPanel(theme=self._theme)
        tabs = QTabWidget()
        tabs.addTab(self.diag_panel, "Diagnostics")
        tabs.addTab(self.sec_panel, "Security")
        root.addWidget(tabs, stretch=1)

        # -- reports -------------------------------------------------------------
        self.report_panel = ReportPanel(self._settings, lambda: self._report)
        root.addWidget(self.report_panel)

        # -- activity log ----------------------------------------------------------
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setProperty("log", True)
        self.log_view.setMaximumBlockCount(1000)
        self.log_view.setPlaceholderText("Activity log…")
        self.log_view.setFixedHeight(120)
        root.addWidget(self.log_view)

        self.setCentralWidget(central)

    # ─── scan lifecycle ─────────────────────────────────────────────────
    def _on_run_requested(self, target: str, mode: str) -> None:
        if self._worker is not None:
            return  # a scan is already running; TargetBar is disabled anyway

        mode_names = {"diagnose": "diagnostics", "security": "security audit", "full": "full scan"}
        self._report = ScanReport(target=target)
        self._append_log(f"Starting {mode_names[mode]} against {target}")
        self.diag_panel.begin_run()
        self.sec_panel.begin_run()
        self.report_panel.set_has_report(False)
        self.summary_label.clear()
        self.target_bar.set_busy(True)
        self.btn_cancel.setVisible(True)
        self.progress.setVisible(True)
        self._status_dot.setText("● Running")

        worker = ScanWorker(target, mode=mode, timeout=self._settings.timeout())
        worker.progress.connect(self._on_progress)
        worker.diagnostic_result.connect(self.diag_panel.add_diagnostic)
        worker.security_finding.connect(self.sec_panel.add_finding)
        worker.completed.connect(self._on_completed)
        worker.aborted.connect(self._on_aborted)
        worker.finished.connect(worker.deleteLater)
        worker.finished.connect(self._on_thread_finished)
        self._worker = worker
        worker.start()

    def _on_progress(self, message: str) -> None:
        self.progress_label.setText(message)
        self._append_log(message)

    def _on_completed(self, report: ScanReport) -> None:
        self._report = report
        self._finish_run()
        self.summary_label.setText(
            f"{report.passed} passed · {report.failed} failed · "
            f"{len(report.findings)} security result(s) "
            f"({report.security_failures} failure(s))"
        )
        self.report_panel.set_has_report(True)
        self._append_log(
            f"Completed: {report.passed} passed, {report.failed} failed, "
            f"{report.errors} errors, {len(report.findings)} security result(s)."
        )

    def _on_aborted(self, message: str, report: ScanReport | None = None) -> None:
        self._append_log(message)
        self._finish_run()
        if report is None:
            return
        # Keep whatever completed before cancellation so it can still be exported.
        self._report = report
        if report.results or report.findings:
            self.summary_label.setText(
                f"Cancelled — partial results: {report.passed} passed · {report.failed} failed · "
                f"{len(report.findings)} security result(s)"
            )
            self.report_panel.set_has_report(True)
            self._append_log(
                f"Partial results kept: {len(report.results)} diagnostic(s), "
                f"{len(report.findings)} security result(s)."
            )

    def _on_thread_finished(self) -> None:
        self._worker = None

    def _on_cancel(self) -> None:
        if self._worker is not None:
            self._append_log("Cancellation requested — stopping the running tests…")
            self._worker.cancel()
            self.btn_cancel.setEnabled(False)

    def _finish_run(self) -> None:
        self.progress.setVisible(False)
        self.progress_label.clear()
        self.btn_cancel.setVisible(False)
        self.btn_cancel.setEnabled(True)
        self.target_bar.set_busy(False)
        self._status_dot.setText("● Ready")

    # ─── settings / theme ────────────────────────────────────────────────
    def _open_preferences(self) -> None:
        dialog = PreferencesDialog(self._settings, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            dialog.apply()
            self.apply_theme(self._settings.theme())
            self._apply_log_level(self._settings.log_level())
            self._append_log(f"Settings updated (theme={self._settings.theme()}, "
                             f"level={self._settings.log_level()})")

    def apply_theme(self, theme: str) -> None:
        self._theme = theme
        app = QApplication.instance()
        if isinstance(app, QApplication):
            app.setStyleSheet(build_stylesheet(theme))
        self.diag_panel.set_theme(theme)
        self.sec_panel.set_theme(theme)

    def _apply_log_level(self, level: str) -> None:
        numeric = getattr(logging, level, logging.WARNING)
        self._logger.setLevel(numeric)
        self._log_handler.setLevel(numeric)
        if self._log_handler not in self._logger.handlers:
            self._logger.addHandler(self._log_handler)

    def _connect_log(self) -> None:
        self._log_handler.message.connect(self._append_log)

    def _append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)

    # ─── misc ─────────────────────────────────────────────────────────────
    def _show_about(self) -> None:
        QMessageBox.about(
            self, "About NetDiag-Toolkit",
            f"<b>NetDiag-Toolkit</b><br>GUI {GUI_VERSION} · core {__version__}<br><br>"
            "Network diagnostics and security configuration auditing.<br>"
            "Read-only: no exploitation, no credential attacks, no remediation.<br><br>"
            "Copyright (c) 2026 Iyad Engle — MIT License"
        )

    def closeEvent(self, event) -> None:  # noqa: N802 — Qt naming
        worker = self._worker
        if worker is not None and worker.isRunning():
            if self._close_pending:
                event.ignore()  # already waiting for the current step to finish
                return
            answer = QMessageBox.question(
                self, "Scan in progress",
                "A scan is still running. Cancel it and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            worker.cancel()
            if not worker.wait(2000):
                # Never destroy a QThread that is still running (Qt aborts the
                # process). Cancellation kills running commands at once, but a
                # network check can take a moment to time out: close again when
                # the worker has finished.
                self._close_pending = True
                self._status_dot.setText("● Closing…")
                self._append_log("Waiting for the running tests to stop before exiting…")
                central = self.centralWidget()
                if central is not None:
                    central.setEnabled(False)
                worker.finished.connect(self.close)
                event.ignore()
                return
        self._detach_log_handler()
        event.accept()

    def _detach_log_handler(self) -> None:
        """Stop routing 'netdiag' log records to this window once it closes."""
        if self._log_handler in self._logger.handlers:
            self._logger.removeHandler(self._log_handler)
