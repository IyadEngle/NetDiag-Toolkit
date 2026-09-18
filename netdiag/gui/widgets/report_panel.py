# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Report export row: JSON / CSV / HTML buttons over the existing exporters."""

from __future__ import annotations

from typing import Callable

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QWidget,
)

from netdiag.utils.models import ScanReport


class ReportPanel(QWidget):
    """Exports the current ScanReport using netdiag.reports (no duplication)."""

    def __init__(self, settings, get_report: Callable[[], ScanReport | None],
                 parent=None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._get_report = get_report

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.btn_json = QPushButton("Export JSON")
        self.btn_csv = QPushButton("Export CSV")
        self.btn_html = QPushButton("Export HTML")
        for btn in (self.btn_json, self.btn_csv, self.btn_html):
            btn.setEnabled(False)
            layout.addWidget(btn)

        self.path_label = QLabel("")
        self.path_label.setObjectName("Muted")
        layout.addWidget(self.path_label, stretch=1)

        self.btn_json.clicked.connect(lambda: self._export("json"))
        self.btn_csv.clicked.connect(lambda: self._export("csv"))
        self.btn_html.clicked.connect(lambda: self._export("html"))

    # -- API -------------------------------------------------------------
    def set_has_report(self, has_report: bool) -> None:
        for btn in (self.btn_json, self.btn_csv, self.btn_html):
            btn.setEnabled(has_report)

    # -- internals -----------------------------------------------------------
    def _export(self, kind: str) -> None:
        report = self._get_report()
        if report is None:
            QMessageBox.information(self, "NetDiag", "Run a scan first — there is nothing to export.")
            return

        filters = {
            "json": "JSON report (*.json)",
            "csv": "CSV report (*.csv)",
            "html": "HTML report (*.html)",
        }
        suggested = f"netdiag_report.{kind}"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save report", str(self._settings.report_dir()) + "/" + suggested,
            filters[kind],
        )
        if not path:
            return

        try:
            if kind == "json":
                from netdiag.reports.json_report import export_json
                export_json(report, path)
            elif kind == "csv":
                from netdiag.reports.csv_report import export_csv
                export_csv(report, path)
            else:
                from netdiag.reports.html_report import export_html
                export_html(report, path)
        except Exception as exc:
            QMessageBox.warning(self, "Export failed",
                                f"Could not write the {kind.upper()} report:\n{exc}")
            return

        self.path_label.setText(f"Saved: {path}")
