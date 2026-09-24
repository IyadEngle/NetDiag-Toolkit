# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Diagnostics tab: summary card row + results table."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netdiag.gui.styles import status_colors
from netdiag.gui.widgets.result_card import ResultCard
from netdiag.utils.models import DiagnosticResult

# Card key -> display title (matches worker step outputs)
_CARDS: list[tuple[str, str]] = [
    ("ping", "Ping"),
    ("dns", "DNS"),
    ("https", "HTTPS"),
    ("tcp", "TCP"),
    ("mtu", "MTU"),
    ("gateway", "Gateway"),
    ("trace", "Traceroute"),
]


def _card_key_for(result: DiagnosticResult) -> str | None:
    name = result.test_name
    if name in ("icmp_ping", "dns_resolution", "https_connectivity",
                "path_mtu", "gateway_detection", "traceroute"):
        return {
            "icmp_ping": "ping", "dns_resolution": "dns",
            "https_connectivity": "https", "path_mtu": "mtu",
            "gateway_detection": "gateway", "traceroute": "trace",
        }[name]
    if name == "tcp_connect":
        try:
            port = int(result.target.rsplit(":", 1)[-1])
        except (ValueError, AttributeError):
            return None
        return "tcp" if port == 443 else None
    return None


class DiagnosticPanel(QWidget):
    """Summary cards for the seven headline tests + full results table."""

    def __init__(self, theme: str = "dark", parent=None) -> None:
        super().__init__(parent)
        self._theme = theme
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # -- summary card row -------------------------------------------------
        cards_row = QHBoxLayout()
        cards_row.setSpacing(8)
        self._cards: dict[str, ResultCard] = {}
        for key, title in _CARDS:
            card = ResultCard(title, theme=self._theme)
            self._cards[key] = card
            cards_row.addWidget(card)
        cards_row.addStretch(1)
        layout.addLayout(cards_row)

        # -- results table ----------------------------------------------------
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Status", "Test", "Target", "Duration", "Evidence"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 100)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(1, 170)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, 150)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(3, 85)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table, stretch=1)

    # -- API -------------------------------------------------------------
    def set_theme(self, theme: str) -> None:
        self._theme = theme
        for card in self._cards.values():
            card.set_theme(theme)

    def begin_run(self) -> None:
        self.clear()

    def clear(self) -> None:
        self.table.setRowCount(0)
        for card in self._cards.values():
            card.set_status("PENDING", "")

    def add_diagnostic(self, result: DiagnosticResult) -> None:
        self._append_row(result)
        key = _card_key_for(result)
        if key:
            self._cards[key].set_status(result.status.value, result.evidence)

    # -- internals -----------------------------------------------------------
    def _append_row(self, result: DiagnosticResult) -> None:
        fg, bg = status_colors(result.status.value, self._theme)
        row = self.table.rowCount()
        self.table.insertRow(row)

        status_item = QTableWidgetItem(result.status.value)
        status_item.setForeground(QBrush(QColor(fg)))
        status_item.setBackground(QBrush(QColor(bg)))
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 0, status_item)

        self.table.setItem(row, 1, QTableWidgetItem(result.test_name))
        self.table.setItem(row, 2, QTableWidgetItem(result.target))
        self.table.setItem(row, 3, QTableWidgetItem(f"{result.duration_ms:.0f} ms"))
        evidence_item = QTableWidgetItem(result.evidence)
        evidence_item.setToolTip(result.evidence)
        self.table.setItem(row, 4, evidence_item)

        if result.error:
            for col in range(5):
                item = self.table.item(row, col)
                if item:
                    item.setToolTip(f"{item.toolTip()}\nError: {result.error}".strip())
