# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Compact summary card showing one diagnostic test's latest status."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout

from netdiag.gui.styles import status_colors


class ResultCard(QFrame):
    """Summary card: test name, colored status pill, short evidence line."""

    def __init__(self, title: str, theme: str = "dark", parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("ResultCard")
        self.setMinimumSize(112, 74)
        self._title = title
        self._theme = theme
        self._last_status = "PENDING"
        self._last_detail = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        self._name_label = QLabel(title)
        self._name_label.setObjectName("Muted")
        layout.addWidget(self._name_label)

        self._pill = QLabel("—")
        self._pill.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._pill)

        self._detail = QLabel("")
        self._detail.setObjectName("Detail")
        self._detail.setWordWrap(False)
        layout.addWidget(self._detail, stretch=1)

        self.set_status("PENDING", "")

    # -- API -------------------------------------------------------------
    def set_status(self, status: str, detail: str = "") -> None:
        self._last_status = status
        self._last_detail = detail or ""
        fg, bg = status_colors(status, self._theme)
        self._pill.setText(status if status != "PENDING" else "—")
        self._pill.setStyleSheet(
            f"color: {fg}; background: {bg}; border-radius: 4px;"
            f"padding: 1px 8px; font-weight: 600; font-size: 11px;"
        )
        text = self._last_detail
        metrics = self._detail.fontMetrics()
        self._detail.setText(metrics.elidedText(text, Qt.TextElideMode.ElideRight, 150))
        self._detail.setToolTip(text)

    def set_theme(self, theme: str) -> None:
        self._theme = theme
        self.set_status(self._last_status, self._last_detail)
