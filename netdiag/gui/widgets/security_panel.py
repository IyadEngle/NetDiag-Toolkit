# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Security tab: scrollable list of security check results."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from netdiag.gui.styles import status_colors
from netdiag.utils.models import SecurityFinding


class _FindingCard(QFrame):
    """One security finding: badge, title, description, evidence, recommendation."""

    def __init__(self, finding: SecurityFinding, theme: str, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("FindingCard")
        fg, bg = status_colors(finding.status.value, theme)
        self.setStyleSheet(f"QFrame#FindingCard {{ border-left: 3px solid {fg}; }}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 10)
        layout.setSpacing(4)

        header = QHBoxLayout()
        badge = QLabel(f"{finding.severity.value} · {finding.status.value}")
        badge.setStyleSheet(
            f"color: {fg}; background: {bg}; border-radius: 4px;"
            f"padding: 1px 8px; font-weight: 600; font-size: 11px;"
        )
        header.addWidget(badge)
        title = QLabel(finding.title)
        title.setWordWrap(True)
        f = title.font()
        f.setBold(True)
        title.setFont(f)
        header.addWidget(title, stretch=1)
        layout.addLayout(header)

        desc = QLabel(finding.description)
        desc.setObjectName("Detail")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        layout.addWidget(self._line("Evidence", finding.evidence, theme))

        rec = QLabel(f"→ {finding.recommendation}")
        rec.setWordWrap(True)
        layout.addWidget(rec)

        meta = QLabel(f"test: {finding.test_name} · confidence: {finding.confidence.value}")
        meta.setObjectName("Muted")
        layout.addWidget(meta)

    @staticmethod
    def _line(label: str, text: str, theme: str) -> QLabel:
        lbl = QLabel(f"{label}: {text}")
        lbl.setObjectName("Evidence")
        lbl.setWordWrap(True)
        return lbl


class SecurityPanel(QWidget):
    """Scrollable list of SecurityFinding cards with a result counter."""

    def __init__(self, theme: str = "dark", parent=None) -> None:
        super().__init__(parent)
        self._theme = theme
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.count_label = QLabel("No security results yet.")
        self.count_label.setObjectName("Muted")
        layout.addWidget(self.count_label)

        self._container = QWidget()
        self._list_layout = QVBoxLayout(self._container)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(8)
        self._list_layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self._container)
        layout.addWidget(scroll, stretch=1)

        self._findings: list[SecurityFinding] = []   # in display order
        self._orders: list[int | None] = []          # plan positions, parallel to _findings

    # -- API -------------------------------------------------------------
    def set_theme(self, theme: str) -> None:
        """Re-render all finding cards with the new theme colors."""
        self._theme = theme
        entries = list(zip(self._findings, self._orders))
        self.clear()
        for finding, order in entries:
            self.add_finding(finding, order)

    def begin_run(self) -> None:
        self.clear()

    def clear(self) -> None:
        self._findings = []
        self._orders = []
        while self._list_layout.count() > 1:
            item = self._list_layout.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget:
                widget.deleteLater()
        self.count_label.setText("No security results yet.")

    def add_finding(self, finding: SecurityFinding, order: int | None = None) -> None:
        """Add a finding card. `order` (its position in the scan plan) keeps cards in
        plan order although parallel checks finish in any order; without it the
        card is appended."""
        index = len(self._findings)
        if order is not None:
            index = next((i for i, existing in enumerate(self._orders)
                          if existing is not None and existing > order), index)
        self._findings.insert(index, finding)
        self._orders.insert(index, order)
        card = _FindingCard(finding, self._theme)
        # cards occupy layout slots 0..n-1, followed by the trailing stretch
        self._list_layout.insertWidget(index, card)
        self._update_count()

    def _update_count(self) -> None:
        failures = sum(1 for f in self._findings if f.status.value == "FAIL")
        observations = sum(1 for f in self._findings if f.status.value == "OBSERVATION")
        inconclusive = sum(1 for f in self._findings if f.status.value == "INCONCLUSIVE")
        self.count_label.setText(
            f"{len(self._findings)} result(s): "
            f"{failures} failure(s), {observations} observation(s), "
            f"{inconclusive} inconclusive"
        )
