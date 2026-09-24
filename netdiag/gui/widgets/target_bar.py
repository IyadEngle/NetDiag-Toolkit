# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Target input row with validation and the three run actions."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget

from netdiag.utils.validation import validate_target


class TargetBar(QWidget):
    """Target input + Run Diagnostics / Security Audit / Full Scan buttons."""

    run_requested = Signal(str, str)  # (target, mode)

    def __init__(self, default_target: str = "", parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Target hostname or IP (e.g. example.com or 1.1.1.1)")
        self.input.returnPressed.connect(lambda: self._request("diagnose"))
        layout.addWidget(self.input, stretch=1)

        self.btn_diagnose = QPushButton("Run Diagnostics")
        self.btn_diagnose.setProperty("accent", True)
        self.btn_diagnose.clicked.connect(lambda: self._request("diagnose"))
        layout.addWidget(self.btn_diagnose)

        self.btn_security = QPushButton("Security Audit")
        self.btn_security.clicked.connect(lambda: self._request("security"))
        layout.addWidget(self.btn_security)

        self.btn_full = QPushButton("Full Scan")
        self.btn_full.clicked.connect(lambda: self._request("full"))
        layout.addWidget(self.btn_full)

        self.error_label = QLabel("")
        self.error_label.setObjectName("Muted")
        layout.addWidget(self.error_label)

        if default_target:
            self.input.setText(default_target)

    # -- API -------------------------------------------------------------
    def validate(self, text: str) -> tuple[bool, str]:
        """Public so it can be unit tested directly."""
        return validate_target(text)

    def set_busy(self, busy: bool) -> None:
        """Disable inputs and run buttons while a scan is running."""
        for widget in (self.input, self.btn_diagnose, self.btn_security, self.btn_full):
            widget.setEnabled(not busy)

    def set_target(self, target: str) -> None:
        self.input.setText(target)

    def _request(self, mode: str) -> None:
        ok, normalized_or_error = self.validate(self.input.text())
        if not ok:
            self.error_label.setText(normalized_or_error)
            return
        self.error_label.clear()
        self.run_requested.emit(normalized_or_error, mode)
