# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""GUI settings persistence (QSettings) with safe defaults."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings, QStandardPaths

_ORG = "IyadEngle"
_APP = "NetDiag-Toolkit"

_THEMES = ("dark", "light")
_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


def default_report_dir() -> str:
    """Documents directory if available, otherwise the user home."""
    docs = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
    return docs if docs else str(Path.home())


class GuiSettings:
    """Typed wrapper over QSettings. All reads are defensive with defaults."""

    def __init__(self) -> None:
        self._q = QSettings(_ORG, _APP)

    # -- timeout (seconds, applied to ping/TCP where supported) ------------
    def timeout(self) -> int:
        try:
            value = int(str(self._q.value("diagnostics/timeout", 5)))
        except (TypeError, ValueError):
            value = 5
        return min(max(value, 1), 60)

    def set_timeout(self, seconds: int) -> None:
        self._q.setValue("diagnostics/timeout", min(max(int(seconds), 1), 60))

    # -- default target ----------------------------------------------------
    def default_target(self) -> str:
        return str(self._q.value("general/default_target", ""))

    def set_default_target(self, target: str) -> None:
        self._q.setValue("general/default_target", target.strip())

    # -- theme ---------------------------------------------------------------
    def theme(self) -> str:
        theme = str(self._q.value("appearance/theme", "dark"))
        return theme if theme in _THEMES else "dark"

    def set_theme(self, theme: str) -> None:
        if theme in _THEMES:
            self._q.setValue("appearance/theme", theme)

    # -- logging level -------------------------------------------------------
    def log_level(self) -> str:
        level = str(self._q.value("logging/level", "WARNING")).upper()
        return level if level in _LOG_LEVELS else "WARNING"

    def set_log_level(self, level: str) -> None:
        level = level.upper()
        if level in _LOG_LEVELS:
            self._q.setValue("logging/level", level)

    # -- report output directory ----------------------------------------------
    def report_dir(self) -> str:
        value = str(self._q.value("reports/output_dir", ""))
        return value if value else default_report_dir()

    def set_report_dir(self, directory: str) -> None:
        self._q.setValue("reports/output_dir", directory)
