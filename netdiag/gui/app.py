# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""GUI application entry point (`netdiag-gui`)."""

from __future__ import annotations

import sys
from pathlib import Path


def resource_path(relative: str) -> Path:
    """Resolve a bundled resource path.

    Works both from source and under PyInstaller:
    under PyInstaller, data files land in sys._MEIPASS.
    """
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / "resources" / relative


def main(argv: list[str] | None = None) -> int:
    try:
        from PySide6.QtGui import QIcon
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(
            "PySide6 is required for the NetDiag GUI.\n"
            "Install it with:  pip install netdiag-toolkit[gui]\n"
            "or:               pip install PySide6\n"
            "The CLI remains available as:  netdiag",
            file=sys.stderr,
        )
        return 1

    from netdiag.gui.main_window import MainWindow
    from netdiag.gui.settings import GuiSettings
    from netdiag.gui.styles import build_stylesheet

    settings = GuiSettings()

    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("NetDiag-Toolkit")
    app.setOrganizationName("IyadEngle")
    app.setApplicationDisplayName("NetDiag-Toolkit")
    icon = QIcon(str(resource_path("app.ico")))
    app.setWindowIcon(icon)
    app.setStyleSheet(build_stylesheet(settings.theme()))

    window = MainWindow()
    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
