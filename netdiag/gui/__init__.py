# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""
NetDiag-Toolkit GUI (PySide6).

This package must remain importable WITHOUT PySide6 installed so that the
CLI and unit tests are unaffected. Qt imports happen only inside app.py,
main_window.py, workers.py, and the widget modules.
"""

GUI_VERSION = "0.4.0b0"
