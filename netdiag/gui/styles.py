# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Theme palettes, stylesheet generation, and status color mapping.

This module is intentionally Qt-free (pure Python strings) so the status
mapping can be unit tested without PySide6 installed.
"""

from __future__ import annotations

PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "bg":          "#0d1117",
        "bg_alt":      "#161b22",
        "bg_card":     "#161b22",
        "bg_input":    "#0d1117",
        "border":      "#30363d",
        "text":        "#c9d1d9",
        "text_muted":  "#8b949e",
        "accent":      "#58a6ff",
        "accent_hover": "#79c0ff",
        "green":       "#3fb950",
        "red":         "#f85149",
        "amber":       "#d29922",
        "gray":        "#8b949e",
        "pass_bg":     "#12261e",
        "fail_bg":     "#2d1517",
        "warn_bg":     "#2a2113",
        "neutral_bg":  "#1b2027",
        "run_bg":      "#12233a",
        "menu_bg":     "#1c2128",
    },
    "light": {
        "bg":          "#ffffff",
        "bg_alt":      "#f6f8fa",
        "bg_card":     "#ffffff",
        "bg_input":    "#ffffff",
        "border":      "#d0d7de",
        "text":        "#1f2328",
        "text_muted":  "#656d76",
        "accent":      "#0969da",
        "accent_hover": "#218bff",
        "green":       "#1a7f37",
        "red":         "#cf222e",
        "amber":       "#9a6700",
        "gray":        "#656d76",
        "pass_bg":     "#dafbe1",
        "fail_bg":     "#ffebe9",
        "warn_bg":     "#fff8c5",
        "neutral_bg":  "#eff2f5",
        "run_bg":      "#ddf4ff",
        "menu_bg":     "#f6f8fa",
    },
}

# status -> (palette fg key, palette bg key)
_STATUS_MAP: dict[str, tuple[str, str]] = {
    "PASS":         ("green", "pass_bg"),
    "FAIL":         ("red", "fail_bg"),
    "ERROR":        ("red", "fail_bg"),
    "WARN":         ("amber", "warn_bg"),
    "OBSERVATION":  ("amber", "warn_bg"),
    "SKIP":         ("gray", "neutral_bg"),
    "INCONCLUSIVE": ("gray", "neutral_bg"),
    "PENDING":      ("text_muted", "neutral_bg"),
    "RUNNING":      ("accent", "run_bg"),
}


def status_colors(status: str, theme: str = "dark") -> tuple[str, str]:
    """Return (foreground_hex, background_hex) for a status name. Unknown -> PENDING style."""
    palette = PALETTES[theme]
    fg_key, bg_key = _STATUS_MAP.get(status, _STATUS_MAP["PENDING"])
    return palette[fg_key], palette[bg_key]


def build_stylesheet(theme: str = "dark") -> str:
    """Generate the application-wide QSS for the given theme."""
    p = PALETTES[theme]
    return f"""
QMainWindow, QDialog {{ background: {p['bg']}; color: {p['text']}; }}
QWidget {{ color: {p['text']}; font-size: 13px; }}
QLabel#HeaderTitle {{ font-size: 17px; font-weight: 700; color: {p['text']}; }}
QLabel#HeaderVersion {{ color: {p['text_muted']}; font-size: 12px; }}
QLabel#Muted {{ color: {p['text_muted']}; }}
QLabel#Evidence {{ color: {p['text_muted']}; }}
QLabel#Detail {{ color: {p['text_muted']}; font-size: 12px; }}

QFrame#HeaderFrame {{ background: {p['bg_alt']}; border-bottom: 1px solid {p['border']}; }}
QFrame#ResultCard {{ background: {p['bg_card']}; border: 1px solid {p['border']}; border-radius: 6px; }}
QFrame#FindingCard {{ background: {p['bg_card']}; border: 1px solid {p['border']}; border-radius: 6px; }}
QFrame#SummaryBadge {{ background: {p['bg_alt']}; border: 1px solid {p['border']}; border-radius: 4px; }}

QLineEdit, QComboBox, QSpinBox {{
    background: {p['bg_input']}; border: 1px solid {p['border']};
    border-radius: 4px; padding: 6px 8px; selection-background-color: {p['accent']};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {p['accent']}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {p['menu_bg']}; border: 1px solid {p['border']};
    selection-background-color: {p['accent']}; selection-color: #ffffff;
}}

QPushButton {{
    background: {p['bg_alt']}; border: 1px solid {p['border']};
    border-radius: 4px; padding: 7px 14px; font-weight: 600;
}}
QPushButton:hover {{ border-color: {p['accent']}; }}
QPushButton:disabled {{ color: {p['text_muted']}; background: {p['bg_alt']}; border-color: {p['border']}; }}
QPushButton[accent="true"] {{ background: {p['accent']}; color: #ffffff; border-color: {p['accent']}; }}
QPushButton[accent="true"]:hover {{ background: {p['accent_hover']}; }}
QPushButton[accent="true"]:disabled {{ background: {p['bg_alt']}; color: {p['text_muted']}; }}

QTabWidget::pane {{ border: 1px solid {p['border']}; border-radius: 0px; background: {p['bg']}; }}
QTabBar::tab {{
    background: {p['bg_alt']}; color: {p['text_muted']}; padding: 7px 18px;
    border: 1px solid {p['border']}; border-bottom: none;
}}
QTabBar::tab:selected {{ color: {p['text']}; border-bottom: 2px solid {p['accent']}; }}

QTableWidget {{
    background: {p['bg']}; alternate-background-color: {p['bg_alt']};
    gridline-color: {p['border']}; border: 1px solid {p['border']};
}}
QHeaderView::section {{
    background: {p['bg_alt']}; color: {p['text_muted']}; border: none;
    border-right: 1px solid {p['border']}; border-bottom: 1px solid {p['border']};
    padding: 6px 8px; font-weight: 600;
}}
QTableCornerButton::section {{ background: {p['bg_alt']}; border: none; }}

QPlainTextEdit {{ background: {p['bg_input']}; border: 1px solid {p['border']}; border-radius: 4px; }}
QPlainTextEdit[log="true"] {{
    font-family: "Consolas", "Courier New", monospace; font-size: 12px; color: {p['text_muted']};
}}
QProgressBar {{
    background: {p['bg_alt']}; border: 1px solid {p['border']};
    border-radius: 4px; text-align: center; color: {p['text_muted']};
}}
QProgressBar::chunk {{ background: {p['accent']}; border-radius: 3px; }}

QMenuBar {{ background: {p['bg_alt']}; border-bottom: 1px solid {p['border']}; }}
QMenuBar::item:selected {{ background: {p['accent']}; color: #ffffff; }}
QMenu {{ background: {p['menu_bg']}; border: 1px solid {p['border']}; }}
QMenu::item:selected {{ background: {p['accent']}; color: #ffffff; }}

QScrollBar:vertical {{ background: {p['bg']}; width: 10px; border: none; }}
QScrollBar::handle:vertical {{ background: {p['border']}; border-radius: 5px; min-height: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0px; }}
QScrollBar:horizontal {{ background: {p['bg']}; height: 10px; border: none; }}
QScrollBar::handle:horizontal {{ background: {p['border']}; border-radius: 5px; min-width: 24px; }}

QStatusBar {{ background: {p['bg_alt']}; color: {p['text_muted']}; border-top: 1px solid {p['border']}; }}
QToolTip {{ background: {p['menu_bg']}; color: {p['text']}; border: 1px solid {p['border']}; }}
"""
