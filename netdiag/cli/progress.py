# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Single updating progress line for interactive terminals.

Used by the CLI only when stderr is a TTY, so piped or redirected output is
unchanged. The line is rewritten in place with a carriage return (no ANSI
escape codes, so it also works in the classic Windows console) and erased
when the scan finishes, before any report is printed.
"""

from __future__ import annotations

import shutil
from typing import TextIO

from netdiag.runner.events import ScanEvent, ScanFinished, ScanStarted, StepFinished, StepStarted


def stream_is_interactive(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


class ProgressLine:
    """Scan-event consumer that shows `[finished/total] <running step>…`."""

    def __init__(self, stream: TextIO, width: int | None = None) -> None:
        self._stream = stream
        self._width = width
        self._total = 0
        self._finished = 0
        self._running: dict[str, str] = {}   # step id -> label, in start order
        self._shown = 0                        # length of the text currently on the line

    def __call__(self, event: ScanEvent) -> None:
        if isinstance(event, ScanStarted):
            self._total = event.total
        elif isinstance(event, StepStarted):
            self._running[event.step_id] = event.label
        elif isinstance(event, StepFinished):
            self._running.pop(event.step_id, None)
            self._finished += 1
        elif isinstance(event, ScanFinished):
            self.clear()
            return
        else:
            return
        self._render()

    def _render(self) -> None:
        label = next(reversed(self._running.values())) if self._running else ""
        text = f"[{self._finished}/{self._total}] {label}…" if label else f"[{self._finished}/{self._total}]"
        width = self._width or shutil.get_terminal_size(fallback=(80, 24)).columns
        text = text[: max(1, width - 1)]           # never wrap onto a second line
        padding = " " * max(0, self._shown - len(text))
        self._write(f"\r{text}{padding}")
        self._shown = len(text)

    def clear(self) -> None:
        if self._shown:
            self._write("\r" + " " * self._shown + "\r")
            self._shown = 0

    def _write(self, text: str) -> None:
        try:
            self._stream.write(text)
            self._stream.flush()
        except (OSError, ValueError):
            pass   # progress is best effort (e.g. closed or broken stream)
