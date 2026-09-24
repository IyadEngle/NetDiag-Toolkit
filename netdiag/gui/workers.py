# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Background scan worker.

A thin Qt adapter over the shared scan runner: it runs the GUI profile of the
shared scan plan (netdiag.runner.plans.gui_plan, the same step definitions the
CLI uses) on ScanRunner inside a QThread and re-emits runner events as Qt
signals. Steps run in parallel within the plan's dependency and lane rules.

Cancellation is immediate: running system commands (ping, tracert, ...) are
terminated, nothing new starts, and the partial report is delivered.
"""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from netdiag.runner import (
    CancelToken,
    ResultProduced,
    ScanEvent,
    ScanPlan,
    ScanRunner,
    StepStarted,
)
from netdiag.runner.plans import gui_plan
from netdiag.utils.models import DiagnosticResult, ScanReport

# Order key = step position in the plan * stride + item position within the step,
# so a step's several results (e.g. gateway detection + gateway ping) stay together.
ORDER_STRIDE = 1000


class ScanWorker(QThread):
    """Executes a diagnose / security / full scan plan against one target."""

    progress = Signal(str)
    diagnostic_result = Signal(object, int)   # (DiagnosticResult, plan order key)
    security_finding = Signal(object, int)    # (SecurityFinding, plan order key)
    completed = Signal(object)                # ScanReport, in plan order
    aborted = Signal(str, object)             # (message, partial ScanReport)

    def __init__(self, target: str, mode: str = "diagnose",
                 timeout: int = 5, parent=None) -> None:
        super().__init__(parent)
        self._plan = gui_plan(target, mode, timeout)   # type: ignore[arg-type]  # validates mode
        self._token = CancelToken()
        self._step_index = {step.id: index for index, step in enumerate(self._plan.steps)}
        self._items_emitted: dict[str, int] = {}
        self.report = ScanReport(target=target)

    # -- control ------------------------------------------------------------
    def cancel(self) -> None:
        """Cancel the scan: running commands are stopped and nothing new starts."""
        self._token.cancel()

    @property
    def cancelled(self) -> bool:
        return self._token.cancelled

    @property
    def plan(self) -> ScanPlan:
        return self._plan

    @property
    def total_steps(self) -> int:
        return len(self._plan)

    # -- execution ------------------------------------------------------------
    def run(self) -> None:  # noqa: D102 — QThread entry point
        runner = ScanRunner(hide_console_windows=True)   # no console window per ping/tracert
        result = runner.run(self._plan, on_event=self._on_event, cancel_token=self._token)
        self.report = result.report
        if result.cancelled:
            self.progress.emit("Scan cancelled.")
            self.aborted.emit("Scan cancelled by user.", result.report)
        else:
            self.progress.emit("Scan complete.")
            self.completed.emit(result.report)

    def _on_event(self, event: ScanEvent) -> None:
        """Runner events arrive one at a time on this thread; signals queue to the GUI."""
        if isinstance(event, StepStarted):
            self.progress.emit(f"[{event.index}/{event.total}] {event.label}…")
        elif isinstance(event, ResultProduced):
            position = self._items_emitted.get(event.step_id, 0)
            self._items_emitted[event.step_id] = position + 1
            order = self._step_index[event.step_id] * ORDER_STRIDE + position
            if isinstance(event.item, DiagnosticResult):
                self.diagnostic_result.emit(event.item, order)
            else:
                self.security_finding.emit(event.item, order)
