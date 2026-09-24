# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""The scan runner: executes a ScanPlan with bounded parallelism.

Threading model
- A coordinator loop runs in the caller's thread (CLI main thread, GUI QThread).
  It schedules steps, enforces budgets, handles cancellation, assembles the
  report and delivers every event, so consumers never see concurrent callbacks.
- Each step runs in its own daemon thread inside a copy of the caller's
  context with its own ExecutionScope (shared cancel token and ScanCache,
  per-step deadline). A daemon thread per step, rather than a pool, lets a step
  that overruns its budget be abandoned without holding a worker slot; Python
  cannot kill a thread, and the diagnostics' own socket/subprocess timeouts end
  an abandoned thread shortly after.

Scheduling: a step starts when every step in its `after` has finished (in any
state), none of its lanes is busy, and fewer than `max_workers` steps are
active. Ready steps start in plan order. The report is assembled in plan order
regardless of completion order.
"""

from __future__ import annotations

import contextvars
import logging
import queue
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from netdiag.runner.events import (
    ResultProduced,
    ScanEvent,
    ScanFinished,
    ScanStarted,
    StepFinished,
    StepStarted,
)
from netdiag.runner.plan import Result, ScanPlan, Step
from netdiag.runner.result import ScanOutcome, ScanResult, StepState
from netdiag.utils.execution import CancelToken, ExecutionScope, ScanCache, ScanCancelled, activate
from netdiag.utils.models import (
    Confidence,
    DiagnosticResult,
    ScanReport,
    SecurityFinding,
    SecurityStatus,
    Severity,
    Status,
)

logger = logging.getLogger("netdiag.runner")

DEFAULT_MAX_WORKERS = 4
# How long a timed-out or cancelled step may take to wind down before it is
# abandoned. Longer than process.KILL_GRACE_S (2 s) so a killed subprocess is
# normally reaped first.
DEFAULT_GRACE_S = 3.0

EventCallback = Callable[[ScanEvent], None]

_WAKE = object()   # queued by the cancel callback to wake the coordinator immediately


@dataclass
class _Running:
    step: Step
    index: int
    scope: ExecutionScope
    started: float
    thread: threading.Thread | None = None
    expired_at: float | None = None    # budget exceeded; waiting for the thread to wind down


@dataclass
class _Completion:
    step_id: str
    kind: str          # "ok" | "cancelled" | "error"
    payload: Any = None
    finished_at: float = field(default_factory=time.monotonic)   # set in the step thread


@dataclass
class _Execution:
    plan: ScanPlan
    on_event: EventCallback | None
    token: CancelToken
    max_workers: int
    grace_s: float
    poll_interval_s: float
    hide_console_windows: bool
    report: ScanReport = field(init=False)
    cache: ScanCache = field(default_factory=ScanCache)
    completions: queue.Queue = field(default_factory=queue.Queue)
    pending: list[Step] = field(init=False)
    running: dict[str, _Running] = field(default_factory=dict)
    finished: set[str] = field(default_factory=set)
    busy_lanes: set[str] = field(default_factory=set)
    states: dict[str, StepState] = field(init=False)
    items: dict[str, list[Result]] = field(default_factory=dict)
    durations_ms: dict[str, float] = field(default_factory=dict)
    started_count: int = 0

    def __post_init__(self) -> None:
        self.report = ScanReport(target=self.plan.target)
        self.pending = list(self.plan.steps)
        self.states = {step.id: StepState.NOT_STARTED for step in self.plan.steps}

    # ── main loop ─────────────────────────────────────────────────────────
    def execute(self) -> ScanResult:
        remove_wake = self.token.add_callback(lambda: self.completions.put(_WAKE))
        interrupted = False
        try:
            try:
                self._emit(ScanStarted(self.plan.target, self.plan.step_ids, len(self.plan)))
                self._loop()
            except KeyboardInterrupt:
                # Ctrl+C in the coordinating thread: cancel cleanly and keep partial results.
                interrupted = True
                self.token.cancel()
                self._wind_down_after_cancel()
        finally:
            remove_wake()

        self._assemble_report()
        cancelled = any(state in (StepState.CANCELLED, StepState.NOT_STARTED)
                        for state in self.states.values())
        result = ScanResult(
            report=self.report,
            outcome=ScanOutcome.CANCELLED if cancelled else ScanOutcome.COMPLETED,
            states=dict(self.states),
            durations_ms=dict(self.durations_ms),
            interrupted=interrupted,
        )
        self._emit(ScanFinished(result))
        return result

    def _loop(self) -> None:
        while self.pending or self.running:
            if self.token.cancelled:
                self._wind_down_after_cancel()
                return
            self._start_ready_steps()
            self._process_completions(timeout=self.poll_interval_s)
            self._enforce_budgets()

    # ── scheduling ────────────────────────────────────────────────────────
    def _start_ready_steps(self) -> None:
        for step in list(self.pending):
            if len(self.running) >= self.max_workers:
                return
            if self.token.cancelled:
                return
            if not all(dep in self.finished for dep in step.after):
                continue
            if any(lane in self.busy_lanes for lane in step.lanes):
                continue
            self.pending.remove(step)
            self._start(step)

    def _start(self, step: Step) -> None:
        self.started_count += 1
        scope = ExecutionScope.with_budget(
            step.budget_s, cancel_token=self.token, cache=self.cache,
            hide_console_windows=self.hide_console_windows,
        )
        entry = _Running(step=step, index=self.started_count, scope=scope, started=time.monotonic())
        self.running[step.id] = entry
        self.busy_lanes.update(step.lanes)
        context = contextvars.copy_context()
        thread = threading.Thread(
            target=context.run, args=(self._run_step, step, scope),
            name=f"netdiag-step-{step.id}", daemon=True,
        )
        entry.thread = thread
        thread.start()
        # Emitted after start so an interrupt raised by the callback never leaves a
        # registered step without a thread. StepStarted still precedes the step's
        # results: only this thread reads the completion queue, after this call.
        self._emit(StepStarted(step.id, step.label, entry.index, len(self.plan)))

    def _run_step(self, step: Step, scope: ExecutionScope) -> None:
        """Step thread: run the step inside its scope and report back to the coordinator."""
        with activate(scope):
            try:
                output = step.run()
            except ScanCancelled:
                self.completions.put(_Completion(step.id, "cancelled"))
            except BaseException as exc:   # noqa: BLE001 — reported as a crashed step
                self.completions.put(_Completion(step.id, "error", exc))
            else:
                self.completions.put(_Completion(step.id, "ok", output))

    # ── completions ───────────────────────────────────────────────────────
    def _process_completions(self, timeout: float) -> None:
        try:
            message = self.completions.get(timeout=timeout)
        except queue.Empty:
            return
        while True:
            if isinstance(message, _Completion):
                self._complete(message)
            try:
                message = self.completions.get_nowait()
            except queue.Empty:
                return

    def _complete(self, message: _Completion) -> None:
        entry = self.running.get(message.step_id)
        if entry is None:
            return   # a late result from an abandoned step: ignored
        step = entry.step
        # Timed out if the step finished at or after its deadline, whether or not the
        # coordinator noticed first: process.run stops commands at the deadline, so the
        # step's own timeout result can reach the queue before the next budget check.
        deadline = entry.scope.deadline
        timed_out = entry.expired_at is not None or (deadline is not None and message.finished_at >= deadline)
        if message.kind == "cancelled":
            self._finish(entry, StepState.CANCELLED, [])
        elif timed_out:
            self._finish(entry, StepState.TIMED_OUT, [self._timeout_result(step)])
        elif message.kind == "error":
            self._finish(entry, StepState.CRASHED, [self._crash_result(step, message.payload)])
        else:
            try:
                items = _normalize_output(step, message.payload)
            except TypeError as exc:
                self._finish(entry, StepState.CRASHED, [self._crash_result(step, exc)])
            else:
                self._finish(entry, StepState.COMPLETED, items)

    def _finish(self, entry: _Running, state: StepState, items: list[Result]) -> None:
        step = entry.step
        items = [self._relabel(step, item) for item in items]
        del self.running[step.id]
        self.busy_lanes.difference_update(step.lanes)
        self.finished.add(step.id)
        self.states[step.id] = state
        self.items[step.id] = items
        duration_ms = (time.monotonic() - entry.started) * 1000
        self.durations_ms[step.id] = duration_ms
        for item in items:
            self._emit(ResultProduced(step.id, item))
        self._emit(StepFinished(step.id, step.label, state, duration_ms))

    # ── budgets ───────────────────────────────────────────────────────────
    def _enforce_budgets(self) -> None:
        now = time.monotonic()
        for entry in list(self.running.values()):
            if entry.expired_at is None:
                if entry.scope.deadline is not None and now >= entry.scope.deadline:
                    entry.expired_at = now
                    entry.scope.expire()   # process.run stops the step's commands
            elif now - entry.expired_at >= self.grace_s:
                logger.warning("step %s did not stop after its budget; abandoning it", entry.step.id)
                self._finish(entry, StepState.TIMED_OUT, [self._timeout_result(entry.step)])

    # ── cancellation ──────────────────────────────────────────────────────
    def _wind_down_after_cancel(self) -> None:
        """Start nothing new; give running steps `grace_s` to stop, then abandon them."""
        self.pending.clear()
        deadline = time.monotonic() + self.grace_s
        while self.running:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._process_completions(timeout=min(self.poll_interval_s, remaining))
        for entry in list(self.running.values()):
            logger.warning("step %s did not stop after cancellation; abandoning it", entry.step.id)
            self._finish(entry, StepState.CANCELLED, [])

    # ── results ───────────────────────────────────────────────────────────
    def _assemble_report(self) -> None:
        for step in self.plan.steps:
            for item in self.items.get(step.id, []):
                if isinstance(item, DiagnosticResult):
                    self.report.results.append(item)
                else:
                    self.report.findings.append(item)

    def _relabel(self, step: Step, item: Result) -> Result:
        if step.relabel is None:
            return item
        try:
            return step.relabel(item)
        except Exception:
            logger.exception("relabel failed for step %s", step.id)
            return item

    def _timeout_result(self, step: Step) -> Result:
        budget = f"{step.budget_s:g}"
        if step.kind == "security":
            return SecurityFinding(
                test_name=step.result_test_name, status=SecurityStatus.ERROR, severity=Severity.INFO,
                title=f"{step.label}: Timed Out",
                description=f"The check did not finish within its {budget} s time budget.",
                evidence=f"Step exceeded its {budget} s time budget",
                recommendation="Retry the check or verify manually.",
                confidence=Confidence.INCONCLUSIVE,
            )
        return DiagnosticResult(
            test_name=step.result_test_name, target=self.plan.target, status=Status.ERROR,
            evidence=f"Step exceeded its {budget} s time budget",
            duration_ms=(step.budget_s or 0) * 1000, error="StepTimeout",
        )

    def _crash_result(self, step: Step, exc: BaseException) -> Result:
        # Same shape as the GUI worker's former _error_artifact, but by step kind.
        if step.kind == "security":
            return SecurityFinding(
                test_name=step.result_test_name, status=SecurityStatus.ERROR, severity=Severity.INFO,
                title=f"{step.label}: Unexpected Error",
                description="An unexpected error prevented this security check.",
                evidence=f"{type(exc).__name__}: {exc}",
                recommendation="Review logs for details.",
                confidence=Confidence.INCONCLUSIVE,
            )
        return DiagnosticResult(
            test_name=step.result_test_name, target=self.plan.target, status=Status.ERROR,
            evidence=f"Unexpected error: {exc}", duration_ms=0, error=type(exc).__name__,
        )

    # ── events ────────────────────────────────────────────────────────────
    def _emit(self, event: ScanEvent) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(event)
        except Exception:
            logger.exception("scan event callback failed for %s", type(event).__name__)


def _normalize_output(step: Step, output: object) -> list[Result]:
    if output is None:
        return []
    items: Sequence[object] = output if isinstance(output, (list, tuple)) else [output]
    for item in items:
        if not isinstance(item, (DiagnosticResult, SecurityFinding)):
            raise TypeError(f"step {step.id!r} returned {type(item).__name__}, "
                            "expected DiagnosticResult or SecurityFinding")
    return list(items)   # type: ignore[arg-type]


class ScanRunner:
    """Runs scan plans. Reusable and stateless between runs."""

    def __init__(
        self,
        max_workers: int = DEFAULT_MAX_WORKERS,
        *,
        grace_s: float = DEFAULT_GRACE_S,
        poll_interval_s: float = 0.05,
        hide_console_windows: bool = False,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.max_workers = max_workers
        self.grace_s = grace_s
        self.poll_interval_s = poll_interval_s
        self.hide_console_windows = hide_console_windows

    def run(
        self,
        plan: ScanPlan,
        on_event: EventCallback | None = None,
        cancel_token: CancelToken | None = None,
    ) -> ScanResult:
        """Execute `plan` and return its result. Blocks until done or cancelled.

        `on_event` is called from this thread only. Cancel from any thread with
        `cancel_token.cancel()`; a KeyboardInterrupt in this thread also cancels
        (ScanResult.interrupted is then True).
        """
        execution = _Execution(
            plan=plan, on_event=on_event,
            token=cancel_token if cancel_token is not None else CancelToken(),
            max_workers=self.max_workers, grace_s=self.grace_s,
            poll_interval_s=self.poll_interval_s,
            hide_console_windows=self.hide_console_windows,
        )
        return execution.execute()


def run_scan(
    plan: ScanPlan,
    on_event: EventCallback | None = None,
    cancel_token: CancelToken | None = None,
    *,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> ScanResult:
    """Convenience wrapper: `ScanRunner(max_workers).run(plan, on_event, cancel_token)`."""
    return ScanRunner(max_workers).run(plan, on_event, cancel_token)
