# Copyright (c) 2026 Iyad Engle. All rights reserved.

"""Phase 4: the shared scan runner with synthetic steps.

Covers plan validation, report ordering, dependencies, lanes, max_workers,
parallelism, per-step budgets, cancellation (including real subprocess
termination), crashes, event delivery and the execution scope given to steps.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import psutil
import pytest

from netdiag.runner import (
    DEFAULT_BUDGETS_S,
    DEFAULT_MAX_WORKERS,
    ResultProduced,
    ScanFinished,
    ScanOutcome,
    ScanPlan,
    ScanRunner,
    ScanStarted,
    Step,
    StepFinished,
    StepStarted,
    StepState,
    host_discovery_budget,
    port_scan_budget,
    run_scan,
)
from netdiag.runner.budgets import WORST_CASE_S
from netdiag.utils import process
from netdiag.utils.execution import CancelToken, ScanCancelled, cached, current_scope
from netdiag.utils.models import (
    Confidence,
    DiagnosticResult,
    SecurityFinding,
    SecurityStatus,
    Severity,
    Status,
)

PY = sys.executable
TARGET = "example.com"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def diag(name: str, status: Status = Status.PASS) -> DiagnosticResult:
    return DiagnosticResult(test_name=name, target=TARGET, status=status, evidence=f"{name} evidence",
                            duration_ms=1)


def finding(name: str, status: SecurityStatus = SecurityStatus.PASS) -> SecurityFinding:
    return SecurityFinding(test_name=name, status=status, severity=Severity.INFO, title=name,
                           description="d", evidence="e", recommendation="r",
                           confidence=Confidence.CONFIRMED)


class Tracker:
    """Records step intervals and concurrency from inside step threads."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.intervals: dict[str, tuple[float, float]] = {}
        self.order: list[str] = []

    def step(self, name: str, delay: float = 0.0, output=None, kind: str = "diagnostic", **step_kwargs):
        def run():
            began = time.monotonic()
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
                self.order.append(name)
            try:
                time.sleep(delay)
            finally:
                with self.lock:
                    self.active -= 1
                    self.intervals[name] = (began, time.monotonic())
            if output is not None:
                return output
            return diag(name) if kind == "diagnostic" else finding(name)
        return Step(id=name, label=name.upper(), kind=kind, run=run, **step_kwargs)

    def overlap(self, a: str, b: str) -> bool:
        (a0, a1), (b0, b1) = self.intervals[a], self.intervals[b]
        return a0 < b1 and b0 < a1


class Recorder:
    """Event callback that also detects concurrent or off-thread delivery."""

    def __init__(self) -> None:
        self.events: list = []
        self.threads: set[int] = set()
        self._busy = threading.Lock()
        self.concurrent_calls = 0

    def __call__(self, event) -> None:
        if not self._busy.acquire(blocking=False):
            self.concurrent_calls += 1
            return
        try:
            self.threads.add(threading.get_ident())
            self.events.append(event)
            time.sleep(0.001)   # widen the window a concurrent call would hit
        finally:
            self._busy.release()

    def of(self, kind) -> list:
        return [e for e in self.events if isinstance(e, kind)]


def names(result) -> list[str]:
    return [r.test_name for r in result.report.results] + [f.test_name for f in result.report.findings]


def sleeper_writing_pid(pid_file: Path) -> list[str]:
    code = f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    return [PY, "-c", code]


def wait_for_pid(path: Path, timeout: float = 10.0) -> int:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if path.exists() and path.read_text().strip():
            return int(path.read_text())
        time.sleep(0.02)
    raise AssertionError(f"{path} was not written")


def gone(pid: int, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        except psutil.NoSuchProcess:
            return True
        time.sleep(0.05)
    return False


def subprocess_step(step_id: str, pid_file: Path, kind: str = "diagnostic", **kwargs) -> Step:
    def run():
        process.run(sleeper_writing_pid(pid_file), capture_output=True, timeout=60)
        return diag(step_id) if kind == "diagnostic" else finding(step_id)
    return Step(id=step_id, label=f"Slow {step_id}", kind=kind, run=run, **kwargs)


# ---------------------------------------------------------------------------
# plan validation
# ---------------------------------------------------------------------------

class TestPlanValidation:
    def _step(self, step_id, **kwargs):
        return Step(id=step_id, label=step_id, kind="diagnostic", run=lambda: None, **kwargs)

    def test_valid_plan(self):
        plan = ScanPlan(TARGET, [self._step("a"), self._step("b", after=["a"], lanes=["x"])])
        assert plan.step_ids == ("a", "b")
        assert len(plan) == 2
        assert plan.steps[1].after == ("a",) and plan.steps[1].lanes == ("x",)   # lists -> tuples

    def test_duplicate_ids(self):
        with pytest.raises(ValueError, match="Duplicate step ids: a"):
            ScanPlan(TARGET, [self._step("a"), self._step("a")])

    def test_unknown_dependency(self):
        with pytest.raises(ValueError, match="unknown step"):
            ScanPlan(TARGET, [self._step("a", after=("missing",))])

    def test_cycle(self):
        with pytest.raises(ValueError, match="Dependency cycle"):
            ScanPlan(TARGET, [self._step("a", after=("c",)), self._step("b", after=("a",)),
                              self._step("c", after=("b",))])

    def test_self_dependency(self):
        with pytest.raises(ValueError, match="itself"):
            self._step("a", after=("a",))

    @pytest.mark.parametrize("kwargs,message", [
        ({"kind": "bogus"}, "kind"),
        ({"budget_s": 0}, "budget_s"),
        ({"budget_s": -1}, "budget_s"),
    ])
    def test_invalid_step(self, kwargs, message):
        base = {"id": "a", "label": "A", "kind": "diagnostic", "run": lambda: None}
        with pytest.raises(ValueError, match=message):
            Step(**{**base, **kwargs})

    def test_empty_id(self):
        with pytest.raises(ValueError):
            Step(id="", label="A", kind="diagnostic", run=lambda: None)

    def test_result_test_name_default_slug(self):
        assert Step(id="p", label="ICMP ping", kind="diagnostic", run=lambda: None).result_test_name == "icmp_ping"
        assert Step(id="p", label="x", kind="diagnostic", run=lambda: None, test_name="custom").result_test_name \
            == "custom"

    def test_invalid_max_workers(self):
        with pytest.raises(ValueError):
            ScanRunner(max_workers=0)


# ---------------------------------------------------------------------------
# ordering, dependencies, lanes, concurrency
# ---------------------------------------------------------------------------

class TestOrderingAndScheduling:
    def test_report_follows_plan_order_not_completion_order(self):
        t = Tracker()
        plan = ScanPlan(TARGET, [t.step("slow", 0.3), t.step("medium", 0.15), t.step("fast", 0.0)])
        result = ScanRunner().run(plan)
        assert names(result) == ["slow", "medium", "fast"]
        assert result.outcome == ScanOutcome.COMPLETED
        assert t.intervals["fast"][1] < t.intervals["slow"][1]   # finished first, reported last

    def test_multiple_items_none_and_mixed_kinds(self):
        steps = [
            Step("multi", "Multi", "diagnostic", lambda: [diag("m1"), diag("m2")]),
            Step("none", "None", "diagnostic", lambda: None),
            Step("sec", "Sec", "security", lambda: [finding("s1"), finding("s2")]),
            Step("tuple", "Tuple", "diagnostic", lambda: (diag("t1"),)),
        ]
        result = ScanRunner().run(ScanPlan(TARGET, steps))
        assert [r.test_name for r in result.report.results] == ["m1", "m2", "t1"]
        assert [f.test_name for f in result.report.findings] == ["s1", "s2"]
        assert all(state == StepState.COMPLETED for state in result.states.values())

    def test_report_is_the_existing_model(self):
        result = ScanRunner().run(ScanPlan(TARGET, [Step("a", "A", "diagnostic", lambda: diag("a"))]))
        assert result.report.target == TARGET
        assert result.report.to_dict()["diagnostics"][0]["test_name"] == "a"

    def test_after_orders_steps(self):
        t = Tracker()
        plan = ScanPlan(TARGET, [
            t.step("dns", 0.2),
            t.step("ping", 0.05, after=("dns",)),
            t.step("tcp", 0.05, after=("dns",)),
            t.step("independent", 0.05),
        ])
        ScanRunner().run(plan)
        dns_end = t.intervals["dns"][1]
        assert t.intervals["ping"][0] >= dns_end
        assert t.intervals["tcp"][0] >= dns_end
        assert t.intervals["independent"][0] < dns_end   # not held back

    def test_dependent_runs_even_if_dependency_crashed(self):
        def boom():
            raise RuntimeError("dns exploded")
        t = Tracker()
        plan = ScanPlan(TARGET, [Step("dns", "DNS", "diagnostic", boom), t.step("ping", after=("dns",))])
        result = ScanRunner().run(plan)
        assert result.states == {"dns": StepState.CRASHED, "ping": StepState.COMPLETED}

    def test_lane_members_never_overlap(self):
        t = Tracker()
        plan = ScanPlan(TARGET, [
            t.step("ping", 0.15, lanes=("icmp",)),
            t.step("mtu", 0.15, lanes=("icmp",)),
            t.step("trace", 0.15, lanes=("icmp",)),
            t.step("https", 0.3),
        ])
        ScanRunner().run(plan)
        for a, b in (("ping", "mtu"), ("ping", "trace"), ("mtu", "trace")):
            assert not t.overlap(a, b)
        assert t.overlap("https", "ping")   # other lanes run concurrently

    def test_steps_in_multiple_lanes(self):
        t = Tracker()
        plan = ScanPlan(TARGET, [
            t.step("a", 0.15, lanes=("x",)),
            t.step("b", 0.15, lanes=("y",)),
            t.step("ab", 0.15, lanes=("x", "y")),
        ])
        ScanRunner().run(plan)
        assert t.overlap("a", "b")
        assert not t.overlap("ab", "a") and not t.overlap("ab", "b")

    def test_default_max_workers_is_four_and_respected(self):
        assert DEFAULT_MAX_WORKERS == 4
        t = Tracker()
        plan = ScanPlan(TARGET, [t.step(f"s{i}", 0.15) for i in range(10)])
        result = ScanRunner().run(plan)
        assert t.peak == 4
        assert len(result.report.results) == 10

    @pytest.mark.parametrize("workers", [1, 2, 6])
    def test_custom_max_workers(self, workers):
        t = Tracker()
        plan = ScanPlan(TARGET, [t.step(f"s{i}", 0.1) for i in range(8)])
        run_scan(plan, max_workers=workers)
        assert t.peak == min(workers, 8)

    def test_single_worker_runs_sequentially_in_plan_order(self):
        t = Tracker()
        ids = [f"s{i}" for i in range(6)]
        ScanRunner(max_workers=1).run(ScanPlan(TARGET, [t.step(i, 0.01) for i in ids]))
        assert t.order == ids
        assert t.peak == 1

    def test_parallel_speedup(self):
        t = Tracker()
        plan = ScanPlan(TARGET, [t.step(f"s{i}", 0.4) for i in range(4)])
        began = time.monotonic()
        ScanRunner().run(plan)
        assert time.monotonic() - began < 1.2   # sequential would take 1.6 s


# ---------------------------------------------------------------------------
# crashes
# ---------------------------------------------------------------------------

class TestCrashes:
    def test_diagnostic_crash_becomes_error_result(self):
        def boom():
            raise ValueError("bad parse")
        plan = ScanPlan(TARGET, [Step("ping", "ICMP ping", "diagnostic", boom)])
        result = ScanRunner().run(plan)
        (item,) = result.report.results
        assert result.states["ping"] == StepState.CRASHED
        assert (item.test_name, item.target, item.status, item.error) == \
               ("icmp_ping", TARGET, Status.ERROR, "ValueError")
        assert item.evidence == "Unexpected error: bad parse"

    def test_security_crash_becomes_security_finding(self):
        """A crash in a security step is a SecurityFinding (previously a DiagnosticResult in GUI full mode)."""
        def boom():
            raise RuntimeError("tls exploded")
        plan = ScanPlan(TARGET, [Step("tls.expiry", "TLS certificate expiry", "security", boom)])
        result = ScanRunner().run(plan)
        assert result.report.results == []
        (item,) = result.report.findings
        assert item.status == SecurityStatus.ERROR and item.confidence == Confidence.INCONCLUSIVE
        assert item.title == "TLS certificate expiry: Unexpected Error"
        assert item.evidence == "RuntimeError: tls exploded"

    def test_wrong_return_type_is_a_crash(self):
        plan = ScanPlan(TARGET, [Step("odd", "Odd", "diagnostic", lambda: "not a result")])
        result = ScanRunner().run(plan)
        assert result.states["odd"] == StepState.CRASHED
        assert result.report.results[0].error == "TypeError"

    def test_crash_does_not_affect_other_steps(self):
        def boom():
            raise RuntimeError
        t = Tracker()
        plan = ScanPlan(TARGET, [t.step("a"), Step("b", "B", "diagnostic", boom), t.step("c")])
        result = ScanRunner().run(plan)
        assert [r.status for r in result.report.results] == [Status.PASS, Status.ERROR, Status.PASS]


# ---------------------------------------------------------------------------
# budgets
# ---------------------------------------------------------------------------

class TestBudgets:
    def test_subprocess_step_over_budget_is_stopped(self, tmp_path):
        pid_file = tmp_path / "pid"
        plan = ScanPlan(TARGET, [subprocess_step("trace", pid_file, budget_s=0.5)])
        began = time.monotonic()
        result = ScanRunner().run(plan)
        assert time.monotonic() - began < 5
        assert result.states["trace"] == StepState.TIMED_OUT
        (item,) = result.report.results
        assert (item.status, item.error, item.test_name) == (Status.ERROR, "StepTimeout", "slow_trace")
        assert item.evidence == "Step exceeded its 0.5 s time budget"
        assert gone(wait_for_pid(pid_file))

    def test_step_ignoring_its_budget_is_abandoned_after_grace(self):
        release = threading.Event()
        late = []

        def stubborn():
            release.wait(10)          # no subprocess: cannot be stopped
            late.append(True)
            return diag("late")

        plan = ScanPlan(TARGET, [Step("stuck", "Stuck", "diagnostic", stubborn, budget_s=0.2)])
        began = time.monotonic()
        result = ScanRunner(grace_s=0.3).run(plan)
        elapsed = time.monotonic() - began
        release.set()
        assert elapsed < 3
        assert result.states["stuck"] == StepState.TIMED_OUT
        assert [r.error for r in result.report.results] == ["StepTimeout"]
        time.sleep(0.1)
        assert late == [True]                                       # thread finished later...
        assert [r.error for r in result.report.results] == ["StepTimeout"]   # ...and was ignored

    def test_security_timeout_is_a_security_finding(self, tmp_path):
        plan = ScanPlan(TARGET, [subprocess_step("tls", tmp_path / "pid", kind="security", budget_s=0.5)])
        result = ScanRunner().run(plan)
        (item,) = result.report.findings
        assert item.status == SecurityStatus.ERROR and item.title == "Slow tls: Timed Out"

    def test_result_returned_after_expiry_is_discarded(self):
        """A step that returns after its budget expired gets the standard timeout result."""
        def slow_but_returns():
            time.sleep(0.5)
            return diag("would-be-misleading")
        plan = ScanPlan(TARGET, [Step("mtu", "Path MTU", "diagnostic", slow_but_returns, budget_s=0.2)])
        result = ScanRunner(grace_s=2).run(plan)
        assert result.states["mtu"] == StepState.TIMED_OUT
        assert [r.test_name for r in result.report.results] == ["path_mtu"]

    # With a long poll interval the coordinator only wakes when the step's completion
    # arrives, so it processes the completion before any budget check: the race that
    # made the classification timing-dependent is forced deterministically here.
    def test_step_stopped_by_its_capped_timeout_is_timed_out_not_crashed(self, tmp_path):
        plan = ScanPlan(TARGET, [subprocess_step("trace", tmp_path / "pid", budget_s=0.5)])
        result = ScanRunner(poll_interval_s=30).run(plan)   # process.run raises TimeoutExpired
        assert result.states["trace"] == StepState.TIMED_OUT
        assert [r.error for r in result.report.results] == ["StepTimeout"]

    def test_own_timeout_result_at_the_deadline_is_replaced(self, tmp_path):
        """A diagnostic that catches the capped timeout returns its own ERROR result."""
        def ping_like():
            try:
                process.run(sleeper_writing_pid(tmp_path / "pid"), capture_output=True, timeout=60)
            except Exception:   # like ping(): subprocess.TimeoutExpired -> its own result
                return diag("icmp_ping", Status.ERROR)
            return diag("icmp_ping")

        plan = ScanPlan(TARGET, [Step("ping", "ICMP ping", "diagnostic", ping_like, budget_s=0.5)])
        result = ScanRunner(poll_interval_s=30).run(plan)
        assert result.states["ping"] == StepState.TIMED_OUT
        assert [r.error for r in result.report.results] == ["StepTimeout"]

    def test_finishing_before_the_deadline_is_completed_even_with_slow_polling(self):
        t = Tracker()
        result = ScanRunner(poll_interval_s=30).run(ScanPlan(TARGET, [t.step("ok", 0.05, budget_s=2)]))
        assert result.states["ok"] == StepState.COMPLETED

    def test_step_within_budget_is_untouched(self):
        t = Tracker()
        result = ScanRunner().run(ScanPlan(TARGET, [t.step("ok", 0.05, budget_s=5)]))
        assert result.states["ok"] == StepState.COMPLETED

    def test_unbounded_step(self):
        seen = []
        step = Step("u", "U", "diagnostic", lambda: seen.append(current_scope().deadline) or diag("u"))
        ScanRunner().run(ScanPlan(TARGET, [step]))
        assert seen == [None]

    def test_budget_sets_step_deadline(self):
        seen = []

        def run():
            seen.append(current_scope().remaining())
            return diag("b")

        ScanRunner().run(ScanPlan(TARGET, [Step("b", "B", "diagnostic", run, budget_s=30)]))
        assert 25 < seen[0] <= 30 + 1e-6

    def test_timed_out_step_frees_its_lane(self, tmp_path):
        t = Tracker()
        plan = ScanPlan(TARGET, [
            subprocess_step("mtu", tmp_path / "pid", budget_s=0.3, lanes=("icmp",)),
            t.step("trace", lanes=("icmp",)),
        ])
        result = ScanRunner().run(plan)
        assert result.states == {"mtu": StepState.TIMED_OUT, "trace": StepState.COMPLETED}


class TestDefaultBudgets:
    def test_every_budget_exceeds_its_worst_case(self):
        for step_id, budget in DEFAULT_BUDGETS_S.items():
            assert budget > WORST_CASE_S[step_id], step_id

    def test_expected_steps_have_budgets(self):
        assert {"dns", "ping", "https", "tcp", "gateway", "mtu", "traceroute", "tls.expiry",
                "tls.versions", "tls.hostname", "http_headers", "dnssec", "open_resolver",
                "tcp_exposure"} <= set(DEFAULT_BUDGETS_S)

    def test_size_based_budgets(self):
        assert port_scan_budget(7, 2.0, 20) == 12.0              # one wave
        assert port_scan_budget(45, 2.0, 20) == 16.0             # three waves
        assert host_discovery_budget(254, 2, 50) == 6 * 4 + 10   # 6 waves x (2 + 2) s
        assert host_discovery_budget(0, 2, 50) == 14.0


# ---------------------------------------------------------------------------
# cancellation
# ---------------------------------------------------------------------------

class TestCancellation:
    def test_cancelled_before_start_runs_nothing(self):
        t = Tracker()
        token = CancelToken()
        token.cancel()
        recorder = Recorder()
        result = ScanRunner().run(ScanPlan(TARGET, [t.step("a"), t.step("b")]), recorder, token)
        assert t.order == []
        assert result.outcome == ScanOutcome.CANCELLED
        assert result.states == {"a": StepState.NOT_STARTED, "b": StepState.NOT_STARTED}
        assert [type(e) for e in recorder.events] == [ScanStarted, ScanFinished]

    def test_cancel_kills_running_subprocess_and_keeps_completed_results(self, tmp_path):
        pid_file = tmp_path / "pid"
        t = Tracker()
        plan = ScanPlan(TARGET, [
            t.step("dns"),
            subprocess_step("trace", pid_file, after=("dns",)),
            t.step("later", after=("trace",)),
        ])
        token = CancelToken()
        holder = {}
        thread = threading.Thread(target=lambda: holder.update(result=ScanRunner().run(plan, None, token)))
        thread.start()
        pid = wait_for_pid(pid_file)
        began = time.monotonic()
        token.cancel()
        thread.join(10)
        assert not thread.is_alive()
        assert time.monotonic() - began < 3
        result = holder["result"]
        assert result.outcome == ScanOutcome.CANCELLED
        assert result.states == {"dns": StepState.COMPLETED, "trace": StepState.CANCELLED,
                                 "later": StepState.NOT_STARTED}
        assert names(result) == ["dns"]          # partial results preserved
        assert gone(pid)

    def test_step_finishing_within_grace_keeps_its_results(self):
        """A socket-style step (no subprocess) that completes shortly after cancel is kept."""
        token = CancelToken()
        started = threading.Event()

        def quick_socket_check():
            started.set()
            time.sleep(0.2)
            return diag("socket")

        plan = ScanPlan(TARGET, [Step("sock", "Socket", "diagnostic", quick_socket_check)])
        threading.Thread(target=lambda: (started.wait(5), token.cancel())).start()
        result = ScanRunner(grace_s=2).run(plan, None, token)
        assert result.states["sock"] == StepState.COMPLETED
        assert names(result) == ["socket"]
        assert result.outcome == ScanOutcome.COMPLETED   # nothing was actually cut short

    def test_step_ignoring_cancel_is_abandoned_after_grace(self):
        token = CancelToken()
        release = threading.Event()
        started = threading.Event()

        def stubborn():
            started.set()
            release.wait(10)
            return diag("late")

        plan = ScanPlan(TARGET, [Step("stuck", "Stuck", "diagnostic", stubborn)])
        threading.Thread(target=lambda: (started.wait(5), token.cancel())).start()
        began = time.monotonic()
        result = ScanRunner(grace_s=0.3).run(plan, None, token)
        release.set()
        assert time.monotonic() - began < 3
        assert result.states["stuck"] == StepState.CANCELLED
        assert result.report.results == []

    def test_cancel_from_an_event_callback(self):
        t = Tracker()
        token = CancelToken()

        def on_event(event):
            if isinstance(event, StepFinished) and event.step_id == "first":
                token.cancel()

        plan = ScanPlan(TARGET, [t.step("first"), t.step("second", after=("first",))])
        result = ScanRunner().run(plan, on_event, token)
        assert result.states == {"first": StepState.COMPLETED, "second": StepState.NOT_STARTED}

    def test_scan_cancelled_raised_in_step_is_cancelled_not_crashed(self):
        token = CancelToken()

        def cancelling_step():
            token.cancel()
            raise ScanCancelled()

        result = ScanRunner().run(ScanPlan(TARGET, [Step("c", "C", "diagnostic", cancelling_step)]),
                                  None, token)
        assert result.states["c"] == StepState.CANCELLED
        assert result.report.results == []

    def test_keyboard_interrupt_cancels_and_returns_partial_result(self, tmp_path):
        pid_file = tmp_path / "pid"

        def marker():
            wait_for_pid(pid_file)   # finishes once the slow step's subprocess is running
            return diag("marker")

        plan = ScanPlan(TARGET, [
            subprocess_step("trace", pid_file),
            Step("marker", "Marker", "diagnostic", marker),
            Step("after", "After", "diagnostic", lambda: diag("after"), after=("marker",)),
        ])

        def on_event(event):
            if isinstance(event, StepFinished) and event.step_id == "marker":
                raise KeyboardInterrupt   # Ctrl+C arriving in the coordinating thread

        began = time.monotonic()
        result = ScanRunner().run(plan, on_event)
        assert time.monotonic() - began < 8
        assert result.interrupted is True
        assert result.outcome == ScanOutcome.CANCELLED
        assert result.states == {"trace": StepState.CANCELLED, "marker": StepState.COMPLETED,
                                 "after": StepState.NOT_STARTED}
        assert names(result) == ["marker"]
        assert gone(int(pid_file.read_text()))

    def test_keyboard_interrupt_in_step_started_callback(self, tmp_path):
        """The interrupt arrives right after a step thread starts; it must still be wound down."""
        pid_file = tmp_path / "pid"
        plan = ScanPlan(TARGET, [subprocess_step("trace", pid_file)])

        def on_event(event):
            if isinstance(event, StepStarted):
                raise KeyboardInterrupt

        began = time.monotonic()
        result = ScanRunner(grace_s=3).run(plan, on_event)
        # The started thread observes the cancellation at once; a step registered without
        # a thread would instead be abandoned only after the full 3 s grace period.
        assert time.monotonic() - began < 1.5
        assert result.interrupted and result.states["trace"] == StepState.CANCELLED
        if pid_file.exists() and pid_file.read_text().strip():
            assert gone(int(pid_file.read_text()))


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------

class TestEvents:
    def _plan(self, t):
        return ScanPlan(TARGET, [
            t.step("a", 0.1),
            Step("b", "B", "diagnostic", lambda: [diag("b1"), diag("b2")]),
            t.step("c", 0.05, after=("a",)),
            t.step("d", 0.02, kind="security"),
        ])

    def test_sequence_and_contents(self):
        recorder = Recorder()
        result = ScanRunner().run(self._plan(Tracker()), recorder)
        events = recorder.events
        assert isinstance(events[0], ScanStarted) and isinstance(events[-1], ScanFinished)
        assert events[0] == ScanStarted(TARGET, ("a", "b", "c", "d"), 4)
        assert events[-1].result is result
        for step_id in ("a", "b", "c", "d"):
            positions = {type(e): i for i, e in enumerate(events) if getattr(e, "step_id", None) == step_id
                         and not isinstance(e, ResultProduced)}
            results = [i for i, e in enumerate(events) if isinstance(e, ResultProduced) and e.step_id == step_id]
            assert results, step_id
            assert positions[StepStarted] < min(results) and max(results) < positions[StepFinished]
        assert sorted(e.index for e in recorder.of(StepStarted)) == [1, 2, 3, 4]
        assert all(e.total == 4 for e in recorder.of(StepStarted))
        assert [e.item.test_name for e in recorder.of(ResultProduced) if e.step_id == "b"] == ["b1", "b2"]
        assert {e.state for e in recorder.of(StepFinished)} == {StepState.COMPLETED}
        assert all(e.duration_ms >= 0 for e in recorder.of(StepFinished))

    def test_delivered_one_at_a_time_on_the_calling_thread(self):
        recorder = Recorder()
        plan = ScanPlan(TARGET, [Tracker().step(f"s{i}", 0.02) for i in range(12)])
        ScanRunner().run(plan, recorder)
        assert recorder.concurrent_calls == 0
        assert recorder.threads == {threading.get_ident()}

    def test_failing_callback_does_not_break_the_scan(self):
        calls = []

        def bad(event):
            calls.append(event)
            raise RuntimeError("consumer bug")

        result = ScanRunner().run(self._plan(Tracker()), bad)
        assert result.outcome == ScanOutcome.COMPLETED
        assert isinstance(calls[-1], ScanFinished)

    def test_synthesized_results_are_announced(self):
        def boom():
            raise RuntimeError
        recorder = Recorder()
        ScanRunner().run(ScanPlan(TARGET, [Step("x", "X", "diagnostic", boom)]), recorder)
        (produced,) = recorder.of(ResultProduced)
        assert produced.item.status == Status.ERROR
        assert recorder.of(StepFinished)[0].state == StepState.CRASHED

    def test_durations_recorded(self):
        result = ScanRunner().run(ScanPlan(TARGET, [Tracker().step("a", 0.1)]))
        assert result.durations_ms["a"] >= 90


# ---------------------------------------------------------------------------
# execution scope given to steps
# ---------------------------------------------------------------------------

class TestStepScope:
    def test_steps_share_one_cache_per_scan(self):
        calls = []

        def compute():
            calls.append(1)
            return "resolved"

        steps = [Step(f"s{i}", f"S{i}", "diagnostic",
                      lambda: cached("dns", compute) and diag("x")) for i in range(3)]
        runner = ScanRunner(max_workers=1)
        runner.run(ScanPlan(TARGET, steps))
        assert calls == [1]
        runner.run(ScanPlan(TARGET, steps))   # a new scan gets a fresh cache
        assert calls == [1, 1]

    def test_scope_carries_token_and_console_flag(self):
        token = CancelToken()
        seen = []

        def run():
            scope = current_scope()
            seen.append((scope.cancel_token is token, scope.hide_console_windows))
            return diag("s")

        ScanRunner(hide_console_windows=True).run(ScanPlan(TARGET, [Step("s", "S", "diagnostic", run)]),
                                                   None, token)
        assert seen == [(True, True)]

    def test_no_scope_leaks_to_the_caller(self):
        ScanRunner().run(ScanPlan(TARGET, [Tracker().step("a")]))
        assert current_scope() is None

    def test_relabel_applies_to_results_and_synthesized_errors(self):
        def relabel(item):
            item.target = f"gateway({TARGET})"
            return item

        def boom():
            raise RuntimeError

        plan = ScanPlan(TARGET, [
            Step("gw", "Default gateway", "diagnostic", lambda: [diag("gateway_detection")], relabel=relabel),
            Step("gw2", "Default gateway 2", "diagnostic", boom, relabel=relabel),
        ])
        result = ScanRunner().run(plan)
        assert [r.target for r in result.report.results] == [f"gateway({TARGET})"] * 2

    def test_failing_relabel_keeps_the_item(self):
        def bad_relabel(item):
            raise RuntimeError

        plan = ScanPlan(TARGET, [Step("a", "A", "diagnostic", lambda: diag("a"), relabel=bad_relabel)])
        assert names(ScanRunner().run(plan)) == ["a"]

    def test_step_threads_finish(self):
        before = {t.ident for t in threading.enumerate()}
        ScanRunner().run(ScanPlan(TARGET, [Tracker().step(f"s{i}", 0.01) for i in range(6)]))
        time.sleep(0.05)
        leftover = [t for t in threading.enumerate()
                    if t.ident not in before and t.name.startswith("netdiag-step-")]
        assert leftover == []
