# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Scan plans: the ordered list of steps a scan executes.

A Step wraps an existing diagnostic or security function (with its arguments
already bound) plus scheduling metadata. The plan order is the report order.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from netdiag.utils.models import DiagnosticResult, SecurityFinding

Result = DiagnosticResult | SecurityFinding
StepOutput = Result | Sequence[Result] | None
StepKind = Literal["diagnostic", "security"]

_KINDS = ("diagnostic", "security")


def default_test_name(label: str) -> str:
    """Test name for results the runner synthesizes (same slug the GUI used)."""
    return label.lower().replace(" ", "_").replace("…", "")


@dataclass(frozen=True)
class Step:
    """One unit of work in a scan.

    run      -- the existing function with its arguments bound; returns a result,
                a sequence of results, or None
    budget_s -- hard time budget (None = unbounded); see netdiag.runner.budgets
    after    -- step ids that must have finished (in any state) before this
                step starts; ordering only, a dependency's failure never skips it
    lanes    -- steps sharing a lane never run at the same time
    relabel  -- applied to every result item of this step, e.g. to rename the
                gateway result's target; returns the (possibly same) item
    test_name -- name used for ERROR results the runner synthesizes (timeout,
                crash); defaults to a slug of the label
    """

    id: str
    label: str
    kind: StepKind
    run: Callable[[], StepOutput] = field(compare=False)
    budget_s: float | None = None
    after: tuple[str, ...] = ()
    lanes: tuple[str, ...] = ()
    relabel: Callable[[Result], Result] | None = field(default=None, compare=False)
    test_name: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Step id must not be empty")
        if self.kind not in _KINDS:
            raise ValueError(f"Step {self.id!r}: kind must be one of {_KINDS}, not {self.kind!r}")
        if self.budget_s is not None and self.budget_s <= 0:
            raise ValueError(f"Step {self.id!r}: budget_s must be positive or None")
        object.__setattr__(self, "after", tuple(self.after))
        object.__setattr__(self, "lanes", tuple(self.lanes))
        if self.id in self.after:
            raise ValueError(f"Step {self.id!r} cannot run after itself")

    @property
    def result_test_name(self) -> str:
        return self.test_name or default_test_name(self.label)


@dataclass(frozen=True)
class ScanPlan:
    """A validated, ordered set of steps for one target."""

    target: str
    steps: tuple[Step, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "steps", tuple(self.steps))
        ids = [step.id for step in self.steps]
        duplicates = sorted({step_id for step_id in ids if ids.count(step_id) > 1})
        if duplicates:
            raise ValueError(f"Duplicate step ids: {', '.join(duplicates)}")
        known = set(ids)
        for step in self.steps:
            unknown = [dep for dep in step.after if dep not in known]
            if unknown:
                raise ValueError(f"Step {step.id!r} runs after unknown step(s): {', '.join(unknown)}")
        self._check_acyclic()

    def _check_acyclic(self) -> None:
        after = {step.id: step.after for step in self.steps}
        state: dict[str, int] = {}   # 1 = visiting, 2 = done

        def visit(step_id: str, path: list[str]) -> None:
            if state.get(step_id) == 2:
                return
            if state.get(step_id) == 1:
                cycle = path[path.index(step_id):] + [step_id]
                raise ValueError(f"Dependency cycle: {' -> '.join(cycle)}")
            state[step_id] = 1
            for dep in after[step_id]:
                visit(dep, path + [step_id])
            state[step_id] = 2

        for step in self.steps:
            visit(step.id, [])

    @property
    def step_ids(self) -> tuple[str, ...]:
        return tuple(step.id for step in self.steps)

    def __len__(self) -> int:
        return len(self.steps)
