# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Progress events emitted by the scan runner.

All events are delivered by the runner's coordinating thread, one at a time,
so consumers never see concurrent callbacks. For each step: StepStarted, then
its ResultProduced events, then StepFinished. ScanStarted is always first and
ScanFinished always last.
"""

from __future__ import annotations

from dataclasses import dataclass

from netdiag.runner.plan import Result
from netdiag.runner.result import ScanResult, StepState


@dataclass(frozen=True)
class ScanStarted:
    target: str
    step_ids: tuple[str, ...]
    total: int


@dataclass(frozen=True)
class StepStarted:
    step_id: str
    label: str
    index: int      # 1-based start order
    total: int


@dataclass(frozen=True)
class ResultProduced:
    step_id: str
    item: Result


@dataclass(frozen=True)
class StepFinished:
    step_id: str
    label: str
    state: StepState
    duration_ms: float


@dataclass(frozen=True)
class ScanFinished:
    result: ScanResult


ScanEvent = ScanStarted | StepStarted | ResultProduced | StepFinished | ScanFinished
