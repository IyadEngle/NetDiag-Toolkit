# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Outcome of a scan run. The ScanReport itself is the existing result model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from netdiag.utils.models import ScanReport


class StepState(str, Enum):
    """How a step ended. Reported by the runner; not part of the report model."""

    COMPLETED = "completed"       # returned normally; its results are in the report
    TIMED_OUT = "timed_out"       # exceeded its budget; one ERROR result replaces its output
    CRASHED = "crashed"           # raised an exception; one ERROR result replaces its output
    CANCELLED = "cancelled"       # running when the scan was cancelled; contributes nothing
    NOT_STARTED = "not_started"   # never started (scan cancelled first)


class ScanOutcome(str, Enum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass
class ScanResult:
    report: ScanReport                                   # results in plan order
    outcome: ScanOutcome
    states: dict[str, StepState] = field(default_factory=dict)
    durations_ms: dict[str, float] = field(default_factory=dict)
    interrupted: bool = False                            # cancelled by KeyboardInterrupt (Ctrl+C)

    @property
    def cancelled(self) -> bool:
        return self.outcome == ScanOutcome.CANCELLED
