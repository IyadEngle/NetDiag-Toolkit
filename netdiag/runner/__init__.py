# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Shared scan runner used by the CLI and GUI.

Build a ScanPlan of Steps (each wrapping an existing diagnostic function),
run it with ScanRunner, observe progress through events, cancel with a
CancelToken. See runner.py for the threading model.
"""

from netdiag.runner.budgets import DEFAULT_BUDGETS_S, host_discovery_budget, port_scan_budget
from netdiag.runner.events import (
    ResultProduced,
    ScanEvent,
    ScanFinished,
    ScanStarted,
    StepFinished,
    StepStarted,
)
from netdiag.runner.plan import Result, ScanPlan, Step, StepKind, StepOutput
from netdiag.runner.plans import (
    build_plan,
    cli_diagnose_plan,
    cli_full_plan,
    cli_report_plan,
    cli_security_plan,
    discover_plan,
    dns_plan,
    gui_plan,
    mtu_plan,
    network_plan,
    scan_plan,
    tcp_plan,
    traceroute_plan,
)
from netdiag.runner.result import ScanOutcome, ScanResult, StepState
from netdiag.runner.runner import DEFAULT_GRACE_S, DEFAULT_MAX_WORKERS, ScanRunner, run_scan
from netdiag.utils.execution import CancelToken

__all__ = [
    "CancelToken", "DEFAULT_BUDGETS_S", "DEFAULT_GRACE_S", "DEFAULT_MAX_WORKERS",
    "Result", "ResultProduced", "ScanEvent", "ScanFinished", "ScanOutcome", "ScanPlan",
    "ScanResult", "ScanRunner", "ScanStarted", "Step", "StepFinished", "StepKind",
    "StepOutput", "StepStarted", "StepState", "host_discovery_budget", "port_scan_budget",
    "run_scan",
    # plans
    "build_plan", "cli_diagnose_plan", "cli_full_plan", "cli_report_plan", "cli_security_plan",
    "discover_plan", "dns_plan", "gui_plan", "mtu_plan", "network_plan", "scan_plan", "tcp_plan",
    "traceroute_plan",
]
