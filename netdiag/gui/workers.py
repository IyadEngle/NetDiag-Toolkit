# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""
Background scan workers.

Runs the EXISTING netdiag diagnostic and security functions on a QThread
and emits per-item results plus progress. Cancellation is cooperative:
it takes effect between tests, after the currently running test finishes.
A running subprocess (ping/tracert) cannot be aborted without rewriting
stable diagnostics, which is out of scope.
"""

from __future__ import annotations

import threading
from typing import Callable

from PySide6.QtCore import QThread, Signal

from netdiag.utils.models import (
    Confidence,
    DiagnosticResult,
    ScanReport,
    SecurityFinding,
    SecurityStatus,
    Severity,
    Status,
)


class ScanWorker(QThread):
    """Executes a diagnose / security / full scan plan against one target."""

    progress = Signal(str)
    diagnostic_result = Signal(object)   # DiagnosticResult
    security_finding = Signal(object)    # SecurityFinding
    completed = Signal(object)           # ScanReport
    aborted = Signal(str)

    def __init__(self, target: str, mode: str = "diagnose",
                 timeout: int = 5, parent=None) -> None:
        super().__init__(parent)
        if mode not in ("diagnose", "security", "full"):
            raise ValueError(f"Unknown scan mode: {mode}")
        self._target = target
        self._mode = mode
        self._timeout = timeout
        self._cancel_event = threading.Event()
        self.report = ScanReport(target=target)

    # -- control ------------------------------------------------------------
    def cancel(self) -> None:
        """Request cancellation. Takes effect after the current test step."""
        self._cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    # -- plan -----------------------------------------------------------------
    def _steps(self) -> list[tuple[str, Callable]]:
        target, timeout = self._target, self._timeout
        steps: list[tuple[str, Callable]] = []

        if self._mode in ("diagnose", "full"):
            from netdiag.core.connectivity import ping
            from netdiag.core.dns import resolve_hostname
            from netdiag.core.gateway import gateway_diagnostics
            from netdiag.core.https import https_connectivity
            from netdiag.core.tcp import tcp_connect

            steps += [
                ("DNS resolution",
                 lambda: resolve_hostname(target)),
                ("ICMP ping",
                 lambda: ping(target, count=4, timeout_seconds=max(1, int(timeout)))),
                ("HTTPS connectivity",
                 lambda: https_connectivity(target, timeout_seconds=max(1, int(timeout)))),
                ("TCP port 80",
                 lambda: tcp_connect(target, 80, timeout_seconds=float(timeout))),
                ("TCP port 443",
                 lambda: tcp_connect(target, 443, timeout_seconds=float(timeout))),
                ("Default gateway",
                 gateway_diagnostics),
            ]
            if self._mode == "full":
                from netdiag.core.mtu import estimate_path_mtu
                from netdiag.core.traceroute import traceroute
                steps += [
                    ("Path MTU", lambda: estimate_path_mtu(target)),
                    ("Traceroute", lambda: traceroute(target)),
                ]

        if self._mode in ("security", "full"):
            from netdiag.security.dns_security import check_dnssec, check_open_resolver
            from netdiag.security.exposure import check_tcp_exposure
            from netdiag.security.http_security import check_http_security_headers
            from netdiag.security.tls import (
                check_certificate_expiry,
                check_certificate_hostname,
                check_tls_protocol_versions,
            )

            steps += [
                ("TLS certificate expiry",
                 lambda: check_certificate_expiry(target)),
                ("TLS protocol versions",
                 lambda: check_tls_protocol_versions(target)),
                ("Certificate hostname",
                 lambda: check_certificate_hostname(target)),
                ("HTTP security headers",
                 lambda: check_http_security_headers(target)),
                ("DNSSEC status",
                 lambda: check_dnssec(target)),
                ("Open resolver",
                 lambda: check_open_resolver(target)),
                ("TCP exposure",
                 lambda: check_tcp_exposure(target)),
            ]

        return steps

    @property
    def total_steps(self) -> int:
        return len(self._steps())

    # -- execution ------------------------------------------------------------
    def run(self) -> None:  # noqa: D102 — QThread entry point
        steps = self._steps()
        total = len(steps)

        for index, (label, func) in enumerate(steps, start=1):
            if self._cancel_event.is_set():
                self.progress.emit("Scan cancelled.")
                self.aborted.emit("Scan cancelled by user.")
                return

            self.progress.emit(f"[{index}/{total}] {label}…")
            try:
                output = func()
            except Exception as exc:  # defensive: never crash the scan loop
                output = self._error_artifact(label, exc)

            self._dispatch(output)

        self.progress.emit("Scan complete.")
        self.completed.emit(self.report)

    # -- helpers ------------------------------------------------------------
    def _test_slug(self, label: str) -> str:
        return label.lower().replace(" ", "_").replace("…", "")

    def _error_artifact(self, label: str, exc: Exception):
        """Wrap an unexpected exception as an ERROR artifact of the right type."""
        name = self._test_slug(label)
        if self._mode == "security":
            return SecurityFinding(
                test_name=name, status=SecurityStatus.ERROR, severity=Severity.INFO,
                title=f"{label}: Unexpected Error",
                description="An unexpected error prevented this security check.",
                evidence=f"{type(exc).__name__}: {exc}",
                recommendation="Review logs for details.",
                confidence=Confidence.INCONCLUSIVE,
            )
        return DiagnosticResult(
            test_name=name, target=self._target, status=Status.ERROR,
            evidence=f"Unexpected error: {exc}", duration_ms=0,
            error=type(exc).__name__,
        )

    def _dispatch(self, output) -> None:
        if output is None:
            return
        items = output if isinstance(output, (list, tuple)) else [output]
        for item in items:
            if isinstance(item, DiagnosticResult):
                self.report.results.append(item)
                self.diagnostic_result.emit(item)
            elif isinstance(item, SecurityFinding):
                self.report.findings.append(item)
                self.security_finding.emit(item)
