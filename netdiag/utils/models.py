# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Data models for all diagnostic and security results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from netdiag import __version__


class Status(str, Enum):
    """Status of a diagnostic test."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


class SecurityStatus(str, Enum):
    """
    Status of a security check.

    FAIL         = confirmed security condition
    OBSERVATION  = informational configuration observation
    PASS         = check completed, no issue found
    SKIP         = not runnable / not applicable
    ERROR        = unexpected error
    INCONCLUSIVE = check ran but evidence is insufficient
    """
    PASS = "PASS"
    FAIL = "FAIL"
    OBSERVATION = "OBSERVATION"
    SKIP = "SKIP"
    ERROR = "ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class DiagnosticResult:
    """Result of a single diagnostic test."""
    test_name: str
    target: str
    status: Status
    evidence: str
    duration_ms: float
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_name": self.test_name,
            "target": self.target,
            "status": self.status.value,
            "evidence": self.evidence,
            "duration_ms": round(self.duration_ms, 2),
            "timestamp": self.timestamp,
            "error": self.error,
            "details": self.details,
        }


@dataclass
class SecurityFinding:
    """Result of a single security check."""
    test_name: str
    status: SecurityStatus
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
    confidence: Confidence
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_name": self.test_name,
            "status": self.status.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence.value,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanReport:
    """Container for a complete scan run."""
    target: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool_version: str = field(default_factory=lambda: __version__)
    results: list[DiagnosticResult] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == Status.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == Status.FAIL)

    @property
    def warned(self) -> int:
        return sum(1 for r in self.results if r.status == Status.WARN)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.status == Status.ERROR)

    @property
    def security_failures(self) -> int:
        return sum(1 for f in self.findings if f.status == SecurityStatus.FAIL)

    @property
    def security_observations(self) -> int:
        return sum(1 for f in self.findings if f.status == SecurityStatus.OBSERVATION)

    @property
    def security_inconclusive(self) -> int:
        return sum(1 for f in self.findings if f.status == SecurityStatus.INCONCLUSIVE)

    @property
    def security_skipped(self) -> int:
        return sum(1 for f in self.findings if f.status == SecurityStatus.SKIP)

    @property
    def security_passed(self) -> int:
        return sum(1 for f in self.findings if f.status == SecurityStatus.PASS)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "NetDiag-Toolkit",
            "version": self.tool_version,
            "target": self.target,
            "started_at": self.started_at,
            "summary": {
                "passed": self.passed,
                "failed": self.failed,
                "warned": self.warned,
                "errors": self.errors,
                "security_total": self.total_findings,
                "security_failures": self.security_failures,
                "security_observations": self.security_observations,
                "security_inconclusive": self.security_inconclusive,
                "security_skipped": self.security_skipped,
                "security_passed": self.security_passed,
            },
            "diagnostics": [r.to_dict() for r in self.results],
            "security_findings": [f.to_dict() for f in self.findings],
        }
