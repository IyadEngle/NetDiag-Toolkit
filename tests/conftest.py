# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from netdiag.utils.models import (
    Confidence,
    DiagnosticResult,
    ScanReport,
    SecurityFinding,
    SecurityStatus,
    Severity,
    Status,
)


@pytest.fixture
def sample_result() -> DiagnosticResult:
    return DiagnosticResult(
        test_name="test_ping", target="127.0.0.1",
        status=Status.PASS, evidence="4/4 received, avg 0.5ms", duration_ms=25.0,
    )


@pytest.fixture
def sample_security_failure() -> SecurityFinding:
    return SecurityFinding(
        test_name="tls_cert_expiry", status=SecurityStatus.FAIL,
        severity=Severity.HIGH, title="Cert Expired",
        description="Cert expired.", evidence="notAfter: 2024-01-01",
        recommendation="Renew.", confidence=Confidence.CONFIRMED,
    )


@pytest.fixture
def sample_observation() -> SecurityFinding:
    return SecurityFinding(
        test_name="http_security_headers", status=SecurityStatus.OBSERVATION,
        severity=Severity.INFO, title="Missing HSTS",
        description="HSTS header absent.", evidence="Not in response",
        recommendation="Add HSTS.", confidence=Confidence.CONFIRMED,
    )


@pytest.fixture
def sample_inconclusive() -> SecurityFinding:
    return SecurityFinding(
        test_name="tls_protocol_versions", status=SecurityStatus.INCONCLUSIVE,
        severity=Severity.INFO, title="TLS 1.0 Inconclusive",
        description="Cannot determine.", evidence="SSL error",
        recommendation="Manual check.", confidence=Confidence.INCONCLUSIVE,
    )


@pytest.fixture
def sample_report(sample_result, sample_security_failure, sample_observation, sample_inconclusive):
    report = ScanReport(target="example.com")
    report.results = [sample_result]
    report.findings = [sample_security_failure, sample_observation, sample_inconclusive]
    return report
