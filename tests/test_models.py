# Copyright (c) 2026 Iyad Engle. All rights reserved.

from netdiag.utils.models import (
    Confidence,
    ScanReport,
    SecurityFinding,
    SecurityStatus,
    Severity,
)


def _f(status: SecurityStatus) -> SecurityFinding:
    return SecurityFinding(
        test_name="t", status=status, severity=Severity.INFO,
        title="t", description="t", evidence="t",
        recommendation="t", confidence=Confidence.CONFIRMED,
    )


class TestSecurityStatusEnum:
    def test_observation_exists(self):
        assert SecurityStatus.OBSERVATION == "OBSERVATION"

    def test_all_statuses(self):
        expected = {"PASS", "FAIL", "OBSERVATION", "SKIP", "ERROR", "INCONCLUSIVE"}
        assert {s.value for s in SecurityStatus} == expected


class TestDiagnosticResult:
    def test_to_dict(self, sample_result):
        d = sample_result.to_dict()
        assert d["test_name"] == "test_ping"
        assert d["status"] == "PASS"


class TestSecurityFinding:
    def test_to_dict(self, sample_security_failure):
        d = sample_security_failure.to_dict()
        assert d["status"] == "FAIL"
        assert d["confidence"] == "CONFIRMED"


class TestScanReport:
    def test_security_failures_counts_only_fail(self):
        report = ScanReport(target="t")
        report.findings = [_f(SecurityStatus.FAIL), _f(SecurityStatus.OBSERVATION),
                           _f(SecurityStatus.PASS), _f(SecurityStatus.FAIL)]
        assert report.security_failures == 2
        assert report.security_observations == 1
        assert report.security_passed == 1

    def test_empty_report(self):
        report = ScanReport(target="t")
        assert report.security_failures == 0
        assert report.total_findings == 0

    def test_to_dict_includes_new_fields(self):
        report = ScanReport(target="t")
        report.findings = [_f(SecurityStatus.FAIL), _f(SecurityStatus.OBSERVATION)]
        d = report.to_dict()
        assert d["summary"]["security_failures"] == 1
        assert d["summary"]["security_observations"] == 1

    def test_diagnostic_counts(self, sample_result):
        report = ScanReport(target="t")
        report.results = [sample_result]
        assert report.passed == 1
        assert report.failed == 0
