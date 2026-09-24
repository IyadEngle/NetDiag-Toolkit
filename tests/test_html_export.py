# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

from netdiag.reports.html_report import export_html


class TestHTMLExport:
    def test_valid_html(self, sample_report):
        output = export_html(sample_report)
        assert "<!DOCTYPE html>" in output

    def test_escapes_html(self):
        from netdiag.utils.models import DiagnosticResult, ScanReport, Status
        report = ScanReport(target="<script>alert(1)</script>")
        report.results = [DiagnosticResult(
            test_name="<img onerror=x>", target="<script>",
            status=Status.PASS, evidence="t", duration_ms=0,
        )]
        output = export_html(report)
        assert "<script>alert" not in output
