# Copyright (c) 2026 Iyad Engle. All rights reserved.

import json
from netdiag.reports.json_report import export_json
from netdiag.reports.console import format_console_report


class TestJSONReport:
    def test_valid_json(self, sample_report):
        data = json.loads(export_json(sample_report))
        assert data["target"] == "example.com"
        assert "summary" in data

    def test_summary_has_security_fields(self, sample_report):
        data = json.loads(export_json(sample_report))
        s = data["summary"]
        assert "security_failures" in s
        assert "security_observations" in s
        assert "security_inconclusive" in s


class TestConsoleReport:
    def test_contains_target(self, sample_report):
        assert "example.com" in format_console_report(sample_report)

    def test_contains_security_summary(self, sample_report):
        output = format_console_report(sample_report)
        assert "observation" in output.lower()
