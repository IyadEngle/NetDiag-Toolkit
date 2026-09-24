# Copyright (c) 2026 Iyad Engle. All rights reserved.

import csv
import io

from netdiag.reports.csv_report import export_csv


class TestCSVExport:
    def test_csv_structure(self, sample_report):
        output = export_csv(sample_report)
        rows = list(csv.reader(io.StringIO(output)))
        assert len(rows) >= 2

    def test_csv_has_both_types(self, sample_report):
        output = export_csv(sample_report)
        assert "diagnostic" in output
        assert "security_finding" in output
