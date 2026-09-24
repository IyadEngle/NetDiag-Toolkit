# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""CSV report exporter."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from netdiag.utils.models import ScanReport


def export_csv(report: ScanReport, filepath: str | None = None) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "test_name", "target", "status_or_severity", "title_or_evidence", "details", "duration_ms", "timestamp", "confidence_or_error"])

    for r in report.results:
        writer.writerow(["diagnostic", r.test_name, r.target, r.status.value, r.evidence,
                         str(r.details) if r.details else "", round(r.duration_ms, 2), r.timestamp, r.error])

    for f in report.findings:
        writer.writerow(["security_finding", f.test_name, report.target, f.severity.value, f.title,
                         f"{f.description} | Evidence: {f.evidence} | Recommendation: {f.recommendation}",
                         "", f.timestamp, f.confidence.value])

    csv_string = output.getvalue()
    if filepath:
        Path(filepath).write_text(csv_string, encoding="utf-8")
    return csv_string
