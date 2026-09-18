# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""JSON report exporter."""

from __future__ import annotations

import json
from pathlib import Path

from netdiag.utils.models import ScanReport


def export_json(report: ScanReport, filepath: str | None = None) -> str:
    output = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if filepath:
        Path(filepath).write_text(output, encoding="utf-8")
    return output
