# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Default gateway diagnostics."""

from __future__ import annotations

import platform
import re
import subprocess
import time

from netdiag.utils.models import DiagnosticResult, Status


def get_default_gateway() -> str | None:
    os_name = platform.system()
    try:
        if os_name == "Windows":
            result = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=5)
            match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        elif os_name == "Linux":
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def gateway_diagnostics() -> list[DiagnosticResult]:
    start = time.monotonic()
    results = []
    gateway = get_default_gateway()
    duration_ms = (time.monotonic() - start) * 1000

    if gateway is None:
        results.append(DiagnosticResult(
            test_name="gateway_detection", target="default_gateway",
            status=Status.FAIL, evidence="Could not detect default gateway",
            duration_ms=duration_ms,
        ))
        return results

    results.append(DiagnosticResult(
        test_name="gateway_detection", target="default_gateway",
        status=Status.PASS, evidence=f"Default gateway: {gateway}",
        duration_ms=duration_ms, details={"gateway": gateway},
    ))

    from netdiag.core.connectivity import ping
    ping_result = ping(gateway, count=3, timeout_seconds=3)
    ping_result.test_name = "gateway_ping"
    results.append(ping_result)

    return results
