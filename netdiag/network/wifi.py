# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Wi-Fi information (Windows only, via netsh)."""

from __future__ import annotations

import platform
import re
import subprocess
import time

from netdiag.utils.models import DiagnosticResult, Status


def wifi_info() -> DiagnosticResult:
    os_name = platform.system()
    if os_name != "Windows":
        return DiagnosticResult(
            test_name="wifi_info", target="localhost", status=Status.SKIP,
            evidence=f"Wi-Fi information is only supported on Windows. Current OS: {os_name}",
            duration_ms=0,
        )

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        output = result.stdout
        duration_ms = (time.monotonic() - start) * 1000
        details: dict[str, str | int] = {}

        for pattern, key in [
            (r"^\s*SSID\s*:\s*(.+)$", "ssid"),
            (r"^\s*BSSID\s*:\s*(.+)$", "bssid"),
            (r"^\s*State\s*:\s*(.+)$", "state"),
            (r"^\s*Signal\s*:\s*(.+)$", "signal"),
            (r"^\s*Radio type\s*:\s*(.+)$", "radio_type"),
            (r"^\s*Channel\s*:\s*(\d+)$", "channel"),
            (r"^\s*Authentication\s*:\s*(.+)$", "authentication"),
        ]:
            match = re.search(pattern, output, re.MULTILINE)
            if match:
                if key == "channel":
                    details[key] = int(match.group(1))
                else:
                    details[key] = match.group(1).strip()

        if details.get("state") == "connected" or details.get("ssid"):
            return DiagnosticResult(
                test_name="wifi_info", target="localhost", status=Status.PASS,
                evidence=f"Connected to '{details.get('ssid', 'Unknown')}' (Signal: {details.get('signal', 'N/A')})",
                duration_ms=duration_ms, details=details,
            )
        return DiagnosticResult(
            test_name="wifi_info", target="localhost", status=Status.FAIL,
            evidence="No active Wi-Fi connection found", duration_ms=duration_ms, details=details,
        )
    except FileNotFoundError:
        return DiagnosticResult(
            test_name="wifi_info", target="localhost", status=Status.SKIP,
            evidence="netsh command not found", duration_ms=(time.monotonic() - start) * 1000,
        )
    except Exception as e:
        return DiagnosticResult(
            test_name="wifi_info", target="localhost", status=Status.ERROR,
            evidence=f"Error: {e}", duration_ms=(time.monotonic() - start) * 1000,
            error=type(e).__name__,
        )
