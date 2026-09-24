# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Wi-Fi information (Windows only, via netsh).

Status semantics:
- PASS  connected to a wireless network
- SKIP  Wi-Fi not applicable: no wireless interface, WLAN service not running,
        netsh unavailable, or a wireless adapter that is simply not connected
        (e.g. the machine is on Ethernet)
- WARN  a wireless interface is mid-connection, or its state could not be read
- ERROR netsh could not be run as expected

A machine without an active Wi-Fi connection is therefore never a diagnostic
FAIL, so it does not affect the CLI exit code.
"""

from __future__ import annotations

import platform
import re
import time

from netdiag.utils import process
from netdiag.utils.models import DiagnosticResult, Status

# netsh messages meaning there is no usable Wi-Fi subsystem on this machine.
_NOT_APPLICABLE_MARKERS = (
    "there is no wireless interface",
    "wireless autoconfig service",  # "... (wlansvc) is not running."
    "wlansvc",
)
_DISCONNECTED_STATES = ("disconnected",)
_CONNECTED_STATE = "connected"


def _parse_interfaces(output: str) -> dict[str, str | int]:
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
    return details


def wifi_info() -> DiagnosticResult:
    os_name = platform.system()
    if os_name != "Windows":
        return DiagnosticResult(
            test_name="wifi_info", target="localhost", status=Status.SKIP,
            evidence=f"Wi-Fi information is only supported on Windows. Current OS: {os_name}",
            duration_ms=0, details={"availability": "unsupported_os"},
        )

    start = time.monotonic()
    try:
        result = process.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        output = result.stdout or ""
        combined = f"{output}\n{result.stderr or ''}".lower()
        duration_ms = (time.monotonic() - start) * 1000

        if any(marker in combined for marker in _NOT_APPLICABLE_MARKERS):
            return DiagnosticResult(
                test_name="wifi_info", target="localhost", status=Status.SKIP,
                evidence="Wi-Fi not applicable: no wireless interface or WLAN service on this system",
                duration_ms=duration_ms, details={"availability": "no_wireless_interface"},
            )

        details = _parse_interfaces(output)
        state = str(details.get("state", "")).lower()

        if state == _CONNECTED_STATE or (not state and details.get("ssid")):
            details["availability"] = "connected"
            return DiagnosticResult(
                test_name="wifi_info", target="localhost", status=Status.PASS,
                evidence=f"Connected to '{details.get('ssid', 'Unknown')}' (Signal: {details.get('signal', 'N/A')})",
                duration_ms=duration_ms, details=details,
            )

        if state in _DISCONNECTED_STATES:
            details["availability"] = "not_connected"
            return DiagnosticResult(
                test_name="wifi_info", target="localhost", status=Status.SKIP,
                evidence="Wi-Fi adapter present but not connected (not applicable; another link may be in use)",
                duration_ms=duration_ms, details=details,
            )

        if state:
            details["availability"] = "transitional"
            return DiagnosticResult(
                test_name="wifi_info", target="localhost", status=Status.WARN,
                evidence=f"Wi-Fi adapter state is '{details['state']}' (not connected yet)",
                duration_ms=duration_ms, details=details,
            )

        if result.returncode != 0:
            return DiagnosticResult(
                test_name="wifi_info", target="localhost", status=Status.SKIP,
                evidence=f"Wi-Fi not applicable: netsh wlan exited with code {result.returncode}",
                duration_ms=duration_ms, details={"availability": "unavailable"},
            )

        details["availability"] = "unknown"
        return DiagnosticResult(
            test_name="wifi_info", target="localhost", status=Status.WARN,
            evidence="Could not read the Wi-Fi interface state from netsh output",
            duration_ms=duration_ms, details=details,
        )
    except FileNotFoundError:
        return DiagnosticResult(
            test_name="wifi_info", target="localhost", status=Status.SKIP,
            evidence="netsh command not found", duration_ms=(time.monotonic() - start) * 1000,
            details={"availability": "unavailable"},
        )
    except Exception as e:
        return DiagnosticResult(
            test_name="wifi_info", target="localhost", status=Status.ERROR,
            evidence=f"Error: {e}", duration_ms=(time.monotonic() - start) * 1000,
            error=type(e).__name__,
        )
