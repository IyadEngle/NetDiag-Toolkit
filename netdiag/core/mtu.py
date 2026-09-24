# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Path MTU estimation using ICMP DF-bit pings with increasing sizes."""

from __future__ import annotations

import platform
import subprocess
import time

from netdiag.utils.models import DiagnosticResult, Status


def estimate_path_mtu(
    target: str, min_size: int = 68, max_size: int = 1500, timeout_seconds: int = 3,
) -> DiagnosticResult:
    start = time.monotonic()
    os_name = platform.system()

    if os_name not in ("Windows", "Linux"):
        return DiagnosticResult(
            test_name="path_mtu", target=target, status=Status.SKIP,
            evidence=f"MTU discovery not supported on {os_name}", duration_ms=0,
        )

    # `size` is the ICMP payload on both platforms (Windows -l, Linux -s);
    # the path MTU estimate adds the 28-byte IPv4 + ICMP header overhead once.
    def _try_size(size: int) -> bool:
        try:
            if os_name == "Windows":
                cmd = ["ping", "-n", "1", "-f", "-l", str(size), "-w", str(timeout_seconds * 1000), target]
            else:
                cmd = ["ping", "-c", "1", "-M", "do", "-s", str(size), "-W", str(timeout_seconds), target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds + 2)
            output = proc.stdout.lower()
            if os_name == "Windows":
                return "ttl=" in output
            return "1 received" in output or "1 packets received" in output
        except Exception:
            return False

    low, high = min_size, max_size
    best_mtu: int | None = None

    while low <= high:
        mid = (low + high) // 2
        if _try_size(mid):
            best_mtu = mid
            low = mid + 1
        else:
            high = mid - 1

    duration_ms = (time.monotonic() - start) * 1000

    if best_mtu is not None:
        estimated_mtu = best_mtu + 28
        return DiagnosticResult(
            test_name="path_mtu", target=target, status=Status.PASS,
            evidence=f"Estimated path MTU: {estimated_mtu} bytes",
            duration_ms=duration_ms,
            details={"mtu_estimate": estimated_mtu, "max_payload": best_mtu},
        )
    return DiagnosticResult(
        test_name="path_mtu", target=target, status=Status.FAIL,
        evidence=f"Could not determine path MTU (min {min_size} failed)", duration_ms=duration_ms,
    )
