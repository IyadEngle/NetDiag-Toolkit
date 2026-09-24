# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""ICMP connectivity diagnostics using system ping."""

from __future__ import annotations

import platform
import re
import subprocess
import time
from dataclasses import dataclass

from netdiag.utils.models import DiagnosticResult, Status


@dataclass
class PingResult:
    sent: int = 0
    received: int = 0
    lost: int = 0
    loss_percent: float = 0.0
    min_ms: float | None = None
    max_ms: float | None = None
    avg_ms: float | None = None
    raw_output: str = ""


def _parse_windows_ping(output: str) -> PingResult:
    result = PingResult(raw_output=output)
    sent_match = re.search(r"Sent\s*=\s*(\d+)", output)
    recv_match = re.search(r"Received\s*=\s*(\d+)", output)
    lost_match = re.search(r"Lost\s*=\s*(\d+)", output)
    if sent_match:
        result.sent = int(sent_match.group(1))
    if recv_match:
        result.received = int(recv_match.group(1))
    if lost_match:
        result.lost = int(lost_match.group(1))
    if result.sent > 0:
        result.loss_percent = round((result.lost / result.sent) * 100, 1)
    times = re.findall(r"time[=<]\s*(\d+)ms", output)
    if times:
        ms_values = [int(t) for t in times]
        result.min_ms = min(ms_values)
        result.max_ms = max(ms_values)
        result.avg_ms = round(sum(ms_values) / len(ms_values), 1)
    return result


def _parse_linux_ping(output: str) -> PingResult:
    result = PingResult(raw_output=output)
    pkt_match = re.search(
        r"(\d+)\s+packets transmitted,\s+(\d+)\s+received,\s+(\d+(?:\.\d+)?)%\s+packet loss",
        output,
    )
    if pkt_match:
        result.sent = int(pkt_match.group(1))
        result.received = int(pkt_match.group(2))
        result.loss_percent = float(pkt_match.group(3))
        result.lost = result.sent - result.received
    rtt_match = re.search(r"rtt min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", output)
    if rtt_match:
        result.min_ms = float(rtt_match.group(1))
        result.avg_ms = float(rtt_match.group(2))
        result.max_ms = float(rtt_match.group(3))
    return result


def ping(target: str, count: int = 4, timeout_seconds: int = 10) -> DiagnosticResult:
    os_name = platform.system()
    start = time.monotonic()

    try:
        if os_name == "Windows":
            cmd = ["ping", "-n", str(count), "-w", str(timeout_seconds * 1000), target]
        elif os_name == "Linux":
            cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds), target]
        else:
            return DiagnosticResult(
                test_name="icmp_ping", target=target, status=Status.SKIP,
                evidence=f"Ping not supported on {os_name}", duration_ms=0,
            )

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds + count + 5)
        output = proc.stdout + proc.stderr
        duration_ms = (time.monotonic() - start) * 1000

        parsed = _parse_windows_ping(output) if os_name == "Windows" else _parse_linux_ping(output)

        if parsed.received > 0:
            if parsed.loss_percent <= 0:
                status = Status.PASS
            elif parsed.loss_percent < 100:
                status = Status.WARN  # partial packet loss
            else:
                status = Status.FAIL
            evidence = (
                f"Sent={parsed.sent} Received={parsed.received} Loss={parsed.loss_percent}% "
                f"Min={parsed.min_ms}ms Avg={parsed.avg_ms}ms Max={parsed.max_ms}ms"
            )
        else:
            status = Status.FAIL
            evidence = "No responses received"

        return DiagnosticResult(
            test_name="icmp_ping", target=target, status=status, evidence=evidence,
            duration_ms=duration_ms,
            details={
                "sent": parsed.sent, "received": parsed.received, "lost": parsed.lost,
                "loss_percent": parsed.loss_percent, "min_ms": parsed.min_ms,
                "avg_ms": parsed.avg_ms, "max_ms": parsed.max_ms,
            },
        )
    except subprocess.TimeoutExpired:
        return DiagnosticResult(
            test_name="icmp_ping", target=target, status=Status.ERROR,
            evidence="Ping command timed out",
            duration_ms=(time.monotonic() - start) * 1000, error="TimeoutExpired",
        )
    except FileNotFoundError:
        return DiagnosticResult(
            test_name="icmp_ping", target=target, status=Status.ERROR,
            evidence="System ping command not found",
            duration_ms=(time.monotonic() - start) * 1000, error="FileNotFoundError",
        )
    except Exception as e:
        return DiagnosticResult(
            test_name="icmp_ping", target=target, status=Status.ERROR,
            evidence=f"Unexpected error: {e}",
            duration_ms=(time.monotonic() - start) * 1000, error=type(e).__name__,
        )
