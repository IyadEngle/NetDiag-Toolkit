# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Traceroute using system tools."""

from __future__ import annotations

import platform
import re
import subprocess
import time
from dataclasses import dataclass, field

from netdiag.utils.models import DiagnosticResult, Status


@dataclass
class TracerouteHop:
    hop_number: int
    hostname: str = ""
    ip: str = ""
    latencies_ms: list[float] = field(default_factory=list)


def _parse_windows_tracert(output: str) -> list[TracerouteHop]:
    hops = []
    for line in output.split("\n"):
        line = line.strip()
        match = re.match(r"\s*(\d+)\s+", line)
        if not match:
            continue
        hop_num = int(match.group(1))
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        ip = ip_match.group(1) if ip_match else ""
        latencies = [float(x) for x in re.findall(r"(?:[=<]\s*)?(\d+)\s*ms", line)]
        hostname = ""
        if ip:
            parts = line.split()
            for part in parts:
                if part != ip and not part.replace("ms", "").replace("*", "").strip().replace(".", "").isdigit():
                    if not part.startswith("[") and not part.endswith("]"):
                        hostname = part
                        break
        hops.append(TracerouteHop(hop_number=hop_num, hostname=hostname, ip=ip, latencies_ms=latencies))
    return hops


def _parse_linux_traceroute(output: str) -> list[TracerouteHop]:
    hops = []
    for line in output.split("\n"):
        line = line.strip()
        match = re.match(r"\s*(\d+)\s+", line)
        if not match:
            continue
        hop_num = int(match.group(1))
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        ip = ip_match.group(1) if ip_match else ""
        latencies = [float(x) for x in re.findall(r"([\d.]+)\s*ms", line)]
        hostname = ""
        if ip:
            parts = line.split()
            for part in parts:
                if part != ip and not part.startswith("(") and not part.endswith("ms") and not part.startswith("*"):
                    hostname = part
                    break
        hops.append(TracerouteHop(hop_number=hop_num, hostname=hostname, ip=ip, latencies_ms=latencies))
    return hops


def traceroute(target: str, max_hops: int = 30, timeout_seconds: int = 60) -> DiagnosticResult:
    start = time.monotonic()
    os_name = platform.system()

    try:
        if os_name == "Windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", target]
        elif os_name == "Linux":
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", target]
        else:
            return DiagnosticResult(
                test_name="traceroute", target=target, status=Status.SKIP,
                evidence=f"Traceroute not supported on {os_name}", duration_ms=0,
            )

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        output = proc.stdout
        duration_ms = (time.monotonic() - start) * 1000

        if os_name == "Windows":
            hops = _parse_windows_tracert(output)
        else:
            hops = _parse_linux_traceroute(output)

        reachable = [h for h in hops if h.ip]
        if reachable:
            hop_summary = " → ".join(h.ip for h in reachable[:5])
            if len(reachable) > 5:
                hop_summary += f" ... ({len(reachable)} hops total)"
            return DiagnosticResult(
                test_name="traceroute", target=target, status=Status.PASS,
                evidence=f"Completed in {len(reachable)} hops: {hop_summary}",
                duration_ms=duration_ms,
                details={
                    "hop_count": len(reachable),
                    "hops": [
                        {"hop": h.hop_number, "ip": h.ip, "hostname": h.hostname, "latencies_ms": h.latencies_ms}
                        for h in hops
                    ],
                },
            )
        return DiagnosticResult(
            test_name="traceroute", target=target, status=Status.FAIL,
            evidence="No hops responded", duration_ms=duration_ms,
        )

    except subprocess.TimeoutExpired:
        return DiagnosticResult(
            test_name="traceroute", target=target, status=Status.ERROR,
            evidence="Traceroute timed out", duration_ms=(time.monotonic() - start) * 1000,
            error="TimeoutExpired",
        )
    except FileNotFoundError:
        return DiagnosticResult(
            test_name="traceroute", target=target, status=Status.ERROR,
            evidence="Traceroute command not found", duration_ms=(time.monotonic() - start) * 1000,
            error="FileNotFoundError",
        )
    except Exception as e:
        return DiagnosticResult(
            test_name="traceroute", target=target, status=Status.ERROR,
            evidence=f"Unexpected error: {e}", duration_ms=(time.monotonic() - start) * 1000,
            error=type(e).__name__,
        )
