# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Traceroute using system tools."""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import time
from dataclasses import dataclass, field

from netdiag.utils.models import DiagnosticResult, Status

_IPV4 = r"\d+\.\d+\.\d+\.\d+"


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
        ip_match = re.search(rf"({_IPV4})", line)
        ip = ip_match.group(1) if ip_match else ""
        latencies = [float(x) for x in re.findall(r"(?:[=<]\s*)?(\d+)\s*ms", line)]
        # Without -d, tracert prints "hostname [a.b.c.d]"; with -d only the IP.
        name_match = re.search(rf"(\S+)\s+\[({_IPV4})\]", line)
        hostname = name_match.group(1) if name_match else ""
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
        ip_match = re.search(rf"({_IPV4})", line)
        ip = ip_match.group(1) if ip_match else ""
        latencies = [float(x) for x in re.findall(r"([\d.]+)\s*ms", line)]
        # Without -n, traceroute prints "hostname (a.b.c.d)"; with -n only the IP.
        name_match = re.search(rf"(\S+)\s+\(({_IPV4})\)", line)
        hostname = name_match.group(1) if name_match and name_match.group(1) != name_match.group(2) else ""
        hops.append(TracerouteHop(hop_number=hop_num, hostname=hostname, ip=ip, latencies_ms=latencies))
    return hops


def _destination_ip(output: str, target: str) -> str:
    """Destination IPv4 from the tool's header line, or the target itself if it is an IP."""
    header = re.search(rf"(?:Tracing route to|traceroute to)\s+\S+\s+[\[(]({_IPV4})[\])]", output)
    if header:
        return header.group(1)
    try:
        return str(ipaddress.IPv4Address(target))
    except ValueError:
        return ""


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
            destination_ip = _destination_ip(output, target)
            reached = bool(destination_ip) and any(h.ip == destination_ip for h in reachable)
            hop_summary = " → ".join(h.ip for h in reachable[:5])
            if len(reachable) > 5:
                hop_summary += f" ... ({len(reachable)} hops total)"
            if reached:
                status = Status.PASS
                evidence = f"Completed in {len(reachable)} hops: {hop_summary}"
            else:
                status = Status.WARN
                evidence = (f"Destination not reached; last responding hop {reachable[-1].ip} "
                            f"({len(reachable)} hops responded): {hop_summary}")
            return DiagnosticResult(
                test_name="traceroute", target=target, status=status,
                evidence=evidence,
                duration_ms=duration_ms,
                details={
                    "hop_count": len(reachable),
                    "destination_ip": destination_ip,
                    "destination_reached": reached,
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
