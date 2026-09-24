# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""DNS resolution and DNS server comparison."""

from __future__ import annotations

import ipaddress
import socket
import time

from netdiag.utils import process
from netdiag.utils.models import DiagnosticResult, Status


def resolve_hostname(target: str, dns_server: str | None = None) -> DiagnosticResult:
    start = time.monotonic()
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        duration_ms = (time.monotonic() - start) * 1000
        unique_ips = sorted({addr[4][0] for addr in ips if isinstance(addr[4][0], str)})
        return DiagnosticResult(
            test_name="dns_resolution", target=target, status=Status.PASS,
            evidence=f"Resolved to: {', '.join(unique_ips)}",
            duration_ms=duration_ms, details={"resolved_ips": unique_ips},
        )
    except socket.gaierror as e:
        return DiagnosticResult(
            test_name="dns_resolution", target=target, status=Status.FAIL,
            evidence=f"Resolution failed: {e}",
            duration_ms=(time.monotonic() - start) * 1000, error="socket.gaierror",
        )
    except Exception as e:
        return DiagnosticResult(
            test_name="dns_resolution", target=target, status=Status.ERROR,
            evidence=f"Unexpected error: {e}",
            duration_ms=(time.monotonic() - start) * 1000, error=type(e).__name__,
        )


def _parse_nslookup_answers(output: str, server_ip: str) -> list[str]:
    """Extract answer addresses (IPv4 and IPv6) from Windows nslookup output.

    Handles single "Address:" lines and multi-line "Addresses:" blocks whose
    continuation lines hold one bare address each.
    """
    ips: list[str] = []
    in_answer = False
    in_address_block = False
    for raw_line in output.split("\n"):
        line = raw_line.strip()
        if line.startswith("Name:"):
            in_answer = True
            in_address_block = False
            continue
        if not in_answer or not line:
            continue
        if line.startswith("Address"):
            # Split on the first colon only: IPv6 addresses contain colons.
            candidate = line.split(":", 1)[1].strip()
            in_address_block = True
        elif in_address_block and _is_ip(line):
            candidate = line
        else:
            in_address_block = False
            continue
        if candidate and candidate != server_ip:
            ips.append(candidate)
    return ips


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def compare_dns_servers(target: str) -> list[DiagnosticResult]:
    servers = {"System": None, "Google": "8.8.8.8", "Cloudflare": "1.1.1.1", "Quad9": "9.9.9.9"}
    results = []
    for name, server_ip in servers.items():
        start = time.monotonic()
        test_name = f"dns_comparison_{name.lower().replace(' ', '_')}"
        try:
            if server_ip is None:
                result = resolve_hostname(target)
                result.test_name = test_name
                results.append(result)
                continue
            import platform
            os_name = platform.system()
            if os_name == "Windows":
                cmd = ["nslookup", target, server_ip]
            elif os_name == "Linux":
                cmd = ["dig", f"@{server_ip}", target, "+short"]
            else:
                results.append(DiagnosticResult(
                    test_name=test_name, target=target, status=Status.SKIP,
                    evidence=f"DNS comparison not supported on {os_name}", duration_ms=0,
                ))
                continue
            proc = process.run(cmd, capture_output=True, text=True, timeout=5)
            duration_ms = (time.monotonic() - start) * 1000
            output = proc.stdout.strip()
            if os_name == "Linux":
                ips = [line.strip() for line in output.split("\n") if line.strip()]
            else:
                ips = _parse_nslookup_answers(output, server_ip)
            if ips:
                results.append(DiagnosticResult(
                    test_name=test_name, target=target, status=Status.PASS,
                    evidence=f"{name} resolved to: {', '.join(ips[:3])}",
                    duration_ms=duration_ms, details={"server": server_ip, "resolved_ips": ips[:5]},
                ))
            else:
                results.append(DiagnosticResult(
                    test_name=test_name, target=target, status=Status.FAIL,
                    evidence=f"{name} returned no results", duration_ms=duration_ms,
                    details={"server": server_ip},
                ))
        except Exception as e:
            results.append(DiagnosticResult(
                test_name=test_name, target=target, status=Status.ERROR,
                evidence=f"Error querying {name}: {e}",
                duration_ms=(time.monotonic() - start) * 1000, error=type(e).__name__,
            ))
    return results
