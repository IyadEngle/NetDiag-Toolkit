# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""
TCP service exposure audit. ALL findings are OBSERVATION with INFO severity.
An open port is NOT a vulnerability.
"""

from __future__ import annotations

import concurrent.futures
import contextvars
import socket

from netdiag.utils.execution import connect_host
from netdiag.utils.models import Confidence, SecurityFinding, SecurityStatus, Severity

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


def check_tcp_exposure(
    target: str, ports: list[int] | None = None,
    timeout_seconds: float = 3.0, max_concurrent: int = 10,
) -> list[SecurityFinding]:
    findings = []
    if ports is None:
        ports = sorted(SERVICE_NAMES.keys())

    def _check_port(port: int) -> int | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(timeout_seconds)
                result = sock.connect_ex((connect_host(target), port))
            finally:
                sock.close()
            return port if result == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        # One context copy per task so an active scan scope reaches the pool threads.
        futures = [executor.submit(contextvars.copy_context().run, _check_port, port) for port in ports]
        results = [future.result() for future in futures]

    reachable = [p for p in results if p is not None]

    if not reachable:
        findings.append(SecurityFinding(
            test_name="tcp_exposure", status=SecurityStatus.PASS, severity=Severity.INFO,
            title="TCP Exposure: No Targeted Ports Reachable",
            description=f"None of the {len(ports)} tested TCP ports are reachable on {target}.",
            evidence=f"Tested ports: {', '.join(map(str, ports))}. All closed or filtered.",
            recommendation="No action needed (from this vantage point).",
            confidence=Confidence.CONFIRMED,
        ))
        return findings

    for port in sorted(reachable):
        service_name = SERVICE_NAMES.get(port, "Unknown")
        findings.append(SecurityFinding(
            test_name="tcp_exposure", status=SecurityStatus.OBSERVATION,
            severity=Severity.INFO,
            title=f"TCP Service Reachable: {service_name} (Port {port})",
            description=(f"A service responding on port {port} ({service_name}) is reachable "
                         f"on {target} from this network position. "
                         f"This is an informational observation about network configuration. "
                         f"An open port does NOT indicate a vulnerability."),
            evidence=f"TCP connect to {target}:{port} succeeded.",
            recommendation=(f"Verify that the {service_name} service on port {port} is intended "
                            f"to be accessible from this network position."),
            confidence=Confidence.CONFIRMED,
        ))

    return findings
