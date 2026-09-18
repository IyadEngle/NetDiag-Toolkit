# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""
TCP service exposure audit. ALL findings are OBSERVATION with INFO severity.
An open port is NOT a vulnerability.
"""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Optional

from netdiag.utils.models import SecurityFinding, SecurityStatus, Severity, Confidence

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


def check_tcp_exposure(
    target: str, ports: Optional[list[int]] = None,
    timeout_seconds: float = 3.0, max_concurrent: int = 10,
) -> list[SecurityFinding]:
    findings = []
    if ports is None:
        ports = sorted(SERVICE_NAMES.keys())

    def _check_port(port: int) -> Optional[int]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_seconds)
            result = sock.connect_ex((target, port))
            sock.close()
            return port if result == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        results = list(executor.map(_check_port, ports))

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
