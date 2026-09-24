# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Network discovery (port scan + host discovery). Requires explicit target."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import subprocess
import time

from netdiag.utils.models import DiagnosticResult, Status

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080]
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
}


def port_scan(
    target: str, ports: list[int] | None = None,
    timeout_seconds: float = 2.0, max_concurrent: int = 20,
) -> DiagnosticResult:
    start = time.monotonic()
    if ports is None:
        ports = COMMON_PORTS

    open_ports = []
    closed_count = 0
    filtered_count = 0

    def _check_port(port: int) -> tuple[int, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(timeout_seconds)
                result = sock.connect_ex((target, port))
            finally:
                sock.close()
            if result == 0:
                return port, "OPEN"
            elif result in (10061, 111):
                return port, "CLOSED"
            return port, "FILTERED"
        except Exception:
            return port, "FILTERED"

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        states = list(executor.map(_check_port, ports))

    for port, state in states:
        if state == "OPEN":
            open_ports.append({"port": port, "service": SERVICE_NAMES.get(port, "unknown")})
        elif state == "CLOSED":
            closed_count += 1
        else:
            filtered_count += 1

    duration_ms = (time.monotonic() - start) * 1000
    open_list = ", ".join(f"{p['port']}({p['service']})" for p in open_ports) if open_ports else "none"

    return DiagnosticResult(
        test_name="tcp_port_scan", target=target, status=Status.PASS,
        evidence=f"Scanned {len(ports)} ports: {len(open_ports)} open, {closed_count} closed, {filtered_count} filtered. Open: [{open_list}]",
        duration_ms=duration_ms,
        details={"ports_scanned": len(ports), "open_ports": open_ports, "closed": closed_count, "filtered": filtered_count},
    )


def host_discovery(
    subnet: str, timeout_seconds: int = 2, max_concurrent: int = 50,
) -> DiagnosticResult:
    import platform
    start = time.monotonic()
    os_name = platform.system()

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        return DiagnosticResult(
            test_name="host_discovery", target=subnet, status=Status.ERROR,
            evidence=f"Invalid subnet: {e}", duration_ms=0, error="ValueError",
        )

    all_ips = [str(ip) for ip in network.hosts()]

    def _check_host(ip: str) -> str | None:
        try:
            if os_name == "Windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout_seconds * 1000), ip]
            elif os_name == "Linux":
                cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), ip]
            else:
                return None
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds + 2)
            output = proc.stdout.lower()
            if "ttl=" in output or "1 received" in output:
                return ip
            return None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        results = list(executor.map(_check_host, all_ips))

    active = [ip for ip in results if ip is not None]
    duration_ms = (time.monotonic() - start) * 1000

    return DiagnosticResult(
        test_name="host_discovery", target=subnet, status=Status.PASS,
        evidence=f"Discovered {len(active)} active host(s) out of {len(all_ips)} scanned",
        duration_ms=duration_ms,
        details={"active_hosts": active, "total_scanned": len(all_ips)},
    )
