# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""TCP connectivity diagnostics."""

from __future__ import annotations

import concurrent.futures
import socket
import time

from netdiag.utils.models import DiagnosticResult, Status


def tcp_connect(host: str, port: int, timeout_seconds: float = 5.0) -> DiagnosticResult:
    start = time.monotonic()
    target = f"{host}:{port}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_seconds)
        result = sock.connect_ex((host, port))
        duration_ms = (time.monotonic() - start) * 1000
        sock.close()

        if result == 0:
            return DiagnosticResult(
                test_name="tcp_connect", target=target, status=Status.PASS,
                evidence=f"TCP connection to port {port} succeeded", duration_ms=duration_ms,
            )
        elif result in (10061, 111):
            return DiagnosticResult(
                test_name="tcp_connect", target=target, status=Status.FAIL,
                evidence=f"Connection refused (port {port} is closed)", duration_ms=duration_ms,
            )
        elif result in (10060, 110):
            return DiagnosticResult(
                test_name="tcp_connect", target=target, status=Status.FAIL,
                evidence=f"Connection timed out (port {port} may be filtered)", duration_ms=duration_ms,
            )
        return DiagnosticResult(
            test_name="tcp_connect", target=target, status=Status.FAIL,
            evidence=f"Connect failed with errno {result}", duration_ms=duration_ms,
        )
    except socket.gaierror as e:
        return DiagnosticResult(
            test_name="tcp_connect", target=target, status=Status.ERROR,
            evidence=f"DNS resolution failed: {e}",
            duration_ms=(time.monotonic() - start) * 1000, error="socket.gaierror",
        )
    except Exception as e:
        return DiagnosticResult(
            test_name="tcp_connect", target=target, status=Status.ERROR,
            evidence=f"Unexpected error: {e}",
            duration_ms=(time.monotonic() - start) * 1000, error=type(e).__name__,
        )


def tcp_multi_port(
    host: str, ports: list[int], timeout_seconds: float = 3.0, max_concurrent: int = 10,
) -> list[DiagnosticResult]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        future_to_port = {executor.submit(tcp_connect, host, p, timeout_seconds): p for p in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                results.append(future.result())
            except Exception as e:
                port = future_to_port[future]
                results.append(DiagnosticResult(
                    test_name="tcp_connect", target=f"{host}:{port}", status=Status.ERROR,
                    evidence=f"Unexpected error: {e}", duration_ms=0, error=type(e).__name__,
                ))
    results.sort(key=lambda r: int(r.target.split(":")[-1]))
    return results
