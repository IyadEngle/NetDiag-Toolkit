# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""HTTPS connectivity diagnostics."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from netdiag import __version__
from netdiag.utils.models import DiagnosticResult, Status


def https_connectivity(target: str, port: int = 443, timeout_seconds: int = 10) -> DiagnosticResult:
    start = time.monotonic()
    url = f"https://{target}:{port}/"
    try:
        context = ssl.create_default_context()
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", f"NetDiag-Toolkit/{__version__}")
        with urllib.request.urlopen(req, timeout=timeout_seconds, context=context) as response:
            return DiagnosticResult(
                test_name="https_connectivity", target=target, status=Status.PASS,
                evidence=f"HTTPS {response.status} OK",
                duration_ms=(time.monotonic() - start) * 1000,
                details={"status_code": response.status, "url": url},
            )
    except urllib.error.HTTPError as e:
        return DiagnosticResult(
            test_name="https_connectivity", target=target, status=Status.PASS,
            evidence=f"HTTPS responded with HTTP {e.code}",
            duration_ms=(time.monotonic() - start) * 1000,
            details={"status_code": e.code, "url": url},
        )
    except ssl.SSLError as e:
        return DiagnosticResult(
            test_name="https_connectivity", target=target, status=Status.FAIL,
            evidence=f"SSL error: {e}",
            duration_ms=(time.monotonic() - start) * 1000, error="ssl.SSLError",
        )
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return DiagnosticResult(
            test_name="https_connectivity", target=target, status=Status.FAIL,
            evidence=f"Connection failed: {e}",
            duration_ms=(time.monotonic() - start) * 1000, error=type(e).__name__,
        )
    except Exception as e:
        return DiagnosticResult(
            test_name="https_connectivity", target=target, status=Status.ERROR,
            evidence=f"Unexpected error: {e}",
            duration_ms=(time.monotonic() - start) * 1000, error=type(e).__name__,
        )
