# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""
HTTP security headers audit. Header absence is an OBSERVATION, not a security failure.
Uses GET (not HEAD) for maximum compatibility.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from typing import TypedDict

from netdiag import __version__
from netdiag.utils.models import Confidence, SecurityFinding, SecurityStatus, Severity


class HeaderInfo(TypedDict):
    severity: Severity
    title: str
    description: str
    recommendation: str


REQUIRED_HEADERS: dict[str, HeaderInfo] = {
    "strict-transport-security": {
        "severity": Severity.INFO,
        "title": "Strict-Transport-Security Header Not Detected",
        "description": ("The HSTS header was not found. This is an observation. "
                        "Header absence does not automatically constitute a vulnerability."),
        "recommendation": "Consider adding 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    },
    "content-security-policy": {
        "severity": Severity.LOW,
        "title": "Content-Security-Policy Header Not Detected",
        "description": ("The CSP header was not found. This is an observation. "
                        "CSP is a defense-in-depth mechanism against XSS."),
        "recommendation": "Consider adding a Content-Security-Policy header.",
    },
    "x-content-type-options": {
        "severity": Severity.INFO,
        "title": "X-Content-Type-Options Header Not Detected",
        "description": ("The X-Content-Type-Options header was not found. "
                        "This is an observation about configuration."),
        "recommendation": "Consider adding 'X-Content-Type-Options: nosniff'.",
    },
    "x-frame-options": {
        "severity": Severity.INFO,
        "title": "X-Frame-Options Header Not Detected",
        "description": ("The X-Frame-Options header was not found. "
                        "This is an observation about configuration."),
        "recommendation": "Consider adding 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
    },
}


def check_http_security_headers(
    target: str, port: int = 443, use_https: bool = True, timeout: int = 10,
) -> list[SecurityFinding]:
    findings = []
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}:{port}/"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", f"NetDiag-Toolkit/{__version__}")
        context = ssl.create_default_context() if use_https else None

        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}

            for header_name, info in REQUIRED_HEADERS.items():
                if header_name not in headers:
                    findings.append(SecurityFinding(
                        test_name="http_security_headers",
                        status=SecurityStatus.OBSERVATION,
                        severity=info["severity"],
                        title=info["title"], description=info["description"],
                        evidence=f"Header '{header_name}' not found in GET response from {url}",
                        recommendation=info["recommendation"],
                        confidence=Confidence.CONFIRMED,
                    ))

            server_header = headers.get("server", "")
            if server_header:
                version_match = re.search(r'(\d+\.\d+[\.\d]*)', server_header)
                if version_match:
                    findings.append(SecurityFinding(
                        test_name="http_security_headers",
                        status=SecurityStatus.OBSERVATION,
                        severity=Severity.INFO,
                        title="Server Version Disclosed in Response Header",
                        description=f"The Server header reveals version: '{server_header}'. "
                                    "This is an informational configuration observation.",
                        evidence=f"Server: {server_header}",
                        recommendation="Consider removing or generalizing the Server header.",
                        confidence=Confidence.CONFIRMED,
                    ))

    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        for header_name, info in REQUIRED_HEADERS.items():
            if header_name not in headers:
                findings.append(SecurityFinding(
                    test_name="http_security_headers",
                    status=SecurityStatus.OBSERVATION,
                    severity=info["severity"],
                    title=info["title"], description=info["description"],
                    evidence=f"Header '{header_name}' not found (HTTP {e.code}) from {url}",
                    recommendation=info["recommendation"],
                    confidence=Confidence.CONFIRMED,
                ))

    except (ConnectionRefusedError, ConnectionResetError, OSError, urllib.error.URLError) as e:
        findings.append(SecurityFinding(
            test_name="http_security_headers", status=SecurityStatus.SKIP,
            severity=Severity.INFO, title="HTTP Security Headers: Connection Failed",
            description=f"Could not connect to {url}.", evidence=str(e),
            recommendation="Verify target is reachable.", confidence=Confidence.INCONCLUSIVE,
        ))
    except Exception as e:
        findings.append(SecurityFinding(
            test_name="http_security_headers", status=SecurityStatus.ERROR,
            severity=Severity.INFO, title="HTTP Security Headers: Unexpected Error",
            description="An unexpected error occurred.", evidence=str(e),
            recommendation="Review logs.", confidence=Confidence.INCONCLUSIVE,
        ))

    return findings
