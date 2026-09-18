# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Console report formatter with colored output."""

from __future__ import annotations

from netdiag.utils.models import ScanReport, SecurityStatus, Severity, Status


class _C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"

    STATUS_COLORS = {
        Status.PASS: GREEN, Status.FAIL: RED, Status.WARN: YELLOW,
        Status.SKIP: DIM, Status.ERROR: RED,
    }
    SEVERITY_COLORS = {
        Severity.INFO: BLUE, Severity.LOW: CYAN, Severity.MEDIUM: YELLOW,
        Severity.HIGH: RED, Severity.CRITICAL: RED + BOLD,
    }
    STATUS_ICONS = {
        Status.PASS: "✓", Status.FAIL: "✗", Status.WARN: "⚠",
        Status.SKIP: "○", Status.ERROR: "!",
    }
    SECURITY_STATUS_ICONS = {
        SecurityStatus.FAIL: "■",
        SecurityStatus.OBSERVATION: "◇",
        SecurityStatus.PASS: "✓",
        SecurityStatus.SKIP: "○",
        SecurityStatus.ERROR: "!",
        SecurityStatus.INCONCLUSIVE: "?",
    }
    SECURITY_STATUS_LABELS = {
        SecurityStatus.FAIL: "FAIL",
        SecurityStatus.OBSERVATION: "NOTE",
        SecurityStatus.PASS: "PASS",
        SecurityStatus.SKIP: "SKIP",
        SecurityStatus.ERROR: "ERR",
        SecurityStatus.INCONCLUSIVE: "?",
    }


class _NoColor(_C):
    RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = CYAN = ""
    STATUS_COLORS = {status: "" for status in Status}
    SEVERITY_COLORS = {severity: "" for severity in Severity}


def format_console_report(report: ScanReport, use_color: bool = True) -> str:
    C: _C = _C() if use_color else _NoColor()
    lines = []
    width = 64

    lines.append(f"{C.CYAN}{'═' * width}{C.RESET}")
    lines.append(f"{C.BOLD}  🛡️  NetDiag-Toolkit v{report.tool_version}{C.RESET}")
    lines.append(f"  Target: {C.BOLD}{report.target}{C.RESET}")
    lines.append(f"  Started: {report.started_at}")
    lines.append(f"{C.CYAN}{'═' * width}{C.RESET}")
    lines.append("")

    lines.append(f"{C.BOLD}  Summary:{C.RESET}")
    lines.append(
        f"    {C.GREEN}Passed: {report.passed}{C.RESET}  "
        f"{C.RED}Failed: {report.failed}{C.RESET}  "
        f"{C.YELLOW}Warned: {report.warned}{C.RESET}  "
        f"{C.RED}Errors: {report.errors}{C.RESET}"
    )
    if report.findings:
        lines.append(
            f"    Security: {report.security_failures} failure(s), "
            f"{report.security_observations} observation(s), "
            f"{report.security_inconclusive} inconclusive, "
            f"{report.security_skipped} skipped"
        )
    lines.append("")

    if report.results:
        lines.append(f"{C.BOLD}  Diagnostics:{C.RESET}")
        lines.append(f"  {'':2} {'STATUS':<8} {'TEST':<25} {'DURATION':<10} {'EVIDENCE'}")
        lines.append(f"  {'':2} {'─' * 6} {'─' * 25} {'─' * 10} {'─' * 30}")
        for r in report.results:
            color = C.STATUS_COLORS.get(r.status, "")
            icon = C.STATUS_ICONS.get(r.status, "?")
            duration = f"{r.duration_ms:.0f}ms"
            evidence = r.evidence[:45] + "..." if len(r.evidence) > 45 else r.evidence
            lines.append(f"  {color}{icon}{C.RESET} {color}{r.status.value:<8}{C.RESET} {r.test_name:<25} {duration:<10} {evidence}")
            if r.error:
                lines.append(f"    {C.DIM}  Error: {r.error}{C.RESET}")
        lines.append("")

    if report.findings:
        lines.append(f"{C.BOLD}  Security Findings:{C.RESET}")
        lines.append("")
        for i, f in enumerate(report.findings, 1):
            sev_color = C.SEVERITY_COLORS.get(f.severity, "")
            icon = C.SECURITY_STATUS_ICONS.get(f.status, "•")
            status_label = C.SECURITY_STATUS_LABELS.get(f.status, f.status.value)
            lines.append(f"  {sev_color}{icon} [{f.severity.value}:{status_label}]{C.RESET} {C.BOLD}{f.title}{C.RESET}")
            lines.append(f"     {C.DIM}Test: {f.test_name} | Confidence: {f.confidence.value}{C.RESET}")
            lines.append(f"     Evidence: {f.evidence}")
            lines.append(f"     {C.CYAN}→ {f.recommendation}{C.RESET}")
            lines.append("")
        lines.append(f"  Total findings: {len(report.findings)}")
        lines.append("")

    lines.append(f"{C.CYAN}{'═' * width}{C.RESET}")
    return "\n".join(lines)
