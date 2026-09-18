# 🛡️ NetDiag-Toolkit

**Advanced Network Diagnostics & Security Audit Toolkit** — CLI + native desktop GUI

Copyright (c) 2026 Iyad Engle

![Version](https://img.shields.io/badge/version-0.4.0--beta-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F%2011-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

> ⚠️ **Beta release.** `0.4.0b0` adds a lightweight PySide6 GUI on top of the existing `0.3.0` diagnostics, security audit, reporting, and CLI core. The GUI is a frontend over the existing logic; it does not duplicate diagnostic checks.

---

## CLI vs GUI

| | CLI (`netdiag`) | GUI (`netdiag-gui`) |
|---|---|---|
| Dependency | Core dependencies | Requires optional PySide6 dependency |
| Use case | Scripting, automation, CI | Interactive diagnostics and review |
| Backends | `netdiag.core` / `netdiag.security` | Same modules and result models |
| Reports | Console / JSON / CSV / HTML | JSON / CSV / HTML via file dialogs |

The GUI and CLI share the same core diagnostics and security audit implementations.

## GUI

The GUI is a native PySide6 desktop application. It does not use Electron or a browser runtime.

### Included

- Target validation and target input
- **Run Diagnostics**
- **Security Audit**
- **Full Scan**
- Summary cards for Ping, DNS, HTTPS, TCP, MTU, Gateway, and Traceroute
- Diagnostic results table
- Security findings panel
- PASS / FAIL / OBSERVATION / SKIP / ERROR / INCONCLUSIVE status semantics
- Background workers so the window remains responsive
- Cooperative cancellation between test steps
- JSON / CSV / HTML export using the existing report exporters
- Activity log
- Preferences for timeout, default target, theme, log level, and report directory
- Dark and light themes
- `netdiag-gui` entry point

### GUI limitations

Cancellation is cooperative. A currently running system subprocess such as `ping` or `tracert` finishes before cancellation is applied.

Wi-Fi and adapter details remain available through the CLI; they are not duplicated into the current GUI dashboard.

---

# Installation

## Requirements

- Python **3.10 or newer**
- Windows 10/11 for the primary supported environment
- Git is useful for development, but **end users can also use GitHub's Download ZIP option**

## Windows — CLI only

For a lightweight installation without the GUI:

```powershell
# after downloading/cloning the project and opening PowerShell in it
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Verify:

```powershell
netdiag --version
```

## Windows — CLI + GUI

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[gui]"
```

Launch:

```powershell
netdiag-gui
```

For development and testing:

```powershell
pip install -e ".[gui,dev]"
```

If PowerShell blocks environment activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Linux

The core CLI is implemented with Linux-specific system utilities where needed.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For the GUI:

```bash
pip install -e ".[gui]"
netdiag-gui
```

Some Linux diagnostics depend on native utilities such as `ping`, `ip`, `traceroute`, and `dig`.

## macOS

macOS is **not currently supported**. Unsupported commands may return `SKIP`.

---

# Quick Start

```bash
netdiag --version
netdiag diagnose --target 1.1.1.1
netdiag diagnose --target google.com --full
netdiag security --target example.com
netdiag network
```

GUI on Windows/Linux with the optional GUI dependency:

```bash
netdiag-gui
```

---

# Command Reference

## `netdiag diagnose`

Core diagnostics:

```bash
netdiag diagnose --target 1.1.1.1
```

Full diagnostics including MTU and traceroute:

```bash
netdiag diagnose --target google.com --full
```

Windows Wi-Fi information:

```powershell
netdiag diagnose --target 1.1.1.1 --wifi
```

Export:

```bash
netdiag diagnose --target 1.1.1.1 --reporter json --output report.json
netdiag diagnose --target 1.1.1.1 --reporter csv --output report.csv
netdiag diagnose --target 1.1.1.1 --reporter html --output report.html
```

## `netdiag security`

Run the read-only security audit:

```bash
netdiag security --target example.com
```

Checks:

- TLS certificate expiry
- TLS protocol versions
- Certificate hostname
- HTTP security headers
- DNSSEC
- Open resolver behavior
- TCP service exposure

## `netdiag full`

Run the full diagnostics + security workflow:

```bash
netdiag full --target example.com
```

Reports:

```bash
netdiag full --target example.com --reporter json --output report.json
netdiag full --target example.com --reporter csv --output report.csv
netdiag full --target example.com --reporter html --output report.html
```

## `netdiag dns`

```bash
netdiag dns --target google.com
netdiag dns --target google.com --compare
```

The comparison checks the system resolver plus Google (`8.8.8.8`), Cloudflare (`1.1.1.1`), and Quad9 (`9.9.9.9`).

## `netdiag mtu`

```bash
netdiag mtu --target 1.1.1.1
```

Custom bounds:

```bash
netdiag mtu --target 1.1.1.1 --min-size 68 --max-size 1500
```

## `netdiag tcp`

```bash
netdiag tcp --target 1.1.1.1 --ports 443
netdiag tcp --target example.com --ports 80,443,8080 --timeout 5
```

## `netdiag trace`

```bash
netdiag trace --target 1.1.1.1
netdiag trace --target example.com --max-hops 30
```

## `netdiag network`

```bash
netdiag network
```

Shows local network adapter, gateway, and Windows Wi-Fi information where supported.

## `netdiag scan`

Scan explicitly selected TCP ports:

```bash
netdiag scan --target 192.168.1.1
netdiag scan --target 192.168.1.1 --ports 22,80,443
```

Use only against systems you are authorized to test.

## `netdiag discover`

ICMP host discovery on an explicitly selected subnet:

```bash
netdiag discover --subnet 192.168.1.0/24
```

Use only on networks you own or are authorized to test.

## `netdiag report`

Run diagnostics + security and export:

```bash
netdiag report --target example.com --reporter console
netdiag report --target example.com --reporter json --output report.json
netdiag report --target example.com --reporter csv --output report.csv
netdiag report --target example.com --reporter html --output report.html
```

---

# Supported Platforms

| Platform | Status | Notes |
|---|---|---|
| Windows 10 | ✅ Primary | Main development target |
| Windows 11 | ✅ Primary | Main development target |
| Linux | ⚠️ Implemented | Some diagnostics depend on native utilities |
| macOS | ❌ Not supported | Unsupported commands may return `SKIP` |

The GUI has been designed as a Windows-first desktop interface. Linux GUI execution is CI-tested headlessly, while Linux desktop window behavior remains less validated.

---

# Security Status Semantics

| Status | Meaning |
|---|---|
| `PASS` | Check completed and no issue was found |
| `FAIL` | Confirmed security condition |
| `OBSERVATION` | Informational configuration observation |
| `SKIP` | Not runnable or not applicable |
| `ERROR` | Unexpected error |
| `INCONCLUSIVE` | Evidence is insufficient for a definitive result |

**Open TCP ports are observations, not vulnerabilities.**

Missing HTTP security headers are observations, not automatically vulnerabilities.

Ambiguous TLS/SSL errors are reported as `INCONCLUSIVE` rather than being treated automatically as proof of protocol support or rejection.

---

# Security Scope

NetDiag-Toolkit is read-only.

It intentionally does **not** perform:

- Exploitation
- Credential attacks
- Brute force authentication
- Packet injection
- Firewall modification
- Automatic remediation
- Destructive scanning

The tool **does contact user-specified targets** as part of diagnostics, including ICMP, TCP, DNS, HTTPS, and traceroute traffic.

It has **no telemetry and no centralized third-party data collection**. Reports are generated locally.

---

# Reporting

Supported output formats:

- Console
- JSON
- CSV
- HTML

The GUI uses the same existing report exporters as the CLI.

---

# Development and Testing

Install development dependencies:

```powershell
pip install -e ".[gui,dev]"
```

Run non-integration tests without Qt:

```bash
pytest tests/ -m "not integration and not gui" -v
```

Run all non-integration tests with PySide6 installed:

```bash
pytest tests/ -m "not integration" -v
```

Lint:

```bash
ruff check netdiag/
```

Type check:

```bash
mypy netdiag/ --ignore-missing-imports
```

GitHub Actions checks:

- Ruff
- Mypy
- Unit tests
- Pure GUI tests
- Headless Qt GUI tests
- Windows tests

---

# Packaging a Windows Executable

A PyInstaller workflow is planned for a later release.

The GUI keeps resource paths relative and exposes a clean `netdiag-gui` entry point so packaging can be added without changing the core diagnostics.

---

# Project Structure

```text
NetDiag-Toolkit/
├── netdiag/
│   ├── core/
│   ├── network/
│   ├── security/
│   ├── reports/
│   ├── cli/
│   ├── gui/
│   │   ├── widgets/
│   │   └── resources/
│   └── utils/
├── tests/
├── .github/
│   └── workflows/
├── pyproject.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── CODE_OF_CONDUCT.md
```

---

# Legacy PowerShell Implementation

The original PowerShell implementation remains available as:

```text
NetDiag.ps1
```

The Python implementation is the current project direction.

---

# Limitations

- Beta software
- Windows is the primary target
- Linux support has platform-specific limitations
- macOS is not currently supported
- GUI cancellation applies between test steps
- GUI does not currently duplicate adapter/Wi-Fi details
- IPv6 targets are rejected by GUI validation
- Path MTU depends on ICMP/DF behavior
- Traceroute parsing depends on system command output
- TCP connectivity is a TCP connect test, not a vulnerability assessment
- No dedicated IPv6 diagnostic workflow
- Linux GUI desktop behavior is less validated than Windows
- A full Windows GUI smoke test should be completed before calling `0.4.0b0` production-ready

---

# Screenshots

Screenshots are intentionally not included yet. Add them after validating the Windows GUI:

- Main dashboard
- Security findings panel
- Preferences dialog

---

# License

MIT License.

Copyright (c) 2026 Iyad Engle

See [LICENSE](LICENSE).

---

# Author

**Iyad Engle**

GitHub: https://github.com/IyadEngle/NetDiag-Toolkit
