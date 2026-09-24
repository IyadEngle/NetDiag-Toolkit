# 🛡️ NetDiag-Toolkit

**Advanced Network Diagnostics & Security Audit Toolkit** — CLI + native desktop GUI

Copyright (c) 2026 Iyad Engle · Author: **Iyad Engle** ([@IyadEngle](https://github.com/IyadEngle)) ·
Repository: https://github.com/IyadEngle/NetDiag-Toolkit · License: [MIT](LICENSE) ·
Security: [SECURITY.md](SECURITY.md)

![Version](https://img.shields.io/badge/version-0.5.0--beta-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F%2011-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

> ⚠️ **Beta release.** `0.5.0b0` moves the CLI and the PySide6 GUI onto one shared scan runner: both build the same scan plan, run independent checks in parallel, support real cancellation, and reuse DNS and TLS results within a scan. Diagnostics, security checks, result models and status semantics are unchanged.

---

## CLI vs GUI

| | CLI (`netdiag`) | GUI (`netdiag-gui`) |
|---|---|---|
| Dependency | Core dependencies | Requires optional PySide6 dependency |
| Use case | Scripting, automation, CI | Interactive diagnostics and review |
| Backends | `netdiag.core` / `netdiag.security` | Same modules and result models |
| Reports | Console / JSON / CSV / HTML | JSON / CSV / HTML via file dialogs |

The GUI and CLI share the same core diagnostics and security audit implementations, and the same scan plans and runner (see [How scans run](#how-scans-run)).

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
- Immediate cancellation: running commands (`ping`, `tracert`, …) are stopped and completed results are kept
- JSON / CSV / HTML export using the existing report exporters
- Activity log
- Preferences for timeout, default target, theme, log level, and report directory
- Dark and light themes
- `netdiag-gui` entry point

### GUI limitations

Independent checks run in parallel, so the activity log numbers steps in the order they start; the results table and findings panel always show results in the scan's fixed order.

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

Windows PowerShell legacy workflow:

```powershell
.\NetDiag.ps1
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

## Targets

Every `--target` is validated the same way as in the GUI: an IPv4 address or an
RFC 1123 hostname, without URL scheme, path, port, whitespace, or a leading `-`.
Dotted numbers that are not valid IPv4 addresses (for example `1.2.3.999`) are
rejected. IPv6 addresses are recognised but not supported yet (planned for 0.6).
Invalid targets, and invalid `--ports` lists, are rejected with a usage error
(exit code 2).

## Exit codes

Exit codes are bit flags, so scripts and CI jobs can test each condition:

| Code | Meaning |
|---|---|
| `0` | No diagnostic failures and no security `FAIL` findings |
| `1` | One or more diagnostics returned `FAIL` or `ERROR` |
| `2` | Usage error (invalid or missing options) |
| `4` | One or more security findings with status `FAIL` |
| `5` | Both `1` and `4` |
| `130` | Interrupted with Ctrl+C; the partial report is still printed |

`WARN`, `SKIP`, `OBSERVATION` and `INCONCLUSIVE` results do not change the exit code.
Diagnostics report `WARN` for partial packet loss and for a traceroute that does not
reach its destination.

Wi-Fi (`--wifi`, `full`, `network`) is `SKIP` when it does not apply: no wireless
interface, WLAN service not running, or an adapter that is not connected (for example
a machine on Ethernet). It is `WARN` while an adapter is still connecting or when its
state cannot be read, so it never fails a run on its own.

## Progress and Ctrl+C

When stderr is an interactive terminal, the CLI shows a single progress line
(`[finished/total] <running check>…`) that is erased before the report is printed.
Piped or redirected output contains no progress output.

Ctrl+C cancels the scan cleanly: running commands are stopped, the report of the
checks that completed is printed with the requested reporter (or written to
`--output`), stderr says `Interrupted: partial results (N of M steps completed).`,
and the exit code is `130`.

## How scans run

Every CLI command and GUI mode builds a scan plan (`netdiag/runner/plans.py`) and runs
it on the shared scan runner (`netdiag/runner/`):

- **Parallel with rules**: up to 4 checks run at once. DNS resolution runs first for
  the checks that reuse its result; ping, path MTU and traceroute never overlap (so
  they cannot distort each other's measurements); the TLS checks run one at a time.
- **Report order is fixed**: results are reported in the plan's order, whichever
  check finishes first.
- **Time budgets**: each check has a budget above its own worst-case timeouts; a
  check that exceeds it is stopped and reported as `ERROR` (`StepTimeout`).
- **Reuse within a scan**: the address resolved by the DNS check is reused for TCP,
  TLS, ping, MTU and traceroute connections (reports, TLS SNI and certificate
  hostname checks keep the hostname), and one TLS certificate handshake is shared
  by the TLS checks.
- **Diagnostic functions are unchanged**: called directly (outside a scan) they
  behave exactly as before.

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

To report a vulnerability in NetDiag-Toolkit itself, follow [SECURITY.md](SECURITY.md) (private reporting; please do not open a public issue).

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
QT_QPA_PLATFORM=offscreen pytest tests/ -m "not integration" -v
```

Lint:

```bash
ruff check netdiag/ tests/
```

Type check:

```bash
mypy netdiag/ --ignore-missing-imports
```

GitHub Actions checks (on every branch and pull request):

- Ruff (`netdiag/` and `tests/`)
- Mypy (with PySide6 installed)
- Unit tests on Linux, Python 3.10–3.13, including headless Qt GUI tests
- Unit tests on Windows, including headless Qt GUI tests
- PowerShell syntax check and Pester tests for `NetDiag.ps1`

PowerShell tests (Pester 5):

```powershell
Invoke-Pester -Path tests/powershell
```

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
│   ├── runner/        # shared scan plans, runner, events, budgets
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

## Legacy PowerShell implementation

The original Windows PowerShell implementation is still included for users who prefer the classic command-line workflow:

```text
NetDiag.ps1
```

It runs the original diagnostics directly from PowerShell and remains available alongside the Python CLI and GUI. The legacy script covers connectivity/latency, DNS, HTTPS, path MTU, default gateway, TCP ports, traceroute, Wi-Fi, adapter/IP state, and JSON/CSV reporting.

### Run the legacy script

From the project folder:

```powershell
.\NetDiag.ps1
```

### Legacy examples

Run with the default targets/settings:

```powershell
.\NetDiag.ps1
```

Set the ping target, DNS name, and HTTPS URL:

```powershell
.\NetDiag.ps1 `
  -Target 1.1.1.1 `
  -DnsName cloudflare.com `
  -HttpsUrl https://www.cloudflare.com/
```

Test selected TCP ports and save JSON/CSV reports:

```powershell
.\NetDiag.ps1 `
  -TcpHost 1.1.1.1 `
  -TcpPorts 80,443,53 `
  -CsvPath .\report.csv `
  -JsonPath .\report.json
```

Compare specific DNS servers:

```powershell
.\NetDiag.ps1 `
  -DnsServers 1.1.1.1,8.8.8.8 `
  -DnsQuery cloudflare.com
```

### Legacy parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-Target` | `1.1.1.1` | Main ping target |
| `-DnsName` | `cloudflare.com` | DNS lookup name |
| `-HttpsUrl` | `https://www.cloudflare.com/` | HTTPS endpoint |
| `-MtuHost` | `1.1.1.1` | Host used for Path MTU testing |
| `-TcpHost` | `1.1.1.1` | Host used for TCP connectivity tests |
| `-TcpPorts` | `80,443` | TCP ports to test |
| `-TraceHost` | `1.1.1.1` | Host used for traceroute |
| `-TraceMaxHops` | `12` | Maximum traceroute hops |
| `-PingCount` | `5` | Number of ICMP ping requests |
| `-TcpTimeoutMs` | `2000` | TCP connection timeout in milliseconds |
| `-MtuStartPayload` | `1200` | Starting ICMP payload size |
| `-MtuMaxPayload` | `1472` | Maximum ICMP payload size |
| `-DnsServers` | `1.1.1.1,8.8.8.8` | DNS servers to compare |
| `-DnsQuery` | `cloudflare.com` | Name queried against selected DNS servers |
| `-JsonPath` | unset | Save the complete report as JSON |
| `-CsvPath` | unset | Save a flattened report as CSV |

### Which interface should I use?

- **`netdiag`** — current Python CLI for scripting, automation, reporting, and the security audit.
- **`netdiag-gui`** — current native desktop GUI for interactive use.
- **`NetDiag.ps1`** — original Windows PowerShell workflow for users who prefer the legacy commands and parameters.

The PowerShell script is Windows-only and does not require the optional PySide6 GUI dependency.
---

# Limitations

- Beta software
- Windows is the primary target
- Linux support has platform-specific limitations
- macOS is not currently supported
- GUI does not currently duplicate adapter/Wi-Fi details
- IPv6 targets are rejected by GUI validation
- Path MTU depends on ICMP/DF behavior
- Traceroute parsing depends on system command output
- TCP connectivity is a TCP connect test, not a vulnerability assessment
- No dedicated IPv6 diagnostic workflow
- Linux GUI desktop behavior is less validated than Windows
- A full Windows GUI smoke test should be completed before calling `0.5.0b0` production-ready

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
