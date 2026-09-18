# 🛡️ NetDiag-Toolkit v0.3.0 Beta

**Advanced Network Diagnostics & Security Audit Toolkit**

Copyright (c) 2026 Iyad Engle

[![Version](https://img.shields.io/badge/version-0.3.0--beta-orange)](https://github.com/IyadEngle/NetDiag-Toolkit/releases/tag/v0.3.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **Beta release.** The Python implementation is Windows-first. Linux support is implemented with some limitations. macOS is not currently supported.

---

## Overview

NetDiag-Toolkit is a read-only network diagnostics and basic security configuration audit tool.

It can help you inspect:

- Network connectivity
- Latency and packet loss
- DNS resolution and DNS server comparison
- HTTPS/TLS connectivity
- TCP connectivity
- Path MTU
- Default gateway
- Traceroute
- Network adapters
- Wi-Fi information on Windows
- TLS certificate and protocol configuration
- HTTP security headers
- DNSSEC status
- Open DNS resolver behavior
- TCP service exposure
- JSON, CSV, and HTML reports

The project does **not** perform exploitation, credential attacks, packet injection, automatic remediation, or destructive system changes.

### Network traffic and privacy

NetDiag-Toolkit **does make network requests to targets you specify** as part of diagnostics and security checks.

Examples include ICMP ping, TCP connections, DNS queries, HTTPS requests, and traceroute probes.

The project does **not** include telemetry, analytics, or centralized third-party data collection. Reports are generated locally.

---

# Installation

## Requirements

- Python **3.10 or newer**
- Git
- A supported operating system
- Network access for network-based diagnostics

---

## Windows 10 / 11

Windows is the primary supported platform.

### 1. Clone the repository

```powershell
git clone https://github.com/IyadEngle/NetDiag-Toolkit.git
cd NetDiag-Toolkit
```

### 2. Create a virtual environment

```powershell
py -3.12 -m venv .venv
```

### 3. Activate it

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 4. Install NetDiag-Toolkit

For normal use:

```powershell
pip install -e .
```

For development and testing:

```powershell
pip install -e ".[dev]"
```

### 5. Verify installation

```powershell
netdiag --version
```

Expected:

```text
NetDiag-Toolkit, version 0.3.0
```

---

## Linux

Linux support is implemented, but some features depend on native Linux utilities.

### 1. Clone the repository

```bash
git clone https://github.com/IyadEngle/NetDiag-Toolkit.git
cd NetDiag-Toolkit
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate it

```bash
source .venv/bin/activate
```

### 4. Install NetDiag-Toolkit

```bash
pip install -e .
```

For development and testing:

```bash
pip install -e ".[dev]"
```

### 5. Verify installation

```bash
netdiag --version
```

### Linux utility notes

Some diagnostics use native system commands:

- `ping` for ICMP
- `ip` for default gateway and interface information
- `traceroute` for traceroute
- `dig` for Linux DNS comparison

If a required native command is not installed, the affected diagnostic may return an error or skip.

---

## macOS

macOS is **not currently supported**.

Some commands may return `SKIP` rather than running.

---

# Quick Start

After installation:

```bash
netdiag --version
```

Basic diagnostics:

```bash
netdiag diagnose --target 1.1.1.1
```

Full diagnostics:

```bash
netdiag diagnose --target google.com --full
```

Security audit:

```bash
netdiag security --target example.com
```

Local network information:

```bash
netdiag network
```

---

# Command Reference

## `netdiag diagnose`

Runs the core network diagnostics.

```bash
netdiag diagnose --target 1.1.1.1
```

The standard diagnostic run includes:

- DNS resolution
- ICMP ping
- HTTPS connectivity
- TCP connectivity to ports 80 and 443
- Default gateway detection and ping

### Full diagnostics

Add MTU and traceroute:

```bash
netdiag diagnose --target google.com --full
```

### Include Wi-Fi information

Windows only:

```bash
netdiag diagnose --target 1.1.1.1 --wifi
```

### Choose a report format

```bash
netdiag diagnose --target 1.1.1.1 --reporter console
netdiag diagnose --target 1.1.1.1 --reporter json --output report.json
netdiag diagnose --target 1.1.1.1 --reporter csv --output report.csv
netdiag diagnose --target 1.1.1.1 --reporter html --output report.html
```

---

## `netdiag security`

Runs the security audit.

```bash
netdiag security --target example.com
```

Checks include:

- TLS certificate expiry
- TLS protocol versions
- Certificate hostname
- HTTP security headers
- DNSSEC status
- Open DNS resolver behavior
- TCP service exposure

Example:

```bash
netdiag security --target example.com
```

### Security result meanings

| Status | Meaning |
|---|---|
| `PASS` | Check completed and no issue was found |
| `FAIL` | A security condition was confirmed |
| `OBSERVATION` | Informational configuration observation |
| `SKIP` | Check was not runnable or not applicable |
| `ERROR` | An unexpected error prevented the check |
| `INCONCLUSIVE` | The check ran but the evidence was insufficient |

Important:

> An open TCP port is an observation, not automatically a vulnerability.

> A missing HTTP security header is an observation, not automatically a vulnerability.

---

## `netdiag full`

Runs the complete diagnostic set and security audit.

```bash
netdiag full --target example.com
```

Export as JSON:

```bash
netdiag full --target example.com --reporter json --output report.json
```

Export as CSV:

```bash
netdiag full --target example.com --reporter csv --output report.csv
```

Export as HTML:

```bash
netdiag full --target example.com --reporter html --output report.html
```

---

## `netdiag dns`

Resolve a hostname:

```bash
netdiag dns --target google.com
```

Compare DNS results:

```bash
netdiag dns --target google.com --compare
```

The comparison checks:

- System DNS
- Google DNS (`8.8.8.8`)
- Cloudflare DNS (`1.1.1.1`)
- Quad9 DNS (`9.9.9.9`)

---

## `netdiag mtu`

Estimate Path MTU using DF-bit ICMP probes.

```bash
netdiag mtu --target 1.1.1.1
```

Custom limits:

```bash
netdiag mtu --target 1.1.1.1 --min-size 68 --max-size 1500
```

This requires ICMP responses from the target/path.

---

## `netdiag tcp`

Test TCP connectivity to selected ports.

```bash
netdiag tcp --target 1.1.1.1 --ports 443
```

Multiple ports:

```bash
netdiag tcp --target example.com --ports 80,443,8080
```

Custom timeout:

```bash
netdiag tcp --target example.com --ports 80,443 --timeout 5
```

---

## `netdiag trace`

Run traceroute.

```bash
netdiag trace --target 1.1.1.1
```

Maximum hop count:

```bash
netdiag trace --target example.com --max-hops 30
```

On Windows it uses `tracert`.

On Linux it uses `traceroute`.

---

## `netdiag network`

Show local network information:

```bash
netdiag network
```

Depending on the platform, this includes:

- Network adapters
- IPv4/IPv6 information
- Adapter state and speed
- Wi-Fi information on Windows
- Default gateway
- Gateway connectivity

---

## `netdiag scan`

Run a TCP connect scan against an explicitly specified target.

Default ports:

```bash
netdiag scan --target 192.168.1.1
```

Custom ports:

```bash
netdiag scan --target 192.168.1.1 --ports 22,80,443
```

Use this only against systems and networks you are authorized to test.

---

## `netdiag discover`

Discover active hosts on a subnet using ICMP ping.

```bash
netdiag discover --subnet 192.168.1.0/24
```

Use this only on networks you own or are explicitly authorized to test.

---

## `netdiag report`

Run diagnostics plus the security audit and export the result.

Console:

```bash
netdiag report --target example.com --reporter console
```

JSON:

```bash
netdiag report --target example.com --reporter json --output report.json
```

CSV:

```bash
netdiag report --target example.com --reporter csv --output report.csv
```

HTML:

```bash
netdiag report --target example.com --reporter html --output report.html
```

---

# Supported Platforms

| Platform | Status | Notes |
|---|---|---|
| Windows 10 | ✅ Primary | Main development target |
| Windows 11 | ✅ Primary | Main development target |
| Linux | ⚠️ Implemented | Some diagnostics depend on native utilities |
| macOS | ❌ Not supported | Commands may return `SKIP` |

### Windows

Best-supported environment.

Includes:

- ICMP
- DNS
- HTTPS
- TCP
- MTU
- Gateway
- Traceroute
- Adapter information
- Wi-Fi information
- Security audit
- Reports

### Linux

Core diagnostics are implemented with platform-specific system tools.

Wi-Fi information is not currently supported.

### macOS

Not currently supported.

---

# Security Audit Details

## TLS Certificate Expiry

Reports confirmed certificate expiry conditions.

- Expired certificates → confirmed finding
- Certificates expiring soon → confirmed finding
- Valid certificates → pass

## TLS Protocol Versions

Attempts to determine whether protocol versions can be negotiated.

Deprecated protocols are treated as confirmed findings only when they are actually negotiated.

Ambiguous TLS/SSL errors are reported as `INCONCLUSIVE` rather than being treated automatically as proof of protocol support or rejection.

## Certificate Hostname

Checks whether the certificate identity matches the requested hostname.

## HTTP Security Headers

Checks common security headers and reports missing or disclosed configuration as observations.

## DNSSEC

Checks DNSSEC-related state and distinguishes positive evidence from inconclusive conditions.

## Open DNS Resolver

Checks whether the target accepts recursive DNS resolution from the current network position.

This is a single-vantage-point observation and should be interpreted in that context.

## TCP Exposure

Reports reachable TCP services as observations.

A reachable port alone does **not** mean that the service is vulnerable.

---

# Reporting

NetDiag-Toolkit supports:

### Console

Human-readable terminal output:

```bash
netdiag security --target example.com
```

### JSON

Machine-readable report:

```bash
netdiag full --target example.com --reporter json --output report.json
```

### CSV

Tabular report:

```bash
netdiag full --target example.com --reporter csv --output report.csv
```

### HTML

Local browser-friendly report:

```bash
netdiag full --target example.com --reporter html --output report.html
```

All reports are generated locally.

---

# Security Scope

NetDiag-Toolkit is designed for **read-only diagnostics and security auditing**.

It intentionally does **not** provide:

- Exploit execution
- Credential attacks
- Brute-force authentication
- Packet injection
- Firewall modification
- Automatic remediation
- Destructive scanning
- Centralized telemetry

Network discovery and port scanning should only be used against systems and networks you are authorized to test.

---

# Development

Clone the repository:

```bash
git clone https://github.com/IyadEngle/NetDiag-Toolkit.git
cd NetDiag-Toolkit
```

Create a virtual environment and install development dependencies.

Windows:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

# Testing

Run unit tests:

```bash
pytest tests/ -m "not integration" -v
```

Run integration tests:

```bash
pytest tests/ -m "integration" -v
```

Run Ruff:

```bash
ruff check netdiag/
```

Run Mypy:

```bash
mypy netdiag/ --ignore-missing-imports
```

### CI

GitHub Actions runs:

- Ruff
- Mypy
- Unit tests
- Windows unit tests

The project should not be treated as release-ready until the CI checks pass.

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

The original PowerShell implementation remains available in:

```text
NetDiag.ps1
```

The Python implementation is the current `v0.3.0` beta direction of the project.

---

# Limitations

Current known limitations include:

- Beta software
- Windows is the primary target
- Linux support has platform-specific limitations
- macOS is not currently supported
- Wi-Fi information is Windows-only
- Path MTU depends on ICMP/DF behavior
- Traceroute parsing depends on system command output
- TCP connectivity is a TCP connect test, not a vulnerability assessment
- No IPv6-specific diagnostic workflow
- DNS and network behavior may vary by local firewall, ISP, router, and network path
- Security observations are evidence from the current network position and are not a substitute for a full security assessment

---

# License

MIT License.

Copyright (c) 2026 Iyad Engle

See [LICENSE](LICENSE).

---

# Author

**Iyad Engle**

GitHub: https://github.com/IyadEngle/NetDiag-Toolkit
