# 🛡️ NetDiag-Toolkit v0.3.0

**Advanced Network Diagnostics & Security Audit Toolkit**

Copyright (c) 2026 Iyad Engle

![Version](https://img.shields.io/badge/version-0.3.0--beta-orange)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F%2011-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

> ⚠️ **Beta release.** Parity with the PowerShell version (v0.2.x) has not been fully verified on all Windows configurations.

## Purpose

Read-only network diagnostics and basic security configuration audits. Does not modify system configuration or perform destructive operations.

The tool makes network requests to user-specified targets as part of diagnostics (ICMP ping, TCP connect, DNS queries, HTTPS requests). It does **not** include telemetry, analytics, or centralized third-party data collection. All results remain local.

## Features

| Test | Description | Platform |
|------|-------------|----------|
| ICMP Ping | Latency, packet loss | Windows ✅, Linux ✅ |
| DNS Resolution | Hostname → IP | Cross-platform ✅ |
| DNS Comparison | Multiple servers | Windows ✅, Linux ✅ |
| HTTPS | TLS connectivity | Cross-platform ✅ |
| TCP Connectivity | Specific ports | Cross-platform ✅ |
| Path MTU | DF-bit binary search | Windows ✅, Linux implemented |
| Default Gateway | Detect & ping | Windows ✅, Linux ✅ |
| Traceroute | Hop-by-hop | Windows ✅, Linux ✅ |
| Adapter Info | Interfaces, IPs | Windows ✅, Linux implemented |
| Wi-Fi Info | SSID, signal | Windows only |

## Security Audit

| Check | Confidence | Severity Range |
|-------|------------|---------------|
| TLS Certificate Expiry | CONFIRMED | HIGH (expired), MEDIUM (<14 days) |
| TLS Protocol Versions | CONFIRMED/INCONCLUSIVE | HIGH/MEDIUM |
| Certificate Hostname | CONFIRMED | HIGH/MEDIUM |
| HTTP Security Headers | CONFIRMED | INFO/LOW (observations) |
| DNSSEC Status | CONFIRMED/INCONCLUSIVE | INFO (observation) |
| Open DNS Resolver | CONFIRMED | MEDIUM |
| TCP Service Exposure | CONFIRMED | INFO (observation) |

**Open ports are observations, not vulnerabilities. Header absence is an observation, not a vulnerability.**

## Security Status Semantics

| Status | Meaning |
|--------|---------|
| FAIL | Confirmed security condition (e.g., expired certificate, deprecated TLS negotiated) |
| OBSERVATION | Informational configuration observation (e.g., missing header, open port) |
| PASS | Check completed, no issue found |
| SKIP | Not runnable or not applicable |
| ERROR | Unexpected error |
| INCONCLUSIVE | Check ran but evidence is insufficient |

## Installation

```bash
git clone https://github.com/IyadEngle/NetDiag-Toolkit.git
cd NetDiag-Toolkit
pip install -e ".[dev]"
