# Security Policy

Copyright (c) 2026 Iyad Engle — NetDiag-Toolkit
(https://github.com/IyadEngle/NetDiag-Toolkit)

## Supported versions

Security fixes are made on the latest release line only.

| Version | Supported |
|---|---|
| 0.5.x (beta) | ✅ |
| < 0.5 | ❌ |

## Reporting a vulnerability

**Please do not report security vulnerabilities in public issues, pull requests
or discussions.**

Report them privately through GitHub:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub private vulnerability reporting).

If that option is not available, contact the maintainer privately through the
GitHub profile of [@IyadEngle](https://github.com/IyadEngle) and ask for a
private channel before sharing any details.

Please include:

- the affected version (`netdiag --version`) and operating system
- the command or GUI action involved
- steps to reproduce, and the impact you observed or expect
- any proof of concept, kept to the minimum needed to demonstrate the issue

Do not include real credentials, tokens, private network information or
other people's data in a report.

## What to expect

- Acknowledgement within **7 days**.
- An initial assessment (confirmed / not reproducible / out of scope) within
  **30 days**.
- Fixes are released as soon as practical; you will be credited in the
  release notes unless you prefer otherwise.
- Please allow a fix to be released before disclosing details publicly.
  Coordinated disclosure timelines can be agreed case by case.

## Scope

In scope:

- the `netdiag` CLI, the `netdiag-gui` desktop application and the Python
  package in this repository
- the legacy `NetDiag.ps1` script
- the repository's GitHub Actions workflows

Examples of relevant issues: command or argument injection through targets or
options, unsafe handling of system command output, report files that leak
data the user did not scan, or dependency vulnerabilities that affect
NetDiag-Toolkit.

Out of scope:

- results of scans against third-party systems (NetDiag-Toolkit only reports
  what it observes; see the README's security status semantics)
- vulnerabilities in the operating system tools NetDiag-Toolkit invokes
  (`ping`, `tracert`/`traceroute`, `dig`, `netsh`, …)
- issues that require an already compromised local machine

## Design principles

NetDiag-Toolkit runs diagnostics locally and is read-only: it does not
exploit, brute-force, modify firewall or network configuration, or collect
telemetry. It contacts only the targets the user specifies (plus the public
DNS resolvers used by DNS comparison and DNSSEC checks). Reports are written
only where the user asks.

Use NetDiag-Toolkit only against systems and networks you own or are
authorized to test.
