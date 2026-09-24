# Changelog

Copyright (c) 2026 Iyad Engle

## [Unreleased] - 0.4.1

### Fixed
- Linux path MTU estimate was 28 bytes too high (a 1500-byte path reported 1528)
- Traceroute hostnames: Linux reported the hop number and Windows reported "<1"/"ms" as the hostname
- OpenSSL 3 self-signed certificates were reported as a generic verification failure;
  classification now uses the OpenSSL verify code
- Windows `nslookup` parsing truncated IPv6 answers and missed multi-line `Addresses:` blocks
- Open-resolver check always ended INCONCLUSIVE for hostname targets; the name is now resolved first
- DNSSEC check reported "not detected" for every subdomain; names without DNSKEY records
  are now checked at their zone apex
- Sockets were not closed when connect or the TLS handshake raised
- GUI: closing the window during a scan could destroy a running QThread; close now waits
  for the current step to finish
- GUI: cancelling a scan discarded completed results; partial results are kept and exportable

### Changed
- Ping with partial packet loss is `WARN` (was `PASS`)
- Traceroute is `PASS` only when the destination is reached; otherwise `WARN`
- CLI exits with meaningful codes (0 clean, 1 diagnostic FAIL/ERROR, 2 usage error,
  4 security FAIL, 5 both); previously always 0
- CLI targets use the GUI's validation (`netdiag.utils.validation`); targets beginning with
  `-` are rejected so they cannot be read as options by system tools
- CI runs on every branch, installs the GUI extra (Qt tests were previously always skipped),
  lints `tests/`, and tests Python 3.10–3.13
- Removed committed `__pycache__` files; `.gitignore` covers Python and tool caches

## [0.4.0b0] - 2026-09-18

### Added
- Native desktop GUI (`netdiag-gui`, PySide6) as a frontend over the existing core:
  - Dashboard with header/status indicator, validated target bar (Run Diagnostics / Security Audit / Full Scan)
  - Seven summary cards (Ping, DNS, HTTPS, TCP, MTU, Gateway, Traceroute)
  - Diagnostics results table and Security findings panel preserving all status semantics
  - QThread-based background workers; UI never blocks; cancel between test steps
  - JSON/CSV/HTML export via the existing netdiag.reports exporters
  - Activity log panel; stack traces only at DEBUG logging level
  - Preferences: timeout, default target, dark/light theme, log level, report folder (QSettings)
- `gui` optional dependency group (`PySide6>=6.5`) and `netdiag-gui` entry point
- `netdiag.gui.validation` and `netdiag.gui.styles` are Qt-free and unit tested without PySide6
- GUI tests: pure-logic tests always run; Qt widget/worker tests marked `gui` and auto-skipped without PySide6
- CI: dedicated GUI job (offscreen) and Windows job now includes GUI

### Changed
- Version advanced to 0.4.0b0 (beta). 0.3.0 functionality is unchanged.
- `ScanReport.tool_version`, CLI `--version`, and HTTP User-Agent now derive from `netdiag.__version__`
  instead of hard-coded "0.3.0"
- README network-traffic wording clarified (no telemetry; does contact user-specified targets)

### Unchanged
- All diagnostic, security, reporting modules; CLI commands and behavior; PASS/FAIL/OBSERVATION/SKIP/ERROR/INCONCLUSIVE semantics

## [0.3.0] - 2026-01-15
- Python rewrite of the PowerShell toolkit; see release notes for the full list
  (core diagnostics, security audit with evidence-based semantics, reports, CLI).
