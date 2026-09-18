# Changelog

Copyright (c) 2026 Iyad Engle

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
