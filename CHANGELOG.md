# Changelog

Copyright (c) 2026 Iyad Engle

## [Unreleased]

### Changed
- License changed from MIT to the GNU General Public License v3.0 or later
  (`GPL-3.0-or-later`): `LICENSE` now contains the unmodified GPLv3 text;
  package metadata, SPDX headers in all source, test and workflow files, the
  README, the GUI About box and the `NetDiag.ps1` help were updated to match.
  No functional changes. Releases up to and including 0.5.0b0 remain available
  under the MIT License.

## [0.5.0b0] - 2026-09-24

Beta. The CLI and GUI now run every scan through one shared scan runner.
Diagnostic and security checks, result models and status semantics are
unchanged; piped or redirected CLI output is byte-identical to 0.4.x apart
from the version string and the new exit code 130 in `--help`. Also includes
the correctness and hygiene fixes originally planned as 0.4.1.

### Added
- Shared scan architecture (`netdiag/runner/`):
  - `build_plan()` and per-command plans: the single definition of every scan
    step, used by both the CLI and the GUI (two presentation profiles keep
    their existing ordering, labels and timeouts)
  - `ScanRunner`: runs up to 4 checks in parallel with dependencies and lanes
    (DNS first where its result is reused; ping/MTU/traceroute never overlap;
    TLS checks serialized), reports results in plan order, and delivers
    progress events from a single thread
  - per-check time budgets (above each check's worst-case timeouts, scaled
    with the probe timeout); an overrunning check is stopped and reported as
    `ERROR` with `StepTimeout`
  - real cancellation: running system commands (ping, tracert, dig, netsh …)
    are terminated, including their child processes on POSIX
- Reuse within a scan: the DNS check's address is reused for TCP, TLS, ping,
  MTU and traceroute connections (hostname kept for reports, TLS SNI and
  certificate verification); one TLS certificate handshake is shared by the
  TLS checks (2-3 fewer connections per audit)
- CLI progress line on stderr when it is an interactive terminal
- CLI Ctrl+C: clean cancellation, partial report printed, exit code `130`
- GUI hides console windows of the commands it runs (Windows)
- Pester tests for `NetDiag.ps1` in CI

### Changed
- `full` and `report` run diagnostics and the security audit as one parallel plan
- GUI scans run on the shared runner; results appear as soon as they are
  produced and are shown in the scan's fixed order; Cancel and closing the
  window stop running commands immediately instead of after the current step
- Errors from a crashed or timed-out check use the check's real test name
- Version 0.5.0b0

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
  for the scan to stop
- GUI: cancelling a scan discarded completed results; partial results are kept and exportable
- Wi-Fi: a machine without an active Wi-Fi connection (e.g. on Ethernet) made `full`
  and `diagnose --wifi` exit 1; "not applicable" is now `SKIP`, in-progress/unreadable is `WARN`
- Windows ping counted "Destination host unreachable" and "TTL expired" replies as received
- Invalid IPv4-looking targets such as `1.2.3.999` were accepted as hostnames
- Invalid `--ports` values crashed with a traceback; they are now usage errors (exit 2)
- `NetDiag.ps1` reported 100% packet loss on PowerShell 7 (`Latency` replaced `ResponseTime`)
  and discarded all samples when any probe failed

### Changed
- Ping with partial packet loss is `WARN` (was `PASS`)
- Traceroute is `PASS` only when the destination is reached; otherwise `WARN`
- CLI exits with meaningful codes (0 clean, 1 diagnostic FAIL/ERROR, 2 usage error,
  4 security FAIL, 5 both); previously always 0
- CLI targets use the GUI's validation (`netdiag.utils.validation`); targets beginning with
  `-` are rejected so they cannot be read as options by system tools
- Target validation separates parsing (`parse_target`, which recognises IPv4, IPv6 and
  hostnames) from support policy (`IPV6_TARGETS_SUPPORTED`); IPv6 is rejected as
  "not supported yet" rather than by the parser
- `NetDiag.ps1` can be dot-sourced to load its functions without running; Pester tests in CI
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
