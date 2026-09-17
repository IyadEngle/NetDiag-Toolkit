# Changelog

## 0.2.0 - 2026-09-17

### Added
- Default gateway discovery and ping test
- TCP port connectivity diagnostics
- Windows traceroute support
- Wi-Fi information discovery
- Direct comparison of selected DNS servers
- CSV report export
- Expanded report output and command-line options

### Improved
- Path MTU probing now relies on the native Windows `ping.exe` exit status, making the result less dependent on localized command output.
- Documentation expanded with examples and result interpretation guidance.

## 0.1.1 - 2026-09-17

### Fixed
- Improved path MTU detection on Windows.
- Switched MTU probing to the native Windows ping utility.
- Added explicit Don't Fragment handling.
- Improved MTU boundary detection.

## 0.1.0 - 2026-09-17

- Initial public release
- Added latency and packet-loss diagnostics
- Added DNS timing
- Added HTTPS reachability timing
- Added ICMP path-MTU estimation
- Added active adapter/IP configuration summary
- Added JSON report export
