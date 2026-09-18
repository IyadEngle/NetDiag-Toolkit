# Changelog

Copyright (c) 2026 Iyad Engle

## [0.3.0] - 2026-01-15

### Fixed
- Windows tracert latency parser now correctly matches "1 ms" format (previously only matched "time<1ms" / "time=1ms")
- pyproject.toml classifier updated from Alpha to Beta (consistent with README)

### Changed
- README network traffic wording clarified: no telemetry or third-party data collection; tool does make network requests to user-specified targets as part of diagnostics
- SecurityStatus.OBSERVATION added for informational configuration observations
- Missing HTTP security headers → OBSERVATION (not FAIL)
- DNSSEC not detected → OBSERVATION (not FAIL)
- TCP open ports → OBSERVATION (not FAIL)
- ALL SSL errors during TLS protocol testing → INCONCLUSIVE (not NOT_SUPPORTED)
- Certificate self-signed status cryptographically verified
- Connection failures in security checks → SKIP (not FAIL)
- Gateway integration test: tautological assertion replaced with IP validation
- dnspython added as required dependency (DNSSEC/open resolver work on Windows without WSL)

### Added
- SecurityStatus enum: PASS, FAIL, OBSERVATION, SKIP, ERROR, INCONCLUSIVE
- ScanReport security_failures counts only FAIL status
- ScanReport security_observations, security_inconclusive, security_skipped, security_passed
- Two-phase TLS protocol detection (probe → test deprecated versions)
- Cryptographic self-signed certificate verification using cryptography library
- CertificateInfo dataclass with is_self_signed (crypto) and is_self_issued (DN match)
