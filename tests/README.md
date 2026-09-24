# Tests

## Automated tests

```bash
pip install -e ".[gui,dev]"
QT_QPA_PLATFORM=offscreen pytest tests/ -m "not integration"   # as CI runs it
QT_QPA_PLATFORM=offscreen pytest tests/                        # also the integration tests
ruff check netdiag/ tests/
mypy netdiag/ --ignore-missing-imports
```

GUI tests are skipped when PySide6 is not installed. Integration tests
(marker `integration`) need network access or real system tools such as `ping`.

The legacy `NetDiag.ps1` script has Pester 5 tests:

```powershell
Invoke-Pester -Path tests/powershell
```

GitHub Actions runs Ruff, mypy and the test suite on Python 3.10–3.13 (Linux)
and on Windows, the PowerShell syntax check and Pester tests, and CodeQL code
scanning, on every push and pull request.

## Manual smoke testing

Manual smoke testing should cover:
- Basic run
- Ping and packet-loss output
- DNS and HTTPS checks
- MTU result
- Gateway detection
- TCP tests
- Traceroute
- Wi-Fi parsing on a Wi-Fi-connected machine
- JSON and CSV export
- Cancelling a GUI scan and pressing Ctrl+C during a CLI scan (partial results, no leftover `ping`/`tracert` processes)
