# NetDiag Toolkit

Lightweight, transparent Windows network diagnostics for troubleshooting connectivity, latency, DNS, HTTPS and path MTU.

> **Status:** Early open-source release. Contributions, bug reports and test results are welcome.

## What it does

NetDiag Toolkit runs a repeatable local diagnostic report:

- ICMP latency, packet loss, minimum/average/maximum latency
- DNS resolution timing and resolved addresses
- HTTPS reachability and response timing
- Path MTU discovery using ICMP with the Don't Fragment flag
- Active network adapter and IP configuration summary
- Optional JSON export for sharing or automation

## Requirements

- Windows 10/11
- Windows PowerShell 5.1 or PowerShell 7+
- ICMP may be affected by firewalls or remote-host configuration

## Quick start

Download `NetDiag.ps1`, open PowerShell in its folder, and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\NetDiag.ps1
```

Custom targets:

```powershell
.\NetDiag.ps1 -Target 1.1.1.1 -DnsName cloudflare.com -MtuHost 1.1.1.1
```

Export a machine-readable report:

```powershell
.\NetDiag.ps1 -JsonPath .\report.json
```

## Interpreting results

A failed ping does **not** automatically mean the internet is down: some hosts block ICMP.

The MTU result is an **estimate of the ICMP path MTU** to the selected host. VPN tunnels, firewalls, packet filtering and the remote host can change the result. It should not be treated as a universal interface-MTU recommendation.

HTTPS success confirms that the selected URL was reachable at the application layer. It does not measure download speed.

## Why this project exists

Network problems are often reported with vague symptoms such as "the internet drops", "websites are slow", or "ping is unstable". NetDiag Toolkit aims to turn those symptoms into a small, repeatable evidence report that can be attached to an issue or support ticket.

## Roadmap

- [ ] Add optional TCP connectivity tests
- [ ] Add structured exit codes for automation
- [ ] Add Pester test coverage
- [ ] Add CSV export
- [ ] Improve MTU boundary testing and diagnostics

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please see [SECURITY.md](SECURITY.md).

## License

MIT License. See [LICENSE](LICENSE).
