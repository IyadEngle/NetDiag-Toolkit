# NetDiag Toolkit

Lightweight, transparent Windows network diagnostics for troubleshooting connectivity, latency, DNS, HTTPS, path MTU and local network configuration.

> **Current release:** `v0.2.0`

## What it does

NetDiag Toolkit runs a repeatable local diagnostic report:

- ICMP latency and packet loss
- DNS resolution timing
- Direct DNS-server comparison
- HTTPS reachability and response timing
- Path MTU estimation using ICMP + Don't Fragment
- Default gateway discovery and gateway ping
- TCP connectivity checks for selected ports
- Traceroute using the native Windows `tracert`
- Wi-Fi state, signal and link information when available
- Active adapter and IP configuration summary
- Optional JSON and CSV report export

The toolkit is intentionally transport-agnostic and does not silently change network settings or upload diagnostic data.

## Requirements

- Windows 10/11
- Windows PowerShell 5.1+ or PowerShell 7+
- Administrator rights are **not** normally required
- Some tests depend on local firewall policy and the destination allowing ICMP/TCP

## Quick start

Open PowerShell in the project folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\NetDiag.ps1
```

### Customize targets

```powershell
.\NetDiag.ps1 `
  -Target 1.1.1.1 `
  -DnsName cloudflare.com `
  -HttpsUrl https://www.cloudflare.com/ `
  -MtuHost 1.1.1.1 `
  -TraceHost 1.1.1.1
```

### Test specific TCP ports

```powershell
.\NetDiag.ps1 -TcpHost 1.1.1.1 -TcpPorts 53,80,443
```

### Compare DNS servers

```powershell
.\NetDiag.ps1 `
  -DnsServers 1.1.1.1,8.8.8.8 `
  -DnsQuery cloudflare.com
```

### Export reports

```powershell
.\NetDiag.ps1 -JsonPath .\report.json -CsvPath .\report.csv
```

## Interpreting results

A failed ICMP ping does not automatically mean the internet is down because some hosts and firewalls block ICMP.

The MTU result is an **estimate of the ICMP path MTU** to the selected host. It may be affected by routing, packet filtering, firewalls, and the remote host. It should not be treated as a universal network-interface MTU recommendation.

A TCP port reported as closed or blocked can mean the service is not listening, a firewall filtered the connection, or the path is unavailable.

Traceroute is based on the Windows `tracert` utility and may contain missing hops because intermediate routers can suppress or rate-limit responses.

## Example report

A normal run prints sections for:

```text
Ping
DNS
DNS server comparison
HTTPS
MTU
Default gateway
TCP ports
Wi-Fi
Traceroute
Network state
```

## Project structure

```text
NetDiag-Toolkit/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── pull_request_template.md
│   └── workflows/
├── tests/
├── NetDiag.ps1
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
└── CHANGELOG.md
```

## Roadmap

- [x] Ping and packet-loss diagnostics
- [x] DNS timing
- [x] HTTPS reachability
- [x] Path MTU estimation
- [x] Default gateway test
- [x] TCP connectivity test
- [x] Traceroute
- [x] Wi-Fi information
- [x] DNS server comparison
- [x] JSON export
- [x] CSV export
- [ ] Add optional latency/jitter summary across multiple targets
- [ ] Add structured exit codes for automation
- [ ] Expand automated test coverage
- [ ] Add richer machine-readable diagnostics

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please see [SECURITY.md](SECURITY.md).

## License

MIT License. See [LICENSE](LICENSE).
