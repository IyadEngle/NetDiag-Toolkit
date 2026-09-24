<#
.SYNOPSIS
    NetDiag Toolkit - practical Windows network diagnostics.

.DESCRIPTION
    Runs a repeatable set of local network tests for connectivity, latency,
    DNS, HTTPS, path MTU, default gateway, TCP ports, traceroute, Wi-Fi and
    adapter/IP state.

    The toolkit is intentionally transport-agnostic. It reports the current
    Windows network environment without silently changing network settings
    or sending diagnostic data anywhere.

.EXAMPLE
    .\NetDiag.ps1

.EXAMPLE
    .\NetDiag.ps1 -Target 1.1.1.1 -DnsName cloudflare.com -HttpsUrl https://www.cloudflare.com/

.EXAMPLE
    .\NetDiag.ps1 -TcpHost 1.1.1.1 -TcpPorts 80,443,53 -CsvPath .\report.csv -JsonPath .\report.json

.EXAMPLE
    .\NetDiag.ps1 -DnsServers 1.1.1.1,8.8.8.8 -DnsQuery cloudflare.com

.NOTES
    Copyright (c) 2026 Iyad Engle.
    Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
    This program comes with ABSOLUTELY NO WARRANTY. See the LICENSE file.
    https://github.com/IyadEngle/NetDiag-Toolkit
#>

[CmdletBinding()]
param(
    [string]$Target = "1.1.1.1",
    [string]$DnsName = "cloudflare.com",
    [string]$HttpsUrl = "https://www.cloudflare.com/",
    [string]$MtuHost = "1.1.1.1",
    [string]$TcpHost = "1.1.1.1",
    [int[]]$TcpPorts = @(80, 443),
    [string]$TraceHost = "1.1.1.1",
    [int]$TraceMaxHops = 12,
    [int]$PingCount = 5,
    [int]$TcpTimeoutMs = 2000,
    [int]$MtuStartPayload = 1200,
    [int]$MtuMaxPayload = 1472,
    [string[]]$DnsServers = @("1.1.1.1", "8.8.8.8"),
    [string]$DnsQuery = "cloudflare.com",
    [string]$JsonPath,
    [string]$CsvPath
)

$ErrorActionPreference = "Continue"

function Get-ND-PingLatency {
    # Returns the round-trip time in ms of a successful echo reply, or $null.
    # Windows PowerShell 5.1 returns Win32_PingStatus (StatusCode, ResponseTime);
    # PowerShell 7 returns PingStatus (Status, Latency) and has no ResponseTime.
    param($Reply)

    if ($null -eq $Reply) { return $null }
    $props = $Reply.PSObject.Properties

    if ($props["Status"] -and $props["Latency"]) {
        if ("$($Reply.Status)" -ne "Success") { return $null }
        return [double]$Reply.Latency
    }

    if ($props["StatusCode"]) {
        # Non-zero StatusCode = timeout, destination unreachable, etc.
        if ($null -eq $Reply.StatusCode -or [int]$Reply.StatusCode -ne 0) { return $null }
    }

    if ($props["ResponseTime"] -and $null -ne $Reply.ResponseTime) {
        return [double]$Reply.ResponseTime
    }
    return $null
}

function Test-ND-Ping {
    param([string]$ComputerName, [int]$Count)

    $samples = @()
    try {
        # SilentlyContinue: one lost probe must not discard the replies that arrived.
        $replies = @(Test-Connection -ComputerName $ComputerName -Count $Count -ErrorAction SilentlyContinue)
        foreach ($r in $replies) {
            $latency = Get-ND-PingLatency -Reply $r
            if ($null -ne $latency) {
                $samples += $latency
            }
        }
    } catch {}

    [pscustomobject]@{
        Target      = $ComputerName
        Sent        = $Count
        Received    = $samples.Count
        LossPercent = if ($Count) { [math]::Round((1 - ($samples.Count / $Count)) * 100, 1) } else { $null }
        MinMs       = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Minimum).Minimum, 2) } else { $null }
        AvgMs       = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Average).Average, 2) } else { $null }
        MaxMs       = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Maximum).Maximum, 2) } else { $null }
    }
}

function Test-ND-Dns {
    param([string]$Name)

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($Name)
        $sw.Stop()
        [pscustomobject]@{
            Name         = $Name
            Success      = $true
            AddressCount = $addresses.Count
            Addresses    = ($addresses | ForEach-Object { $_.IPAddressToString }) -join ", "
            LookupMs     = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error        = $null
        }
    } catch {
        $sw.Stop()
        [pscustomobject]@{
            Name         = $Name
            Success      = $false
            AddressCount = 0
            Addresses    = ""
            LookupMs     = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error        = $_.Exception.Message
        }
    }
}

function Test-ND-DnsServer {
    param([string]$Server, [string]$Name)

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $result = Resolve-DnsName -Name $Name -Server $Server -Type A -ErrorAction Stop |
            Where-Object { $_.Type -eq "A" } |
            Select-Object -First 1

        $sw.Stop()

        [pscustomobject]@{
            Server      = $Server
            Query       = $Name
            Success     = $true
            Answer      = if ($result) { $result.IPAddress } else { "" }
            LookupMs    = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error       = $null
        }
    } catch {
        $sw.Stop()

        [pscustomobject]@{
            Server      = $Server
            Query       = $Name
            Success     = $false
            Answer      = ""
            LookupMs    = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error       = $_.Exception.Message
        }
    }
}

function Test-ND-Https {
    param([string]$Url)

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -TimeoutSec 15
        $sw.Stop()

        [pscustomobject]@{
            Url        = $Url
            Success    = $true
            StatusCode = [int]$response.StatusCode
            TotalMs    = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error      = $null
        }
    } catch {
        $sw.Stop()

        [pscustomobject]@{
            Url        = $Url
            Success    = $false
            StatusCode = $null
            TotalMs    = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error      = $_.Exception.Message
        }
    }
}

function Test-ND-MtuPayload {
    param([string]$ComputerName, [int]$Payload)

    try {
        & ping.exe -4 -f -l $Payload -n 1 -w 1500 $ComputerName 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Test-ND-Mtu {
    param([string]$ComputerName, [int]$StartPayload, [int]$MaxPayload)

    $working = $null

    for ($size = $StartPayload; $size -le $MaxPayload; $size += 8) {
        if (Test-ND-MtuPayload -ComputerName $ComputerName -Payload $size) {
            $working = $size
        } else {
            break
        }
    }

    if ($null -ne $working -and $working -lt $MaxPayload) {
        $low = $working
        $high = [math]::Min($working + 8, $MaxPayload)

        while ($low -lt $high) {
            $mid = [math]::Floor(($low + $high + 1) / 2)

            if (Test-ND-MtuPayload -ComputerName $ComputerName -Payload $mid) {
                $low = $mid
            } else {
                $high = $mid - 1
            }
        }

        $working = $low
    }

    [pscustomobject]@{
        Host             = $ComputerName
        MaxIcmpPayload   = $working
        EstimatedPathMtu = if ($null -ne $working) { $working + 28 } else { $null }
        Note             = "ICMP/DF result; firewalls, packet filtering and remote hosts can affect this test."
    }
}

function Test-ND-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs)

    $client = New-Object System.Net.Sockets.TcpClient
    $sw = [Diagnostics.Stopwatch]::StartNew()

    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $success = $async.AsyncWaitHandle.WaitOne($TimeoutMs)

        if ($success) {
            $client.EndConnect($async)
        }

        $sw.Stop()

        [pscustomobject]@{
            Host    = $ComputerName
            Port    = $Port
            Open    = [bool]($success -and $client.Connected)
            ElapsedMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error   = if ($success) { $null } else { "Connection timeout" }
        }
    } catch {
        $sw.Stop()

        [pscustomobject]@{
            Host      = $ComputerName
            Port      = $Port
            Open      = $false
            ElapsedMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error     = $_.Exception.Message
        }
    } finally {
        $client.Close()
        $client.Dispose()
    }
}

function Get-ND-DefaultGateway {
    try {
        $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -AddressFamily IPv4 -ErrorAction Stop |
            Sort-Object RouteMetric, InterfaceMetric |
            Select-Object -First 1

        if ($route -and $route.NextHop) {
            $gateway = $route.NextHop
            return [pscustomobject]@{
                Gateway = $gateway
                InterfaceIndex = $route.InterfaceIndex
                Metric = $route.RouteMetric
                Ping = Test-ND-Ping -ComputerName $gateway -Count 3
            }
        }
    } catch {}

    [pscustomobject]@{
        Gateway = $null
        InterfaceIndex = $null
        Metric = $null
        Ping = $null
    }
}

function Invoke-ND-Traceroute {
    param([string]$ComputerName, [int]$MaxHops)

    try {
        $lines = @(& tracert.exe -4 -d -h $MaxHops -w 1000 $ComputerName 2>&1)

        $hops = foreach ($line in $lines) {
            if ($line -match "^\s*(\d+)\s+(.+)$") {
                [pscustomobject]@{
                    Hop = [int]$Matches[1]
                    Raw = $Matches[2].Trim()
                }
            }
        }

        [pscustomobject]@{
            Target = $ComputerName
            Hops   = @($hops)
            Raw    = ($lines -join "`n")
            Success = ($LASTEXITCODE -eq 0)
        }
    } catch {
        [pscustomobject]@{
            Target = $ComputerName
            Hops   = @()
            Raw    = ""
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-ND-WifiInfo {
    try {
        $raw = @(& netsh.exe wlan show interfaces 2>&1)
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{
                Available = $false
                SSID = $null
                Signal = $null
                Channel = $null
                ReceiveRateMbps = $null
                TransmitRateMbps = $null
                State = $null
            }
        }

        function Get-FieldValue {
            param([string]$Label)

            $line = $raw | Where-Object { $_ -match "^\s*$([regex]::Escape($Label))\s*:" } | Select-Object -First 1
            if ($line) {
                return ($line -replace "^\s*$([regex]::Escape($Label))\s*:\s*", "").Trim()
            }
            return $null
        }

        [pscustomobject]@{
            Available = $true
            SSID = Get-FieldValue -Label "SSID"
            Signal = Get-FieldValue -Label "Signal"
            Channel = Get-FieldValue -Label "Channel"
            ReceiveRateMbps = Get-FieldValue -Label "Receive rate (Mbps)"
            TransmitRateMbps = Get-FieldValue -Label "Transmit rate (Mbps)"
            State = Get-FieldValue -Label "State"
        }
    } catch {
        [pscustomobject]@{
            Available = $false
            SSID = $null
            Signal = $null
            Channel = $null
            ReceiveRateMbps = $null
            TransmitRateMbps = $null
            State = $null
            Error = $_.Exception.Message
        }
    }
}

function Get-ND-NetworkState {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object Status -eq "Up" |
        Select-Object Name, InterfaceDescription, LinkSpeed, MacAddress, Status

    $configs = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.NetAdapter.Status -eq "Up" } |
        Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer

    [pscustomobject]@{
        Adapters = @($adapters)
        Configurations = @($configs)
    }
}

function Export-ND-Csv {
    param([hashtable]$Report, [string]$Path)

    $rows = New-Object System.Collections.Generic.List[object]

    $rows.Add([pscustomobject]@{
        Test = "Ping"
        Target = $Report.Ping.Target
        Status = if ($Report.Ping.LossPercent -lt 100) { "Success" } else { "Failed" }
        Details = "Avg=$($Report.Ping.AvgMs)ms; Loss=$($Report.Ping.LossPercent)%"
    })

    $rows.Add([pscustomobject]@{
        Test = "DNS"
        Target = $Report.DNS.Name
        Status = if ($Report.DNS.Success) { "Success" } else { "Failed" }
        Details = "Lookup=$($Report.DNS.LookupMs)ms; Addresses=$($Report.DNS.AddressCount)"
    })

    $rows.Add([pscustomobject]@{
        Test = "HTTPS"
        Target = $Report.HTTPS.Url
        Status = if ($Report.HTTPS.Success) { "Success" } else { "Failed" }
        Details = "Status=$($Report.HTTPS.StatusCode); Time=$($Report.HTTPS.TotalMs)ms"
    })

    $rows.Add([pscustomobject]@{
        Test = "MTU"
        Target = $Report.MTU.Host
        Status = if ($null -ne $Report.MTU.EstimatedPathMtu) { "Success" } else { "Failed" }
        Details = "EstimatedPathMtu=$($Report.MTU.EstimatedPathMtu)"
    })

    $rows.Add([pscustomobject]@{
        Test = "Gateway"
        Target = $Report.Gateway.Gateway
        Status = if ($Report.Gateway.Gateway) { "Detected" } else { "Not found" }
        Details = if ($Report.Gateway.Ping) { "Avg=$($Report.Gateway.Ping.AvgMs)ms" } else { "" }
    })

    foreach ($item in $Report.Tcp) {
        $rows.Add([pscustomobject]@{
            Test = "TCP"
            Target = "$($item.Host):$($item.Port)"
            Status = if ($item.Open) { "Open" } else { "Closed/Blocked" }
            Details = "Time=$($item.ElapsedMs)ms; $($item.Error)"
        })
    }

    foreach ($item in $Report.DnsServers) {
        $rows.Add([pscustomobject]@{
            Test = "DNS Server"
            Target = "$($item.Server) -> $($item.Query)"
            Status = if ($item.Success) { "Success" } else { "Failed" }
            Details = "Time=$($item.LookupMs)ms; Answer=$($item.Answer)"
        })
    }

    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

# When dot-sourced (e.g. by the Pester tests), load the functions only.
if ($MyInvocation.InvocationName -eq ".") {
    return
}

Write-Host ""
Write-Host "=== NetDiag Toolkit 0.2.0 ===" -ForegroundColor Cyan
Write-Host "Windows network diagnostics for connectivity, latency, DNS, HTTPS, MTU and path analysis."
Write-Host ""

$gateway = Get-ND-DefaultGateway

$report = [ordered]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    Computer     = $env:COMPUTERNAME
    PowerShell   = $PSVersionTable.PSVersion.ToString()
    Network      = Get-ND-NetworkState
    WiFi         = Get-ND-WifiInfo
    Ping         = Test-ND-Ping -ComputerName $Target -Count $PingCount
    DNS          = Test-ND-Dns -Name $DnsName
    DnsServers   = @($DnsServers | ForEach-Object { Test-ND-DnsServer -Server $_ -Name $DnsQuery })
    HTTPS        = Test-ND-Https -Url $HttpsUrl
    MTU          = Test-ND-Mtu -ComputerName $MtuHost -StartPayload $MtuStartPayload -MaxPayload $MtuMaxPayload
    Gateway      = $gateway
    Tcp          = @($TcpPorts | ForEach-Object { Test-ND-TcpPort -ComputerName $TcpHost -Port $_ -TimeoutMs $TcpTimeoutMs })
    Traceroute   = Invoke-ND-Traceroute -ComputerName $TraceHost -MaxHops $TraceMaxHops
}

Write-Host "Ping" -ForegroundColor Yellow
$report.Ping | Format-List

Write-Host "DNS" -ForegroundColor Yellow
$report.DNS | Format-List

Write-Host "DNS server comparison" -ForegroundColor Yellow
$report.DnsServers | Format-Table Server, Query, Success, LookupMs, Answer -AutoSize

Write-Host "HTTPS" -ForegroundColor Yellow
$report.HTTPS | Format-List

Write-Host "MTU" -ForegroundColor Yellow
$report.MTU | Format-List

Write-Host "Default gateway" -ForegroundColor Yellow
$report.Gateway | Format-List
if ($report.Gateway.Ping) {
    $report.Gateway.Ping | Format-List
}

Write-Host "TCP ports" -ForegroundColor Yellow
$report.Tcp | Format-Table Host, Port, Open, ElapsedMs, Error -AutoSize

Write-Host "Wi-Fi" -ForegroundColor Yellow
$report.WiFi | Format-List

Write-Host "Traceroute" -ForegroundColor Yellow
$report.Traceroute.Hops | Format-Table -AutoSize

Write-Host "Network state" -ForegroundColor Yellow
$report.Network.Configurations | Format-Table -AutoSize

if ($JsonPath) {
    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $JsonPath -Encoding UTF8
    Write-Host "JSON report saved to: $JsonPath" -ForegroundColor Green
}

if ($CsvPath) {
    Export-ND-Csv -Report $report -Path $CsvPath
    Write-Host "CSV report saved to: $CsvPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
