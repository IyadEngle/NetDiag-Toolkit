<#
.SYNOPSIS
    NetDiag Toolkit - lightweight Windows network diagnostics for DNS, latency, HTTPS and MTU.

.DESCRIPTION
    Runs a repeatable set of local network tests and prints a readable report.
    Designed for Windows PowerShell 5.1+ and PowerShell 7+.

.EXAMPLE
    .\NetDiag.ps1

.EXAMPLE
    .\NetDiag.ps1 -Target 1.1.1.1 -HttpsUrl https://example.com -MtuHost 1.1.1.1

.EXAMPLE
    .\NetDiag.ps1 -JsonPath .\report.json
#>

[CmdletBinding()]
param(
    [string]$Target = "1.1.1.1",
    [string]$DnsName = "cloudflare.com",
    [string]$HttpsUrl = "https://www.cloudflare.com/",
    [string]$MtuHost = "1.1.1.1",
    [int]$PingCount = 5,
    [int]$MtuStartPayload = 1200,
    [int]$MtuMaxPayload = 1472,
    [string]$JsonPath
)

$ErrorActionPreference = "Continue"

function Test-ND-Ping {
    param([string]$ComputerName, [int]$Count)
    $samples = @()
    try {
        $replies = Test-Connection -ComputerName $ComputerName -Count $Count -ErrorAction Stop
        foreach ($r in $replies) {
            if ($null -ne $r.ResponseTime) { $samples += [double]$r.ResponseTime }
        }
    } catch {}
    [pscustomobject]@{
        Target = $ComputerName
        Sent = $Count
        Received = $samples.Count
        LossPercent = if ($Count) { [math]::Round((1 - ($samples.Count / $Count)) * 100, 1) } else { $null }
        MinMs = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Minimum).Minimum, 2) } else { $null }
        AvgMs = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Average).Average, 2) } else { $null }
        MaxMs = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Maximum).Maximum, 2) } else { $null }
    }
}

function Test-ND-Dns {
    param([string]$Name)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($Name)
        $sw.Stop()
        [pscustomobject]@{
            Name = $Name
            Success = $true
            AddressCount = $addresses.Count
            Addresses = ($addresses | ForEach-Object IPAddressToString) -join ", "
            LookupMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error = $null
        }
    } catch {
        $sw.Stop()
        [pscustomobject]@{
            Name = $Name
            Success = $false
            AddressCount = 0
            Addresses = ""
            LookupMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error = $_.Exception.Message
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
            Url = $Url
            Success = $true
            StatusCode = [int]$response.StatusCode
            TotalMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error = $null
        }
    } catch {
        $sw.Stop()
        [pscustomobject]@{
            Url = $Url
            Success = $false
            StatusCode = $null
            TotalMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            Error = $_.Exception.Message
        }
    }
}

function Test-ND-MtuPayload {
    param([string]$ComputerName, [int]$Payload)
    try {
        $reply = Test-Connection -ComputerName $ComputerName -Count 1 -BufferSize $Payload -DontFragment -ErrorAction Stop
        return $true
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
        }
    }
    # Binary-search the final boundary after the coarse scan.
    if ($null -ne $working) {
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
        Host = $ComputerName
        MaxIcmpPayload = $working
        EstimatedPathMtu = if ($null -ne $working) { $working + 28 } else { $null }
        Note = "ICMP/DF result; firewalls, packet filtering and remote hosts can affect this test."
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

Write-Host ""
Write-Host "=== NetDiag Toolkit ===" -ForegroundColor Cyan
Write-Host "Windows network diagnostics for connectivity, DNS, HTTPS and path MTU."
Write-Host ""

$report = [ordered]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    Computer = $env:COMPUTERNAME
    PowerShell = $PSVersionTable.PSVersion.ToString()
    Network = Get-ND-NetworkState
    Ping = Test-ND-Ping -ComputerName $Target -Count $PingCount
    DNS = Test-ND-Dns -Name $DnsName
    HTTPS = Test-ND-Https -Url $HttpsUrl
    MTU = Test-ND-Mtu -ComputerName $MtuHost -StartPayload $MtuStartPayload -MaxPayload $MtuMaxPayload
}

Write-Host "Ping" -ForegroundColor Yellow
$report.Ping | Format-List

Write-Host "DNS" -ForegroundColor Yellow
$report.DNS | Format-List

Write-Host "HTTPS" -ForegroundColor Yellow
$report.HTTPS | Format-List

Write-Host "MTU" -ForegroundColor Yellow
$report.MTU | Format-List

Write-Host "Network state" -ForegroundColor Yellow
$report.Network.Configurations | Format-Table -AutoSize

if ($JsonPath) {
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $JsonPath -Encoding UTF8
    Write-Host "JSON report saved to: $JsonPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
