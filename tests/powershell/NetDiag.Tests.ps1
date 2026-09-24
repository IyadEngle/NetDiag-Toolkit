# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later
# Pester 5 tests for the legacy NetDiag.ps1 script.
# Run: Invoke-Pester -Path tests/powershell

BeforeAll {
    # Dot-sourcing loads the functions only; the script skips its main body.
    . (Join-Path $PSScriptRoot "..\..\NetDiag.ps1")

    function New-Ps51Reply([int]$StatusCode, $ResponseTime) {
        # Shape of Win32_PingStatus (Windows PowerShell 5.1 Test-Connection).
        [pscustomobject]@{ StatusCode = $StatusCode; ResponseTime = $ResponseTime }
    }
    function New-Ps7Reply([string]$Status, [long]$Latency) {
        # Shape of TestConnectionCommand+PingStatus (PowerShell 7 Test-Connection).
        [pscustomobject]@{ Status = $Status; Latency = $Latency; Reply = $null }
    }
}

Describe "Get-ND-PingLatency" {
    It "reads Latency from a successful PowerShell 7 reply" {
        Get-ND-PingLatency -Reply (New-Ps7Reply "Success" 12) | Should -Be 12
    }
    It "accepts a 0 ms PowerShell 7 reply (e.g. localhost)" {
        Get-ND-PingLatency -Reply (New-Ps7Reply "Success" 0) | Should -Be 0
    }
    It "ignores failed PowerShell 7 replies" {
        Get-ND-PingLatency -Reply (New-Ps7Reply "TimedOut" 0) | Should -BeNullOrEmpty
        Get-ND-PingLatency -Reply (New-Ps7Reply "DestinationHostUnreachable" 0) | Should -BeNullOrEmpty
    }
    It "reads ResponseTime from a successful Windows PowerShell 5.1 reply" {
        Get-ND-PingLatency -Reply (New-Ps51Reply 0 15) | Should -Be 15
    }
    It "ignores failed Windows PowerShell 5.1 replies" {
        Get-ND-PingLatency -Reply (New-Ps51Reply 11010 $null) | Should -BeNullOrEmpty
        Get-ND-PingLatency -Reply (New-Ps51Reply 11003 5) | Should -BeNullOrEmpty
    }
    It "returns null for null input" {
        Get-ND-PingLatency -Reply $null | Should -BeNullOrEmpty
    }
}

Describe "Test-ND-Ping" {
    It "counts PowerShell 7 replies (previously reported 100% loss)" {
        Mock Test-Connection { 1..4 | ForEach-Object { New-Ps7Reply "Success" (10 + $_) } }
        $r = Test-ND-Ping -ComputerName "192.0.2.1" -Count 4
        $r.Received | Should -Be 4
        $r.LossPercent | Should -Be 0
        $r.MinMs | Should -Be 11
        $r.MaxMs | Should -Be 14
    }
    It "reports partial loss instead of discarding every sample" {
        Mock Test-Connection {
            New-Ps7Reply "Success" 10
            New-Ps7Reply "TimedOut" 0
            New-Ps7Reply "Success" 20
            New-Ps7Reply "TimedOut" 0
        }
        $r = Test-ND-Ping -ComputerName "192.0.2.1" -Count 4
        $r.Received | Should -Be 2
        $r.LossPercent | Should -Be 50
        $r.AvgMs | Should -Be 15
    }
    It "still works with Windows PowerShell 5.1 replies" {
        Mock Test-Connection { New-Ps51Reply 0 8; New-Ps51Reply 11003 $null }
        $r = Test-ND-Ping -ComputerName "192.0.2.1" -Count 2
        $r.Received | Should -Be 1
        $r.LossPercent | Should -Be 50
    }
    It "reports 100% loss when nothing answers" {
        Mock Test-Connection { }
        $r = Test-ND-Ping -ComputerName "192.0.2.1" -Count 3
        $r.Received | Should -Be 0
        $r.LossPercent | Should -Be 100
        $r.AvgMs | Should -BeNullOrEmpty
    }
    It "does not stop on errors from Test-Connection" {
        Mock Test-Connection { Write-Error "host unreachable"; New-Ps7Reply "Success" 7 }
        $r = Test-ND-Ping -ComputerName "192.0.2.1" -Count 2
        $r.Received | Should -Be 1
    }
}
