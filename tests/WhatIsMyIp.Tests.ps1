<#
.SYNOPSIS
  Check public IP comparison with local provider fixtures.

.DESCRIPTION
  Replaces DNS and HTTPS commands with in-process fixtures. No public-IP
  service is contacted, and no Windows state is changed.

.EXAMPLE
  Invoke-Pester .\tests\WhatIsMyIp.Tests.ps1

.INPUTS
  None.

.OUTPUTS
  Pester results.

.NOTES
  Compatibility: Pester 5; intended for Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: No network connection or elevation.
  Version: Repository test fixture.
#>

BeforeAll {
    $utility = Join-Path (Split-Path -Parent $PSScriptRoot) 'components/scripts/whatismyip.ps1'
}

Describe 'Public IP comparison' {
    It 'shows help and version without contacting providers' {
        function Resolve-DnsName { throw 'DNS must not be called.' }
        function Invoke-WebRequest { throw 'HTTPS must not be called.' }
        (& $utility -Version) | Should -BeExactly '0.1.0'
        (& $utility -Help) | Should -Match 'Usage: whatismyip.ps1'
    }

    It 'counts matching DNS and HTTPS providers, excluding the local route' {
        function Resolve-DnsName {
            param([string]$Name, [string]$Type, [string]$Server,
                  [switch]$DnsOnly, [switch]$QuickTimeout, [string]$ErrorAction)
            if ($Name -eq 'resolver1.opendns.com') { return [pscustomobject]@{ IPAddress = '208.67.222.222' } }
            if ($Name -eq 'ns1.google.com' -and $Type -eq 'A') { return [pscustomobject]@{ IPAddress = '216.239.32.10' } }
            if ($Name -eq 'ns1.google.com' -and $Type -eq 'AAAA') { return [pscustomobject]@{ IPAddress = '2001:4860:4802:32::a' } }
            if ($Name -eq 'myip.opendns.com') { return [pscustomobject]@{ IPAddress = '203.0.113.10' } }
            if ($Name -eq 'o-o.myaddr.l.google.com' -and $Server -match ':') { return [pscustomobject]@{ Strings = @('"2001:db8::10"') } }
            if ($Name -eq 'o-o.myaddr.l.google.com') { return [pscustomobject]@{ Strings = @('"203.0.113.10"') } }
            throw "Unexpected DNS query: $Name $Type $Server"
        }
        function Invoke-WebRequest {
            param([string]$Uri, [int]$TimeoutSec, [switch]$UseBasicParsing,
                  [string]$ErrorAction)
            if ($Uri -eq 'https://api.ipify.org') { return [pscustomobject]@{ Content = '203.0.113.10' } }
            if ($Uri -eq 'https://api6.ipify.org') { return [pscustomobject]@{ Content = '2001:db8::10' } }
            throw "Unexpected HTTPS request: $Uri"
        }

        $result = & $utility -Json | ConvertFrom-Json
        $result.ipv4.status | Should -BeExactly 'consistent'
        $result.ipv4.providerCount | Should -Be 3
        $result.ipv4.public | Should -BeExactly '203.0.113.10'
        $result.ipv6.status | Should -BeExactly 'consistent'
        $result.ipv6.providerCount | Should -Be 2
        $result.ipv6.public | Should -BeExactly '2001:db8::10'

        $quiet = & $utility -Json -Quiet | ConvertFrom-Json
        $quiet.ipv4 | Should -BeExactly '203.0.113.10'
        $quiet.ipv6 | Should -BeExactly '2001:db8::10'
        @($quiet.PSObject.Properties).Count | Should -Be 2

        $dnsOnly = & $utility -IPv4 -NoIpify -Json | ConvertFrom-Json
        $dnsOnly.ipv4.providerCount | Should -Be 2
        $dnsOnly.ipv4.providers.ipifyHttps | Should -BeNullOrEmpty
    }

    It 'reports disagreement and includes warnings only in diagnostic JSON' {
        function Resolve-DnsName {
            param([string]$Name, [string]$Type, [string]$Server,
                  [switch]$DnsOnly, [switch]$QuickTimeout, [string]$ErrorAction)
            if ($Name -eq 'resolver1.opendns.com') { return [pscustomobject]@{ IPAddress = '208.67.222.222' } }
            if ($Name -eq 'ns1.google.com') { return [pscustomobject]@{ IPAddress = '216.239.32.10' } }
            if ($Name -eq 'myip.opendns.com') { return [pscustomobject]@{ IPAddress = '203.0.113.10' } }
            return [pscustomobject]@{ Strings = @('"203.0.113.10"') }
        }
        function Invoke-WebRequest {
            param([string]$Uri, [int]$TimeoutSec, [switch]$UseBasicParsing,
                  [string]$ErrorAction)
            return [pscustomobject]@{ Content = '198.51.100.7' }
        }

        $result = & $utility -IPv4 -Json -Debug | ConvertFrom-Json
        $result.ipv4.status | Should -BeExactly 'provider_mismatch'
        $result.ipv4.consistent | Should -BeFalse
        $result.ipv4.providerCount | Should -Be 3
        $result.warnings | Should -Contain 'IPv4 providers disagree.'
        $result.options.debug | Should -BeTrue
        $result.ipv4.providers.ipifyHttps.status | Should -BeExactly 'ok'

        $ordinary = & $utility -IPv4 -Json | ConvertFrom-Json
        ($null -eq $ordinary.PSObject.Properties['warnings']) | Should -BeTrue
    }

    It 'uses IPv6 fallbacks only when they return an IPv6 address' {
        function Resolve-DnsName {
            param([string]$Name, [string]$Type, [string]$Server,
                  [switch]$DnsOnly, [switch]$QuickTimeout, [string]$ErrorAction)
            if ($Name -eq 'ns1.google.com' -and $Type -eq 'AAAA') {
                return [pscustomobject]@{ IPAddress = '2001:4860:4802:32::a' }
            }
            if ($Server -match ':') { return [pscustomobject]@{ Strings = @('203.0.113.10') } }
            return [pscustomobject]@{ Strings = @('2001:db8::20') }
        }
        function Invoke-WebRequest {
            param([string]$Uri, [int]$TimeoutSec, [switch]$UseBasicParsing,
                  [string]$ErrorAction)
            if ($Uri -eq 'https://api6.ipify.org') { throw 'Simulated IPv6 endpoint failure.' }
            return [pscustomobject]@{ Content = '2001:db8::20' }
        }

        $result = & $utility -IPv6 -Json | ConvertFrom-Json
        $result.ipv6.public | Should -BeExactly '2001:db8::20'
        $result.ipv6.providerCount | Should -Be 2
        $result.ipv6.status | Should -BeExactly 'consistent'
        ($null -eq $result.PSObject.Properties['ipv4']) | Should -BeTrue
    }
}
