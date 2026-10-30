<#
.SYNOPSIS
  Test read-only parsing and capture of advanced WinHTTP proxy state.
.DESCRIPTION
  Uses documented netsh output fixtures and mocked command/identity boundaries.
  It does not run netsh or query or change Windows proxy configuration.
.EXAMPLE
  Invoke-Pester .\tests\WinHttpProxyInventory.Tests.ps1
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture.
  Changelog: 0.1.0: Cover strict advanced WinHTTP output parsing and read-only binding.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.WinHttpProxyInventory.psm1') -Force
  $script:UserOutput=@'
Current WinHTTP advanced proxy settings:
{
  "ProxyIsEnabled": true,
  "Proxy": "http=proxy.test:8080;https=secure.test:8443",
  "ProxyBypass": "<local>;*.internal.test",
  "AutoConfigIsEnabled": false,
  "AutoDetect": true,
  "PerUserProxySettings": true
}
'@
  $script:MachineOutput=@'
Current WinHTTP advanced proxy settings:
{"ProxyIsEnabled":false,"ProxyBypass":"","AutoConfigIsEnabled":true,"AutoconfigUrl":"https://pac.test/config.pac","AutoDetect":false,"PerUserProxySettings":false}
'@
}
Describe 'Advanced WinHTTP proxy output parser' {
  It 'preserves reported user scope and all reported fields' {
    $result=ConvertFrom-RideWinHttpProxyOutput -Output $script:UserOutput
    $result.Scope|Should -BeExactly 'User'
    $result.ProxyIsEnabled|Should -BeTrue
    $result.Proxy|Should -BeExactly 'http=proxy.test:8080;https=secure.test:8443'
    $result.ProxyBypass|Should -BeExactly '<local>;*.internal.test'
    $result.AutoDetect|Should -BeTrue
    $result.ExactLiteralStateVerified|Should -BeFalse
  }
  It 'identifies machine scope and keeps disabled proxy strings as reported' {
    $result=ConvertFrom-RideWinHttpProxyOutput -Output $script:MachineOutput
    $result.Scope|Should -BeExactly 'Machine'
    $result.ProxyIsEnabled|Should -BeFalse
    $result.ProxyReported|Should -BeFalse
    $result.ProxyBypassReported|Should -BeTrue
    $result.ProxyBypass|Should -BeExactly ''
    $result.AutoConfigIsEnabled|Should -BeTrue
    $result.AutoconfigUrl|Should -BeExactly 'https://pac.test/config.pac'
  }
  It 'rejects output without a complete JSON object' {
    {ConvertFrom-RideWinHttpProxyOutput -Output 'not JSON'}|Should -Throw '*complete JSON object*'
    {ConvertFrom-RideWinHttpProxyOutput -Output '{"ProxyIsEnabled":true'}|Should -Throw '*complete JSON object*'
    {ConvertFrom-RideWinHttpProxyOutput -Output ($script:UserOutput+'{}')}|Should -Throw '*trailing data*'
  }
  It 'rejects non-Boolean state fields and enabled fields without values' {
    {ConvertFrom-RideWinHttpProxyOutput -Output '{"ProxyIsEnabled":"true","AutoConfigIsEnabled":false,"AutoDetect":false,"PerUserProxySettings":true}'}|Should -Throw '*JSON Boolean*'
    {ConvertFrom-RideWinHttpProxyOutput -Output '{"ProxyIsEnabled":true,"AutoConfigIsEnabled":false,"AutoDetect":false,"PerUserProxySettings":true}'}|Should -Throw '*without a Proxy value*'
    {ConvertFrom-RideWinHttpProxyOutput -Output '{"ProxyIsEnabled":false,"AutoConfigIsEnabled":true,"AutoDetect":false,"PerUserProxySettings":true}'}|Should -Throw '*without an AutoconfigUrl value*'
  }
  It 'rejects invalid types, excessive strings, and oversized output' {
    {ConvertFrom-RideWinHttpProxyOutput -Output '{"ProxyIsEnabled":false,"Proxy":7,"AutoConfigIsEnabled":false,"AutoDetect":false,"PerUserProxySettings":true}'}|Should -Throw '*must be a string*'
    $large=('x'*32769)|ConvertTo-Json -Compress
    $json='{"ProxyIsEnabled":false,"Proxy":'+$large+',"AutoConfigIsEnabled":false,"AutoDetect":false,"PerUserProxySettings":true}'
    {ConvertFrom-RideWinHttpProxyOutput -Output $json}|Should -Throw '*32768 characters*'
    {ConvertFrom-RideWinHttpProxyOutput -Output ('x'*65537)}|Should -Throw '*64 KiB*'
  }
}
Describe 'Advanced WinHTTP read-only capture' {
  It 'uses the fixed observer and binds the result to current identity' {
    Mock Get-RideWinHttpProxyCurrentIdentity -ModuleName RIDE.WinHttpProxyInventory { [pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001'} }
    Mock Invoke-RideWinHttpProxyShow -ModuleName RIDE.WinHttpProxyInventory { $script:UserOutput }
    $result=Get-RideWinHttpProxyObservation
    $result.ComputerName|Should -BeExactly 'TEST-VM'
    $result.UserSid|Should -BeExactly 'S-1-5-21-1-2-3-1001'
    $result.Scope|Should -BeExactly 'User'
    Should -Invoke Invoke-RideWinHttpProxyShow -ModuleName RIDE.WinHttpProxyInventory -Exactly 1
  }
  It 'propagates command failures without returning an observation' {
    Mock Get-RideWinHttpProxyCurrentIdentity -ModuleName RIDE.WinHttpProxyInventory { [pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001'} }
    Mock Invoke-RideWinHttpProxyShow -ModuleName RIDE.WinHttpProxyInventory { throw 'netsh query failed.' }
    {Get-RideWinHttpProxyObservation}|Should -Throw '*netsh query failed*'
  }
}
