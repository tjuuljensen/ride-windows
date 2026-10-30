<#
.SYNOPSIS
  Test pure preparation and conflict-aware recovery for advanced WinHTTP settings.
.DESCRIPTION
  Uses supplied observation objects only. It does not query netsh, write files,
  call a setter, or change Windows proxy configuration.
.EXAMPLE
  Invoke-Pester .\tests\WinHttpProxyPreparation.Tests.ps1
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture.
  Changelog: 0.1.0: Cover explicit scope, field preservation, JSON and recovery refusal.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.WinHttpProxyInventory.psm1') -Force
  Import-Module (Join-Path $Root 'modules/RIDE.WinHttpProxyPreparation.psm1') -Force
  function New-WinHttpPreparationObservation {
    param([string]$Scope='User',[string]$Proxy='http=proxy.test:8080',[string]$ProxyBypass='<local>;*.test',[string]$AutoconfigUrl='',[bool]$AutoDetect=$true)
    [pscustomobject]@{
      SchemaVersion=1;Kind='WinHttpProxyConfiguration';Status='Captured';Scope=$Scope
      ProxyIsEnabled=(-not [string]::IsNullOrEmpty($Proxy));Proxy=$Proxy;ProxyReported=$true
      ProxyBypass=$ProxyBypass;ProxyBypassReported=$true
      AutoConfigIsEnabled=(-not [string]::IsNullOrEmpty($AutoconfigUrl));AutoconfigUrl=$AutoconfigUrl;AutoconfigUrlReported=$true
      AutoDetect=$AutoDetect;PerUserProxySettings=($Scope -ceq 'User')
    }
  }
}
Describe 'Advanced WinHTTP configuration preparation' {
  It 'prepares one explicit scope and preserves fields that were not selected' {
    $observation=New-WinHttpPreparationObservation
    $patch=New-RideWinHttpProxyConfigurationPatch -Observation $observation -Scope User -AutoDetect:$false
    $patch.ChangeRequired|Should -BeTrue
    $patch.Scope|Should -BeExactly 'User'
    $patch.DesiredValues.Proxy|Should -BeExactly $observation.Proxy
    $patch.DesiredValues.ProxyBypass|Should -BeExactly $observation.ProxyBypass
    $patch.DesiredValues.AutoDetect|Should -BeFalse
    $settings=ConvertFrom-Json -InputObject $patch.SettingsJson
    $settings.Proxy|Should -BeExactly 'http=proxy.test:8080'
    $settings.ProxyBypass|Should -BeExactly '<local>;*.test'
    $settings.AutoconfigUrl|Should -BeExactly ''
    $settings.AutoDetect|Should -BeFalse
    $patch.ReadyForMutation|Should -BeFalse
    $patch.ExactLiteralStateVerified|Should -BeFalse
  }
  It 'requires the requested scope to match the captured scope' {
    $observation=New-WinHttpPreparationObservation -Scope User
    {New-RideWinHttpProxyConfigurationPatch -Observation $observation -Scope Machine -AutoDetect:$false}|Should -Throw '*differs from the captured scope*'
  }
  It 'marks machine configuration as requiring elevation without authorizing mutation' {
    $observation=New-WinHttpPreparationObservation -Scope Machine
    $patch=New-RideWinHttpProxyConfigurationPatch -Observation $observation -Scope Machine -ProxyBypass ''
    $patch.RequiresElevation|Should -BeTrue
    $patch.ReadyForMutation|Should -BeFalse
    $patch.DesiredValues.ProxyBypass|Should -BeExactly ''
  }
  It 'refuses to prepare when a complete settings payload would erase an omitted prior value' {
    $observation=New-WinHttpPreparationObservation
    $observation.ProxyBypass=$null;$observation.ProxyBypassReported=$false
    {New-RideWinHttpProxyConfigurationPatch -Observation $observation -Scope User -AutoDetect:$false}|Should -Throw '*omitted ''ProxyBypass''*prior value is unknown*'
  }
  It 'prepares recovery only while every configured field remains at its requested value' {
    $original=New-WinHttpPreparationObservation
    $patch=New-RideWinHttpProxyConfigurationPatch -Observation $original -Scope User -AutoDetect:$false
    $current=New-WinHttpPreparationObservation -AutoDetect:$false
    $recovery=Restore-RideWinHttpProxyConfigurationPatch -Observation $current -Snapshot $patch.Snapshot
    $recovery.DesiredValues.AutoDetect|Should -BeTrue
    $recovery.DesiredValues.Proxy|Should -BeExactly $original.Proxy
    $settings=ConvertFrom-Json -InputObject $recovery.SettingsJson
    $settings.Proxy|Should -BeExactly $original.Proxy
    $settings.ProxyBypass|Should -BeExactly $original.ProxyBypass
    $settings.AutoconfigUrl|Should -BeExactly $original.AutoconfigUrl
    $settings.AutoDetect|Should -BeTrue
    $recovery.ReadyForMutation|Should -BeFalse
    $recovery.RecoveryPrecision|Should -BeExactly 'ReportedConfiguration'
  }
  It 'refuses recovery after any field or scope drift' {
    $original=New-WinHttpPreparationObservation
    $patch=New-RideWinHttpProxyConfigurationPatch -Observation $original -Scope User -AutoDetect:$false
    $changed=New-WinHttpPreparationObservation -AutoDetect:$false -ProxyBypass 'later.test'
    {Restore-RideWinHttpProxyConfigurationPatch -Observation $changed -Snapshot $patch.Snapshot}|Should -Throw '*ProxyBypass*changed*'
    $machine=New-WinHttpPreparationObservation -Scope Machine -AutoDetect:$false
    {Restore-RideWinHttpProxyConfigurationPatch -Observation $machine -Snapshot $patch.Snapshot}|Should -Throw '*schema or scope*'
  }
  It 'refuses recovery when a fresh observation omits any string field' {
    $original=New-WinHttpPreparationObservation
    $patch=New-RideWinHttpProxyConfigurationPatch -Observation $original -Scope User -AutoDetect:$false
    $current=New-WinHttpPreparationObservation -AutoDetect:$false
    $current.AutoconfigUrl=$null;$current.AutoconfigUrlReported=$false
    {Restore-RideWinHttpProxyConfigurationPatch -Observation $current -Snapshot $patch.Snapshot}|Should -Throw '*omitted ''AutoconfigUrl''*prior value is unknown*'
  }
  It 'does not claim a change when the complete requested state already matches' {
    $observation=New-WinHttpPreparationObservation
    $patch=New-RideWinHttpProxyConfigurationPatch -Observation $observation -Scope User
    $patch.ChangeRequired|Should -BeFalse
    $patch.ChangedFields.Count|Should -Be 0
  }
  It 'rejects malformed snapshots instead of trusting caller-supplied desired values' {
    $observation=New-WinHttpPreparationObservation
    $patch=New-RideWinHttpProxyConfigurationPatch -Observation $observation -Scope User -AutoDetect:$false
    $patch.Snapshot.ExpectedValues.Proxy='tampered.test'
    {Restore-RideWinHttpProxyConfigurationPatch -Observation (New-WinHttpPreparationObservation -AutoDetect:$false) -Snapshot $patch.Snapshot}|Should -Throw '*snapshot changed-field list disagrees*'
  }
}
