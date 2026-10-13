<#
.SYNOPSIS
  Verify registry inspection/write errors cannot become successful absence or recovery.
.DESCRIPTION
  Registry access is mocked; no HKCU/HKLM key, setting, VM or network is used.
.EXAMPLE
  Invoke-Pester ./tests/RegistryFailures.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Cover missing/denied key distinction and terminating mutations.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-Settings.psm1') -Force
}
Describe 'Registry failure reporting' {
  It 'treats an actual missing key as absent without writes' {
    InModuleScope RIDE-Settings {
      Mock Get-Item { throw [Management.Automation.ItemNotFoundException]::new('fixture missing key') }
      Mock New-ItemProperty {}
      $current = Get-RideSettingState @{ RegistryPath = 'HKCU:\Software\Fixture'; ValueName = 'Value' }
      $current.Exists | Should -BeFalse
      $current.KeyExisted | Should -BeFalse
      Should -Invoke New-ItemProperty -Times 0
    }
  }
  It 'does not turn <Failure> into an absent key' -ForEach @(
    @{ Failure = 'access denied'; Exception = 'UnauthorizedAccessException' },
    @{ Failure = 'unavailable drive'; Exception = 'DriveNotFoundException' }
  ) {
    InModuleScope RIDE-Settings -Parameters @{ Kind = $Exception } {
      param($Kind)
      if ($Kind -eq 'UnauthorizedAccessException') { Mock Get-Item { throw [UnauthorizedAccessException]::new('fixture denied read') } }
      else { Mock Get-Item { throw [Management.Automation.DriveNotFoundException]::new('fixture unavailable drive') } }
      { Get-RideSettingState @{ RegistryPath = 'HKCU:\Software\Fixture'; ValueName = 'Value' } } | Should -Throw '*fixture*'
      Should -Invoke Get-Item -Times 1 -Exactly -ParameterFilter { $ErrorAction -eq 'Stop' }
    }
  }
  It 'captures existing-key absence separately and retains raw expansion/type data' {
    InModuleScope RIDE-Settings {
      $key = [pscustomobject]@{}
      $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @('RawValue') }
      $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param($Name, $Default, $Options)
        if ($Options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) { throw 'unexpected expansion' }
        '%fixture%'
      }
      $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value { [Microsoft.Win32.RegistryValueKind]::ExpandString }
      Mock Get-Item { $key }
      $missing = Get-RideSettingState @{ RegistryPath = 'HKCU:\Software\Fixture'; ValueName = 'Missing' }
      $missing.KeyExisted | Should -BeTrue
      $missing.Exists | Should -BeFalse
      $raw = Get-RideSettingState @{ RegistryPath = 'HKCU:\Software\Fixture'; ValueName = 'RawValue' }
      $raw.Value | Should -Be '%fixture%'
      $raw.ValueType | Should -Be 'ExpandString'
    }
  }
  It 'does not remove an already absent value and propagates removal denial' {
    InModuleScope RIDE-Settings {
      $op = @{ RegistryPath = 'HKCU:\Software\Fixture'; ValueName = 'Value'; ValueType = 'DWord' }
      Mock Get-RideSettingState { [pscustomobject]@{ Exists = $false; KeyExisted = $true } }
      Mock Remove-ItemProperty { throw 'fixture removal denial' }
      Set-RideSettingState $op $null
      Should -Invoke Remove-ItemProperty -Times 0
      Mock Get-RideSettingState { [pscustomobject]@{ Exists = $true; KeyExisted = $true; Value = 1; ValueType = 'DWord' } }
      { Set-RideSettingState $op $null } | Should -Throw '*fixture removal denial*'
      Should -Invoke Remove-ItemProperty -Times 1 -Exactly -ParameterFilter { $ErrorAction -eq 'Stop' }
    }
  }
  It 'propagates typed-write failures with terminating error policy' {
    InModuleScope RIDE-Settings {
      Mock Test-Path { $true }
      Mock Get-RideSettingState { [pscustomobject]@{ Exists = $false; KeyExisted = $true } }
      Mock New-ItemProperty { throw 'fixture write denial' }
      { Set-RideSettingState @{ RegistryPath = 'HKCU:\Software\Fixture'; ValueName = 'Value'; ValueType = 'DWord' } 0 } | Should -Throw '*fixture write denial*'
      Should -Invoke New-ItemProperty -Times 1 -Exactly -ParameterFilter { $ErrorAction -eq 'Stop' -and $Value -eq 0 }
    }
  }
  It 'reports failed empty-key cleanup rather than successful exact recovery' {
    InModuleScope RIDE-Settings {
      $key = [pscustomobject]@{}
      $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @() }
      $key | Add-Member -MemberType ScriptMethod -Name GetSubKeyNames -Value { @() }
      Mock Get-Item { $key }
      Mock Set-RideSettingState {}
      Mock Remove-Item { throw 'fixture key cleanup denial' }
      { Restore-RideSettingState @{ RegistryPath = 'HKCU:\Software\Fixture'; ValueName = 'Value' } @{ Exists = $false; KeyExisted = $false } } | Should -Throw '*fixture key cleanup denial*'
    }
  }
}
