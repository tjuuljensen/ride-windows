<#
.SYNOPSIS
  Test the power setting handler's parsing, setting, and exact restoration behavior.

.DESCRIPTION
  Mocks powercfg.exe and verifies active-scheme selection and AC index lifecycle without changing
  Windows configuration.

.EXAMPLE
  Invoke-Pester .\tests\PowerSettings.Tests.ps1

.INPUTS
  None. Pester invokes the test cases.

.OUTPUTS
  Pester test results.

.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 or PowerShell 7.
  Prerequisites: Repository power setting module.
  Recovery: No system state is changed; powercfg is mocked.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-PowerSettings.psm1') -Force -Global
  $script:PowerOperation = @{
    Id = 'windows.lid-close-action-ac'
    PowerIndex = 'AC'
    PowerSubgroupGuid = '4f971e89-eebd-4455-a8de-9e59040e7347'
    PowerSettingGuid = '5ca83367-6e45-459f-a27b-476b1d01c936'
    States = @{ DoNothing = 0; Sleep = 1 }
  }
}

Describe 'RIDE power setting handler' {
  It 'reads the active scheme and selected AC index' {
    Mock Invoke-RidePowercfg -ModuleName RIDE-PowerSettings {
      if ($Arguments[0] -eq '/getactivescheme') {
        return [pscustomobject]@{ ExitCode = 0; Output = 'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)' }
      }
      return [pscustomobject]@{ ExitCode = 0; Output = "Power Setting GUID: 5ca83367-6e45-459f-a27b-476b1d01c936`n  Current AC Power Setting Index: 0x00000001`n  Current DC Power Setting Index: 0x00000000" }
    }

    $state = Get-RidePowerSettingState -Operation $script:PowerOperation

    $state.SchemeGuid | Should -Be '381b4222-f694-41f0-9685-ff5bb260df2e'
    $state.Index | Should -Be 1
    $state.PowerIndex | Should -Be 'AC'
  }

  It 'reports a device without the requested setting as unavailable' {
    Mock Invoke-RidePowercfg -ModuleName RIDE-PowerSettings {
      if ($Arguments[0] -eq '/getactivescheme') { return [pscustomobject]@{ ExitCode = 0; Output = 'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)' } }
      [pscustomobject]@{ ExitCode = 0; Output = "Subgroup GUID: 4f971e89-eebd-4455-a8de-9e59040e7347`nPower Setting GUID: a7066653-8d6c-40a8-910e-a1f54b84c7e5`nCurrent AC Power Setting Index: 0x00000000" }
    }

    $state = Get-RidePowerSettingState -Operation $script:PowerOperation

    $state.Available | Should -BeFalse
    $state.Index | Should -BeNullOrEmpty
  }

  It 'changes only the declared AC index and verifies the resulting state' {
    $script:PowercfgIndex = 0
    Mock Invoke-RidePowercfg -ModuleName RIDE-PowerSettings {
      if ($Arguments[0] -eq '/getactivescheme') {
        return [pscustomobject]@{ ExitCode = 0; Output = 'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)' }
      }
      if ($Arguments[0] -eq '/setacvalueindex') { $script:PowercfgIndex = [int]$Arguments[4] }
      if ($Arguments[0] -eq '/setdcvalueindex') { throw 'Unexpected DC write' }
      if ($Arguments[0] -eq '/query') { return [pscustomobject]@{ ExitCode = 0; Output = ("Power Setting GUID: 5ca83367-6e45-459f-a27b-476b1d01c936`n  Current AC Power Setting Index: 0x{0:x8}" -f $script:PowercfgIndex) } }
      [pscustomobject]@{ ExitCode = 0; Output = '' }
    }

    Set-RidePowerSettingState -Operation $script:PowerOperation -State Sleep

    $script:PowercfgIndex | Should -Be 1
    Should -Invoke Invoke-RidePowercfg -ModuleName RIDE-PowerSettings -Times 1 -ParameterFilter { $Arguments[0] -eq '/setacvalueindex' }
  }

  It 'restores the exact captured index in the captured scheme' {
    $script:PowercfgCalls = [System.Collections.Generic.List[object]]::new()
    Mock Invoke-RidePowercfg -ModuleName RIDE-PowerSettings {
      $script:PowercfgCalls.Add(@($Arguments))
      if ($Arguments[0] -eq '/getactivescheme') { return [pscustomobject]@{ ExitCode = 0; Output = 'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e' } }
      if ($Arguments[0] -eq '/query') { return [pscustomobject]@{ ExitCode = 0; Output = "Power Setting GUID: 5ca83367-6e45-459f-a27b-476b1d01c936`n  Current AC Power Setting Index: 0x00000000" } }
      [pscustomobject]@{ ExitCode = 0; Output = '' }
    }

    Restore-RidePowerSettingState -Operation $script:PowerOperation -Snapshot @{ SchemeGuid = '381b4222-f694-41f0-9685-ff5bb260df2e'; Index = 0 }

    @($script:PowercfgCalls | Where-Object { $_[0] -eq '/setacvalueindex' }).Count | Should -Be 1
    $restoreCall = $script:PowercfgCalls | Where-Object { $_[0] -eq '/setacvalueindex' } | Select-Object -First 1
    $restoreCall[4] | Should -Be '0'
  }
}

Describe 'RIDE power setting engine integration' {
  It 'builds a standard Set plan for a catalog power setting' {
    InModuleScope RIDE.Engine {
      $plan = @(Get-RideSingleOperationPlan -Id 'windows.lid-close-action-ac' -Action Set -State Sleep)
      $plan.Count | Should -Be 1
      $plan[0].Operation.Kind | Should -Be 'PowerSetting'
      $plan[0].State | Should -Be 'Sleep'
    }
  }

  It 'compares supported and unavailable current states without confusing index zero with availability' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.lid-close-action-ac'
      $sleep = [pscustomobject]@{ Available = $true; Index = 1 }
      $doNothing = [pscustomobject]@{ Available = $true; Index = 0 }
      $unavailable = [pscustomobject]@{ Available = $false; Index = $null }

      (Test-RideCurrentStateMatch -Operation $operation -State 'Sleep' -CurrentState $sleep) | Should -BeTrue
      (Test-RideCurrentStateMatch -Operation $operation -State 'Sleep' -CurrentState $doNothing) | Should -BeFalse
      (Test-RideCurrentStateMatch -Operation $operation -State 'DoNothing' -CurrentState $unavailable) | Should -BeFalse
      (Get-RideCurrentStateName -Operation $operation -CurrentState $unavailable) | Should -Be 'Unavailable'
    }
  }
}
