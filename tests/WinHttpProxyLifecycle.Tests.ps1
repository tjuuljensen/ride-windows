<#
.SYNOPSIS
  Test durable, conflict-checked lifecycle handling for advanced WinHTTP settings.
.DESCRIPTION
  Mocks identity, state-directory security, observations, and the netsh setter.
  These tests never query or change Windows proxy configuration.
.EXAMPLE
  Invoke-Pester .\tests\WinHttpProxyLifecycle.Tests.ps1
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture.
  Changelog: 0.1.0: Cover durable apply, restore, identity checks and conflict refusal.
#>
 $script:Root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $Root 'modules/RIDE.WinHttpProxyLifecycle.psm1') -Force
Describe 'Advanced WinHTTP guarded lifecycle' {
  InModuleScope RIDE.WinHttpProxyLifecycle {
  BeforeEach {
      function New-WinHttpLifecycleObservation {
        param([string]$Scope='User',[string]$Proxy='http=proxy.test:8080',[string]$ProxyBypass='<local>;*.test',[string]$AutoconfigUrl='',[bool]$AutoDetect=$true)
        [pscustomobject]@{
          SchemaVersion=1;Kind='WinHttpProxyConfiguration';Status='Captured';Scope=$Scope
          ProxyIsEnabled=(-not [string]::IsNullOrEmpty($Proxy));Proxy=$Proxy;ProxyReported=$true
          ProxyBypass=$ProxyBypass;ProxyBypassReported=$true
          AutoConfigIsEnabled=(-not [string]::IsNullOrEmpty($AutoconfigUrl));AutoconfigUrl=$AutoconfigUrl;AutoconfigUrlReported=$true
          AutoDetect=$AutoDetect;PerUserProxySettings=($Scope -ceq 'User')
        }
      }
      $script:LifecycleStateRoot=Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) '.local') ('winhttp-lifecycle-test-'+[guid]::NewGuid().ToString('N'))
      $script:LifecycleObservation=New-WinHttpLifecycleObservation
      $script:LifecycleIdentity=[pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001'}
      Mock Get-RideWinHttpProxyLifecycleIdentity { $script:LifecycleIdentity }
      Mock Test-RideWinHttpProxyLifecycleAdministrator { $true }
      Mock Initialize-RideWinHttpProxyLifecycleStateDirectory {
        $path=Join-Path $script:LifecycleStateRoot $Scope
        New-Item -ItemType Directory -Path $path -Force|Out-Null
        $path
      }
      Mock Get-RideWinHttpProxyLifecycleStateDirectory { Join-Path $script:LifecycleStateRoot $Scope }
      Mock Get-RideWinHttpProxyObservation { $script:LifecycleObservation }
      Mock Invoke-RideWinHttpProxyLifecycleSetCommand {
        $record=Get-Content -LiteralPath (Join-Path (Join-Path $script:LifecycleStateRoot $Scope) ($script:LifecycleRunId+'.json')) -Raw|ConvertFrom-Json
        $script:LifecycleRecordWasDurableBeforeSet=($record.Status -eq 'Prepared')
        $settings=Get-Content -LiteralPath $SettingsFile -Raw|ConvertFrom-Json
        $script:LifecycleObservation=New-WinHttpLifecycleObservation -Scope $Scope -Proxy $settings.Proxy -ProxyBypass $settings.ProxyBypass -AutoconfigUrl $settings.AutoconfigUrl -AutoDetect $settings.AutoDetect
        0
      }
      $script:LifecycleRecordWasDurableBeforeSet=$false
      $script:LifecycleRunId=[guid]::NewGuid().ToString('N')
      $script:LifecyclePatch=New-RideWinHttpProxyConfigurationPatch -Observation $script:LifecycleObservation -Scope User -AutoDetect:$false
    }
    AfterEach {
      if ($script:LifecycleStateRoot -and (Test-Path -LiteralPath $script:LifecycleStateRoot)) { Remove-Item -LiteralPath $script:LifecycleStateRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'writes the recovery record before setting and restores only after conflict checks' {
      $applied=Apply-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -Patch $script:LifecyclePatch -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -Confirm:$false
      $applied.Status|Should -BeExactly 'Applied'
      $script:LifecycleRecordWasDurableBeforeSet|Should -BeTrue
      $savedRecord=Get-Content -LiteralPath (Join-Path (Join-Path $script:LifecycleStateRoot 'User') ($script:LifecycleRunId+'.json')) -Raw|ConvertFrom-Json
      $savedRecord.OperationId|Should -BeExactly 'windows.winhttp-automatic-proxy-detection'
      $restored=Restore-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -Confirm:$false
      $restored.Status|Should -BeExactly 'Restored'
      $script:LifecycleObservation.AutoDetect|Should -BeTrue
      $restored.RecoveryPrecision|Should -BeExactly 'ReportedConfiguration'
    }

    It 'rejects target identity drift before writing a snapshot or calling the setter' {
      {Apply-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -Patch $script:LifecyclePatch -ExpectedComputerName 'OTHER-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -Confirm:$false}|Should -Throw '*identity changed*'
      Should -Invoke Invoke-RideWinHttpProxyLifecycleSetCommand -Times 0
      (Test-Path -LiteralPath (Join-Path (Join-Path $script:LifecycleStateRoot User) ($script:LifecycleRunId+'.json')))|Should -BeFalse
    }

    It 'rejects changed reported values after preparation' {
      $script:LifecycleObservation=New-WinHttpLifecycleObservation -ProxyBypass 'changed.test'
      {Apply-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -Patch $script:LifecyclePatch -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -Confirm:$false}|Should -Throw '*changed since preparation*'
      Should -Invoke Invoke-RideWinHttpProxyLifecycleSetCommand -Times 0
    }

    It 'refuses restore after an external writer changes the reported state' {
      $null=Apply-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -Patch $script:LifecyclePatch -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -Confirm:$false
      $script:LifecycleObservation=New-WinHttpLifecycleObservation -ProxyBypass 'other-writer.test' -AutoDetect:$false
      {Restore-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -Confirm:$false}|Should -Throw '*drifted*'
      Should -Invoke Invoke-RideWinHttpProxyLifecycleSetCommand -Times 1
    }

    It 'keeps a usable pre-change record when the setter throws before changing reported state' {
      Mock Invoke-RideWinHttpProxyLifecycleSetCommand { throw 'simulated setter launch failure' }
      $result=Apply-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -Patch $script:LifecyclePatch -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -Confirm:$false
      $result.Status|Should -BeExactly 'FailedNoChange'
      $result.SetterErrorType|Should -BeExactly 'System.Management.Automation.RuntimeException'
      $restored=Restore-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -Confirm:$false
      $restored.Status|Should -BeExactly 'AlreadyOriginal'
    }

    It 'keeps preview read-only and refuses incomplete reported input' {
      $preview=Apply-RideWinHttpProxyPatch -RunId $script:LifecycleRunId -Patch $script:LifecyclePatch -ExpectedComputerName 'TEST-VM' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' -WhatIf
      $preview.Status|Should -BeExactly 'Preview'
      Should -Invoke Invoke-RideWinHttpProxyLifecycleSetCommand -Times 0
      $omitted=New-WinHttpLifecycleObservation
      $omitted.AutoconfigUrl=$null;$omitted.AutoconfigUrlReported=$false
      {New-RideWinHttpProxyConfigurationPatch -Observation $omitted -Scope User -AutoDetect:$false}|Should -Throw '*omitted ''AutoconfigUrl''*prior value is unknown*'
  }
  }
}
