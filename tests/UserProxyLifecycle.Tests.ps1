<#
.SYNOPSIS
  Test the guarded live user-proxy lifecycle through mocked WinINet calls.
.DESCRIPTION
  Mocks proxy observations, policy values and the native setter. No registry,
  WinINet, PAC, network, or Windows state is queried or changed.
.EXAMPLE
  Invoke-Pester .\tests\UserProxyLifecycle.Tests.ps1
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture.
  Changelog: Add fresh-compare apply, readback and compensation candidate tests.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.UserProxyLifecycle.psm1') -Force
  Import-Module (Join-Path $Root 'modules/RIDE.UserProxyPreparation.psm1') -Force
  function New-ProxyLifecycleObservation([uint32]$Flags=15){
    [pscustomobject]@{
      SchemaVersion=1;Kind='UserProxyObservation';Status='Captured'
      ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001';SessionId=1
      ConnectionKind='DefaultLan';ConnectionName=$null
      Flags=$Flags;FlagsSource='FlagsUi';UiQueryError=$null
      ProxyServer='http=proxy.test:80';ProxyBypass='<local>;*.test'
      AutoConfigUrl='https://pac.test/a.pac'
    }
  }
  function New-ProxyLifecyclePatch {
    New-RideUserProxyConfigurationPatch -Observation (New-ProxyLifecycleObservation) -AutomaticDetection Disabled
  }
}
Describe 'Guarded user-proxy lifecycle candidate' {
  BeforeEach {
    $script:Current=New-ProxyLifecycleObservation
    $script:WriteCalls=0
    $script:FailFirstConfiguration=$false
    $script:FailFirstNotification=$false
    $script:ThrowFirstAfterWrite=$false
    $script:FailAfterWriteObservation=$false
    $script:SnapshotVisibleAtSetter=$false
    $script:StateDirectory=Join-Path $TestDrive ('proxy-state-'+[guid]::NewGuid().ToString('N'))
    Mock Get-RideUserProxyLifecycleStateDirectory -ModuleName RIDE.UserProxyLifecycle {$script:StateDirectory}
    Mock Get-RideUserProxyObservation -ModuleName RIDE.UserProxyLifecycle {
      if($script:FailAfterWriteObservation -and $script:WriteCalls -gt 0){throw 'Injected readback failure.'}
      $script:Current
    }
    Mock Get-RideUserProxyPolicyObservation -ModuleName RIDE.UserProxyLifecycle {
      [pscustomobject]@{KnownPolicyStatus='Clear';BlockingValues=@();UnknownValues=@()}
    }
    Mock Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle {
      $script:WriteCalls++
      $script:SnapshotVisibleAtSetter=@(Get-ChildItem -LiteralPath $script:StateDirectory -Filter '*.json' -ErrorAction SilentlyContinue).Count -gt 0
      if($script:FailFirstConfiguration -and $script:WriteCalls -eq 1){return [pscustomobject]@{ConfigurationSet=$false;ConfigurationError=55;SettingsChangedNotified=$false;SettingsChangedError=0;Refreshed=$false;RefreshError=0}}
      $script:Current.Flags=[uint32]$Flags
      if($OwnsAutoConfigUrl){$script:Current.AutoConfigUrl=$AutoConfigUrl}
      if($script:ThrowFirstAfterWrite -and $script:WriteCalls -eq 1){throw 'Injected setter exception after write.'}
      $notify= -not ($script:FailFirstNotification -and $script:WriteCalls -eq 1)
      [pscustomobject]@{ConfigurationSet=$true;ConfigurationError=0;SettingsChangedNotified=$notify;SettingsChangedError=$(if($notify){0}else{87});Refreshed=$true;RefreshError=0}
    }
  }
  It 'compares current values and applies then reads back the requested proxy patch' {
    $engineRunId='11111111111111111111111111111111'
    $result=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -RunId $engineRunId -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $result.Status|Should -BeExactly Applied
    $result.ReadbackMatched|Should -BeTrue
    $result.Current.Flags|Should -Be 7
    $result.Snapshot.Kind|Should -BeExactly UserProxyPreparationSnapshot
    $result.RunId|Should -BeExactly $engineRunId
    (Test-Path -LiteralPath $result.SnapshotPath -PathType Leaf)|Should -BeTrue
    $script:SnapshotVisibleAtSetter|Should -BeTrue
    Should -Invoke Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle -Exactly 1
  }
  It 'refuses current-state drift before the native setter' {
    $script:Current.ProxyServer='http=changed.test:80'
    {Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false}|Should -Throw '*changed since preparation*'
    Should -Invoke Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle -Exactly 0
  }
  It 'confirms the prior state after a failed configuration write' {
    $script:FailFirstConfiguration=$true
    $result=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $result.Status|Should -BeExactly NotApplied
    $result.Changed|Should -BeFalse
    $result.ReadbackMatched|Should -BeTrue
    $result.Current.Flags|Should -Be 15
    $script:WriteCalls|Should -Be 1
  }
  It 'does not call the setter for WhatIf' {
    $result=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -WhatIf
    $result.Status|Should -BeExactly WhatIf
    Should -Invoke Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle -Exactly 0
    (Test-Path -LiteralPath $script:StateDirectory)|Should -BeFalse
  }
  It 'compensates and verifies the prior configuration after a notification failure' {
    $script:FailFirstNotification=$true
    $result=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $result.Status|Should -BeExactly Compensated
    $result.Changed|Should -BeFalse
    $result.Current.Flags|Should -Be 15
    $script:WriteCalls|Should -Be 2
  }
  It 'compensates a setter exception only after readback confirms the desired values' {
    $script:ThrowFirstAfterWrite=$true
    $result=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $result.Status|Should -BeExactly Compensated
    $result.Current.Flags|Should -Be 15
    $script:WriteCalls|Should -Be 2
  }
  It 'does not overwrite values when repeated post-write reads fail' {
    $script:FailAfterWriteObservation=$true
    $result=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $result.Status|Should -BeExactly AppliedUnverified
    $result.Changed|Should -BeTrue
    $script:WriteCalls|Should -Be 1
    $script:Current.Flags|Should -Be 7
  }
  It 'reports post-write drift without overwriting the conflicting value' {
    Mock Get-RideUserProxyObservation -ModuleName RIDE.UserProxyLifecycle {
      if($script:WriteCalls -gt 0){$script:Current.ProxyBypass='later edit'}
      $script:Current
    }
    $result=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $result.Status|Should -BeExactly AppliedMismatch
    $result.Current.ProxyBypass|Should -BeExactly 'later edit'
    $script:WriteCalls|Should -Be 1
  }
  It 'restores only the owned proxy bit while preserving other flags and strings' {
    $patch=New-ProxyLifecyclePatch
    $script:Current.Flags=[uint32]7
    $script:Current.ProxyBypass='<local>;later.test'
    $result=Restore-RideUserProxyConfigurationSnapshot -Snapshot $patch.Snapshot -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $result.Status|Should -BeExactly Applied
    $result.Current.Flags|Should -Be 15
    $result.Current.ProxyBypass|Should -BeExactly '<local>;later.test'
  }
  It 'refuses recovery when the owned flag changed after the prepared apply' {
    $patch=New-ProxyLifecyclePatch
    $script:Current.Flags=[uint32]15
    {Restore-RideUserProxyConfigurationSnapshot -Snapshot $patch.Snapshot -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false}|Should -Throw '*flag conflicts*'
    Should -Invoke Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle -Exactly 0
  }
  It 'restores from a durable run ID bound to the original machine, user and session' {
    $applied=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $restored=Restore-RideUserProxyConfigurationSnapshot -RunId $applied.RunId -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $restored.Status|Should -BeExactly Applied
    $restored.Current.Flags|Should -Be 15
    (Test-Path -LiteralPath $applied.SnapshotPath -PathType Leaf)|Should -BeTrue
    (Test-Path -LiteralPath (Join-Path $script:StateDirectory ($applied.RunId+'.completed.json')) -PathType Leaf)|Should -BeTrue
  }
  It 'makes repeated durable restore idempotent while owned values still match the original state' {
    $applied=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $first=Restore-RideUserProxyConfigurationSnapshot -RunId $applied.RunId -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $second=Restore-RideUserProxyConfigurationSnapshot -RunId $applied.RunId -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $first.Status|Should -BeExactly Applied
    $second.Status|Should -BeExactly AlreadyRestored
    $second.Changed|Should -BeFalse
    Should -Invoke Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle -Exactly 2
  }
  It 'refuses repeated durable restore after owned proxy state drifts from the completed snapshot' {
    $applied=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $null=Restore-RideUserProxyConfigurationSnapshot -RunId $applied.RunId -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $script:Current.Flags=[uint32]7
    {Restore-RideUserProxyConfigurationSnapshot -RunId $applied.RunId -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false}|Should -Throw '*changed after recorded restoration*'
    Should -Invoke Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle -Exactly 2
  }
  It 'reports a verified restore whose completion marker could not be saved' {
    Mock Save-RideUserProxyLifecycleCompletion -ModuleName RIDE.UserProxyLifecycle {throw 'Injected completion-store failure.'}
    $applied=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $restored=Restore-RideUserProxyConfigurationSnapshot -RunId $applied.RunId -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $restored.Status|Should -BeExactly AppliedCompletionUntracked
    $restored.ReadbackMatched|Should -BeTrue
    $restored.Limitation|Should -Match 'completion record could not be saved'
  }
  It 'refuses a durable snapshot requested for another user before the native setter' {
    $applied=Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    {Restore-RideUserProxyConfigurationSnapshot -RunId $applied.RunId -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-9-8-7-1002 -ExpectedSessionId 1 -Confirm:$false}|Should -Throw '*does not match the intended machine/user/session*'
    Should -Invoke Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle -Exactly 1
  }
  It 'does not call the native setter when durable snapshot creation fails' {
    Mock Save-RideUserProxyLifecycleSnapshot -ModuleName RIDE.UserProxyLifecycle {throw 'Injected snapshot-store failure.'}
    {Set-RideUserProxyConfigurationPatch -Patch (New-ProxyLifecyclePatch) -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false}|Should -Throw '*Injected snapshot-store failure*'
    Should -Invoke Set-RideUserProxyNativeConfiguration -ModuleName RIDE.UserProxyLifecycle -Exactly 0
  }
}
