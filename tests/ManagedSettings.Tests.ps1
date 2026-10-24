<#
.SYNOPSIS
  Validate managed-setting resource identity and exact recovery boundaries.
.DESCRIPTION
  Mocks every Windows API; no developer-machine state is changed.
.EXAMPLE
  Invoke-Pester ./tests/ManagedSettings.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-10: Add task, protocol and scheme failure/recovery checks.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-ManagedSettings.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-ScheduledTasks.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-SystemPreferences.psm1') -Force
  InModuleScope RIDE-SystemPreferences {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
      function script:Get-MpPreference { throw 'Defender preference must be mocked in this test.' }
    }
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
      function script:Set-MpPreference { throw 'Defender preference must be mocked in this test.' }
    }
  }
}
Describe 'Exact scheduled-task target' {
  BeforeEach {
    $script:TaskOperation=@{Kind='ScheduledTask';TaskPath='\Microsoft\Windows\Defrag\';TaskName='ScheduledDefrag'}
    $script:managedFixtureTaskEnabled=$true
    Mock Get-ScheduledTask -ModuleName RIDE-ScheduledTasks { [pscustomobject]@{TaskPath='\Microsoft\Windows\Defrag\';TaskName='ScheduledDefrag';Settings=@{Enabled=$script:managedFixtureTaskEnabled}} }
    Mock Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks {$script:managedFixtureTaskEnabled=$true}
    Mock Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks {$script:managedFixtureTaskEnabled=$false}
  }
  It 'reads without executing or rewriting a task and restores a serialized disabled flag' {
    (Get-RideScheduledTaskState $script:TaskOperation).Enabled | Should -BeTrue
    $snapshot=@{Available=$true;TaskPath=$script:TaskOperation.TaskPath;TaskName=$script:TaskOperation.TaskName;Enabled=$false} | ConvertTo-Json | ConvertFrom-Json
    Restore-RideScheduledTaskState $script:TaskOperation $snapshot
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1 -ParameterFilter {$TaskPath -eq '\Microsoft\Windows\Defrag\' -and $TaskName -eq 'ScheduledDefrag'}
    Should -Invoke Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
  }
  It 'reports absence without creating a replacement' {
    Mock Get-ScheduledTask -ModuleName RIDE-ScheduledTasks { @() }
    (Get-RideScheduledTaskState $script:TaskOperation).Available | Should -BeFalse
    {Set-RideScheduledTaskEnabled $script:TaskOperation $true} | Should -Throw '*unavailable*'
    Should -Invoke Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
  }
  It 'propagates denied inspection rather than pretending the task is absent' {
    Mock Get-ScheduledTask -ModuleName RIDE-ScheduledTasks {throw 'access denied'}
    {Get-RideScheduledTaskState $script:TaskOperation} | Should -Throw '*access denied*'
  }
  It 'rejects wildcard metadata and redirected or untyped recovery before writes' {
    $bad=$script:TaskOperation.Clone();$bad.TaskName='*'
    {Get-RideScheduledTaskState $bad} | Should -Throw '*identity*'
    foreach($snapshot in @(@{Available=$true;TaskPath='\Other\';TaskName='ScheduledDefrag';Enabled=$true},@{Available=$true;TaskPath=$script:TaskOperation.TaskPath;TaskName='ScheduledDefrag';Enabled='false'})) {
      {Restore-RideScheduledTaskState $script:TaskOperation $snapshot} | Should -Throw '*snapshot*'
    }
    Should -Invoke Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
  }
}
Describe 'Focused system preferences' {
  It 'sets only the declared SMB flag and rejects unrelated properties' {
    Mock Get-CimInstance -ModuleName RIDE-SystemPreferences { [pscustomobject]@{Name='srv2'} }
    Mock Get-SmbServerConfiguration -ModuleName RIDE-SystemPreferences { [pscustomobject]@{EnableSMB2Protocol=$true} }
    Mock Set-SmbServerConfiguration -ModuleName RIDE-SystemPreferences {}
    Set-RideSmbProtocolState @{Preference='EnableSMB2Protocol'} $false
    Should -Invoke Set-SmbServerConfiguration -ModuleName RIDE-SystemPreferences -Times 1 -Exactly -ParameterFilter {$EnableSMB2Protocol -eq $false}
    {Set-RideSmbProtocolState @{Preference='EncryptData'} $true} | Should -Throw '*Unsupported*'
  }
  It 'reports an absent SMB1 server driver without trying to install or enable it' {
    Mock Get-CimInstance -ModuleName RIDE-SystemPreferences { @() }
    Mock Get-SmbServerConfiguration -ModuleName RIDE-SystemPreferences { throw 'Unexpected protocol inspection' }
    Mock Set-SmbServerConfiguration -ModuleName RIDE-SystemPreferences {}
    $op=@{Preference='EnableSMB1Protocol'}
    (Get-RideSmbProtocolState $op).Available | Should -BeFalse
    {Set-RideSmbProtocolState $op $true} | Should -Throw '*driver is unavailable*'
    Should -Invoke Get-CimInstance -ModuleName RIDE-SystemPreferences -ParameterFilter {$ClassName -eq 'Win32_SystemDriver' -and $Filter -eq "Name='srv'"}
    Should -Invoke Set-SmbServerConfiguration -ModuleName RIDE-SystemPreferences -Times 0
    Should -Invoke Get-SmbServerConfiguration -ModuleName RIDE-SystemPreferences -Times 0
  }
  It 'propagates Defender policy/tamper failure and rejects malformed recovery' {
    Mock Get-MpPreference -ModuleName RIDE-SystemPreferences { [pscustomobject]@{EnableControlledFolderAccess=0} }
    Mock Set-MpPreference -ModuleName RIDE-SystemPreferences {throw 'tamper protection'}
    {Set-RideDefenderPreferenceState @{Preference='EnableControlledFolderAccess'} 1} | Should -Throw '*tamper protection*'
    {Restore-RideManagedSettingState @{Kind='DefenderPreference'} @{Value='1'}} | Should -Throw '*Invalid*'
    {Restore-RideManagedSettingState @{Kind='SmbProtocol'} @{Value='false'}} | Should -Throw '*Invalid*'
  }
}
Describe 'Existing power-scheme selection' {
  It 'captures native stderr and the exit code without weakening the caller error policy' {
    InModuleScope RIDE-ManagedSettings {
      $script:FixtureNativeHost = (Get-Process -Id $PID).Path
      Mock Join-Path { $script:FixtureNativeHost }
      $ErrorActionPreference = 'Stop'
      foreach ($code in @(0,2)) {
        $result = Invoke-RideSchemeCommand -Arguments @('-NoProfile','-Command',("[Console]::Error.WriteLine('native diagnostic'); exit "+$code))
        $result.ExitCode | Should -Be $code
        $result.Output | Should -Match 'native diagnostic'
        $ErrorActionPreference | Should -Be 'Stop'
      }
    }
  }
  It 'queries unlisted schemes and restores the exact GUID with both native argument tokens' {
    InModuleScope RIDE-ManagedSettings {
      $script:FixtureActive='8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
      $op=@{Kind='PowerScheme';States=@{Balanced='381b4222-f694-41f0-9685-ff5bb260df2e';HighPerformance=$script:FixtureActive}}
      Mock Invoke-RideSchemeCommand {
        switch ($Arguments[0]) {
          '/list' { [pscustomobject]@{ExitCode=0;Output='Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)'} }
          '/getactivescheme' { [pscustomobject]@{ExitCode=0;Output=('Power Scheme GUID: '+$script:FixtureActive)} }
          '/query' { [pscustomobject]@{ExitCode=0;Output=('Power Scheme GUID: '+$Arguments[1])} }
          '/setactive' { $script:FixtureActive=$Arguments[1];[pscustomobject]@{ExitCode=0;Output=''} }
          default { throw 'Unexpected native command' }
        }
      }
      $before=Get-RideManagedSettingState $op
      $before.AvailableSchemes | Should -Contain $op.States.HighPerformance
      Set-RideManagedSettingState $op Balanced
      Restore-RideManagedSettingState $op $before
      $script:FixtureActive | Should -Be $before.Value
      Should -Invoke Invoke-RideSchemeCommand -Times 1 -Exactly -ParameterFilter {$Arguments.Count -eq 2 -and $Arguments[0] -eq '/setactive' -and $Arguments[1] -eq $op.States.HighPerformance}
    }
  }
  It 'ignores localized display names and rejects a missing scheme without duplication' {
    InModuleScope RIDE-ManagedSettings {
      $op=@{Kind='PowerScheme';States=@{Balanced='381b4222-f694-41f0-9685-ff5bb260df2e';Missing='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}}
      Mock Invoke-RideSchemeCommand {[pscustomobject]@{ExitCode=0;Output='Strømstyring: 381b4222-f694-41f0-9685-ff5bb260df2e (Balanceret)'}}
      (Get-RideManagedSettingState $op).Value | Should -Be $op.States.Balanced
      {Set-RideManagedSettingState $op Missing} | Should -Throw '*unavailable*'
      Should -Invoke Invoke-RideSchemeCommand -Times 0 -ParameterFilter {$Arguments[0] -eq '/setactive'}
      Should -Invoke Invoke-RideSchemeCommand -Times 0 -ParameterFilter {$Arguments[0] -eq '/duplicatescheme'}
    }
  }
  It 'rejects a successful native exit when the active GUID did not change' {
    InModuleScope RIDE-ManagedSettings {
      $op=@{Kind='PowerScheme';States=@{Balanced='381b4222-f694-41f0-9685-ff5bb260df2e'}}
      Mock Invoke-RideSchemeCommand {
        if($Arguments[0] -eq '/setactive'){[pscustomobject]@{ExitCode=0;Output=''}}
        elseif($Arguments[0] -eq '/query'){[pscustomobject]@{ExitCode=0;Output=$Arguments[1]}}
        else{[pscustomobject]@{ExitCode=0;Output='8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'}}
      }
      {Set-RideManagedSettingState $op Balanced} | Should -Throw '*did not activate*'
    }
  }
}
