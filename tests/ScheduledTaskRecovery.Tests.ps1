<#
.SYNOPSIS
  Verify scheduled-task observations and transitions with inert provider mocks.
.DESCRIPTION
  Exercises missing/invalid enablement, ignored writes and exact recovery without
  creating, enabling, disabling or executing a real Windows task.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-ScheduledTasks.psm1') -Force
}
Describe 'Scheduled-task enablement verification' {
  BeforeEach {
    $operation=@{TaskPath='\Microsoft\Windows\Defrag\';TaskName='ScheduledDefrag'}
    $script:recoveryFixtureEnabled=$true
    Mock Get-ScheduledTask -ModuleName RIDE-ScheduledTasks {
      [pscustomobject]@{TaskPath='\Microsoft\Windows\Defrag\';TaskName='ScheduledDefrag';Settings=@{Enabled=$script:recoveryFixtureEnabled}}
    }
    Mock Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks {$script:recoveryFixtureEnabled=$true}
    Mock Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks {$script:recoveryFixtureEnabled=$false}
    Mock Start-ScheduledTask -ModuleName RIDE-ScheduledTasks {throw 'Unexpected task execution'}
    Mock Stop-ScheduledTask -ModuleName RIDE-ScheduledTasks {throw 'Unexpected task stop'}
    Mock Register-ScheduledTask -ModuleName RIDE-ScheduledTasks {throw 'Unexpected registration'}
    Mock Unregister-ScheduledTask -ModuleName RIDE-ScheduledTasks {throw 'Unexpected deletion'}
  }
  AfterEach {
    foreach($name in @('Start-ScheduledTask','Stop-ScheduledTask','Register-ScheduledTask','Unregister-ScheduledTask')){
      Should -Invoke $name -ModuleName RIDE-ScheduledTasks -Exactly -Times 0
    }
  }
  It 'refuses a missing enabled flag rather than capturing false' {
    Mock Get-ScheduledTask -ModuleName RIDE-ScheduledTasks {[pscustomobject]@{TaskPath='\Microsoft\Windows\Defrag\';TaskName='ScheduledDefrag';Settings=@{}}}
    {Get-RideScheduledTaskState $operation}|Should -Throw '*Boolean*'
  }
  It 'reports a successful provider call that did not change enablement' {
    Mock Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks {}
    {Set-RideScheduledTaskEnabled $operation $false}|Should -Throw '*verification*'
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1
  }
  It 'refuses non-Boolean provider enablement <Label> before writes' -ForEach @(
    @{Label='string false';Value='false'},@{Label='integer zero';Value=0},@{Label='null';Value=$null}
  ) {
    $script:recoveryFixtureEnabled=$Value
    {Set-RideScheduledTaskEnabled $operation $false}|Should -Throw '*Boolean*'
    Should -Invoke Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
  }
  It 'verifies enablement writes as well as disablement' {
    $script:recoveryFixtureEnabled=$false
    Mock Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks {}
    {Set-RideScheduledTaskEnabled $operation $true}|Should -Throw '*verification*'
    Should -Invoke Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1
  }
  It 'leaves an already <State> task unchanged' -ForEach @(@{State='enabled';Value=$true},@{State='disabled';Value=$false}) {
    $script:recoveryFixtureEnabled=$Value
    Set-RideScheduledTaskEnabled $operation $Value
    Should -Invoke Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
    Should -Invoke Get-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1
  }
  It 'round-trips a serialized enablement snapshot and verifies both changes' {
    $snapshot=Get-RideScheduledTaskState $operation|ConvertTo-Json|ConvertFrom-Json
    Set-RideScheduledTaskEnabled $operation $false
    (Get-RideScheduledTaskState $operation).Enabled|Should -BeFalse
    Restore-RideScheduledTaskState $operation $snapshot
    (Get-RideScheduledTaskState $operation).Enabled|Should -BeTrue
    Should -Invoke Enable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1
  }
  It 'reports disappearance after a write without recreating the task' {
    Mock Get-ScheduledTask -ModuleName RIDE-ScheduledTasks {
      if(-not $script:recoveryFixtureEnabled){return @()}
      [pscustomobject]@{TaskPath='\Microsoft\Windows\Defrag\';TaskName='ScheduledDefrag';Settings=@{Enabled=$true}}
    }
    {Set-RideScheduledTaskEnabled $operation $false}|Should -Throw '*verification*'
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1
  }
  It 'propagates denied verification after a write without retrying it' {
    Mock Get-ScheduledTask -ModuleName RIDE-ScheduledTasks {
      if(-not $script:recoveryFixtureEnabled){throw 'readback access denied'}
      [pscustomobject]@{TaskPath='\Microsoft\Windows\Defrag\';TaskName='ScheduledDefrag';Settings=@{Enabled=$true}}
    }
    {Set-RideScheduledTaskEnabled $operation $false}|Should -Throw '*readback access denied*'
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1
  }
  It 'refuses a different task identity returned during verification' {
    Mock Get-ScheduledTask -ModuleName RIDE-ScheduledTasks {
      [pscustomobject]@{TaskPath='\Microsoft\Windows\Defrag\';TaskName=$(if($script:recoveryFixtureEnabled){'ScheduledDefrag'}else{'OtherTask'});Settings=@{Enabled=$script:recoveryFixtureEnabled}}
    }
    {Set-RideScheduledTaskEnabled $operation $false}|Should -Throw '*exactly one declared*'
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Exactly -Times 1
  }
  It 'refuses invalid snapshot availability <Label> before any inspection or write' -ForEach @(
    @{Label='string true';Value='true'},@{Label='integer one';Value=1},@{Label='false';Value=$false},@{Label='null';Value=$null}
  ) {
    $snapshot=@{Available=$Value;TaskPath=$operation.TaskPath;TaskName=$operation.TaskName;Enabled=$false}
    {Restore-RideScheduledTaskState $operation $snapshot}|Should -Throw '*snapshot*'
    Should -Invoke Get-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
    Should -Invoke Disable-ScheduledTask -ModuleName RIDE-ScheduledTasks -Times 0
  }
}
