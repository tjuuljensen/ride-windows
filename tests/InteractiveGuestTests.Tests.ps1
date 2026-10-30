<#
.SYNOPSIS
Verify HashCheck interactive coordination without registering tasks or installing software.
.DESCRIPTION
Mocks guest context, desktop sessions, task APIs and suite execution. Exercises
identity checks, duplicate prevention, failure propagation and task cleanup.
.EXAMPLE
Invoke-Pester .\tests\InteractiveGuestTests.Tests.ps1
.NOTES
Windows PowerShell 5.1, Pester 5.x. Repository fixture; no independent version.
#>
BeforeDiscovery { Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.InteractiveGuestTests.psm1') -Force }

Describe 'Interactive suite process boundary' {
  InModuleScope RIDE.InteractiveGuestTests {
    BeforeEach {
      $source = Join-Path $TestDrive 'source with spaces'
      $results = Join-Path $TestDrive 'results with spaces'
      $null = New-Item -ItemType Directory -Path (Join-Path $source 'tests/integration') -Force
      $null = New-Item -ItemType Directory -Path $results -Force
      $runner = Join-Path $source 'tests/integration/Invoke-RideGuestTests.ps1'
    }
    It 'runs outside module scope while preserving the user and desktop session' {
      @'
param($GuestPath,$ResultsPath,$ResultRunId,[switch]$Integration,$IntegrationSuite)
@{Pid=$PID;ModuleScope=[bool]$ExecutionContext.SessionState.Module;SessionId=(Get-Process -Id $PID).SessionId;Sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;GuestPath=$GuestPath;RunId=$ResultRunId;Integration=[bool]$Integration;Suite=$IntegrationSuite}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $ResultsPath 'boundary.json')
'@ | Set-Content -LiteralPath $runner
      Invoke-RideInteractiveGuestSuite $source $results 'boundary-probe'
      $boundary=Get-Content -LiteralPath (Join-Path $results 'boundary.json') -Raw|ConvertFrom-Json
      $boundary.Pid | Should -Not -Be $PID
      $boundary.ModuleScope | Should -BeFalse
      $boundary.SessionId | Should -Be (Get-Process -Id $PID).SessionId
      $boundary.Sid | Should -Be ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
      $boundary.GuestPath | Should -Be $source
      $boundary.RunId | Should -Be 'boundary-probe'
      $boundary.Integration | Should -BeTrue
      $boundary.Suite | Should -Be ApplicationsBatch11
    }
    It 'propagates a nonzero suite process exit' {
      'exit 7' | Set-Content -LiteralPath $runner
      { Invoke-RideInteractiveGuestSuite $source $results 'failure-probe' } | Should -Throw '*process exited 7*'
    }
  }
}

Describe 'HashCheck interactive guest acceptance' {
  InModuleScope RIDE.InteractiveGuestTests {
    BeforeAll {
      $script:OriginalMarker = $env:RIDE_TEST_GUEST
      function New-ScheduledTaskAction { param($Execute,$Argument,$WorkingDirectory) }
      function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) }
      function New-ScheduledTaskSettingsSet { param($ExecutionTimeLimit,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries,$MultipleInstances) }
      function Register-ScheduledTask { param($TaskName,$TaskPath,$Action,$Principal,$Settings) }
      function Get-ScheduledTask { param($TaskName,$TaskPath) }
      function Get-ScheduledTaskInfo { param($TaskName,$TaskPath) }
      function Start-ScheduledTask { param($TaskName,$TaskPath) }
      function Stop-ScheduledTask { param($TaskName,$TaskPath) }
      function Unregister-ScheduledTask { param($TaskName,$TaskPath,[switch]$Confirm) }
      function Export-ScheduledTask { param($TaskName,$TaskPath) }
    }
    AfterAll { $env:RIDE_TEST_GUEST = $script:OriginalMarker }
    BeforeEach {
      $env:RIDE_TEST_GUEST = '1'
      $script:RunId = [guid]::NewGuid().ToString('N')
      $script:Results = Join-Path $TestDrive $script:RunId
      $script:Guest = Join-Path $TestDrive 'source'
      $null = New-Item -ItemType Directory -Path (Join-Path $script:Guest 'tests/integration') -Force
      Set-Content -LiteralPath (Join-Path $script:Guest 'tests/integration/Invoke-RideInteractiveGuestTests.ps1') -Value '# fixture only'
      $script:Context = [pscustomobject]@{Computer='RIDE-Test';SID='S-1-5-21-1-2-3-1000';User='RIDE-Test\admin';SessionId=0;UserInteractive=$false;Elevated=$true}
      $script:Registered=$false
      $script:TaskState='Ready'
      Mock Assert-RideInteractiveGuestPaths {}
      Mock Get-RideInteractiveGuestContext {$script:Context}
      Mock Get-RideInteractiveGuestDesktop {1}
      Mock New-ScheduledTaskAction {[pscustomobject]@{Arguments=$Argument}}
      Mock New-ScheduledTaskPrincipal {[pscustomobject]@{UserId=$UserId;LogonType=$LogonType;RunLevel=$RunLevel}}
      Mock New-ScheduledTaskSettingsSet {[pscustomobject]@{Limit=$ExecutionTimeLimit}}
      Mock Register-ScheduledTask {$script:Registered=$true}
      Mock Get-ScheduledTask {
        if($TaskName -or $script:Registered){[pscustomobject]@{TaskName=('RIDE-InteractiveGuest-'+$script:RunId);State=$script:TaskState;Principal=[pscustomobject]@{LogonType='Interactive';RunLevel='Highest'}}}
      }
      Mock Get-ScheduledTaskInfo {[pscustomobject]@{LastRunTime=[datetime]::Now;LastTaskResult=0}}
      Mock Export-ScheduledTask {'<Task />'}
      Mock Start-ScheduledTask {
        @{RunId=$script:RunId;Status='Passed'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $script:Results 'interactive-worker.json')
      }
      Mock Stop-ScheduledTask {$script:TaskState='Ready'}
      Mock Unregister-ScheduledTask {$script:Registered=$false}
      Mock Start-Sleep {}
      Mock Invoke-RideInteractiveGuestSuite {
        @{RunId=$RunId;Status='Passed';ValidationPassed=$true;IntegrationPassed=$true;IntegrationSuite='ApplicationsBatch11';Error=$null;StateCollectionError=$null}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $ResultsPath 'summary.json')
      }
    }
    It 'dispatches once as the exact interactive administrator and removes its task' {
      $result=Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'
      $result.Status | Should -Be Passed
      $result.TaskRemoved | Should -BeTrue
      Should -Invoke New-ScheduledTaskPrincipal -Exactly 1 -ParameterFilter {$UserId -eq 'S-1-5-21-1-2-3-1000' -and $LogonType -eq 'Interactive' -and $RunLevel -eq 'Highest'}
      Should -Invoke Start-ScheduledTask -Exactly 1
      Should -Invoke Unregister-ScheduledTask -Exactly 1
    }
    It 'rejects missing VM marker before registering a task' {
      $env:RIDE_TEST_GUEST=$null
      {Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'} | Should -Throw '*disposable-VM*'
      Should -Invoke Register-ScheduledTask -Times 0
    }
    It 'rejects unavailable or ambiguous desktop without falling back' {
      Mock Get-RideInteractiveGuestDesktop {throw 'No unique desktop'}
      {Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'} | Should -Throw '*unique desktop*'
      Should -Invoke Register-ScheduledTask -Times 0
    }
    It 'does not create results or tasks for preview' {
      Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test' -WhatIf
      Test-Path -LiteralPath $script:Results | Should -BeFalse
      Should -Invoke Register-ScheduledTask -Times 0
    }
    It 'refuses duplicate dispatch without overwriting the first task record' {
      $null=Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'
      $path=Join-Path $script:Results 'interactive-task.json'
      $before=(Get-FileHash $path).Hash
      {Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'} | Should -Throw
      (Get-FileHash $path).Hash | Should -Be $before
      Should -Invoke Start-ScheduledTask -Exactly 1
    }
    It 'propagates worker failure and still removes the temporary task' {
      Mock Get-ScheduledTaskInfo {[pscustomobject]@{LastRunTime=[datetime]::Now;LastTaskResult=1}}
      {Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'} | Should -Throw '*exited 1*'
      Should -Invoke Unregister-ScheduledTask -Exactly 1
      (Get-Content (Join-Path $script:Results 'interactive-task.json') -Raw|ConvertFrom-Json).TaskRemoved | Should -BeTrue
    }
    It 'reports cleanup failure instead of claiming success' {
      Mock Unregister-ScheduledTask {throw 'cleanup refused'}
      {Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'} | Should -Throw '*cleanup failed*'
      $record=Get-Content (Join-Path $script:Results 'interactive-task.json') -Raw|ConvertFrom-Json
      $record.TaskRemoved | Should -BeFalse
      $record.CleanupError | Should -Match 'cleanup refused'
    }
    It 'stops and removes a task that exceeds its deadline' {
      $script:TaskState='Running'
      $script:ClockReads=0
      Mock Get-Date {
        $script:ClockReads++
        if($script:ClockReads -eq 1){[datetime]'2026-10-29T10:00:00'}else{[datetime]'2026-10-29T10:32:00'}
      }
      {Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'} | Should -Throw '*deadline*'
      Should -Invoke Stop-ScheduledTask -Exactly 1
      Should -Invoke Unregister-ScheduledTask -Exactly 1
    }
    It 'rejects a successful task without correlated successful worker evidence' {
      Mock Start-ScheduledTask {@{RunId='wrong';Status='Passed'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $script:Results 'interactive-worker.json')}
      {Invoke-RideInteractiveGuestTests $script:Guest $script:Results $script:RunId 'RIDE-Test'} | Should -Throw '*correlated success*'
      Should -Invoke Unregister-ScheduledTask -Exactly 1
    }
    Context 'scheduled worker' {
      BeforeEach {
        $null=New-Item -ItemType Directory -Path $script:Results
        $script:Context.SessionId=1
        $script:Context.UserInteractive=$true
        @{RunId=$script:RunId;GuestPath=$script:Guest;ExpectedComputerName='RIDE-Test';ExpectedUserSid=$script:Context.SID;ExpectedSessionId=1}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $script:Results 'interactive-request.json')
      }
      It 'runs the focused suite once and preserves evidence on duplicate execution' {
        Invoke-RideInteractiveGuestWorker $script:Guest $script:Results $script:RunId 'RIDE-Test' $script:Context.SID 1
        $path=Join-Path $script:Results 'interactive-worker.json'
        $before=(Get-FileHash $path).Hash
        {Invoke-RideInteractiveGuestWorker $script:Guest $script:Results $script:RunId 'RIDE-Test' $script:Context.SID 1}|Should -Throw
        (Get-FileHash $path).Hash|Should -Be $before
        Should -Invoke Invoke-RideInteractiveGuestSuite -Exactly 1
      }
      It 'refuses the wrong desktop before running the suite' {
        {Invoke-RideInteractiveGuestWorker $script:Guest $script:Results $script:RunId 'RIDE-Test' $script:Context.SID 2}|Should -Throw '*identity, session*'
        Should -Invoke Invoke-RideInteractiveGuestSuite -Times 0
      }
      It 'refuses another user even in the expected desktop session' {
        {Invoke-RideInteractiveGuestWorker $script:Guest $script:Results $script:RunId 'RIDE-Test' 'S-1-5-21-9-9-9-1000' 1}|Should -Throw '*identity, session*'
        Should -Invoke Invoke-RideInteractiveGuestSuite -Times 0
      }
      It 'refuses Session 0 even with the correct SID and elevation' {
        $script:Context.SessionId=0
        $script:Context.UserInteractive=$false
        {Invoke-RideInteractiveGuestWorker $script:Guest $script:Results $script:RunId 'RIDE-Test' $script:Context.SID 0}|Should -Throw '*identity, session*'
        Should -Invoke Invoke-RideInteractiveGuestSuite -Times 0
      }
      It 'propagates a failed suite summary and retains worker error evidence' {
        Mock Invoke-RideInteractiveGuestSuite {@{RunId=$RunId;Status='Failed'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $ResultsPath 'summary.json')}
        {Invoke-RideInteractiveGuestWorker $script:Guest $script:Results $script:RunId 'RIDE-Test' $script:Context.SID 1}|Should -Throw '*suite failed*'
        (Get-Content (Join-Path $script:Results 'interactive-worker.json') -Raw|ConvertFrom-Json).Status | Should -Be Failed
      }
    }
  }
}
