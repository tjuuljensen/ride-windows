<#
.SYNOPSIS
  Verify the host watchdog using inert child processes and isolated result files.
.DESCRIPTION
  Exercises normal completion, preparation/recovery hangs, terminal evidence and
  recovery blocking. No Hyper-V, AutomatedLab, guest, installer or credential use.
.EXAMPLE
  Invoke-Pester .\tests\AutomationWatchdog.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Windows PowerShell 5.1/Pester 5.7.1. Version: 0.1.1.
  Changelog: 0.1.1: Exercise concurrent progress updates and bounded read contention.
  0.1.0: Cover the independent host-preparation watchdog.
#>
BeforeDiscovery { Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.TestAutomation.psm1') -Force }

Describe 'Concurrent host progress' {
  InModuleScope RIDE.TestAutomation {
    BeforeEach {
      $script:progressDirectory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $null=New-Item -ItemType Directory $script:progressDirectory
      $script:progressId=[guid]::NewGuid().ToString('N')
      $script:progressPath=Join-Path $script:progressDirectory 'host-phase.json'
      Write-RideAutomationHostProgress $script:progressDirectory $script:progressId Preparation 'Initial'
    }

    It 'reads alongside an existing writable handle without requesting write access' {
      $held=[IO.File]::Open($script:progressPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
      try{(Read-RideAutomationHostProgress $script:progressPath).RunId|Should -Be $script:progressId}
      finally{$held.Dispose()}
    }

    It 'bounds a persistent exclusive lock and closes handles after failure' {
      $held=[IO.File]::Open($script:progressPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
      $elapsed=[Diagnostics.Stopwatch]::StartNew()
      try{{Read-RideAutomationHostProgress $script:progressPath}|Should -Throw}
      finally{$held.Dispose()}
      $elapsed.Elapsed.TotalSeconds|Should -BeLessThan 3
      (Read-RideAutomationHostProgress $script:progressPath).RunId|Should -Be $script:progressId
    }

    It 'does not suppress malformed progress as a transient sharing error' {
      '{invalid'|Set-Content -LiteralPath $script:progressPath
      {Read-RideAutomationHostProgress $script:progressPath}|Should -Throw
    }

    It 'bounds coordination-lock contention and reuses the retained lock file' {
      $held=Enter-RideAutomationHostProgressLock $script:progressPath
      $elapsed=[Diagnostics.Stopwatch]::StartNew()
      try{{Read-RideAutomationHostProgress $script:progressPath}|Should -Throw}
      finally{$held.Dispose()}
      $elapsed.Elapsed.TotalSeconds|Should -BeLessThan 3
      (Read-RideAutomationHostProgress $script:progressPath).RunId|Should -Be $script:progressId
    }

    It 'reads complete snapshots during repeated real child-process updates' {
      $fixture=Join-Path $script:progressDirectory 'writer.ps1'
      @'
param($ModulePath,$Directory,$RunId)
$ErrorActionPreference='Stop'
Import-Module $ModulePath -Force
for($i=1;$i -le 150;$i++){
  Write-RideAutomationHostProgress $Directory $RunId Preparation "Stage $i"
}
'@|Set-Content -LiteralPath $fixture -Encoding UTF8
      $modulePath=(Get-Module RIDE.TestAutomation).Path
      $process=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$fixture`" -ModulePath `"$modulePath`" -Directory `"$script:progressDirectory`" -RunId $script:progressId" -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $script:progressDirectory 'writer.log') -RedirectStandardError (Join-Path $script:progressDirectory 'writer-errors.log')
      $null=$process.Handle
      $elapsed=[Diagnostics.Stopwatch]::StartNew();$reads=0
      try{
        while(-not $process.HasExited -and $elapsed.Elapsed.TotalSeconds -lt 30){
          $snapshot=Read-RideAutomationHostProgress $script:progressPath
          $snapshot.RunId|Should -Be $script:progressId
          $snapshot.Phase|Should -Be 'Preparation'
          $reads++
        }
        $process.HasExited|Should -BeTrue
        $process.Refresh()
        $process.ExitCode|Should -Be 0 -Because (Get-Content (Join-Path $script:progressDirectory 'writer-errors.log') -Raw)
        $reads|Should -BeGreaterThan 1
        (Read-RideAutomationHostProgress $script:progressPath).Stage|Should -Be 'Stage 150'
      }finally{
        if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(5000)}
        $process.Dispose()
      }
    }
  }
}

Describe 'Host preparation watchdog' {
  InModuleScope RIDE.TestAutomation {
    BeforeAll {
      $script:actualWait=${function:Wait-RideAutomationSupervisedProcess}
      $script:startProcessCommand=Get-Command Start-Process -CommandType Cmdlet
      $script:sourceModulePath=(Get-Module RIDE.TestAutomation).Path
    }
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $null=New-Item -ItemType Directory -Path (Join-Path $script:root 'runtime') -Force
      $script:id=[guid]::NewGuid().ToString('N')
      $script:request=[pscustomobject]@{RunId=$script:id;Source='Local';UnitOnly=$true;IntegrationSuite='Full';TimeoutMinutes=1;SubmittedAtUtc=[datetime]::UtcNow.ToString('o')}
      $script:directory=Join-Path $script:root "results\$script:id"
      $script:childBody='Start-Sleep -Seconds 60'
      $script:childProcess=$null
      Mock Start-Process {
        $fixture=Join-Path $script:root 'inert-child.ps1'
        ('param($Directory,$RunId,$ModulePath)' + [Environment]::NewLine + '$ErrorActionPreference="Stop"' + [Environment]::NewLine + $script:childBody) | Set-Content -LiteralPath $fixture -Encoding UTF8
        $script:childProcess=& $script:startProcessCommand -FilePath $FilePath -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$fixture`" -Directory `"$script:directory`" -RunId $script:id -ModulePath `"$script:sourceModulePath`"" -WindowStyle Hidden -PassThru -RedirectStandardOutput $RedirectStandardOutput -RedirectStandardError $RedirectStandardError
        $script:childProcess
      } -ParameterFilter { $FilePath -like '*powershell.exe' }
      Mock Wait-RideAutomationSupervisedProcess {
        & $script:actualWait -Process $Process -ResultDirectory $ResultDirectory -RunId $RunId -DeadlineUtc $DeadlineUtc -PreparationSeconds 15 -RecoverySeconds 0.5
      }
    }
    AfterEach {
      if($script:childProcess -and -not $script:childProcess.HasExited){Stop-RideAutomationProcess $script:childProcess}
    }

    It 'terminates an inert preparation hang and writes a terminal timeout without a recovery block' {
      $elapsed=[Diagnostics.Stopwatch]::StartNew()
      $result=Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root
      $elapsed.Stop()
      $result.Status | Should -Be 'TimedOut'
      $result.LastHostPhase | Should -Be 'Preparation'
      $result.RecoveryRequired | Should -BeFalse
      $script:childProcess.HasExited | Should -BeTrue
      $elapsed.Elapsed.TotalSeconds | Should -BeLessThan 40
      (Test-Path (Join-Path $script:root 'runtime/blocked.json')) | Should -BeFalse
      (Get-Content (Join-Path $script:directory 'result.json') -Raw|ConvertFrom-Json).RunId | Should -Be $script:id
    }

    It 'retains a normal correlated success without fabricating a supervisor failure' {
      $script:childBody=@'
@{RunId=$RunId;IntegrationSuite='Full';Status='Passed'}|ConvertTo-Json|Set-Content (Join-Path $Directory 'result.json')
'@
      (Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root).Status | Should -Be 'Passed'
      (Test-Path (Join-Path $script:root 'runtime/blocked.json')) | Should -BeFalse
    }

    It 'terminates an inert descendant as well as its request parent' {
      $script:childBody=@'
$child=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 60"' -WindowStyle Hidden -PassThru
$child.Id|Set-Content (Join-Path $Directory 'descendant.pid')
Start-Sleep -Seconds 60
'@
      $result=Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root
      $result.Status|Should -Be 'TimedOut'
      $result.RecoveryRequired|Should -BeFalse
      $descendantId=[int](Get-Content (Join-Path $script:directory 'descendant.pid'))
      Get-Process -Id $descendantId -ErrorAction SilentlyContinue|Should -BeNullOrEmpty
    }

    It 'applies the execution deadline without restarting a preparation budget' {
      $null=New-Item -ItemType Directory $script:directory -Force
      Write-RideAutomationHostProgress $script:directory $script:id Execution 'Synthetic execution' $true
      $fake=[pscustomobject]@{}
      $fake|Add-Member ScriptMethod WaitForExit {param($Milliseconds);$false}
      $wait=& $script:actualWait $fake $script:directory $script:id ([datetime]::UtcNow.AddSeconds(-16))
      $wait.TimedOut|Should -BeTrue
      $wait.State.Phase|Should -Be 'Execution'
    }

    It 'retains a correlated child failure as a terminal result' {
      $script:childBody=@'
@{RunId=$RunId;IntegrationSuite='Full';Status='Failed';Error='synthetic failure'}|ConvertTo-Json|Set-Content (Join-Path $Directory 'result.json')
exit 1
'@
      $result=Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root
      $result.Status | Should -Be 'Failed'
      $result.Error | Should -Be 'synthetic failure'
    }

    It 'bounds a recovery hang and blocks further work after possible VM changes' {
      $script:childBody=@'
Import-Module $ModulePath -Force
Write-RideAutomationHostProgress $Directory $RunId Recovery 'Synthetic stuck recovery' $true
Start-Sleep -Seconds 60
'@
      $result=Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root
      if($result.Status -ne 'TimedOut'){throw ((Get-Content (Join-Path $script:directory 'host-worker-errors.log') -Raw) + ($result|ConvertTo-Json))}
      $result.Status | Should -Be 'TimedOut'
      $result.LastHostPhase | Should -Be 'Recovery'
      $result.RecoveryRequired | Should -BeTrue
      (Get-Content (Join-Path $script:root 'runtime/blocked.json') -Raw|ConvertFrom-Json).RunId | Should -Be $script:id
      $script:childProcess.HasExited | Should -BeTrue
    }

    It 'reports child exit without a result and does not assume VM recovery' {
      $script:childBody='exit 7'
      $result=Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root
      $result.Status | Should -Be 'Failed'
      $result.Error | Should -Match 'without a terminal result'
      $result.RecoveryRequired | Should -BeFalse
    }

    It 'blocks after process-tree termination cannot be confirmed' {
      Mock Stop-RideAutomationProcess {throw 'synthetic stop failure'}
      try {
        $result=Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root
        $result.RecoveryRequired | Should -BeTrue
        $result.CleanupError | Should -Be 'synthetic stop failure'
        Test-Path (Join-Path $script:root 'runtime/blocked.json') | Should -BeTrue
      } finally {if($script:childProcess -and -not $script:childProcess.HasExited){$script:childProcess.Kill();$null=$script:childProcess.WaitForExit(5000)}}
    }

    It 'expires an old queued request without launching preparation' {
      $script:request.SubmittedAtUtc=[datetime]::UtcNow.AddMinutes(-2).ToString('o')
      (Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root).Error | Should -Match 'expired'
      Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'does not overwrite an existing terminal result on duplicate dispatch' {
      $null=New-Item -ItemType Directory $script:directory -Force
      $path=Join-Path $script:directory 'result.json'
      'retained evidence'|Set-Content $path
      {Invoke-RideAutomationSupervisedRequest ([pscustomobject]@{}) $script:request $script:root}|Should -Throw '*already exists*'
      (Get-Content $path -Raw).Trim()|Should -Be 'retained evidence'
    }

    It 'keeps phase timing and the VM mutation marker sticky and refuses backward progress' {
      $null=New-Item -ItemType Directory $script:directory -Force
      Write-RideAutomationHostProgress $script:directory $script:id Preparation 'Check host'
      $first=Get-Content (Join-Path $script:directory 'host-phase.json') -Raw|ConvertFrom-Json
      Write-RideAutomationHostProgress $script:directory $script:id Preparation 'Reset VM' $true
      $second=Get-Content (Join-Path $script:directory 'host-phase.json') -Raw|ConvertFrom-Json
      $second.PhaseStartedAtUtc | Should -Be $first.PhaseStartedAtUtc
      Write-RideAutomationHostProgress $script:directory $script:id Recovery 'Cleanup'
      (Get-Content (Join-Path $script:directory 'host-phase.json') -Raw|ConvertFrom-Json).VmMayHaveChanged|Should -BeTrue
      {Write-RideAutomationHostProgress $script:directory $script:id Preparation 'Again'}|Should -Throw '*backwards*'
    }
  }
}
