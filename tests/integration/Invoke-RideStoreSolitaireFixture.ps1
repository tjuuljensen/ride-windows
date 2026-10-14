<#
.SYNOPSIS
  Coordinate one private Solitaire lifecycle fixture on the disposable desktop.
.DESCRIPTION
  Uses a source-bound Interactive/Limited task for the expected real desktop user.
  Verifies correlated actor evidence, retains failures and cleans only its owned task.
  The host independently owns the separate pinned VM and checkpoint recovery.
.PARAMETER RequestPath
  Exact staged Solitaire-only request; no other app/group/action selection.
.PARAMETER EvidencePath
  Correlated guest evidence file path.
.EXAMPLE
  Get-Help .\Invoke-RideStoreSolitaireFixture.ps1 -Full
.INPUTS
  None. Explicit disposable fixture parameters only.
.OUTPUTS
  String. Completion; bounded JSON and console evidence retained.
.NOTES
  Compatibility: Windows PowerShell 5.1 on the disposable Windows 11 guest.
  Prerequisites: Elevated guest coordinator, expected signed-in desktop, private source.
  File/environment inputs: Request JSON and correlated disposable RIDE markers.
  Recovery: Owned transient task cleanup; app registration and checkpoint are separate.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add Solitaire-only bounded desktop lifecycle coordination.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RequestPath,[Parameter(Mandatory)][string]$EvidencePath)
$ErrorActionPreference='Stop'
if($env:RIDE_TEST_GUEST -ne '1' -or $env:RIDE_INTEGRATION_VM -ne '1' -or $env:RIDE_TEST_RUN_ID -notmatch '^[0-9a-f]{32}$'){throw 'Correlated disposable coordinator required.'}
if(-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated disposable coordinator required.'}
$computer=Get-CimInstance Win32_ComputerSystem
if($computer.Manufacturer -ne 'Microsoft Corporation' -or $computer.Model -ne 'Virtual Machine'){throw 'Disposable Hyper-V guest required.'}
if([IO.Path]::GetFullPath($RequestPath) -cne [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'store-solitaire.fixture.json'))){throw 'Exact isolated request path required.'}
$sourceRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $PSScriptRoot 'RIDE.StoreSolitaireFixtureData.psm1') -Force
$fixture=Read-RideSolitaireFixtureRequest -Path $RequestPath -RunId $env:RIDE_TEST_RUN_ID
$report=[ordered]@{SchemaVersion=1;RunId=$fixture.RunId;Target='Windows 11';Scenario='StoreSolitaireLifecycle';Status='Failed';RequestSHA256=(Get-FileHash -LiteralPath $RequestPath).Hash;UserSid=$fixture.ExpectedUserSid;LifecyclePassed=$false;RegistrationRecoveryPassed=$false;FullHandoffPassed=$false;AlternateAdministratorPassed=$false;ExactRecovery=$false;WindowsAppMutation=$null;RecoveryMode='OwnedTransientTaskCleanup';TaskCleanupVerified=$false;Error=$null;CleanupError=$null}
  $taskName='RIDE-Test-StoreSolitaire-'+$fixture.RunId;$registered=$false;$arguments=$null
  $executable=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
  try{
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{if($identity.User.Value -cne $fixture.ExpectedUserSid -or $identity.Name -ine $fixture.ExpectedUserName){throw 'Desktop coordinator guest identity changed.'}}finally{$identity.Dispose()}
    if(Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue){throw 'Owned fixture task already exists; preserve it.'}
    $shells=@(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction Stop)
    if($shells.Count -gt 32){throw 'Desktop shell candidates exceed their bound.'}
    $matches=@(foreach($shell in $shells){
      $owner=Invoke-CimMethod -InputObject $shell -MethodName GetOwnerSid -ErrorAction Stop
      if($owner.ReturnValue -ne 0 -or -not $owner.Sid){throw 'Desktop shell owner unavailable.'}
      if($owner.Sid -ceq $fixture.ExpectedUserSid -and $shell.SessionId -gt 0){$shell}
    })
    if($matches.Count -ne 1){throw 'A unique existing expected-user shell is required; sign-in/session preparation remains pending.'}
    $store=Import-Module (Join-Path $sourceRoot 'modules/RIDE.StoreApps.psm1') -Force -PassThru
    $actorScript=Join-Path $PSScriptRoot 'Invoke-RideStoreSolitaireActor.ps1'
    $sourceHash=& $store {Get-RideStoreHandoffSourceHash}
    $actorHash=(Get-FileHash -LiteralPath $actorScript).Hash
    $actorPath=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('RIDE/TestFixtures/StoreSolitaire/'+$fixture.RunId+'/actor.json')
    $null=& $store {param($p,$r) Assert-RideStorePath -Path $p -Root $r} $actorPath ([Environment]::GetFolderPath('LocalApplicationData'))
    if(Test-Path -LiteralPath (Split-Path -Parent $actorPath)){throw 'Actor evidence already exists; preserve it.'}
    $consolePath=Join-Path (Split-Path -Parent $actorPath) 'actor-console.log'
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $actorPath) -Force
    $request=[ordered]@{RunId=$fixture.RunId;RequestPath=$RequestPath;RequestSHA256=$report.RequestSHA256;ActorScript=$actorScript;ActorSHA256=$actorHash;SourceHash=$sourceHash;SessionId=[int]$matches[0].SessionId;ShellProcessId=[int]$matches[0].ProcessId;ConsolePath=$consolePath}
    $data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Compress)))
    $bootstrap=@'
$ErrorActionPreference='Stop'
$r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__'))|ConvertFrom-Json
$transcribing=$false
try {
 Start-Transcript -LiteralPath $r.ConsolePath -NoClobber -ErrorAction Stop|Out-Null;$transcribing=$true
 $env:RIDE_TEST_GUEST='1';$env:RIDE_INTEGRATION_VM='1';$env:RIDE_TEST_RUN_ID=$r.RunId
 if((Get-FileHash -LiteralPath $r.ActorScript).Hash -cne $r.ActorSHA256){throw 'Actor script changed; no worker invoked.'}
 & $r.ActorScript -RequestPath $r.RequestPath -RequestSHA256 $r.RequestSHA256 -ActorSHA256 $r.ActorSHA256 -SourceHash $r.SourceHash -SessionId $r.SessionId -ShellProcessId $r.ShellProcessId
}catch{Write-Error -ErrorRecord $_ -ErrorAction Continue;exit 1}finally{if($transcribing){Stop-Transcript|Out-Null}}
'@
    $arguments='-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap.Replace('__REQUEST__',$data)))
    if($arguments.Length -gt 30000){throw 'Actor command exceeds its size bound.'}
    $principal=New-ScheduledTaskPrincipal -UserId $fixture.ExpectedUserSid -LogonType Interactive -RunLevel Limited
    $action=New-ScheduledTaskAction -Execute $executable -Argument $arguments
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 300) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $null=Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Principal $principal -Settings $settings -ErrorAction Stop
    $registered=$true
    $initialLastRun=(Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\' -ErrorAction Stop).LastRunTime
    Start-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
    $deadline=[DateTime]::UtcNow.AddSeconds(300)
    do{
      Start-Sleep -Seconds 1
      $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
      $info=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\' -ErrorAction Stop
      if($info.LastRunTime -ne $initialLastRun -and $info.LastTaskResult -ne 0 -and $info.LastTaskResult -ne 267009 -and $task.State -notin @('Running','Queued')){throw "Desktop actor failed: task result $($info.LastTaskResult)."}
    }while(((-not(Test-Path -LiteralPath $actorPath)) -or $task.State -eq 'Running') -and [DateTime]::UtcNow -lt $deadline)
    if(-not(Test-Path -LiteralPath $actorPath) -or $task.State -eq 'Running' -or $info.LastTaskResult -ne 0){throw 'Desktop actor completion unavailable or timed out.'}
    if((Get-Item -LiteralPath $actorPath).Length -gt 1048576){throw 'Actor evidence exceeds its bound.'}
    $null=& $store {param($p,$r) Assert-RideStorePath -Path $p -Root $r} $actorPath ([Environment]::GetFolderPath('LocalApplicationData'))
    $actor=Get-Content -LiteralPath $actorPath -Raw|ConvertFrom-Json
    Copy-Item -LiteralPath $actorPath -Destination (Join-Path (Split-Path -Parent $EvidencePath) 'store-solitaire-actor.json') -ErrorAction Stop
    $report['ActorEvidenceSHA256']=(Get-FileHash -LiteralPath $actorPath).Hash
    if((Get-FileHash -LiteralPath (Join-Path (Split-Path -Parent $EvidencePath) 'store-solitaire-actor.json')).Hash -cne $report.ActorEvidenceSHA256){throw 'Actor evidence copy changed.'}
    $report['Actor']=$actor
    if($actor.Status -cne 'Passed' -or -not $actor.LifecyclePassed -or $actor.RunId -cne $fixture.RunId -or $actor.UserSid -cne $fixture.ExpectedUserSid -or $actor.OperationId -cne $fixture.OperationId -or $actor.SourceHash -cne $sourceHash -or $actor.ActorSHA256 -cne $actorHash -or $actor.RequestSHA256 -cne $report.RequestSHA256 -or $actor.Desktop.CurrentElevated -or $actor.Desktop.ShellElevated -or $actor.Desktop.CurrentSessionId -ne $request.SessionId -or $actor.Desktop.SessionId -ne $request.SessionId -or $actor.Desktop.ShellProcessId -ne $request.ShellProcessId -or $actor.FullHandoffPassed -ne $false -or $actor.LifecyclePassed -ne $true -or $actor.WindowsAppMutation -ne $true){throw 'Actor evidence correlation/desktop/Plan boundary failed.'}
    if(-not $actor.RegistrationRecoveryPassed -or -not $actor.UnrelatedRegistrationsUnchanged -or $actor.OriginalCatalogSHA256 -cne $fixture.OriginalCatalogSHA256 -or $actor.CandidateCatalogSHA256 -cne $fixture.CandidateCatalogSHA256){throw 'Registration recovery or private catalog evidence mismatch.'}
    $report.WindowsAppMutation=$actor.WindowsAppMutation;$report.RegistrationRecoveryPassed=$true;$report.LifecyclePassed=$true;$report.Status='Passed'
  }catch{
    $report.Error=$_.Exception.Message
    if($actorPath -and (Test-Path -LiteralPath $actorPath -PathType Leaf)){
      try{
        $null=& $store {param($p,$r) Assert-RideStorePath -Path $p -Root $r} $actorPath ([Environment]::GetFolderPath('LocalApplicationData'))
        if((Get-Item -LiteralPath $actorPath).Length -gt 1048576){throw 'Failed actor evidence exceeds its bound.'}
        $failurePath=Join-Path (Split-Path -Parent $EvidencePath) 'store-solitaire-actor.json'
        Copy-Item -LiteralPath $actorPath -Destination $failurePath -Force -ErrorAction Stop
        $report['ActorEvidenceSHA256']=(Get-FileHash -LiteralPath $actorPath).Hash
        if((Get-FileHash -LiteralPath $failurePath).Hash -cne $report.ActorEvidenceSHA256){throw 'Failed actor evidence copy changed.'}
      }catch{$report['ActorCollectionError']=$_.Exception.Message}
    }
  }
  finally{
    if($registered){
      try{
        $owned=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
        $ownerSid=if($owned.Principal.UserId -match '^S-1-'){$owned.Principal.UserId}else{([Security.Principal.NTAccount]::new($owned.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
        if(@($owned.Actions).Count -ne 1 -or $owned.Actions[0].Execute -ine $executable -or $owned.Actions[0].Arguments -cne $arguments -or $ownerSid -cne $fixture.ExpectedUserSid -or $owned.Principal.LogonType -ne 'Interactive' -or $owned.Principal.RunLevel -ne 'Limited'){throw 'Fixture task ownership changed; no task cleanup attempted.'}
        if($owned.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop}
        $stopDeadline=[DateTime]::UtcNow.AddSeconds(15)
        while((Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop).State -eq 'Running' -and [DateTime]::UtcNow -lt $stopDeadline){Start-Sleep -Seconds 1}
        if((Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop).State -eq 'Running'){throw 'Owned actor task did not stop.'}
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
        if(Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue){throw 'Owned actor task still exists.'}
        $report.TaskCleanupVerified=$true
      }catch{$report.CleanupError=$_.Exception.Message;$report.Status='Failed';$report.LifecyclePassed=$false}
    }
    if($consolePath -and (Test-Path -LiteralPath $consolePath -PathType Leaf)){
      try{
        $null=& $store {param($p,$r) Assert-RideStorePath -Path $p -Root $r} $consolePath ([Environment]::GetFolderPath('LocalApplicationData'))
        if((Get-Item -LiteralPath $consolePath).Length -gt 1048576){throw 'Actor console exceeds its evidence bound.'}
        $retainedConsole=Join-Path (Split-Path -Parent $EvidencePath) 'store-solitaire-actor-console.log'
        Copy-Item -LiteralPath $consolePath -Destination $retainedConsole -ErrorAction Stop
        $report['ConsoleSHA256']=(Get-FileHash -LiteralPath $consolePath).Hash
        if((Get-FileHash -LiteralPath $retainedConsole).Hash -cne $report.ConsoleSHA256){throw 'Console evidence copy changed.'}
      }catch{$report['ConsoleCollectionError']=$_.Exception.Message;$report.Status='Failed';$report.LifecyclePassed=$false}
    }
  }
  $report|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $EvidencePath -Encoding UTF8
  if($report.Status -ne 'Passed' -or -not $report.TaskCleanupVerified){throw "Solitaire lifecycle fixture failed: $($report.Error) $($report.CleanupError)"}
  'Isolated Solitaire lifecycle passed; owned task removed, registration recovery only.'
  return
