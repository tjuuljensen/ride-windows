<#
.SYNOPSIS
  Exercise Solitaire uninstall and retained-source reinstall in an isolated desktop.
.DESCRIPTION
  Requires a correlated disposable Hyper-V guest, actual unelevated expected
  desktop, source hashes and an exact Solitaire-only private catalog target edit.
  Uses production Store handlers for preview, removal, repeats and re-registration.
  No downloads, provisioning, AllUsers removal or device policy changes.
.PARAMETER RequestPath
  Exact staged store-solitaire.fixture.json request.
.PARAMETER RequestSHA256
  Coordinator-captured request hash.
.PARAMETER SourceHash
  Coordinator-captured private catalog/module handoff hash.
.PARAMETER ActorSHA256
  Coordinator-captured hash of this worker.
.PARAMETER SessionId
  Existing expected-user desktop session.
.PARAMETER ShellProcessId
  Existing expected-user Explorer process.
.EXAMPLE
  Get-Help .\Invoke-RideStoreSolitaireActor.ps1 -Full
.INPUTS
  None. Launched only by the isolated test coordinator.
.OUTPUTS
  String. Progress; actor.json and user-owned Store run records retain evidence.
.NOTES
  Compatibility: Windows PowerShell 5.1 on a disposable Windows 11 guest.
  Prerequisites: Signed-in expected user with unelevated shell; local full payload.
  File/environment inputs: Bound source/request and correlated RIDE test markers.
  Recovery: Best-effort local registration; host checkpoint recovery is separate.
    App data and exact prior versions are not recoverable by this contract.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add one-app native lifecycle and unrelated-registration checks.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RequestPath,
 [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$RequestSHA256,
 [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$SourceHash,
 [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ActorSHA256,
 [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$SessionId,
 [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ShellProcessId)
$ErrorActionPreference='Stop'
if($env:RIDE_TEST_GUEST -ne '1' -or $env:RIDE_INTEGRATION_VM -ne '1' -or $env:RIDE_TEST_RUN_ID -notmatch '^[0-9a-f]{32}$'){throw 'Correlated disposable actor markers required.'}
$machine=Get-CimInstance Win32_ComputerSystem
if($machine.Manufacturer -ne 'Microsoft Corporation' -or $machine.Model -ne 'Virtual Machine'){throw 'Disposable Hyper-V guest required.'}
if([IO.Path]::GetFullPath($RequestPath) -cne [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'store-solitaire.fixture.json')) -or (Get-FileHash -LiteralPath $RequestPath).Hash -cne $RequestSHA256 -or (Get-FileHash -LiteralPath $PSCommandPath).Hash -cne $ActorSHA256){throw 'Actor/request source changed.'}
Import-Module (Join-Path $PSScriptRoot 'RIDE.StoreSolitaireFixtureData.psm1') -Force
$r=Read-RideSolitaireFixtureRequest -Path $RequestPath -RunId $env:RIDE_TEST_RUN_ID
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$original=Join-Path $PSScriptRoot 'store-solitaire.original-catalog.psd1';$catalog=Join-Path $root 'catalog/operations.psd1'
if((Get-FileHash -LiteralPath $original).Hash -cne $r.OriginalCatalogSHA256 -or (Get-FileHash -LiteralPath $catalog).Hash -cne $r.CandidateCatalogSHA256 -or [IO.File]::ReadAllText($catalog) -cne (Get-RideSolitaireFixtureCatalog ([IO.File]::ReadAllText($original)))){throw 'Private catalog must contain exactly the declared Solitaire target edit.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try{if($identity.User.Value -cne $r.ExpectedUserSid -or $identity.Name -ine $r.ExpectedUserName -or ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne $SessionId){throw 'Actual actor SID/session/elevation mismatch.'}}finally{$identity.Dispose()}
$store=Import-Module (Join-Path $root 'modules/RIDE.StoreApps.psm1') -Force -PassThru
$desktop=& $store {Get-RideStoreDesktop}
if($desktop.CurrentSid -cne $r.ExpectedUserSid -or $desktop.TargetSid -cne $r.ExpectedUserSid -or $desktop.CurrentElevated -or $desktop.ShellElevated -or $desktop.CurrentSessionId -ne $SessionId -or $desktop.SessionId -ne $SessionId -or $desktop.ShellProcessId -ne $ShellProcessId -or (& $store {Get-RideStoreHandoffSourceHash}) -cne $SourceHash -or (& $store {Get-RideStoreTarget}) -cne 'Windows 11'){throw 'Actual desktop/source/target changed.'}
$stateRoot=& $store {Get-RideStoreStateRoot}
$evidenceRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('RIDE/TestFixtures/StoreSolitaire/'+$r.RunId)
$path=Join-Path $evidenceRoot 'actor.json'
$null=& $store {param($p,$root) Assert-RideStorePath -Path $p -Root $root} $path ([Environment]::GetFolderPath('LocalApplicationData'))
if(Test-Path -LiteralPath $path){throw 'Prior actor evidence exists; preserve it.'}
$steps=[Collections.Generic.List[object]]::new()
$report=[ordered]@{SchemaVersion=1;RunId=$r.RunId;OperationId='app.solitaire';Status='Failed';LifecyclePassed=$false;ExactRecovery=$false;RecoveryMode='BestEffortRetainedPayload';RegistrationRecoveryPassed=$false;FullHandoffPassed=$false;AlternateAdministratorPassed=$false;WindowsAppMutation=$false;UserSid=$r.ExpectedUserSid;Desktop=$desktop;RequestSHA256=$RequestSHA256;SourceHash=$SourceHash;ActorSHA256=$ActorSHA256;OriginalCatalogSHA256=$r.OriginalCatalogSHA256;CandidateCatalogSHA256=$r.CandidateCatalogSHA256;Steps=$steps;RemovalRunId=$null;ReinstallRunId=$null;SourceSurvivedRemoval=$null;UnrelatedRegistrationsUnchanged=$false;Error=$null;CollectionError=$null}
function Save-Report{[IO.File]::WriteAllText($path,($report|ConvertTo-Json -Depth 24),[Text.UTF8Encoding]::new($false))}
function Get-RunIds{if(Test-Path -LiteralPath $stateRoot){@(Get-ChildItem -LiteralPath $stateRoot -Directory|Select-Object -ExpandProperty Name|Sort-Object)}else{@()}}
function Get-OtherRegistrations{@(Get-AppxPackage -PackageTypeFilter Main,Bundle,Resource,Framework,Optional|Where-Object PackageFamilyName -ine 'Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe'|Select-Object -ExpandProperty PackageFullName|Sort-Object)}
function Assert-Result($Value,[string]$Status,[string]$Stage){if(@($Value).Count -ne 1 -or $Value.Status -cne $Status -or $Value.OperationId -cne 'app.solitaire'){throw "$Stage did not return $Status`: $($Value|ConvertTo-Json -Compress)"};$steps.Add([pscustomobject]@{Stage=$Stage;Result=$Value});Save-Report}
$beforeRuns=@(Get-RunIds);$others=@(Get-OtherRegistrations)
try{
 $plan=@(Get-RideStoreAppPlan -Id app.solitaire -Action Uninstall -ExpectedUserSid $r.ExpectedUserSid)
 if($plan.Count -ne 1 -or $plan[0].Refusals.Count -or -not $plan[0].Before.Present -or -not $plan[0].Source){throw "Solitaire removal preflight refused: $($plan[0].Refusals -join '; ')"}
 $operation=$plan[0].Operation;$report['Before']=$plan[0].Before;$report['CapturedSource']=$plan[0].Source;Save-Report
 $preview=@(Invoke-RideStoreAppAction -Id app.solitaire -Action Uninstall -ExpectedUserSid $r.ExpectedUserSid -WhatIf)
 Assert-Result $preview 'NotApplied' 'UninstallPreview'
 if($preview.RecordCreated -or (ConvertTo-Json -InputObject @(Get-RunIds) -Compress) -cne (ConvertTo-Json -InputObject $beforeRuns -Compress) -or (Get-RideStoreAppState $operation|ConvertTo-Json -Depth 12 -Compress) -cne ($plan[0].Before|ConvertTo-Json -Depth 12 -Compress)){throw 'Uninstall preview changed registration or records.'}
 $report.WindowsAppMutation=$true;Save-Report
 $removed=@(Invoke-RideStoreAppAction -Id app.solitaire -Action Uninstall -ExpectedUserSid $r.ExpectedUserSid -Confirm:$false)
 if($removed.RecordCreated -and $removed.RunId){$report.RemovalRunId=$removed.RunId}
 Assert-Result $removed 'Completed' 'Uninstall'
 if(-not $report.RemovalRunId -or (Get-RideStoreAppState $operation).Present){throw 'Removal record or absent readback missing.'}
 $repeat=@(Invoke-RideStoreAppAction -Id app.solitaire -Action Uninstall -ExpectedUserSid $r.ExpectedUserSid -Confirm:$false)
 Assert-Result $repeat 'AlreadyMatching' 'UninstallRepeat'
 if($repeat.RecordCreated){throw 'Repeat removal created an extra record.'}
 if((ConvertTo-Json -InputObject @(Get-OtherRegistrations) -Compress) -cne (ConvertTo-Json -InputObject $others -Compress)){throw 'Unrelated registration changed after removal.'}
 $reinstallPlan=@(Get-RideStoreAppPlan -Id app.solitaire -Action Reinstall -ExpectedUserSid $r.ExpectedUserSid -RemovalRunId $report.RemovalRunId)
 $report['ReinstallPlan']=$reinstallPlan;$report.SourceSurvivedRemoval=($reinstallPlan.Count -eq 1 -and $reinstallPlan[0].Source -and -not $reinstallPlan[0].Refusals.Count);Save-Report
 if(-not $report.SourceSurvivedRemoval){throw "Local reinstall preflight refused: $($reinstallPlan[0].Refusals -join '; ')"}
 $removedRuns=@(Get-RunIds)
 $preview=@(Invoke-RideStoreAppAction -Id app.solitaire -Action Reinstall -ExpectedUserSid $r.ExpectedUserSid -RemovalRunId $report.RemovalRunId -WhatIf)
 Assert-Result $preview 'NotApplied' 'ReinstallPreview'
 if($preview.RecordCreated -or (Get-RideStoreAppState $operation).Present -or (ConvertTo-Json -InputObject @(Get-RunIds) -Compress) -cne (ConvertTo-Json -InputObject $removedRuns -Compress)){throw 'Reinstall preview changed registration or records.'}
 $installed=@(Invoke-RideStoreAppAction -Id app.solitaire -Action Reinstall -ExpectedUserSid $r.ExpectedUserSid -RemovalRunId $report.RemovalRunId -Confirm:$false)
 if($installed.RecordCreated -and $installed.RunId){$report.ReinstallRunId=$installed.RunId}
 Assert-Result $installed 'Completed' 'Reinstall'
 if(-not $report.ReinstallRunId -or -not (Get-RideStoreAppState $operation).Present){throw 'Reinstall record or present readback missing.'}
 $repeat=@(Invoke-RideStoreAppAction -Id app.solitaire -Action Reinstall -ExpectedUserSid $r.ExpectedUserSid -RemovalRunId $report.RemovalRunId -Confirm:$false)
 Assert-Result $repeat 'AlreadyMatching' 'ReinstallRepeat'
 if($repeat.RecordCreated){throw 'Repeat reinstall created an extra record.'}
 $report['After']=Get-RideStoreAppState $operation
 $report.UnrelatedRegistrationsUnchanged=((ConvertTo-Json -InputObject @(Get-OtherRegistrations) -Compress) -ceq (ConvertTo-Json -InputObject $others -Compress))
 if(-not $report.UnrelatedRegistrationsUnchanged){throw 'Unrelated registrations changed.'}
 $report.RegistrationRecoveryPassed=$true;$report.LifecyclePassed=$true;$report.Status='Passed'
}catch{$report.Error=$_.Exception.Message}
finally{
 try{
  $records=@(foreach($id in @(Get-RunIds|Where-Object {$_ -notin $beforeRuns})){
   if($id -notin @($report.RemovalRunId,$report.ReinstallRunId)){throw 'Unexpected Store run record created.'}
   $recordPath=Join-Path $stateRoot ($id+'/manifest.json');$record=Get-Content -LiteralPath $recordPath -Raw|ConvertFrom-Json
   if($record.SchemaVersion -ne 1 -or $record.UserSid -cne $r.ExpectedUserSid -or @($record.Items).Count -ne 1 -or $record.Items[0].OperationId -cne 'app.solitaire'){throw 'Owned schema-1 record mismatch.'}
   $record
  })
  $report['StoreRecords']=$records
 }catch{$report.CollectionError=$_.Exception.Message;$report.Status='Failed';$report.LifecyclePassed=$false}
 Save-Report
}
if($report.Status -cne 'Passed'){throw $report.Error}
'Solitaire native lifecycle passed; retained registration recovery only, no app-data or launcher acceptance.'
