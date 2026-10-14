<#
.SYNOPSIS
  Inspect a source-bound Store Plan in an existing disposable guest desktop.
.DESCRIPTION
  Test-only worker for schema 7. Requires the expected real unelevated desktop
  SID/session/shell, immutable fixture/source hashes and pinned guest markers.
  Writes correlated observations to the execution user's local fixture directory.
  Never uninstalls, registers, acquires apps or changes device policy.
.PARAMETER FixturePath
  Exact staged request selection, not an arbitrary script or profile.
.PARAMETER FixtureSHA256
  Coordinator-captured selection hash.
.PARAMETER SourceHash
  Coordinator-captured catalog/module handoff hash.
.PARAMETER ActorSHA256
  Coordinator-captured hash of this worker script.
.PARAMETER SessionId
  Expected existing shell session; it must be the worker's actual current session.
.PARAMETER ShellProcessId
  Expected existing desktop shell process.
.EXAMPLE
  Get-Help .\Invoke-RideStoreDesktopPlanActor.ps1 -Full
.INPUTS
  None. Only the isolated disposable fixture launches this worker.
.OUTPUTS
  String. Progress; actor.json retains source-bound Plan observations.
.NOTES
  Compatibility: Windows PowerShell 5.1 on Windows 11/Server 2025 disposable guests.
  Prerequisites: Schema-7 request and existing signed-in expected user; no elevation.
  File/environment inputs: Staged source, RIDE_TEST_GUEST/RIDE_INTEGRATION_VM=1,
    correlated RIDE_TEST_RUN_ID. No credentials or execution-policy changes.
  Recovery: No app mutation; coordinator owns transient task cleanup and checkpoint.
  Owner: RIDE-Windows maintainers. Version: 0.1.2.
  Changelog: 0.1.2: Report exact identity/session/admin-role and read-only UAC prerequisites.
    0.1.1: Share coordinator-owned diagnostic directory; refuse prior actor evidence.
    0.1.0: Add source/identity-bound read-only desktop worker.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$FixturePath,
  [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$FixtureSHA256,
  [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$SourceHash,
  [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ActorSHA256,
  [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$SessionId,
  [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ShellProcessId)
$ErrorActionPreference='Stop'
if($env:RIDE_TEST_GUEST -ne '1' -or $env:RIDE_INTEGRATION_VM -ne '1' -or $env:RIDE_TEST_RUN_ID -notmatch '^[0-9a-f]{32}$'){throw 'Disposable actor markers required.'}
$machine=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
if($machine.Manufacturer -ne 'Microsoft Corporation' -or $machine.Model -ne 'Virtual Machine'){throw 'Disposable Hyper-V guest required.'}
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if([IO.Path]::GetFullPath($FixturePath) -cne [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'settings-validation.fixture.psd1')) -or (Get-FileHash -LiteralPath $FixturePath).Hash -cne $FixtureSHA256 -or (Get-FileHash -LiteralPath $PSCommandPath).Hash -cne $ActorSHA256){throw 'Actor or request source changed.'}
Import-Module (Join-Path $root 'modules/RIDE.SettingsFixtureData.psm1') -Force
$data=Import-PowerShellDataFile -LiteralPath $FixturePath
$fixture=(Read-RideSettingsFixture -Path $FixturePath -RunId $env:RIDE_TEST_RUN_ID -IntegrationSuite $data.IntegrationSuite -CatalogPath (Join-Path $root 'catalog/operations.psd1')).Fixture
if($fixture.SchemaVersion -ne 7 -or $fixture.Scenario -cne 'StoreDesktopPlan'){throw 'Actor supports read-only desktop Plan only.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try{
  $observed=[ordered]@{ActualSid=$identity.User.Value;ExpectedSid=$fixture.ExpectedUserSid;ActualAccount=$identity.Name;ExpectedAccount=$fixture.ExpectedUserName;ActualSessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;ExpectedSessionId=$SessionId;AdministrativeToken=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
  Write-Output ('ActorIdentityObservation='+($observed|ConvertTo-Json -Compress))
  if($observed.ActualSid -cne $fixture.ExpectedUserSid -or $observed.ActualAccount -ine $fixture.ExpectedUserName -or $observed.AdministrativeToken -or $observed.ActualSessionId -ne $SessionId){
    $uac=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    Write-Output ('ActorUacPrerequisites='+(@{EnableLUA=$uac.EnableLUA;ConsentPromptBehaviorAdmin=$uac.ConsentPromptBehaviorAdmin;PromptOnSecureDesktop=$uac.PromptOnSecureDesktop}|ConvertTo-Json -Compress))
    throw 'Actor owner/session/elevation mismatch; see exact observations. No app inspected.'
  }
}finally{$identity.Dispose()}
$store=Import-Module (Join-Path $root 'modules/RIDE.StoreApps.psm1') -Force -PassThru
$desktop=& $store {Get-RideStoreDesktop}
if($desktop.CurrentSid -cne $fixture.ExpectedUserSid -or $desktop.TargetSid -cne $fixture.ExpectedUserSid -or $desktop.CurrentElevated -or $desktop.ShellElevated -or $desktop.SessionId -ne $SessionId -or $desktop.CurrentSessionId -ne $SessionId -or $desktop.ShellProcessId -ne $ShellProcessId){throw 'Actual desktop shell changed or is elevated.'}
if((& $store {Get-RideStoreHandoffSourceHash}) -cne $SourceHash -or (& $store {Get-RideStoreTarget}) -cne $fixture.Target){throw 'Actor source/target changed.'}
$stateRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('RIDE/TestFixtures/StoreDesktopPlan/'+$fixture.RunId)
$path=& $store {param($p,$r) Assert-RideStorePath -Path $p -Root $r} (Join-Path $stateRoot 'actor.json') ([Environment]::GetFolderPath('LocalApplicationData'))
if(Test-Path -LiteralPath $path){throw 'Actor evidence already exists; retain it.'}
$null=New-Item -ItemType Directory -Path $stateRoot -Force
$report=[ordered]@{SchemaVersion=1;RunId=$fixture.RunId;Target=$fixture.Target;SelectionId=$fixture.SelectionId;Status='Failed';DesktopPlanPassed=$false;FullHandoffPassed=$false;AlternateAdministratorPassed=$false;LifecyclePassed=$false;WindowsAppMutation=$false;UserSid=$fixture.ExpectedUserSid;Desktop=$desktop;FixtureSHA256=$FixtureSHA256;SourceHash=$SourceHash;ActorSHA256=$ActorSHA256;Error=$null}
try{
  $before=@(Get-RideStoreAppPlan -Id $fixture.SelectionId -Action Uninstall -ExpectedUserSid $fixture.ExpectedUserSid)
  if(@($before|Where-Object {'Target acceptance pending or unsupported' -notin $_.Refusals}).Count){throw 'Published Store target guard unexpectedly open.'}
  $request=[pscustomobject]@{SchemaVersion=1;Workflow='StoreDesktopHandoff';RequestId=$fixture.RunId;Root=$root;SourceHash=$SourceHash;TargetSid=$fixture.ExpectedUserSid;SessionId=$SessionId;ShellProcessId=$ShellProcessId;Command='Plan';Id=$fixture.SelectionId;Action='Uninstall';RemovalRunId=$null}
  $worker=@(Invoke-RideStoreDesktopRequest -Request $request)
  $after=@(Get-RideStoreAppPlan -Id $fixture.SelectionId -Action Uninstall -ExpectedUserSid $fixture.ExpectedUserSid)
  if($worker.Count -ne $before.Count -or ($before.Before|ConvertTo-Json -Depth 12 -Compress) -cne ($after.Before|ConvertTo-Json -Depth 12 -Compress)){throw 'Desktop Plan count/registration observations changed.'}
  $report['Plan']=$before;$report['WorkerPlan']=$worker
  $report.DesktopPlanPassed=$true;$report.Status='Passed'
}catch{$report.Error=$_.Exception.Message}
[IO.File]::WriteAllText($path,($report|ConvertTo-Json -Depth 18),[Text.UTF8Encoding]::new($false))
if($report.Status -ne 'Passed'){throw $report.Error}
'Desktop Plan worker passed; no launcher/alternate-admin/app lifecycle acceptance claimed.'
