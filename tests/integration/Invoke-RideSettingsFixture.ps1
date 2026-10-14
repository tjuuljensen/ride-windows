<#
.SYNOPSIS
  Validate one explicitly selected setting inside a pinned disposable Windows VM.
.DESCRIPTION
  Requires correlated guest markers, elevation and a Hyper-V guest. Exercises
  preview, declared states, repeat apply and captured recovery in a fresh process.
  A pending candidate can use an explicitly approved target in a private catalog
  copy; published SupportedTargets stay unchanged. Never runs packages or Full.
  Captured setting recovery and the host checkpoint are separate boundaries.
.PARAMETER FixturePath
  Literal path to the request-bound PowerShell data fixture in the staged checkout.
.PARAMETER EvidencePath
  Literal path to retained correlated guest evidence. Required for operational use.
.PARAMETER Version
  Print the version before any operational checks.
.EXAMPLE
  .\Invoke-RideSettingsFixture.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  String. Focused lifecycle progress; structured evidence is written separately.
.NOTES
  Compatibility: Windows PowerShell 5.1; target behavior awaits disposable acceptance.
  Prerequisites: Pinned elevated Hyper-V guest through the existing controller;
    RIDE_TEST_GUEST=1, RIDE_INTEGRATION_VM=1 and a correlated RIDE_TEST_RUN_ID.
  File/environment inputs: Explicit fixture, staged catalog/modules and evidence path.
  Recovery: Captured state in finally, then the host's pinned clean checkpoint.
  Owner: RIDE-Windows maintainers. Version: 0.7.2.
  Changelog: 0.7.2: Describe checkpoint-only guard acceptance accurately in progress.
    0.7.1: Compare interrupted ownership against the saved run's actual
    creation capture, rather than random identities proposed by earlier inspection.
    0.7.0: Add explicit owned active/setting-drift/interrupted-creation
    guards with separate selection recovery and checkpoint-only evidence.
    0.6.6: Verify owned-copy deletion refusal after a temporary name
    mutation, then recover that fixture seed before saved-run compensation.
    0.6.5: Resolve the maximum-age fault setter directly from the engine's
    retained handler, matching its actual route rather than the managed dispatcher.
    0.6.4: Unwind maximum-age saved runs in reverse order to retain
    each run's expected-post-write stale-state guard during multi-state validation.
    0.6.3: Retain consecutive unchanged owned-plan native exports and
    bounded byte-difference evidence before recovery; retain the deletion guard.
    0.6.2: Retain conditional media and Server Manager presence evidence
    separately from literal policy lifecycle; never infer policy consumption.
    0.6.1: Recover the firewall preparation seed through the retained
    engine's internal managed handler rather than an unexported global command.
    0.6.0: Exercise service-startup and maximum-age recovery after a
    controlled interruption following their focused native setter.
    0.5.0: Exercise enable-all partial completion after one native profile
    write; recover the captured mixed state before recovering the fixture seed.
    0.4.1: Bind injection to the engine's actual retained handler module
    and remove the module-scoped override by its provider-visible name.
    0.4.0: Exercise saved recovery after a controlled fault immediately
    after one real native registry mutation, in the isolated guest process.
    0.3.0: Verify owned-copy compensating recovery and unchanged selection
    and plan inventory; proposed random identities are not machine state.
    0.2.0: Add firewall and local maximum-age lifecycle; seed enable-all
    with a bounded mixed local state and recover that seed separately.
    0.1.1: Apply the declared baseline state without assuming an alias for services.
    0.1.0: Add isolated scalar, paired registry and service lifecycle fixtures.
#>
[CmdletBinding()]
param([string] $FixturePath, [string] $EvidencePath, [switch] $Version)
$script:ScriptVersion = '0.7.2'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if ($env:RIDE_TEST_GUEST -ne '1' -or $env:RIDE_INTEGRATION_VM -ne '1' -or $env:RIDE_TEST_RUN_ID -notmatch '^[0-9a-f]{32}$') { throw 'Use only the correlated disposable-VM controller.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An elevated disposable guest is required.' }
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if ($computer.Manufacturer -ne 'Microsoft Corporation' -or $computer.Model -ne 'Virtual Machine') { throw 'This fixture requires the pinned Hyper-V guest, never a developer workstation.' }
if (-not $FixturePath -or -not $EvidencePath) { throw 'Explicit fixture and evidence paths are required.' }
$sourceRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([IO.Path]::GetFullPath($FixturePath) -ine [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'settings-validation.fixture.psd1'))) { throw 'Fixture must be the explicit staged selection file.' }
Import-Module (Join-Path $sourceRoot 'modules/RIDE.SettingsFixtureData.psm1') -Force
$inputFixture=Import-PowerShellDataFile -LiteralPath $FixturePath
$fixtureData=Read-RideSettingsFixture -Path $FixturePath -RunId $env:RIDE_TEST_RUN_ID -IntegrationSuite $inputFixture.IntegrationSuite -CatalogPath (Join-Path $sourceRoot 'catalog/operations.psd1')
$fixture=$fixtureData.Fixture
$scenario=if($fixture.SchemaVersion -eq 2){$fixture.Scenario}else{'Lifecycle'}
Import-Module (Join-Path $sourceRoot 'modules/RIDE.Engine.psm1') -Force
$target = Get-RidePlatform
if ($fixture.Target -cne $target -or $target -notin @('Windows 11','Windows Server 2025')) { throw 'Fixture target does not match the disposable guest.' }
$operation = Get-RideOperation -Id $fixture.OperationId
if ($operation.Kind -notin @('RegistryValue','RegistryValueSet','WindowsService','FirewallProfile','LocalPasswordMaximumAge','OwnedPowerPlan') -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { throw 'This fixture supports only implemented captured setting families.' }
$states = @($fixture.States)
if ($states.Count -lt 1 -or $states.Count -gt 16 -or @($states | Select-Object -Unique).Count -ne $states.Count) { throw 'Fixture states must be a nonempty bounded unique list.' }
foreach ($state in $states) { if ($state -isnot [string] -or -not $operation.States.ContainsKey($state)) { throw 'Fixture state is not declared by the catalog.' } }
$candidate = $target -notin $operation.SupportedTargets
if ($candidate -and (-not $fixture.AllowPendingCandidate -or -not $operation.PendingAcceptance -or $target -notin $operation.CandidateTargets)) { throw 'Pending target requires explicit applicable candidate approval in the fixture.' }
if (-not $candidate -and $fixture.AllowPendingCandidate) { throw 'Do not silently widen an already supported operation.' }
$report = [ordered]@{ SchemaVersion=1; RunId=$fixture.RunId; OperationId=$operation.Id; Target=$target; CandidateFixture=$candidate; FixtureSHA256=(Get-FileHash -LiteralPath $FixturePath).Hash; SourceCatalogSHA256=(Get-FileHash -LiteralPath (Join-Path $sourceRoot 'catalog/operations.psd1')).Hash; FixtureCatalogSHA256=$null; Status='Failed'; LifecyclePassed=$false; ExactRecovery=$false; States=@(); SavedRunIds=@(); Original=$null; Restored=$null; Error=$null; RecoveryError=$null; PendingEvidence=@('GUI/session and actual feature behavior','Deliberate native partial-failure acceptance','Target defaults and managed precedence') }
$privateRoot = $null
$firstRunId = $null
$originalText = $null
$seedSnapshot = $null
$powerInventory = $null
$creationFaultModule=$null
$report['RecoveryMode']=if($operation.Kind -eq 'OwnedPowerPlan'){'Compensating'}else{'Exact'}
$report['RecoveryPassed']=$false
$report['Scenario']=$scenario
$report['GuardValidationPassed']=$false
if($scenario -in @('SettingDrift','InterruptedCreation')){$report.RecoveryMode='CheckpointOnly'}
if($operation.Id -eq 'windows.media-radio-preset-retrieval-policy'){
  $playerPaths=@(Join-Path $env:ProgramFiles 'Windows Media Player/wmplayer.exe')
  if(${env:ProgramFiles(x86)}){$playerPaths+=Join-Path ${env:ProgramFiles(x86)} 'Windows Media Player/wmplayer.exe'}
  $present=@($playerPaths|Where-Object {Test-Path -LiteralPath $_ -PathType Leaf -ErrorAction Stop})
  $report['ComponentObservation']=[ordered]@{Area='Legacy Windows Media Player';ExecutablePaths=$present;ExecutablePresent=($present.Count -gt 0);PolicyConsumptionVerified=$false;FeatureAcceptance='Pending radio-feature and consumer evidence, regardless of executable presence'}
}elseif($operation.Id -eq 'windows.media-drm-online-access-policy'){
  $report['ComponentObservation']=[ordered]@{Area='Windows Media DRM';ConsumerPresenceVerified=$false;PolicyConsumptionVerified=$false;FeatureAcceptance='Pending applicable backend/client and license-acquisition evidence; no consumer is inferred from registry values'}
}elseif($operation.Id -eq 'windows.server-manager-startup-policy'){
  $report['ComponentObservation']=[ordered]@{Area='Server Manager';ExecutablePresent=(Test-Path -LiteralPath (Join-Path $env:WINDIR 'System32/ServerManager.exe') -PathType Leaf -ErrorAction Stop);PolicyConsumptionVerified=$false;FeatureAcceptance='Pending applicable desktop/logon and console-preference behavior'}
}
function ConvertTo-FixtureState($Current) {
  # ActiveStore/network observations are evidence, not fields owned by recovery.
  if ($operation.Kind -eq 'FirewallProfile') {
    return ([ordered]@{SnapshotVersion=$Current.SnapshotVersion;PolicyStore=$Current.PolicyStore;Entries=@($Current.Entries | Sort-Object Name | Select-Object Name,Value)} | ConvertTo-Json -Depth 30 -Compress)
  }
  if ($operation.Kind -eq 'OwnedPowerPlan' -and -not $Current.OriginalOwned) {
    return ($Current | Select-Object SnapshotVersion,OperationId,SourceGuid,OriginalRecord,OriginalOwned,SourceAvailable,Available,DestinationExists,Active,Value,Stage | ConvertTo-Json -Depth 30 -Compress)
  }
  $Current | ConvertTo-Json -Depth 30 -Compress
}
function Get-FixturePowerInventory {
  $listed=@(& (Join-Path $env:WINDIR 'System32/powercfg.exe') /list)
  if($LASTEXITCODE -ne 0){throw 'Cannot inspect power-plan inventory.'}
  $active=@(& (Join-Path $env:WINDIR 'System32/powercfg.exe') /getactivescheme)
  if($LASTEXITCODE -ne 0){throw 'Cannot inspect active power plan.'}
  $pattern='[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
  $activeIds=@([regex]::Matches(($active -join "`n"),$pattern)|ForEach-Object {$_.Value.ToLowerInvariant()})
  if($activeIds.Count -ne 1){throw 'Active power identity is not unique.'}
  [pscustomobject]@{Guids=@([regex]::Matches(($listed -join "`n"),$pattern)|ForEach-Object {$_.Value.ToLowerInvariant()}|Sort-Object -Unique);ActiveGuid=$activeIds[0]}
}
function Get-FixtureRunId($Output) {
  $line = @($Output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: [0-9a-f]{32}$' }) | Select-Object -Last 1
  if ($line) { return ($line -replace '^Run ID: ','') }
}
function Get-FixtureOwnedExportObservation($Current) {
  if($Current.Stage -ne 'Ready' -or -not $Current.DestinationExists -or $Current.Active){throw 'Export observation requires a ready inactive owned copy.'}
  $directory=Join-Path (Split-Path -Parent $EvidencePath) 'owned-plan-exports'
  if(Test-Path -LiteralPath $directory){throw 'Export evidence directory already exists.'}
  $null=New-Item -ItemType Directory -Path $directory
  $exports=@();$comparisons=@();$previous=$null
  for($index=1;$index -le 3;$index++){
    $path=Join-Path $directory ("unchanged-$index.pow")
    $null=& (Join-Path $env:WINDIR 'System32/powercfg.exe') /export $path $Current.DestinationGuid
    if($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'Native diagnostic export failed.'}
    $length=(Get-Item -LiteralPath $path).Length
    if($length -lt 1 -or $length -gt 1048576){throw 'Native diagnostic export exceeds bounded size.'}
    $bytes=[IO.File]::ReadAllBytes($path)
    $exports += [pscustomobject]@{File=(Split-Path -Leaf $path);Length=$length;SHA256=(Get-FileHash -LiteralPath $path).Hash;ExportedAtUtc=[DateTime]::UtcNow.ToString('o')}
    if($null -ne $previous){
      $count=0;$sample=@()
      for($offset=0;$offset -lt [Math]::Min($previous.Length,$bytes.Length);$offset++){
        if($previous[$offset] -ne $bytes[$offset]){$count++;if($sample.Count -lt 128){$sample += [pscustomobject]@{Offset=$offset;Before=[int]$previous[$offset];After=[int]$bytes[$offset]}}}
      }
      $comparisons += [pscustomobject]@{First=$index-1;Second=$index;SameLength=($previous.Length -eq $bytes.Length);DifferentBytesInCommonLength=$count;ExtraBytes=[Math]::Abs($previous.Length-$bytes.Length);FirstDifferences=$sample}
    }
    $previous=$bytes
    Start-Sleep -Milliseconds 100
  }
  [pscustomobject]@{DestinationGuid=$Current.DestinationGuid;CapturedExportSHA256=$Current.OriginalRecord.ExportSha256;Method='Three consecutive native exports without any intervening plan mutation';Exports=$exports;Comparisons=$comparisons;Inference='No bytes are masked and no deletion guard is relaxed; file stability is diagnostic evidence only'}
}
function Wait-FixtureState($Operation, [string] $State) {
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  do { if (Test-RideDesiredState -Operation $Operation -State $State) { return }; Start-Sleep -Milliseconds 250 } while ([DateTime]::UtcNow -lt $deadline)
  throw "Desired-state readback failed: $($Operation.Id) / $State"
}
function Test-FixtureOwnedDriftRefusal {
  $current=Get-RideCurrentState -Operation $operation
  if($current.OriginalRecord.Version -ne 2 -or $current.Active){throw 'Drift fixture requires version-2 inactive ownership.'}
  $native=Join-Path $env:WINDIR 'System32/powercfg.exe'
  $drift=[ordered]@{Method='Temporary name change on the fixture-owned inactive copy';DeletionRefused=$false;DestinationRetained=$false;SeedRecovered=$false;Error=$null}
  try {
    $null=& $native /changename $current.DestinationGuid ('RIDE fixture drift '+$fixture.RunId) ('Owned copy '+$current.OwnerToken)
    if($LASTEXITCODE -ne 0){throw 'Owned drift fixture name change failed.'}
    try {$null=Restore-RideRun -RunId $firstRunId -Confirm:$false;throw 'Changed-copy deletion was not refused.'}
    catch {if($_.Exception.Message -notlike '*Owned copy changed or native export is not reproducible*'){throw};$drift.Error=$_.Exception.Message;$drift.DeletionRefused=$true}
    $after=Get-RideCurrentState -Operation $operation
    $drift.DestinationRetained=$after.DestinationExists -and $after.OriginalRecord.OwnerToken -ceq $current.OwnerToken -and -not $after.Active
    if(-not $drift.DestinationRetained){throw 'Drift refusal did not retain the same inactive owned copy.'}
  }finally{
    # Restore only this fixture's known creation label/description, never an
    # arbitrary pre-existing plan. The normal saved-run fingerprint checks again.
    $null=& $native /changename $current.DestinationGuid ('RIDE '+$operation.Id) ('Owned copy '+$current.OwnerToken)
    if($LASTEXITCODE -ne 0){throw 'Owned drift fixture seed recovery failed.'}
    $module=& (Get-Module RIDE.Engine) {(Get-Command Get-RideOwnedPowerPlanState -CommandType Function).Module}
    $ownershipRoot=& (Get-Module RIDE.Engine) {Join-Path (Get-RideStateRoot -Scope Machine) 'OwnedPowerPlans'}
    $drift.SeedRecovered=& $module {param($Id,$Root,$Expected)(Get-RideOwnedPlanExportHash $Id $Root -Logical) -ceq $Expected} $current.DestinationGuid $ownershipRoot $current.OriginalRecord.ConfigurationSha256
    $report['OwnedDriftRefusal']=$drift
  }
  if(-not $drift.SeedRecovered){throw 'Owned drift seed did not return to its captured logical fingerprint.'}
}
function Get-FixtureOwnedHandler {
  $module=& (Get-Module RIDE.Engine) {(Get-Command Get-RideOwnedPowerPlanState -CommandType Function).Module}
  $moduleRoot=if($privateRoot){$privateRoot}else{$sourceRoot}
  if(-not $module -or $module.Path -ine (Join-Path $moduleRoot 'modules/RIDE-OwnedPowerPlans.psm1')){throw 'Owned guard handler is not the retained isolated source module.'}
  $module
}
function Test-FixtureOwnedActiveRefusal {
  $current=Get-RideCurrentState -Operation $operation
  if(-not $current.DestinationExists -or $current.Active){throw 'Active guard requires its own inactive copy.'}
  $selection=(Get-RideOperation -Id 'windows.active-power-scheme').Clone()
  $selection.States=$selection.States.Clone()
  $selection.States['FixtureOwned']=$current.DestinationGuid
  $selectionPlan=@([pscustomobject]@{Operation=$selection;State='FixtureOwned'})
  $guard=[ordered]@{Method='Engine-captured selection of the fixture-owned copy';SelectionRunId=$null;SelectionPreviewPassed=$false;DeletionRefused=$false;DestinationRetained=$false;SelectionRecoveryPassed=$false;Error=$null}
  try {
    $before=Get-FixturePowerInventory
    $null=Invoke-RidePlan -Plan $selectionPlan -WhatIf -Confirm:$false
    $guard.SelectionPreviewPassed=((Get-FixturePowerInventory|ConvertTo-Json -Compress) -ceq ($before|ConvertTo-Json -Compress))
    if(-not $guard.SelectionPreviewPassed){throw 'Selection preview changed inventory.'}
    $output=@(Invoke-RidePlan -Plan $selectionPlan -Confirm:$false)
    $guard.SelectionRunId=Get-FixtureRunId $output
    if(-not $guard.SelectionRunId -or (Get-FixturePowerInventory).ActiveGuid -ne $current.DestinationGuid){throw 'Captured selection did not activate the owned copy.'}
    try {$null=Restore-RideRun -RunId $firstRunId -Confirm:$false;throw 'Active-copy deletion was not refused.'}
    catch {if($_.Exception.Message -notlike '*Owned copy is active*'){throw};$guard.Error=$_.Exception.Message;$guard.DeletionRefused=$true}
    $after=Get-RideCurrentState -Operation $operation
    $guard.DestinationRetained=$after.DestinationExists -and $after.Active -and $after.OwnerToken -ceq $current.OwnerToken
    if(-not $guard.DestinationRetained){throw 'Active guard did not retain the same active owned copy.'}
  }finally{
    if($guard.SelectionRunId){
      $activeBefore=Get-FixturePowerInventory
      $null=Restore-RideRun -RunId $guard.SelectionRunId -WhatIf -Confirm:$false
      if((Get-FixturePowerInventory|ConvertTo-Json -Compress) -cne ($activeBefore|ConvertTo-Json -Compress)){throw 'Selection recovery preview changed inventory.'}
      $null=Restore-RideRun -RunId $guard.SelectionRunId -Confirm:$false
      $guard.SelectionRecoveryPassed=(Get-FixturePowerInventory).ActiveGuid -eq $powerInventory.ActiveGuid
      $report.SavedRunIds += $guard.SelectionRunId
    }
    $report['OwnedGuard']=$guard
  }
  if(-not $guard.DeletionRefused -or -not $guard.SelectionRecoveryPassed){throw 'Active refusal/selection recovery is incomplete.'}
  $report.GuardValidationPassed=$true
}
function Test-FixtureOwnedSettingDrift {
  $current=Get-RideCurrentState -Operation $operation
  if($current.Active -or -not $current.DestinationExists){throw 'Setting-drift guard requires its own inactive copy.'}
  if(-not ('Ride.FixturePowerRead' -as [type])){
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Ride { public static class FixturePowerRead {
 [DllImport("powrprof.dll")] public static extern uint PowerReadACValueIndex(IntPtr root,ref Guid scheme,ref Guid subgroup,ref Guid setting,out uint value);
} }
'@ -ErrorAction Stop
  }
  [guid]$scheme=$current.DestinationGuid
  [guid]$subgroup='238c9fa8-0aad-41ed-83f4-97be242c8f20'
  [guid]$setting='29f6c1db-86da-48c5-9fdb-f2b67b1f44da'
  [uint32]$old=0
  if([Ride.FixturePowerRead]::PowerReadACValueIndex([IntPtr]::Zero,[ref]$scheme,[ref]$subgroup,[ref]$setting,[ref]$old) -ne 0){throw 'Cannot read the selected owned-copy AC sleep setting.'}
  [uint32]$changed=if($old -eq 120){121}else{120}
  $null=& (Join-Path $env:WINDIR 'System32/powercfg.exe') /setacvalueindex $current.DestinationGuid $subgroup.ToString() $setting.ToString() $changed
  if($LASTEXITCODE -ne 0){throw 'Owned-copy setting drift write failed.'}
  [uint32]$actual=0
  if([Ride.FixturePowerRead]::PowerReadACValueIndex([IntPtr]::Zero,[ref]$scheme,[ref]$subgroup,[ref]$setting,[ref]$actual) -ne 0 -or $actual -ne $changed){throw 'Owned setting mutation readback failed.'}
  $module=Get-FixtureOwnedHandler
  $root=& (Get-Module RIDE.Engine) {Join-Path (Get-RideStateRoot -Scope Machine) 'OwnedPowerPlans'}
  $hash=& $module {param($Id,$Root) Get-RideOwnedPlanExportHash $Id $Root -Logical} $current.DestinationGuid $root
  if($hash -ceq $current.OriginalRecord.ConfigurationSha256){throw 'Real setting mutation did not change the logical fingerprint.'}
  $guard=[ordered]@{Method='AC sleep timeout mutation on the fixture-owned inactive copy';OriginalValue=$old;ChangedValue=$changed;Readback=$actual;LogicalFingerprintChanged=$true;RestorePreviewPassed=$false;DeletionRefused=$false;DestinationRetained=$false;Error=$null;Recovery='CheckpointOnly; changed copy is deliberately retained'}
  $beforePreview=ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)
  $null=Restore-RideRun -RunId $firstRunId -WhatIf -Confirm:$false
  $guard.RestorePreviewPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $beforePreview
  if(-not $guard.RestorePreviewPassed){throw 'Changed-setting restore preview mutated state.'}
  try {$null=Restore-RideRun -RunId $firstRunId -Confirm:$false;throw 'Changed-setting deletion was not refused.'}
  catch {if($_.Exception.Message -notlike '*Owned copy changed or native export is not reproducible*'){throw};$guard.Error=$_.Exception.Message;$guard.DeletionRefused=$true}
  $after=Get-RideCurrentState -Operation $operation
  $guard.DestinationRetained=$after.DestinationExists -and -not $after.Active -and $after.OwnerToken -ceq $current.OwnerToken
  $report['OwnedGuard']=$guard
  if(-not $guard.DestinationRetained -or (Get-FixturePowerInventory).ActiveGuid -ne $powerInventory.ActiveGuid){throw 'Setting drift guard changed unrelated selection or lost ownership.'}
  $report.GuardValidationPassed=$true
}
function Install-FixtureOwnedCreationFault {
  $module=Get-FixtureOwnedHandler
  & $module {
    $script:FixtureOriginalPowerCommand=(Get-Command Invoke-RideOwnedPlanCommand -CommandType Function).ScriptBlock
    $script:FixturePowerCalls=@()
    function script:Invoke-RideOwnedPlanCommand {
      param([string[]]$Arguments)
      $script:FixturePowerCalls += $Arguments[0]
      $result=& $script:FixtureOriginalPowerCommand $Arguments
      if($Arguments[0] -eq '/duplicatescheme' -and $result.ExitCode -eq 0){throw 'RIDE fixture interrupted creation after successful native duplication.'}
      $result
    }
  }
  $module
}
function Test-FixtureOwnedIntentRefusal($Module) {
  $after=Get-RideCurrentState -Operation $operation
  # Absent-state inspections propose fresh random identities. Only the saved
  # pre-write capture is the identity contract used by the actual creation.
  $stateRoot=& (Get-Module RIDE.Engine) {Get-RideStateRoot -Scope Machine}
  $savedPath=Join-Path (Join-Path $stateRoot $firstRunId) ($operation.Id+'.json')
  $saved=Get-Content -LiteralPath $savedPath -Raw -ErrorAction Stop|ConvertFrom-Json
  if($saved.SchemaVersion -ne 1 -or $saved.RunId -cne $firstRunId -or $saved.OperationId -cne $operation.Id -or $saved.Kind -ne 'OwnedPowerPlan' -or $saved.Scope -ne 'Machine'){throw 'Interrupted creation capture is not correlated.'}
  $capture=$saved.Snapshot
  $guard=[ordered]@{Method='Injected interruption after successful native duplication';Stage=$after.Stage;CreationError=$report.CreationInterruption;SavedCapture=$capture;ObservedIntent=$after;RestorePreviewPassed=$false;DeletionRefused=$false;DestinationRetained=$false;Error=$null;NativeCalls=@();Recovery='CheckpointOnly; Intent record and incomplete copy retained'}
  $report['OwnedGuard']=$guard
  if($capture.SnapshotVersion -ne 1 -or $capture.OperationId -cne $operation.Id -or $capture.OriginalOwned -ne $false -or $capture.Stage -ne 'Absent' -or $null -ne $capture.OriginalRecord -or $after.Stage -ne 'Intent' -or -not $after.DestinationExists -or $after.Active -or $after.OwnerToken -cne $capture.OwnerToken -or $after.DestinationGuid -cne $capture.DestinationGuid -or $after.SourceGuid -cne $capture.SourceGuid){throw 'Interrupted creation did not retain the exact captured inactive Intent copy.'}
  $beforePreview=ConvertTo-FixtureState $after
  $null=Restore-RideRun -RunId $firstRunId -WhatIf -Confirm:$false
  $guard.RestorePreviewPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $beforePreview
  if(-not $guard.RestorePreviewPassed){throw 'Intent restore preview mutated state.'}
  try {$null=Restore-RideRun -RunId $firstRunId -Confirm:$false;throw 'Intent-copy deletion was not refused.'}
  catch {if($_.Exception.Message -notlike '*Ownership mismatch or incomplete creation*'){throw};$guard.Error=$_.Exception.Message;$guard.DeletionRefused=$true}
  $check=Get-RideCurrentState -Operation $operation
  $guard.DestinationRetained=$check.Stage -eq 'Intent' -and $check.DestinationExists -and -not $check.Active
  $guard.NativeCalls=& $Module {$script:FixturePowerCalls}
  if('/delete' -in $guard.NativeCalls -or '/changename' -in $guard.NativeCalls -or '/export' -in $guard.NativeCalls){throw 'Interrupted creation unexpectedly continued or attempted deletion.'}
  $report['OwnedGuard']=$guard
  if(-not $guard.DestinationRetained -or (Get-FixturePowerInventory).ActiveGuid -ne $powerInventory.ActiveGuid){throw 'Intent refusal lost ownership or changed selection.'}
  $report.GuardValidationPassed=$true
}
function Invoke-FixtureRegistryFault {
  # This is an injected interruption after a real write, not evidence that the
  # operating system denied access. No override survives this fresh guest process.
  $beforeText=ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)
  $alternate=@($states | Where-Object { -not (Test-RideDesiredState -Operation $operation -State $_) -and $(if($operation.Kind -eq 'RegistryValue'){$null -ne $operation.States[$_]}else{@($operation.States[$_].Values|Where-Object {$_ -is [int] -or $_ -is [string]}).Count -gt 0}) }) | Select-Object -First 1
  if(-not $alternate){throw 'No writable alternate exists for controlled registry failure.'}
  $moduleRoot=if($privateRoot){$privateRoot}else{$sourceRoot}
  $modulePath=Join-Path $moduleRoot 'modules/RIDE-Settings.psm1'
  # Force-imported nested modules can retain several instances with one path.
  # Resolve the module from the exact function the engine will invoke.
  $settingsModule=& (Get-Module RIDE.Engine) {
    param($Kind)
    if($Kind -eq 'RegistryValue'){return (Get-Command Set-RideSettingState -CommandType Function).Module}
    $paired=(Get-Command Set-RideRegistryValueSetState -CommandType Function).Module
    & $paired {(Get-Command Set-RideSettingState -CommandType Function).Module}
  } $operation.Kind
  if(-not $settingsModule){throw 'Cannot identify the exact isolated registry module.'}
  if($settingsModule.Path -ine $modulePath){throw 'Retained registry handler does not belong to the explicit source copy.'}
  $allowed=@(if($operation.Kind -eq 'RegistryValue'){$operation}else{$operation.RegistryValues})
  $fault=[ordered]@{Method='Injected interruption after the first state-changing native New-ItemProperty write';State=$alternate;NativeWrites=0;ChangedMutations=0;RunId=$null;Error=$null;ReadbackAfterFailure=$null;PreviewPassed=$false;RecoveryPassed=$false;RepeatRecoveryPassed=$false}
  $faultRunId=$null
  $injectionInstalled=$false
  try {
    & $settingsModule {
      param($Members)
      if(Get-Command New-ItemProperty -CommandType Function -ErrorAction SilentlyContinue){throw 'An unexpected registry command override already exists.'}
      $script:FixtureAllowedMembers=$Members
      $script:FixtureNativeWrites=0
      $script:FixtureChangedMutations=0
      function script:New-ItemProperty {
        [CmdletBinding()]
        param([string]$LiteralPath,[string]$Name,$Value,[string]$PropertyType,[switch]$Force)
        if(@($script:FixtureAllowedMembers|Where-Object {$_.RegistryPath -ieq $LiteralPath -and $_.ValueName -ceq $Name}).Count -ne 1){throw 'Fault fixture refused an undeclared registry write.'}
        $identity=@{RegistryPath=$LiteralPath;ValueName=$Name}
        $before=Get-RideSettingState -Operation $identity|ConvertTo-Json -Depth 8 -Compress
        $null=Microsoft.PowerShell.Management\New-ItemProperty @PSBoundParameters
        $script:FixtureNativeWrites++
        $after=Get-RideSettingState -Operation $identity|ConvertTo-Json -Depth 8 -Compress
        if($after -cne $before){
          $script:FixtureChangedMutations++
          throw 'RIDE fixture injected interruption after a successful native registry mutation.'
        }
      }
    } $allowed
    $injectionInstalled=$true
    try { $unexpected=@(Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $alternate) -Confirm:$false); $faultRunId=Get-FixtureRunId $unexpected; $fault.RunId=$faultRunId; throw 'Controlled native-write interruption did not trigger.' }
    catch {
      $fault.Error=$_.Exception.Message
      if($fault.Error -match 'Run ID: ([0-9a-f]{32})'){$faultRunId=$Matches[1];$fault.RunId=$faultRunId}
      if($fault.Error -notlike '*injected interruption after a successful native registry mutation*' -or -not $faultRunId){throw}
    }
  }
  finally {
    if($injectionInstalled){
      $fault.NativeWrites=& $settingsModule {$script:FixtureNativeWrites}
      $fault.ChangedMutations=& $settingsModule {$script:FixtureChangedMutations}
      & $settingsModule {Remove-Item Function:New-ItemProperty -Force -ErrorAction Stop;Remove-Variable FixtureAllowedMembers,FixtureNativeWrites,FixtureChangedMutations -Scope Script -ErrorAction SilentlyContinue}
    }
    if($faultRunId){
      try {
        $fault.ReadbackAfterFailure=Get-RideCurrentState -Operation $operation
        if($fault.NativeWrites -lt 1 -or $fault.ChangedMutations -ne 1 -or (ConvertTo-FixtureState $fault.ReadbackAfterFailure) -ceq $beforeText){throw 'Controlled fault did not retain evidence of exactly one state-changing native mutation.'}
        $failureText=ConvertTo-FixtureState $fault.ReadbackAfterFailure
        $null=Restore-RideRun -RunId $faultRunId -WhatIf -Confirm:$false
        $fault.PreviewPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $failureText
      }finally{
        $null=Restore-RideRun -RunId $faultRunId -Confirm:$false
        $fault.RecoveryPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $beforeText
      }
      $null=Restore-RideRun -RunId $faultRunId -Confirm:$false
      $fault.RepeatRecoveryPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $beforeText
    }
    $report['ControlledFailure']=$fault
  }
  if(-not $faultRunId -or -not $fault.PreviewPassed -or -not $fault.RecoveryPassed -or -not $fault.RepeatRecoveryPassed){throw 'Controlled registry-failure preview/recovery was incomplete.'}
  $report.SavedRunIds += $faultRunId
  $report.PendingEvidence=@('GUI/session and actual feature behavior','Other native failures beyond the controlled interruption','Target defaults and managed precedence')
}
function Invoke-FixtureFirewallFault {
  $before=Get-RideCurrentState -Operation $operation
  $beforeText=ConvertTo-FixtureState $before
  if(@($before.Entries|Where-Object Value -eq 'False').Count -lt 2){throw 'Partial-completion fixture needs two local profiles Off.'}
  $module=& (Get-Module RIDE.Engine) {
    $managed=(Get-Command Set-RideManagedSettingState -CommandType Function).Module
    & $managed {(Get-Command Set-RideFirewallProfileState -CommandType Function).Module}
  }
  $moduleRoot=if($privateRoot){$privateRoot}else{$sourceRoot}
  if(-not $module -or $module.Path -ine (Join-Path $moduleRoot 'modules/RIDE-FirewallProfiles.psm1')){throw 'Cannot identify the retained firewall handler.'}
  $fault=[ordered]@{Method='Injected interruption before the second profile setter after one real native change';State='On';NativeWrites=0;ChangedMutations=0;RunId=$null;Error=$null;ReadbackAfterFailure=$null;PreviewPassed=$false;RecoveryPassed=$false;RepeatRecoveryPassed=$false}
  $id=$null;$installed=$false
  try {
    & $module {
      param($Names)
      $existing=Get-Command Set-NetFirewallProfile -CommandType Function -ErrorAction SilentlyContinue
      if($existing -and $existing.ModuleName -ne 'NetSecurity'){throw 'Unexpected firewall command override.'}
      $script:FixtureNames=$Names;$script:FixtureWrites=0
      function script:Set-NetFirewallProfile {
        [CmdletBinding()]
        param([string[]]$Name,[string]$PolicyStore,$Enabled)
        if($PolicyStore -ne 'PersistentStore' -or $Name.Count -ne 1 -or $Name[0] -notin $script:FixtureNames){throw 'Refused undeclared firewall mutation.'}
        if($script:FixtureWrites -ge 1){throw 'RIDE fixture injected interruption before the second native firewall write.'}
        $null=NetSecurity\Set-NetFirewallProfile @PSBoundParameters
        $script:FixtureWrites++
      }
    } @($operation.FirewallProfiles)
    $installed=$true
    try {$output=@(Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State On) -Confirm:$false);$id=Get-FixtureRunId $output;throw 'Firewall controlled interruption did not trigger.'}
    catch {
      $fault.Error=$_.Exception.Message
      if($fault.Error -match 'Run ID: ([0-9a-f]{32})'){$id=$Matches[1]}
      if(-not $id -or $fault.Error -notlike '*injected interruption before the second native firewall write*' -or $fault.Error -notlike '*Completed profiles: Domain*'){throw}
    }
  } finally {
    if($installed){$fault.NativeWrites=& $module {$script:FixtureWrites};& $module {Remove-Item Function:Set-NetFirewallProfile -Force -ErrorAction Stop;Remove-Variable FixtureNames,FixtureWrites -Scope Script -ErrorAction SilentlyContinue}}
    $fault.RunId=$id
    if($id){
      try {
        $fault.ReadbackAfterFailure=Get-RideCurrentState -Operation $operation
        $fault.ChangedMutations=@($fault.ReadbackAfterFailure.Entries|Where-Object {$entry=$_;@($before.Entries|Where-Object {$_.Name -eq $entry.Name -and $_.Value -ne $entry.Value}).Count}).Count
        if($fault.NativeWrites -ne 1 -or $fault.ChangedMutations -ne 1){throw 'Native partial completion was not exactly one profile.'}
        $changed=ConvertTo-FixtureState $fault.ReadbackAfterFailure
        $null=Restore-RideRun -RunId $id -WhatIf -Confirm:$false
        $fault.PreviewPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $changed
      }finally{$null=Restore-RideRun -RunId $id -Confirm:$false;$fault.RecoveryPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $beforeText}
      $null=Restore-RideRun -RunId $id -Confirm:$false
      $fault.RepeatRecoveryPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $beforeText
    }
    $report['ControlledFailure']=$fault
  }
  if(-not $id -or -not $fault.PreviewPassed -or -not $fault.RecoveryPassed -or -not $fault.RepeatRecoveryPassed){throw 'Controlled firewall recovery was incomplete.'}
  $report.SavedRunIds += $id
  $report.PendingEvidence=@('GUI/connection and actual protection behavior','Other native failures beyond the controlled interruption','Target defaults and managed precedence')
}
function Invoke-FixtureConfigurationFault {
  $before=Get-RideCurrentState -Operation $operation
  $beforeText=ConvertTo-FixtureState $before
  $alternate=@($states|Where-Object {-not (Test-RideDesiredState -Operation $operation -State $_) -and $(if($operation.Kind -eq 'WindowsService'){$operation.States[$_].StartupType -ne $before.StartupType}else{$true})})|Select-Object -First 1
  if(-not $alternate){throw 'No focused configuration alternate is available.'}
  $module=& (Get-Module RIDE.Engine) {
    param($Kind)
    if($Kind -eq 'WindowsService'){return (Get-Command Set-RideWindowsServiceState -CommandType Function).Module}
    return (Get-Command Set-RideLocalPasswordAgeState -CommandType Function).Module
  } $operation.Kind
  $moduleRoot=if($privateRoot){$privateRoot}else{$sourceRoot}
  $moduleFile=if($operation.Kind -eq 'WindowsService'){'RIDE-Services.psm1'}else{'RIDE-LocalPasswordAge.psm1'}
  if(-not $module -or $module.Path -ine (Join-Path $moduleRoot ('modules/'+$moduleFile))){throw 'Cannot identify the retained focused handler.'}
  $fault=[ordered]@{Method='Injected interruption after a real focused native configuration write';State=$alternate;NativeWrites=0;ChangedMutations=0;RunId=$null;Error=$null;ReadbackAfterFailure=$null;PreviewPassed=$false;RecoveryPassed=$false;RepeatRecoveryPassed=$false}
  $id=$null;$installed=$false
  try {
    & $module {
      param($Kind,$ServiceName)
      $script:FixtureWrites=0;$script:FixtureServiceName=$ServiceName
      if($Kind -eq 'WindowsService'){
        if(Get-Command Set-Service -CommandType Function -ErrorAction SilentlyContinue){throw 'Unexpected service command override.'}
        function script:Set-Service {
          [CmdletBinding()]
          param([string]$Name,[string]$StartupType)
          if($Name -cne $script:FixtureServiceName){throw 'Refused collateral service mutation.'}
          $null=Microsoft.PowerShell.Management\Set-Service @PSBoundParameters
          $script:FixtureWrites++
          throw 'RIDE fixture injected interruption after a focused native configuration write.'
        }
      }else{
        $script:FixtureOriginalSetter=(Get-Command Set-RideLocalPasswordAgeNative -CommandType Function).ScriptBlock
        function script:Set-RideLocalPasswordAgeNative {
          param([uint32]$Seconds)
          & $script:FixtureOriginalSetter $Seconds
          $script:FixtureWrites++
          throw 'RIDE fixture injected interruption after a focused native configuration write.'
        }
      }
    } $operation.Kind $operation.ServiceName
    $installed=$true
    try {$output=@(Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $alternate) -Confirm:$false);$id=Get-FixtureRunId $output;throw 'Controlled configuration interruption did not trigger.'}
    catch {
      $fault.Error=$_.Exception.Message
      if($fault.Error -match 'Run ID: ([0-9a-f]{32})'){$id=$Matches[1]}
      if(-not $id -or $fault.Error -notlike '*injected interruption after a focused native configuration write*'){throw}
    }
  }finally{
    if($installed){
      $fault.NativeWrites=& $module {$script:FixtureWrites}
      & $module {
        param($Kind)
        if($Kind -eq 'WindowsService'){Remove-Item Function:Set-Service -Force -ErrorAction Stop}
        else{Set-Item Function:script:Set-RideLocalPasswordAgeNative -Value $script:FixtureOriginalSetter -ErrorAction Stop}
        Remove-Variable FixtureWrites,FixtureServiceName,FixtureOriginalSetter -Scope Script -ErrorAction SilentlyContinue
      } $operation.Kind
    }
    $fault.RunId=$id
    if($id){
      try {
        $fault.ReadbackAfterFailure=Get-RideCurrentState -Operation $operation
        $fault.ChangedMutations=if((ConvertTo-FixtureState $fault.ReadbackAfterFailure) -cne $beforeText){1}else{0}
        if($fault.NativeWrites -ne 1 -or $fault.ChangedMutations -ne 1){throw 'Focused native configuration mutation was not evidenced.'}
        $changed=ConvertTo-FixtureState $fault.ReadbackAfterFailure
        $null=Restore-RideRun -RunId $id -WhatIf -Confirm:$false
        $fault.PreviewPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $changed
      }finally{$null=Restore-RideRun -RunId $id -Confirm:$false;$fault.RecoveryPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $beforeText}
      $null=Restore-RideRun -RunId $id -Confirm:$false
      $fault.RepeatRecoveryPassed=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq $beforeText
    }
    $report['ControlledFailure']=$fault
  }
  if(-not $id -or -not $fault.PreviewPassed -or -not $fault.RecoveryPassed -or -not $fault.RepeatRecoveryPassed){throw 'Controlled configuration recovery was incomplete.'}
  $report.SavedRunIds += $id
  $report.PendingEvidence=@('GUI/session and actual feature behavior','Other native failures beyond the controlled interruption','Target defaults and managed precedence')
}
try {
  if ($candidate) {
    # Only a guest-private source copy is changed. AST extents identify exactly
    # the selected catalog table; no global regex replacement or public widening.
    $privateRoot = Join-Path $env:TEMP ('RIDE-settings-fixture-' + $fixture.RunId)
    if (Test-Path -LiteralPath $privateRoot) { throw 'Private fixture directory already exists.' }
    $null = New-Item -ItemType Directory -Path $privateRoot
    foreach ($directory in @('modules','catalog','profiles','components')) { Copy-Item -LiteralPath (Join-Path $sourceRoot $directory) -Destination $privateRoot -Recurse }
    $catalogPath = Join-Path $privateRoot 'catalog/operations.psd1'
    $text = [IO.File]::ReadAllText($catalogPath)
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Source catalog has parser errors.' }
    $tables=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.HashtableAst]},$true) | Where-Object { @($_.KeyValuePairs | Where-Object { $_.Item1.Value -eq 'Id' -and $_.Item2.Extent.Text -ceq ("'"+$fixture.OperationId+"'") }).Count -eq 1 })
    if ($tables.Count -ne 1) { throw 'Candidate catalog table is not unique.' }
    $support=@($tables[0].KeyValuePairs | Where-Object { $_.Item1.Value -eq 'SupportedTargets' })
    $defaults=@($tables[0].KeyValuePairs | Where-Object { $_.Item1.Value -eq 'TargetDefaults' })
    if ($support.Count -ne 1 -or $defaults.Count -ne 1 -or $support[0].Item2.Extent.Text -ne '@()' -or $defaults[0].Item2.Extent.Text -ne '@{}') { throw 'Candidate support/default contract is not the expected empty declaration.' }
    $edits=@(
      @{ Extent=$support[0].Item2.Extent; Text="@('$target')" }
      @{ Extent=$defaults[0].Item2.Extent; Text="@{ '$target' = @{ DefaultValueExists = `$null; DefaultValue = `$null; EffectiveDefault = 'Integration fixture only; defaults remain unverified' } }" }
    )
    if($scenario -eq 'ActiveRefusal' -and $target -eq 'Windows Server 2025'){
      $selectionTables=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.HashtableAst]},$true)|Where-Object {@($_.KeyValuePairs|Where-Object {$_.Item1.Value -eq 'Id' -and $_.Item2.Extent.Text -ceq "'windows.active-power-scheme'"}).Count -eq 1})
      if($selectionTables.Count -ne 1){throw 'Private selection fixture entry is not unique.'}
      $selectionSupport=@($selectionTables[0].KeyValuePairs|Where-Object {$_.Item1.Value -eq 'SupportedTargets'})
      $selectionDefaults=@($selectionTables[0].KeyValuePairs|Where-Object {$_.Item1.Value -eq 'TargetDefaults'})
      if($selectionSupport.Count -ne 1 -or $selectionDefaults.Count -ne 1){throw 'Private selection fixture metadata missing.'}
      $edits += @{Extent=$selectionSupport[0].Item2.Extent;Text="@('$target')"}
      $edits += @{Extent=$selectionDefaults[0].Item2.Extent;Text="@{ '$target' = @{ DefaultValue = 'Unverified fixture'; EffectiveDefault = 'Isolated selection recovery only' } }"}
    }
    foreach ($edit in @($edits | Sort-Object { $_.Extent.StartOffset } -Descending)) { $text=$text.Substring(0,$edit.Extent.StartOffset)+$edit.Text+$text.Substring($edit.Extent.EndOffset) }
    [IO.File]::WriteAllText($catalogPath,$text,[Text.UTF8Encoding]::new($false))
    $report.FixtureCatalogSHA256=(Get-FileHash -LiteralPath $catalogPath).Hash
    Remove-Module RIDE.Engine -Force
    Import-Module (Join-Path $privateRoot 'modules/RIDE.Engine.psm1') -Force
    $operation=Get-RideOperation -Id $fixture.OperationId
  }
  $original=Get-RideCurrentState -Operation $operation
  if($operation.Kind -eq 'OwnedPowerPlan'){
    if($original.OriginalOwned -or $original.DestinationExists){throw 'Owned-copy fixture requires absent ownership; never adopt an existing plan.'}
    if(-not $original.SourceAvailable){throw 'Source template unavailable; creation acceptance remains pending.'}
    $powerInventory=Get-FixturePowerInventory
    $report['PowerInventoryOriginal']=$powerInventory
  }
  if ($operation.Kind -eq 'FirewallProfile' -and @($operation.FirewallProfiles).Count -eq 3) {
    if (-not $original.CanRestoreLocal) { throw 'Enable-all seed requires recoverable local flags.' }
    # Prepare only the profiles owned by this operation. The seed is independent
    # of saved-run acceptance and has its own finally recovery to the clean state.
    $seedSnapshot=$original | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    foreach ($entry in $seedSnapshot.Entries) { $entry | Add-Member NoteProperty ExpectedValue $(if ($entry.Name -in @('Domain','Private')) {'False'} else {'True'}) }
    foreach ($entry in $seedSnapshot.Entries) { Set-NetFirewallProfile -Name $entry.Name -PolicyStore PersistentStore -Enabled $entry.ExpectedValue -ErrorAction Stop | Out-Null }
    $original=Get-RideCurrentState -Operation $operation
    $report['SeedOriginal']=$seedSnapshot
    $report['SeedRecoveryPassed']=$false
  }
  $report.Original=$original
  $originalText=ConvertTo-FixtureState $original
  if ($operation.Kind -eq 'WindowsService' -and $original.Status -notin @('Running','Stopped','Paused')) { throw 'Transient service runtime is not an acceptance baseline.' }
  $first=@($states | Where-Object { -not (Test-RideDesiredState -Operation $operation -State $_) }) | Select-Object -First 1
  if (-not $first) { throw 'No alternate declared state is available for captured recovery.' }
  $plan=@(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $first)
  $null=Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false
  if ((ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -cne $originalText) { throw 'Apply preview changed captured state.' }
  if($scenario -eq 'InterruptedCreation'){$creationFaultModule=Install-FixtureOwnedCreationFault}
  try { $output=@(Invoke-RidePlan -Plan $plan -Confirm:$false); $firstRunId=Get-FixtureRunId $output;if($scenario -eq 'InterruptedCreation'){throw 'Creation interruption did not trigger.'} }
  catch {
    if ($_.Exception.Message -match 'Run ID: ([0-9a-f]{32})') { $firstRunId=$Matches[1] }
    if($scenario -ne 'InterruptedCreation' -or -not $firstRunId -or $_.Exception.Message -notlike '*interrupted creation after successful native duplication*'){throw}
    $report['CreationInterruption']=$_.Exception.Message
  }
  if (-not $firstRunId) { throw 'No pre-change saved run was returned.' }
  $report.SavedRunIds += $firstRunId
  if($scenario -eq 'InterruptedCreation'){
    Test-FixtureOwnedIntentRefusal $creationFaultModule
  }else{
  foreach ($state in $states) {
    $before=Get-RideCurrentState -Operation $operation
    $plan=@(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $state)
    try { $output=@(Invoke-RidePlan -Plan $plan -Confirm:$false) }
    catch { if ($_.Exception.Message -match 'Run ID: ([0-9a-f]{32})') { $report.SavedRunIds += $Matches[1] }; throw }
    $savedId=Get-FixtureRunId $output
    if ($savedId) { $report.SavedRunIds += $savedId }
    Wait-FixtureState $operation $state
    $after=Get-RideCurrentState -Operation $operation
    if($operation.Kind -eq 'OwnedPowerPlan'){
      $inventory=Get-FixturePowerInventory
      if($after.Stage -ne 'Ready' -or -not $after.DestinationExists -or $after.Active -or $inventory.ActiveGuid -ne $powerInventory.ActiveGuid -or @($inventory.Guids|Where-Object {$_ -notin $powerInventory.Guids}).Count -ne 1 -or $after.DestinationGuid -notin $inventory.Guids -or @($powerInventory.Guids|Where-Object {$_ -notin $inventory.Guids}).Count){throw 'Creation changed selection or unrelated power-plan identities.'}
    }
    if ($operation.Kind -eq 'WindowsService' -and -not $operation.States[$state].ContainsKey('Status') -and $before.Status -ne $after.Status) { throw 'Startup-only state changed service runtime.' }
    $repeat=@(Invoke-RidePlan -Plan $plan -Confirm:$false)
    if ('No changes were needed; no state record was created.' -notin $repeat) { throw 'Repeat apply was not idempotent.' }
    $report.States += [pscustomobject]@{State=$state;Readback=$after;RepeatApplyPassed=$true}
    Write-Output "Fixture lifecycle state passed: $($operation.Id) / $state"
  }
  if($operation.Kind -eq 'OwnedPowerPlan'){
    switch($scenario){
      ActiveRefusal {Test-FixtureOwnedActiveRefusal}
      SettingDrift {Test-FixtureOwnedSettingDrift}
      default {$report['ExportObservation']=Get-FixtureOwnedExportObservation (Get-RideCurrentState -Operation $operation);Test-FixtureOwnedDriftRefusal}
    }
  }
  if ($operation.BaselineState) {
    $baseline=@{SchemaVersion=1;Name='Explicit setting fixture baseline';Operations=@(@{Id=$operation.Id;State=$operation.BaselineState})}
    $baselineOutput=@(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $baseline) -Confirm:$false)
    $baselineId=Get-FixtureRunId $baselineOutput
    if($baselineId){$report.SavedRunIds += $baselineId}
    Wait-FixtureState $operation $operation.BaselineState
  }
  $beforeRestore=ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)
  $null=Restore-RideRun -RunId $firstRunId -WhatIf -Confirm:$false
  if ((ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -cne $beforeRestore) { throw 'Restore preview changed captured state.' }
  if($scenario -notin @('SettingDrift','InterruptedCreation')){$report.LifecyclePassed=$true}
  }
}
catch { $report.Error=$_.Exception.Message }
finally {
  if($creationFaultModule){
    & $creationFaultModule {Set-Item Function:script:Invoke-RideOwnedPlanCommand -Value $script:FixtureOriginalPowerCommand;Remove-Variable FixtureOriginalPowerCommand,FixturePowerCalls -Scope Script -ErrorAction SilentlyContinue}
  }
  if ($firstRunId -and $scenario -notin @('SettingDrift','InterruptedCreation')) {
    try {
      if($operation.Kind -eq 'LocalPasswordMaximumAge'){
        # Every maximum-age run captures its expected post-write value. Later
        # fixture runs are owned changes, so unwind them rather than bypass drift.
        $restoreIds=@($report.SavedRunIds|Select-Object -Unique)
        [array]::Reverse($restoreIds)
        $report['RecoverySequence']=@()
        foreach($savedId in $restoreIds){
          $priorPreview=ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)
          $null=Restore-RideRun -RunId $savedId -WhatIf -Confirm:$false
          if((ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -cne $priorPreview){throw 'Sequential maximum-age recovery preview changed state.'}
          $null=Restore-RideRun -RunId $savedId -Confirm:$false
          $report.RecoverySequence += [pscustomobject]@{RunId=$savedId;PreviewPassed=$true;Readback=Get-RideCurrentState -Operation $operation}
        }
      }else{$null=Restore-RideRun -RunId $firstRunId -Confirm:$false}
      $report.Restored=Get-RideCurrentState -Operation $operation
      $report.RecoveryPassed=(ConvertTo-FixtureState $report.Restored) -ceq $originalText
      if($operation.Kind -eq 'OwnedPowerPlan'){
        $report['PowerInventoryRestored']=Get-FixturePowerInventory
        $report.RecoveryPassed=$report.RecoveryPassed -and (($report.PowerInventoryRestored|ConvertTo-Json -Depth 8 -Compress) -ceq ($powerInventory|ConvertTo-Json -Depth 8 -Compress))
        $report.ExactRecovery=$false
      }else{$report.ExactRecovery=$report.RecoveryPassed}
      if (-not $report.RecoveryPassed) { throw 'Declared captured-state recovery failed.' }
      if($operation.Kind -in @('RegistryValue','RegistryValueSet') -and $report.LifecyclePassed){Invoke-FixtureRegistryFault}
      if($operation.Kind -eq 'FirewallProfile' -and @($operation.FirewallProfiles).Count -eq 3 -and $report.LifecyclePassed){Invoke-FixtureFirewallFault}
      if($operation.Kind -in @('WindowsService','LocalPasswordMaximumAge') -and $report.LifecyclePassed){Invoke-FixtureConfigurationFault}
    } catch { $report.RecoveryError=$_.Exception.Message }
  }
  if ($seedSnapshot) {
    try {
      $null=& (Get-Module RIDE.Engine) {param($Selected,$Seed) Restore-RideManagedSettingState -Operation $Selected -Snapshot $Seed} $operation $seedSnapshot
      $report['SeedRecoveryPassed']=(ConvertTo-FixtureState (Get-RideCurrentState -Operation $operation)) -ceq (ConvertTo-FixtureState $seedSnapshot)
      if (-not $report.SeedRecoveryPassed) { throw 'Enable-all seed recovery failed.' }
    } catch { $report.RecoveryError=$_.Exception.Message }
  }
  if((($report.LifecyclePassed -and $report.RecoveryPassed) -or ($report.GuardValidationPassed -and $report.RecoveryMode -eq 'CheckpointOnly')) -and -not $report.Error -and -not $report.RecoveryError){$report.Status='Passed'}
  $report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
  if ($privateRoot) {
    $expected=[IO.Path]::GetFullPath((Join-Path $env:TEMP ('RIDE-settings-fixture-'+$fixture.RunId)))
    if ([IO.Path]::GetFullPath($privateRoot) -cne $expected -or $expected -notlike ([IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\RIDE-settings-fixture-*')) { throw 'Private fixture cleanup path escaped its owned temporary root.' }
    Remove-Item -LiteralPath $privateRoot -Recurse -Force
  }
}
if ($report.Status -ne 'Passed') { Write-Error ("Fixture failed: $($report.Error) Recovery: $($report.RecoveryError)"); exit 1 }
if($report.RecoveryMode -eq 'CheckpointOnly'){
  Write-Output "Setting fixture passed $scenario refusal guard; RIDE recovery did not occur and host checkpoint cleanup is required: $($operation.Id)"
}else{
  Write-Output "Setting fixture passed lifecycle and captured recovery; feature/GUI and deliberate partial-failure evidence remain pending: $($operation.Id)"
}
