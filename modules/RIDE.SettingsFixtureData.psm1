<#
.SYNOPSIS
  Read and validate bounded, request-bound disposable settings fixture metadata.
.DESCRIPTION
  Reads data and catalog declarations only. Imports no operational engine and
  invokes no Windows handler, installer or publisher. Rejects broad/package
  selection and unapproved candidate targets before integration can start.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: 0.10.0.
  Changelog: 0.10.0: Bound the isolated minimum-age conflict to maximum-age Days1.
    0.9.0: Add schema-7 isolated desktop Plan actor; no app action selection.
    0.8.0: Add schema-6 read-only disposable desktop resource probe.
    0.7.0: Add schema-5 non-mutating Store app guard preflight.
    0.6.0: Add schema-4 separate user/provisioning reference collection.
    0.5.0: Add schema-3 read-only Store inventory with expected guest identity.
    0.4.0: Add schema-2 explicit owned guard scenarios; retain schema 1.
    0.3.0: Include owned-copy compensating recovery fixtures.
    0.2.0: Include bounded firewall and local maximum-age fixtures.
    0.1.0: Validate correlated single-setting fixture contracts.
#>
Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -ErrorAction Stop
$ErrorActionPreference='Stop'
function Get-RideSettingsFixtureScenario {
  <#
  .SYNOPSIS
    Enumerate the finite settings fixture scenarios without operational imports.
  .OUTPUTS
    String. Scenario names shared by validation and optional completion.
  #>
  'Lifecycle'; 'ActiveRefusal'; 'SettingDrift'; 'InterruptedCreation'; 'StoreInventory'; 'StoreReferenceInventory'; 'StoreAppPreflight'; 'StoreDesktopProbe'; 'StoreDesktopPlan'; 'MinimumAgeConflict'
}
function Read-RideSettingsFixture {
  <#
  .SYNOPSIS
    Validate a single-setting fixture against the exact request and source catalog.
  .PARAMETER Path
    Literal path to a bounded PowerShell data file.
  .PARAMETER RunId
    Expected correlated lowercase hexadecimal request ID.
  .PARAMETER IntegrationSuite
    Expected named settings-only suite; the fixture replaces its broad batch.
  .PARAMETER CatalogPath
    Literal path to the same source catalog used by the guest engine.
  .OUTPUTS
    PSCustomObject with Fixture metadata and the resolved Operation declaration.
  .NOTES
    Read-only data validation; module version and compatibility apply.
  #>
  param([Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$RunId,
    [Parameter(Mandatory)][ValidateSet('SettingsBatch40','SettingsBatch60','SettingsBatch60Recovery','SettingsRemainingBatch1','SettingsRemainingBatch2')][string]$IntegrationSuite,
    [Parameter(Mandatory)][string]$CatalogPath)
  if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 16384) { throw 'Settings fixture exceeds its data bound.' }
  $fixture=Import-PowerShellDataFile -LiteralPath $Path
  if($fixture.SchemaVersion -in @(5,7)){
    $keys=@('SchemaVersion','RunId','IntegrationSuite','Target','Scenario','ExpectedUserSid','ExpectedUserName','SelectionId')
    $expected=if($fixture.SchemaVersion -eq 5){'StoreAppPreflight'}else{'StoreDesktopPlan'}
    if($fixture.Count -ne $keys.Count -or @($fixture.Keys|Where-Object {$_ -notin $keys}).Count -or $fixture.RunId -cne $RunId -or $fixture.IntegrationSuite -cne $IntegrationSuite -or $fixture.Target -notin @('Windows 11','Windows Server 2025') -or $fixture.Scenario -cne $expected -or $fixture.ExpectedUserSid -notmatch '^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$' -or $fixture.ExpectedUserName -notmatch '^[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+$'){throw 'Invalid or uncorrelated non-mutating Store preflight fixture.'}
    $catalog=Import-RideCatalogData -Path $CatalogPath
    $group=@($catalog.Groups|Where-Object {$_.Id -ceq $fixture.SelectionId -and $_.Workflow -ceq 'StoreApps'})
    if($group.Count -ne 1 -or @($group[0].Members).Count -gt 32){throw 'Store preflight requires a declared Store app group.'}
    $members=@($catalog.Operations|Where-Object {$_.Id -in $group[0].Members})
    if($members.Count -ne @($group[0].Members).Count -or @($members|Where-Object {$_.Kind -ne 'StoreApp' -or -not $_.PendingAcceptance -or @($_.SupportedTargets).Count -or $fixture.Target -notin $_.CandidateTargets}).Count){throw 'Store preflight cannot mutate or widen accepted/package operations.'}
    return [pscustomobject]@{Fixture=$fixture;Operation=$null}
  }
  if($fixture.SchemaVersion -in @(3,4,6)){
    $inventoryKeys=@('SchemaVersion','RunId','IntegrationSuite','Target','Scenario','ExpectedUserSid','ExpectedUserName')
    $expectedScenario=if($fixture.SchemaVersion -eq 3){'StoreInventory'}elseif($fixture.SchemaVersion -eq 4){'StoreReferenceInventory'}else{'StoreDesktopProbe'}
    if($fixture -isnot [hashtable] -or $fixture.Count -ne $inventoryKeys.Count -or @($fixture.Keys|Where-Object {$_ -notin $inventoryKeys}).Count -or $fixture.RunId -cne $RunId -or $fixture.IntegrationSuite -cne $IntegrationSuite -or $fixture.Target -notin @('Windows 11','Windows Server 2025') -or $fixture.Scenario -cne $expectedScenario -or $fixture.ExpectedUserSid -notmatch '^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$' -or $fixture.ExpectedUserName -isnot [string] -or $fixture.ExpectedUserName -notmatch '^[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+$') {throw 'Invalid or uncorrelated read-only inventory fixture.'}
    return [pscustomobject]@{Fixture=$fixture;Operation=$null}
  }
  $keys=@('SchemaVersion','RunId','IntegrationSuite','Target','OperationId','States','AllowPendingCandidate')
  if($fixture.SchemaVersion -eq 2){$keys += 'Scenario'}
  if ($fixture -isnot [hashtable] -or $fixture.Count -ne $keys.Count -or @($fixture.Keys | Where-Object { $_ -notin $keys }).Count -or $fixture.SchemaVersion -notin @(1,2) -or $fixture.RunId -cne $RunId -or $fixture.IntegrationSuite -cne $IntegrationSuite -or $fixture.AllowPendingCandidate -isnot [bool] -or $fixture.Target -notin @('Windows 11','Windows Server 2025')) { throw 'Invalid or uncorrelated settings fixture.' }
  if($fixture.SchemaVersion -eq 2 -and ($fixture.Scenario -isnot [string] -or $fixture.Scenario -cnotin @(Get-RideSettingsFixtureScenario) -or $fixture.Scenario -in @('StoreInventory','StoreReferenceInventory','StoreAppPreflight','StoreDesktopProbe','StoreDesktopPlan'))){throw 'Unknown fixture scenario.'}
  $catalog=Import-RideCatalogData -Path $CatalogPath
  $matches=@($catalog.Operations | Where-Object Id -CEQ $fixture.OperationId)
  if ($matches.Count -ne 1) { throw 'Fixture operation is not a unique catalog ID.' }
  $operation=$matches[0]
  if($fixture.SchemaVersion -eq 2 -and $fixture.Scenario -eq 'MinimumAgeConflict'){
    if($operation.Id -cne 'windows.local-password-maximum-age' -or $operation.Kind -ne 'LocalPasswordMaximumAge' -or @($fixture.States).Count -ne 1 -or $fixture.States[0] -cne 'Days1'){throw 'Minimum-age conflict requires exactly the local maximum-age Days1 selection.'}
  }elseif($fixture.SchemaVersion -eq 2 -and $fixture.Scenario -ne 'Lifecycle' -and $operation.Kind -ne 'OwnedPowerPlan'){throw 'Guard scenarios require an owned power-plan operation.'}
  if ($operation.Kind -notin @('RegistryValue','RegistryValueSet','WindowsService','FirewallProfile','LocalPasswordMaximumAge','OwnedPowerPlan') -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { throw 'Fixture requires an implemented captured settings family; packages are forbidden.' }
  $states=@($fixture.States)
  if ($states.Count -lt 1 -or $states.Count -gt 16 -or @($states | Select-Object -Unique).Count -ne $states.Count) { throw 'Fixture states must be bounded, nonempty and unique.' }
  foreach ($state in $states) { if ($state -isnot [string] -or -not $operation.States.ContainsKey($state)) { throw 'Fixture state is not declared in the source catalog.' } }
  $candidate=$fixture.Target -notin $operation.SupportedTargets
  if ($candidate -and (-not $fixture.AllowPendingCandidate -or -not $operation.PendingAcceptance -or $fixture.Target -notin $operation.CandidateTargets)) { throw 'Candidate target requires explicit applicable fixture approval.' }
  if (-not $candidate -and $fixture.AllowPendingCandidate) { throw 'Do not widen an already supported operation.' }
  [pscustomobject]@{Fixture=$fixture;Operation=$operation}
}
Export-ModuleMember -Function Read-RideSettingsFixture,Get-RideSettingsFixtureScenario
