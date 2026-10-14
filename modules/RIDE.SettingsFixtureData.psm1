<#
.SYNOPSIS
  Read and validate bounded, request-bound disposable settings fixture metadata.
.DESCRIPTION
  Reads data and catalog declarations only. Imports no operational engine and
  invokes no Windows handler, installer or publisher. Rejects broad/package
  selection and unapproved candidate targets before integration can start.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: 0.4.0.
  Changelog: 0.4.0: Add schema-2 explicit owned guard scenarios; retain schema 1.
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
  'Lifecycle'; 'ActiveRefusal'; 'SettingDrift'; 'InterruptedCreation'
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
  $keys=@('SchemaVersion','RunId','IntegrationSuite','Target','OperationId','States','AllowPendingCandidate')
  if($fixture.SchemaVersion -eq 2){$keys += 'Scenario'}
  if ($fixture -isnot [hashtable] -or $fixture.Count -ne $keys.Count -or @($fixture.Keys | Where-Object { $_ -notin $keys }).Count -or $fixture.SchemaVersion -notin @(1,2) -or $fixture.RunId -cne $RunId -or $fixture.IntegrationSuite -cne $IntegrationSuite -or $fixture.AllowPendingCandidate -isnot [bool] -or $fixture.Target -notin @('Windows 11','Windows Server 2025')) { throw 'Invalid or uncorrelated settings fixture.' }
  if($fixture.SchemaVersion -eq 2 -and ($fixture.Scenario -isnot [string] -or $fixture.Scenario -cnotin @(Get-RideSettingsFixtureScenario))){throw 'Unknown fixture scenario.'}
  $catalog=Import-RideCatalogData -Path $CatalogPath
  $matches=@($catalog.Operations | Where-Object Id -CEQ $fixture.OperationId)
  if ($matches.Count -ne 1) { throw 'Fixture operation is not a unique catalog ID.' }
  $operation=$matches[0]
  if($fixture.SchemaVersion -eq 2 -and $fixture.Scenario -ne 'Lifecycle' -and $operation.Kind -ne 'OwnedPowerPlan'){throw 'Guard scenarios require an owned power-plan operation.'}
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
