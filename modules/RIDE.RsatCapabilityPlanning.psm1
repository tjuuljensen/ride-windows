<#
.SYNOPSIS
  Order all observed client RSAT capabilities and their recovery from saved inventory.
.DESCRIPTION
  Selects every RSAT capability in a completed capability inventory, validates the
  reviewed dependency model, and prepares install/removal plus reverse recovery
  steps. Does not query Windows, acquire payloads, save state or invoke DISM.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Inputs: Schema-1 WindowsComponentObservation; explicit WindowsUpdate source.
  Recovery: Data-only outline. Original literal states are retained in the result;
  payload/version recovery and execution readiness are not established.
  Version: 0.1.0.
  Changelog: 0.1.0: Add complete observed selection and dependency-safe step ordering.
.LINK
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod#remote-server-administration-tools-rsat
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ComponentInventory.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.CatalogData.psm1') -ErrorAction Stop

function Get-RideRsatDependencyModel {
  # The operation catalog owns identities and dependency edges. Inventory owns
  # target selection; a catalog entry never implies native availability.
  $catalog=Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../catalog/operations.psd1')
  $operations=@($catalog.Operations | Where-Object CapabilityFamily -CEQ 'RSAT')
  if ($operations.Count -eq 0 -or $operations.Count -gt 64) { throw 'Missing or excessive RSAT catalog definitions.' }
  $byId=@{}
  foreach ($operation in $operations) {
    if ($operation.Handler -cne 'ClientCapability' -or $operation.CapabilityName -cnotmatch '^Rsat\.[A-Za-z0-9.-]+\.Tools~~~~0\.0\.1\.0$' -or $byId.ContainsKey($operation.Id)) { throw 'Invalid RSAT catalog identity.' }
    $byId[$operation.Id]=$operation
  }
  $model=@{}
  foreach ($operation in $operations) {
    if ($model.ContainsKey($operation.CapabilityName)) { throw 'Duplicate RSAT native capability identity.' }
    $model[$operation.CapabilityName]=@(foreach($id in $operation.CapabilityDependencies) {
      if (-not $byId.ContainsKey($id)) { throw "Unknown RSAT prerequisite '$id'." }
      $byId[$id].CapabilityName
    })
  }
  $model
}

function New-RideRsatCapabilityPlan {
  <#
  .SYNOPSIS
    Prepare every available RSAT capability from one supplied target inventory.
  .PARAMETER Inventory
    Complete saved capability observation for the intended Windows 11 client.
    Unknown RSAT identities, missing prerequisites and pending states fail closed.
  .PARAMETER DesiredState
    Present installs prerequisites first; Absent removes dependents first.
  .PARAMETER ServicingSource
    Explicit WindowsUpdate authorization for this outline, respecting configured
    servicing sources. No LocalSource plan or policy override is inferred.
  .EXAMPLE
    New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate
  .INPUTS
    None. Supply the saved observation explicitly.
  .OUTPUTS
    PSCustomObject. Ordered steps, reverse recovery and all observed original states.
  .NOTES
    A plan is not an execution or recovery record. Runtime must revalidate target,
    architecture, source, dependencies and current state and capture durable state
    before each transition. No support is inferred from a capability name.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateSet('Present','Absent')][string]$DesiredState,
    [Parameter(Mandatory)][ValidateSet('WindowsUpdate')][string]$ServicingSource)
  # Reuse the bounded namespace/schema/row validator without invoking an inventory provider.
  $lookup=Find-RideWindowsComponentObservation -Inventory $Inventory -Kind Capability -Name 'Rsat.ServerManager.Tools~~~~0.0.1.0'
  if ($lookup.Status -cnotin @('Observed','NotObserved')) { throw 'RSAT requires a complete captured capability provider; unavailable and uncollected are not empty inventories.' }
  $context=$Inventory.WindowsContext
  foreach ($field in @('ComputerName','Build','EditionId','ProductType','InstallationType')) {
    if ($context.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($context.$field) -or $context.$field.Length -gt 255 -or $context.$field -match '[\x00-\x1f]') { throw 'Invalid RSAT target context.' }
  }
  if ($context.Build -cnotmatch '^[0-9]{4,8}$' -or [long]$context.Build -lt 22000 -or
      $context.ProductType -cne 'WinNT' -or $context.InstallationType -cne 'Client' -or
      $context.NativeProcess -isnot [bool] -or -not $context.NativeProcess -or
      ($context.UpdateBuildRevision -isnot [int] -and $context.UpdateBuildRevision -isnot [long] -and $context.UpdateBuildRevision -isnot [uint32]) -or
      $context.UpdateBuildRevision -lt 0 -or $context.UpdateBuildRevision -gt [uint32]::MaxValue) { throw 'RSAT plan requires a native Windows 11 client observation with a valid revision.' }
  if ($context.EditionId -cnotin @('Professional','ProfessionalN','ProfessionalWorkstation','ProfessionalWorkstationN','Enterprise','EnterpriseN','EnterpriseEval','EnterpriseNEval','EnterpriseS','EnterpriseSN','EnterpriseSEval','EnterpriseSNEval')) {
    throw 'RSAT capability planning is limited to the reviewed Pro and Enterprise edition identities.'
  }
  $provider=@($Inventory.Providers | Where-Object Kind -CEQ 'Capability')[0]
  $rows=@($provider.Rows | Where-Object {$_.Name.StartsWith('Rsat',[StringComparison]::OrdinalIgnoreCase)})
  if ($rows.Count -eq 0) { throw 'No RSAT capabilities were observed; this is not a successful empty selection.' }
  $model=Get-RideRsatDependencyModel
  $selected=@{}
  foreach ($row in $rows) {
    if (-not $model.ContainsKey($row.Name)) { throw "Unreviewed observed RSAT capability '$($row.Name)'; review its dependencies before claiming complete coverage." }
    if ($row.StateObserved -cnotin @('Installed','NotPresent')) { throw "RSAT capability '$($row.Name)' is pending or unknown: $($row.StateObserved)." }
    $selected[$row.Name]=$row
  }
  foreach ($row in $rows) {
    foreach ($dependency in $model[$row.Name]) {
      if (-not $selected.ContainsKey($dependency)) { throw "RSAT prerequisite '$dependency' for '$($row.Name)' was not observed; selection is incomplete." }
      if ($row.StateObserved -ceq 'Installed' -and $selected[$dependency].StateObserved -cne 'Installed') { throw "RSAT installed-state dependency mismatch for '$($row.Name)' and '$dependency'." }
    }
  }
  $ordered=[Collections.Generic.List[string]]::new()
  $visited=@{}
  while ($ordered.Count -lt $rows.Count) {
    $before=$ordered.Count
    foreach ($name in @($selected.Keys | Sort-Object)) {
      if ($visited.ContainsKey($name)) { continue }
      $missing=@($model[$name] | Where-Object {-not $visited.ContainsKey($_)})
      if ($missing.Count -eq 0) { $ordered.Add($selected[$name].Name);$visited[$name]=$true }
    }
    if ($ordered.Count -eq $before) { throw 'RSAT dependency model contains a cycle; refusing an unsafe order.' }
  }
  $names=@($ordered.ToArray())
  $desired=if ($DesiredState -eq 'Present') {'Installed'}else{'NotPresent'}
  if ($DesiredState -eq 'Absent') { [array]::Reverse($names) }
  $steps=@(foreach ($name in $names) {
    if ($selected[$name].StateObserved -ceq $desired) { continue }
    [pscustomobject]@{Name=$name;BeforeState=$selected[$name].StateObserved;DesiredState=$desired;Dependencies=@($model[$name]);Command=if ($desired -ceq 'Installed') {'Dism\Add-WindowsCapability'}else{'Dism\Remove-WindowsCapability'};Parameters=@{Online=$true;Name=$name;ErrorAction='Stop'}}
  })
  $reverse=@($steps);[array]::Reverse($reverse)
  $restore=@(foreach ($step in $reverse) {
    [pscustomobject]@{Name=$step.Name;ExpectedState=$step.DesiredState;DesiredState=$step.BeforeState;Command=if ($step.BeforeState -ceq 'Installed') {'Dism\Add-WindowsCapability'}else{'Dism\Remove-WindowsCapability'};Parameters=@{Online=$true;Name=$step.Name;ErrorAction='Stop'}}
  })
  $identity=[ordered]@{}
  foreach ($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','ProductType','InstallationType','NativeProcess')) { $identity[$field]=$context.$field }
  [pscustomobject]@{
    SchemaVersion=1;Kind='RsatCapabilityPlan';WindowsContext=[pscustomobject]$identity
    Selection='AllObservedRsatCapabilities';DesiredState=$DesiredState;ServicingSource='WindowsUpdate'
    SourcePolicyOverridesAllowed=$false;DependencyModelReviewed='2026-11-02'
    DependencySourceUri='https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod#remote-server-administration-tools-rsat'
    OriginalStates=@($rows | Sort-Object Name | ForEach-Object {[pscustomobject]@{Name=$_.Name;State=$_.StateObserved}})
    InstallOrder=@($ordered.ToArray());Steps=$steps;RestoreSteps=$restore
    Status=if ($steps.Count) {'PreparedOutlineOnly'}else{'NoChangeObserved'}
    ReadyForMutation=$false;RecoverySupported=$false;ExactPayloadRecoverySupported=$false
    Requirements=@('Fresh exact target, architecture and edition validation','Durable pre-change state and partial-run recovery','Recheck dependencies and state before each transition','Stop and retain evidence on unknown/pending states or unexpected dependency effects','Verify native install/repeat/remove/RIDE restore without automatic reboot')
  }
}

Export-ModuleMember -Function New-RideRsatCapabilityPlan
