<#
.SYNOPSIS
  Manage a bounded set of registry values representing one user choice.
.DESCRIPTION
  Reads each declared value and key existence, applies a complete named state,
  and restores every captured value and type. The engine owns ShouldProcess,
  pre-change records and partial-failure reporting. Import performs no inspection.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Registry provider; elevation for machine-scoped values.
  Recovery: Use saved-run restore; it preserves unrelated values in shared keys.
  Owner: RIDE-Windows maintainers. Version: 0.3.0.
  Changelog: 0.3.0: Support explicit KeepCurrent components without erasing subordinate choices.
    0.2.1: Reuse authoritative key-existence capture instead of a second silent read.
    0.2.0: Add bounded read-only registry observations outside mutation/recovery.
    0.1.0: Keep coordinated legacy settings in one catalog operation.
#>

Import-Module (Join-Path $PSScriptRoot 'RIDE-Settings.psm1') -ErrorAction Stop
$script:ModuleVersion = '0.3.0'
$ErrorActionPreference = 'Stop'

function Test-RideRegistryValueKeep {
  param($Value)
  $Value -is [hashtable] -and $Value.Count -eq 1 -and $Value.KeepCurrent -is [bool] -and $Value.KeepCurrent -eq $true
}

function Assert-RideRegistryValueSetDesired {
  param([hashtable] $Operation, [string] $State)
  if (-not $Operation.States.ContainsKey($State)) { throw "Unknown state '$State' for '$($Operation.Id)'." }
  $values = $Operation.States[$State]
  if ($values -isnot [hashtable] -or $values.Count -ne @($Operation.RegistryValues).Count) { throw 'Registry value-set desired state is incomplete.' }
  foreach ($member in $Operation.RegistryValues) {
    if (-not $values.ContainsKey($member.Key)) { throw 'Registry value-set desired component is missing.' }
    $value = $values[$member.Key]
    if ($null -eq $value -or (Test-RideRegistryValueKeep $value)) { continue }
    if (($member.ValueType -eq 'DWord' -and $value -is [int]) -or ($member.ValueType -eq 'String' -and $value -is [string])) { continue }
    throw 'Registry value-set desired value or KeepCurrent marker is invalid.'
  }
}

function Get-RideRegistryValueSetState {
  <#
  .SYNOPSIS
    Read all declared values without changing Windows.
  .PARAMETER Operation
    RegistryValueSet catalog metadata.
  .OUTPUTS
    PSCustomObject with named value snapshots, key existence, and optional separate
    ReadOnlyObservations. Observed values are never included in apply/restore.
  #>
  param([Parameter(Mandatory)][hashtable] $Operation)
  $values = foreach ($member in $Operation.RegistryValues) {
    $current = Get-RideSettingState -Operation $member
    $keyExisted = if ($current.KeyExisted -is [bool]) { $current.KeyExisted } else { [bool](Get-Item -LiteralPath $member.RegistryPath -ErrorAction Stop) }
    [pscustomobject]@{ Key = $member.Key; Exists = $current.Exists; Value = $current.Value; ValueType = $current.ValueType; KeyExisted = $keyExisted }
  }
  $result = [pscustomobject]@{ Values = @($values) }
  if ($Operation.ReadOnlyRegistryValues) {
    $observations = @(foreach ($member in $Operation.ReadOnlyRegistryValues) {
      $current = Get-RideSettingState -Operation $member
      [pscustomobject]@{ Key = $member.Key; Exists = $current.Exists; Value = $current.Value; ValueType = $current.ValueType }
    })
    $result | Add-Member -NotePropertyName ReadOnlyObservations -NotePropertyValue $observations
  }
  $result
}

function Test-RideRegistryValueSetMatch {
  <#
  .SYNOPSIS
    Compare every component with a complete catalog state.
  .PARAMETER Operation
    RegistryValueSet catalog metadata.
  .PARAMETER State
    Declared state name.
  .PARAMETER CurrentState
    Named value snapshots from read-only inspection.
  .OUTPUTS
    Boolean; false for missing components or mismatched registry types. Explicit
    KeepCurrent components must be captured but are not compared to a desired value.
  #>
  param([Parameter(Mandatory)][hashtable] $Operation, [Parameter(Mandatory)][string] $State, [Parameter(Mandatory)] $CurrentState)
  Assert-RideRegistryValueSetDesired $Operation $State
  if (@($CurrentState.Values).Count -ne @($Operation.RegistryValues).Count) { return $false }
  foreach ($member in $Operation.RegistryValues) {
    $matches = @($CurrentState.Values | Where-Object Key -eq $member.Key)
    if ($matches.Count -ne 1) { return $false }
    $current = $matches[0]
    $desired = $Operation.States[$State][$member.Key]
    if (Test-RideRegistryValueKeep $desired) { continue }
    if ($null -eq $desired) { if ($current.Exists) { return $false }; continue }
    if (-not $current.Exists -or $current.ValueType -ne $member.ValueType -or $current.Value -cne $desired) { return $false }
  }
  $true
}

function Set-RideRegistryValueSetState {
  <#
  .SYNOPSIS
    Apply each component of one named state.
  .DESCRIPTION
    Engine-internal writer. A later component can fail after an earlier write;
    the engine retains the complete pre-change snapshot for saved-run recovery.
  .PARAMETER Operation
    RegistryValueSet catalog metadata.
  .PARAMETER State
    Declared state name; WindowsDefault removes every declared override. A declared
    KeepCurrent component is captured by the engine but receives no write/removal.
  .OUTPUTS
    None. Errors propagate to the engine.
  #>
  param([Parameter(Mandatory)][hashtable] $Operation, [Parameter(Mandatory)][string] $State)
  Assert-RideRegistryValueSetDesired $Operation $State
  foreach ($member in $Operation.RegistryValues) {
    if (Test-RideRegistryValueKeep $Operation.States[$State][$member.Key]) { continue }
    Set-RideSettingState -Operation $member -Value $Operation.States[$State][$member.Key]
  }
}

function Restore-RideRegistryValueSetState {
  <#
  .SYNOPSIS
    Restore captured values in reverse order, preserving unrelated content.
  .PARAMETER Operation
    RegistryValueSet catalog metadata; supplies the permitted paths and names.
  .PARAMETER Snapshot
    Complete named pre-change value snapshots.
  .OUTPUTS
    None. Invalid snapshots fail before any write.
  #>
  param([Parameter(Mandatory)][hashtable] $Operation, [Parameter(Mandatory)] $Snapshot)
  if (@($Snapshot.Values).Count -ne @($Operation.RegistryValues).Count) { throw 'Registry value-set snapshot is incomplete.' }
  foreach ($member in $Operation.RegistryValues) {
    if (@($Snapshot.Values | Where-Object Key -eq $member.Key).Count -ne 1) { throw 'Registry value-set snapshot has missing or duplicate components.' }
  }
  for ($index = $Operation.RegistryValues.Count - 1; $index -ge 0; $index--) {
    $member = $Operation.RegistryValues[$index]
    $prior = @($Snapshot.Values | Where-Object Key -eq $member.Key)[0]
    Restore-RideSettingState -Operation $member -Snapshot $prior
  }
}

Export-ModuleMember -Function Get-RideRegistryValueSetState, Test-RideRegistryValueSetMatch, Set-RideRegistryValueSetState, Restore-RideRegistryValueSetState
