<#
.SYNOPSIS
  Manage a bounded set of registry values representing one user choice.
.DESCRIPTION
  Reads each declared value and the existence of its key ancestors, applies a
  complete named state, and restores captured values and key structure without
  deleting nonempty keys. The engine owns ShouldProcess, pre-change records and
  partial-failure reporting. Import performs no inspection.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Registry provider; elevation for machine-scoped values.
  Recovery: Use saved-run restore; it preserves unrelated values in shared keys.
  Owner: RIDE-Windows maintainers. Version: 0.5.0.
  Changelog: 0.5.0: Capture and restore empty intermediate registry-key existence for exact value-set recovery.
    0.4.0: Resolve a fixed allowlist of user-scope RIDE/runtime path tokens for dynamic Shell commands.
    0.3.0: Support explicit KeepCurrent components without erasing subordinate choices.
    0.2.1: Reuse authoritative key-existence capture instead of a second silent read.
    0.2.0: Add bounded read-only registry observations outside mutation/recovery.
    0.1.0: Keep coordinated legacy settings in one catalog operation.
#>

Import-Module (Join-Path $PSScriptRoot 'RIDE-Settings.psm1') -ErrorAction Stop
$script:ModuleVersion = '0.5.0'
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

function Get-RideRegistryValueSetEffectiveDesiredState {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable] $Operation,
    [Parameter(Mandatory)][string] $State
  )

  Assert-RideRegistryValueSetDesired -Operation $Operation -State $State
  $root = Split-Path -Parent $PSScriptRoot
  $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $tokens = @{
    '{RIDE_ROOT}' = $root
    '{WINDOWS_POWERSHELL_5_1}' = $windowsPowerShell
  }
  $effective = @{}
  foreach ($member in $Operation.RegistryValues) {
    $value = $Operation.States[$State][$member.Key]
    if ($value -is [string]) {
      foreach ($token in $tokens.Keys) {
        if ($value.Contains($token)) {
          if ($Operation.Scope -ne 'User' -or $token.Trim('{}') -notin @($Operation.ValueTokens)) {
            throw "Registry value-set token '$token' is not declared for '$($Operation.Id)'."
          }
          $value = $value.Replace($token, [string]$tokens[$token])
        }
      }
      if ($value -match '\{[A-Z0-9_]+\}') { throw "Registry value-set contains an unsupported token for '$($Operation.Id)' / '$($member.Key)'" }
    }
    $effective[$member.Key] = $value
  }
  $effective
}

function Get-RideRegistryValueSetKeyPaths {
  param([Parameter(Mandatory)][hashtable] $Operation)
  $paths=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($member in $Operation.RegistryValues){
    $path=[string]$member.RegistryPath
    if($path -notmatch '^(HKCU|HKLM):\\'){throw "Registry value-set path is outside a supported hive: $path"}
    while($path.Length -gt 6){
      if(-not $paths.ContainsKey($path)){$paths.Add($path,$path)}
      $separator=$path.LastIndexOf('\')
      if($separator -le 5){break}
      $path=$path.Substring(0,$separator)
    }
  }
  @($paths.Keys | Sort-Object)
}

function Get-RideRegistryValueSetKey {
  param([Parameter(Mandatory)][string] $Path)
  try { Get-Item -LiteralPath $Path -ErrorAction Stop }
  catch {
    if($_.Exception -is [Management.Automation.ItemNotFoundException] -or $_.FullyQualifiedErrorId -like 'PathNotFound,*'){return $null}
    throw
  }
}

function Get-RideRegistryValueSetState {
  <#
  .SYNOPSIS
    Read all declared values without changing Windows.
  .PARAMETER Operation
    RegistryValueSet catalog metadata.
  .OUTPUTS
    PSCustomObject with named value snapshots, key-path existence, and optional
    separate ReadOnlyObservations. Observed values are never included in apply/restore.
  #>
  param([Parameter(Mandatory)][hashtable] $Operation)
  $values = foreach ($member in $Operation.RegistryValues) {
    $current = Get-RideSettingState -Operation $member
    $keyExisted = if ($current.KeyExisted -is [bool]) { $current.KeyExisted } else { [bool](Get-Item -LiteralPath $member.RegistryPath -ErrorAction Stop) }
    [pscustomobject]@{ Key = $member.Key; Exists = $current.Exists; Value = $current.Value; ValueType = $current.ValueType; KeyExisted = $keyExisted }
  }
  $keyPathExistence=@(foreach($path in (Get-RideRegistryValueSetKeyPaths -Operation $Operation)){
    $key=Get-RideRegistryValueSetKey -Path $path
    [pscustomobject]@{Path=$path;Existed=($null -ne $key)}
  })
  $result = [pscustomobject]@{ Values = @($values); KeyPathExistence = $keyPathExistence }
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
  $desiredValues = Get-RideRegistryValueSetEffectiveDesiredState -Operation $Operation -State $State
  foreach ($member in $Operation.RegistryValues) {
    $matches = @($CurrentState.Values | Where-Object Key -eq $member.Key)
    if ($matches.Count -ne 1) { return $false }
    $current = $matches[0]
    $desired = $desiredValues[$member.Key]
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
  $desiredValues = Get-RideRegistryValueSetEffectiveDesiredState -Operation $Operation -State $State
  foreach ($member in $Operation.RegistryValues) {
    if (Test-RideRegistryValueKeep $Operation.States[$State][$member.Key]) { continue }
    Set-RideSettingState -Operation $member -Value $desiredValues[$member.Key]
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
  $hasKeyPathExistence=if($Snapshot -is [Collections.IDictionary]){$Snapshot.Contains('KeyPathExistence')}else{$null -ne $Snapshot.PSObject.Properties['KeyPathExistence']}
  $keyPaths=@()
  if($hasKeyPathExistence){
    $allowedPaths=@(Get-RideRegistryValueSetKeyPaths -Operation $Operation)
    $keyPaths=@($Snapshot.KeyPathExistence)
    if($keyPaths.Count -ne $allowedPaths.Count){throw 'Registry value-set key-path snapshot is incomplete.'}
    $capturedPaths=[Collections.Generic.Dictionary[string,bool]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $keyPaths){
      if($entry.Path -isnot [string] -or $entry.Existed -isnot [bool] -or $entry.Path -notin $allowedPaths -or $capturedPaths.ContainsKey($entry.Path)){throw 'Registry value-set key-path snapshot is invalid.'}
      $capturedPaths.Add($entry.Path,[bool]$entry.Existed)
    }
    foreach($member in $Operation.RegistryValues){
      $prior=@($Snapshot.Values|Where-Object Key -CEQ $member.Key)[0]
      if($prior.KeyExisted -isnot [bool] -or -not $capturedPaths.ContainsKey($member.RegistryPath) -or $capturedPaths[$member.RegistryPath] -ne [bool]$prior.KeyExisted){throw 'Registry value-set key-path snapshot conflicts with a value snapshot.'}
    }
  }
  for ($index = $Operation.RegistryValues.Count - 1; $index -ge 0; $index--) {
    $member = $Operation.RegistryValues[$index]
    $prior = @($Snapshot.Values | Where-Object Key -eq $member.Key)[0]
    Restore-RideSettingState -Operation $member -Snapshot $prior
  }
  foreach($entry in @($keyPaths|Where-Object {-not $_.Existed}|Sort-Object @{Expression={$_.Path.Length};Descending=$true},Path)){
    $key=Get-RideRegistryValueSetKey -Path $entry.Path
    if($key -and $key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0){Remove-Item -LiteralPath $entry.Path -Force -ErrorAction Stop}
  }
}

Export-ModuleMember -Function Get-RideRegistryValueSetState, Get-RideRegistryValueSetEffectiveDesiredState, Test-RideRegistryValueSetMatch, Set-RideRegistryValueSetState, Restore-RideRegistryValueSetState
