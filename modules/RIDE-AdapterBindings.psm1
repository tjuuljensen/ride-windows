<#
.SYNOPSIS
  Manage declared protocol bindings on visible network adapters.
.DESCRIPTION
  Captures adapter GUIDs and each declared binding's flag. Restore resolves GUIDs,
  so adapter renames are supported and new adapters are not changed. Missing
  adapters or bindings fail before restore writes. Disabling bindings can interrupt
  connectivity. The engine owns preview and complete pre-change snapshots.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: NetAdapter module; administrator rights.
  Recovery: Local saved-run restore or disposable-VM checkpoint if connectivity is lost.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add GUID-bound protocol enablement and exact flag recovery.
#>
function Get-RideAdapterBindingState {
  <#
  .SYNOPSIS
    Read declared bindings on visible adapters.
  .PARAMETER Operation
    Catalog ComponentIds; no display-name or arbitrary command matching.
  .OUTPUTS
    PSCustomObject with availability and GUID-bound binding flags.
  #>
  param([hashtable] $Operation)
  $recovery = foreach ($adapter in @(Get-NetAdapter -ErrorAction Stop | Sort-Object InterfaceGuid)) {
      $found = @(Get-NetAdapterBinding -Name ([WildcardPattern]::Escape($adapter.Name)) -AllBindings -ErrorAction Stop | Sort-Object ComponentID)
      foreach ($binding in $found) {
        [pscustomobject]@{ InterfaceGuid = ([guid]$adapter.InterfaceGuid).ToString(); Name = $adapter.Name; ComponentId = $binding.ComponentID; Enabled = [bool]$binding.Enabled }
      }
  }
  $bindings = @($recovery | Where-Object { $_.ComponentId -in $Operation.ComponentIds })
  $affected = @($bindings.InterfaceGuid | Select-Object -Unique)
  [pscustomobject]@{ Available = ($bindings.Count -gt 0); Bindings = $bindings; RecoveryBindings = @($recovery | Where-Object { $_.InterfaceGuid -in $affected }) }
}
function Set-RideAdapterBindingFlags {
  <#
  .SYNOPSIS
    Validate all captured identities before changing any binding.
  .PARAMETER Operation
    Catalog allowlist of component IDs.
  .PARAMETER Bindings
    Captured GUID/component/Boolean flags; names are informational.
  .OUTPUTS
    None; disappearance and invalid snapshots throw before writes.
  #>
  param([hashtable] $Operation, [object[]] $Bindings, [switch] $Recovery)
  if (-not $Bindings.Count) { throw 'No available adapter bindings.' }
  $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
  $seen = @{}
  $writes = foreach ($entry in $Bindings) {
    $guid = ([guid]$entry.InterfaceGuid).ToString()
    $key = "$guid/$($entry.ComponentId)"
    if ($seen.ContainsKey($key) -or ($entry.ComponentId -notin $Operation.ComponentIds -and -not $Recovery) -or $entry.ComponentId -notmatch '^[a-zA-Z0-9_.-]+$' -or $entry.Enabled -isnot [bool]) { throw 'Invalid adapter-binding snapshot.' }
    $seen[$key] = $true
    $adapter = @($adapters | Where-Object { ([guid]$_.InterfaceGuid).ToString() -eq $guid })
    if ($adapter.Count -ne 1) { throw "Captured adapter is missing: $guid" }
    $binding = @(Get-NetAdapterBinding -Name ([WildcardPattern]::Escape($adapter[0].Name)) -ComponentID $entry.ComponentId -IncludeHidden -AllBindings -ErrorAction Stop)
    if ($binding.Count -ne 1) { throw "Captured binding is missing: $key" }
    [pscustomobject]@{ Binding = $binding[0]; Name = $adapter[0].Name; ComponentId = $entry.ComponentId; Enabled = $entry.Enabled }
  }
  # Windows may couple protocol flags. Validate the complete snapshot first, then
  # converge captured flags in a bounded number of passes without touching new ones.
  $attempts = if ($Recovery) { 3 } else { 1 }
  for ($pass = 0; $pass -lt $attempts; $pass++) {
    foreach ($write in $writes) {
      $live = @(Get-NetAdapterBinding -Name ([WildcardPattern]::Escape($write.Name)) -ComponentID $write.ComponentId -IncludeHidden -AllBindings -ErrorAction Stop)
      if ($live.Count -ne 1) { throw 'Adapter binding disappeared during apply/restore.' }
      if ($live[0].Enabled -ne $write.Enabled) { Set-NetAdapterBinding -InputObject $live[0] -Enabled $write.Enabled -Confirm:$false -ErrorAction Stop | Out-Null }
    }
    if (-not $Recovery) { return }
    $different = @($writes | Where-Object { (Get-NetAdapterBinding -Name ([WildcardPattern]::Escape($_.Name)) -ComponentID $_.ComponentId -IncludeHidden -AllBindings -ErrorAction Stop).Enabled -ne $_.Enabled })
    if (-not $different.Count) { return }
  }
  throw 'Windows did not restore all coupled binding flags; use local recovery or the VM checkpoint.'
}
function Set-RideAdapterBindingState {
  <#
  .SYNOPSIS
    Set every currently reported declared binding to one flag.
  .PARAMETER Operation
    Catalog component IDs.
  .PARAMETER Enabled
    Desired flag; disabling TCP/IP can interrupt remoting.
  .OUTPUTS
    None; failures propagate for saved-run recovery.
  #>
  param([hashtable] $Operation, [bool] $Enabled)
  $current = Get-RideAdapterBindingState $Operation
  $flags = @($current.Bindings | ForEach-Object { [pscustomobject]@{ InterfaceGuid = $_.InterfaceGuid; ComponentId = $_.ComponentId; Enabled = $Enabled } })
  Set-RideAdapterBindingFlags $Operation $flags
}
function Restore-RideAdapterBindingState {
  <#
  .SYNOPSIS
    Restore captured per-adapter flags, preserving uncaptured adapters.
  .PARAMETER Operation
    Catalog component allowlist.
  .PARAMETER Snapshot
    Complete pre-change bindings.
  .OUTPUTS
    None; validation precedes writes.
  #>
  param([hashtable] $Operation, $Snapshot)
  $recovery = @($Snapshot.RecoveryBindings)
  if (-not $Snapshot.Available -or -not $recovery.Count -or @($Snapshot.Bindings).Count -eq 0) { throw 'Incomplete adapter-binding snapshot.' }
  foreach ($entry in $Snapshot.Bindings) {
    if ($entry.ComponentId -notin $Operation.ComponentIds -or @($recovery | Where-Object { $_.InterfaceGuid -eq $entry.InterfaceGuid -and $_.ComponentId -eq $entry.ComponentId -and $_.Enabled -eq $entry.Enabled }).Count -ne 1) { throw 'Incomplete adapter-binding snapshot.' }
  }
  foreach ($entry in $recovery) { if ($entry.InterfaceGuid -notin @($Snapshot.Bindings.InterfaceGuid)) { throw 'Snapshot includes an uncaptured adapter.' } }
  Set-RideAdapterBindingFlags $Operation $recovery -Recovery
}
Export-ModuleMember -Function Get-RideAdapterBindingState, Set-RideAdapterBindingState, Restore-RideAdapterBindingState
