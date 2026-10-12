<#
.SYNOPSIS
  Select registered sound presets and restore captured current event mappings.
.DESCRIPTION
  Coordinates the scheme selector and every existing application/event Current
  value. Preserves source presets, unrelated values and newly registered events.
  Captures raw data, types and key/value absence for exact saved-run recovery.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Current-user AppEvents scheme registration; no elevation.
  Recovery: Saved-run restore; engine preview prevents all writes.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add coherent event/selector sound-scheme lifecycle.
#>
function Get-RideSoundEvents {
  <#
  .SYNOPSIS
    Enumerate existing application/event identities under the fixed user root.
  .OUTPUTS
    Application and Event names; no registry writes.
  #>
  $root=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('AppEvents\Schemes\Apps')
  if (-not $root) { return }
  try {
    foreach ($app in ($root.GetSubKeyNames() | Sort-Object)) {
      $key=$root.OpenSubKey($app)
      try { foreach ($event in ($key.GetSubKeyNames() | Sort-Object)) { [pscustomobject]@{Application=$app;Event=$event} } }
      finally { $key.Dispose() }
    }
  }
  finally { $root.Dispose() }
}
function Get-RideSoundValue {
  <#
  .SYNOPSIS
    Read an unnamed registry value with raw data and its original kind.
  .PARAMETER Path
    Fixed-root internal subkey path.
  .OUTPUTS
    KeyExisted, Exists, Value and ValueType.
  #>
  param([string]$Path)
  $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path)
  if (-not $key) { return [pscustomobject]@{KeyExisted=$false;Exists=$false;Value=$null;ValueType=$null} }
  try {
    $exists=$key.GetValueNames() -contains ''
    [pscustomobject]@{KeyExisted=$true;Exists=$exists;Value=$(if($exists){$key.GetValue('', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)});ValueType=$(if($exists){$key.GetValueKind('').ToString()})}
  }
  finally { $key.Dispose() }
}
function Set-RideSoundValue {
  <#
  .SYNOPSIS
    Write or restore an internal sound selector/event value without deleting unrelated data.
  .PARAMETER Path
    Fixed-root internal subkey path.
  .PARAMETER Snapshot
    Validated typed data and presence. A newly created key is removed only if empty.
  .OUTPUTS
    None; registry errors propagate.
  #>
  param([string]$Path,$Snapshot)
  if ($Snapshot.Exists) {
    $data = switch ($Snapshot.ValueType) {
      Binary { ,([byte[]]$Snapshot.Value) }
      MultiString { ,([string[]]$Snapshot.Value) }
      DWord { [int]$Snapshot.Value }
      QWord { [long]$Snapshot.Value }
      default { [string]$Snapshot.Value }
    }
    $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($Path)
    try { $key.SetValue('', $data, [Microsoft.Win32.RegistryValueKind]([Enum]::Parse([Microsoft.Win32.RegistryValueKind],$Snapshot.ValueType))) }
    finally { $key.Dispose() }
    return
  }
  $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path,$true)
  if (-not $key) { return }
  try { $key.DeleteValue('',$false); $empty=($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) }
  finally { $key.Dispose() }
  if (-not $Snapshot.KeyExisted -and $empty) { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey($Path,$false) }
}
function Get-RideSoundSchemeState {
  <#
  .SYNOPSIS
    Capture current mappings and resolved registered preset values.
  .PARAMETER Operation
    Fixed SoundScheme catalog metadata.
  .OUTPUTS
    Availability, root selector and complete event/value snapshots.
  #>
  param([hashtable]$Operation)
  $selector=Get-RideSoundValue 'AppEvents\Schemes'
  $events=@(Get-RideSoundEvents | ForEach-Object {
    $path='AppEvents\Schemes\Apps\{0}\{1}' -f $_.Application,$_.Event
    $presets=@{}
    foreach ($scheme in @('.None','.Default')) {
      $source=Get-RideSoundValue "$path\$scheme"
      $presets[$scheme]=if($source.Exists){[Environment]::ExpandEnvironmentVariables([string]$source.Value)}else{''}
    }
    [pscustomobject]@{Application=$_.Application;Event=$_.Event;Current=(Get-RideSoundValue "$path\.Current");Presets=$presets}
  })
  [pscustomobject]@{Available=($selector.KeyExisted -and $events.Count -gt 0);Selector=$selector;Events=$events}
}
function Test-RideSoundSchemeMatch {
  <#
  .SYNOPSIS
    Require the selector and every current event mapping to match the preset.
  .PARAMETER Operation
    Catalog preset states.
  .PARAMETER State
    Named preset.
  .PARAMETER Current
    Read-only captured state.
  .OUTPUTS
    Boolean; an empty/unavailable configuration never matches.
  #>
  param([hashtable]$Operation,[string]$State,$Current)
  $scheme=$Operation.States[$State]
  if (-not $Current.Available -or -not $Current.Selector.Exists -or $Current.Selector.Value -ne $scheme -or $Current.Selector.ValueType -ne 'String') { return $false }
  return @($Current.Events | Where-Object { -not $_.Current.Exists -or $_.Current.ValueType -ne 'String' -or $_.Current.Value -cne $_.Presets[$scheme] }).Count -eq 0
}
function Set-RideSoundSchemeState {
  <#
  .SYNOPSIS
    Copy an existing preset into current mappings without rewriting its source.
  .PARAMETER Operation
    Catalog preset allowlist.
  .PARAMETER State
    NoneScheme or WindowsDefaultScheme.
  .OUTPUTS
    None; no event is played and registry failures propagate.
  #>
  param([hashtable]$Operation,[string]$State)
  $scheme=$Operation.States[$State]
  if ($scheme -notin @('.None','.Default')) { throw 'Invalid sound preset.' }
  $current=Get-RideSoundSchemeState $Operation
  if (-not $current.Available) { throw 'Sound scheme registration is unavailable.' }
  foreach ($entry in $current.Events) {
    Set-RideSoundValue ('AppEvents\Schemes\Apps\{0}\{1}\.Current' -f $entry.Application,$entry.Event) @{Exists=$true;Value=$entry.Presets[$scheme];ValueType='String'}
  }
  Set-RideSoundValue 'AppEvents\Schemes' @{Exists=$true;Value=$scheme;ValueType='String'}
}
function Restore-RideSoundSchemeState {
  <#
  .SYNOPSIS
    Restore selector and captured event data/kinds/absence after complete validation.
  .PARAMETER Operation
    Fixed SoundScheme metadata.
  .PARAMETER Snapshot
    Captured existing event identities; cannot redirect writes outside the root.
  .OUTPUTS
    None; malformed snapshots throw before writes.
  #>
  param([hashtable]$Operation,$Snapshot)
  if (-not $Snapshot.Available -or -not @($Snapshot.Events).Count) { throw 'Incomplete sound snapshot.' }
  $seen=@{}
  foreach ($entry in $Snapshot.Events) {
    if (-not $entry.Application -or -not $entry.Event -or $entry.Application -match '[\\\r\n]' -or $entry.Event -match '[\\\r\n]') { throw 'Invalid sound event identity.' }
    $id=$entry.Application+'\'+$entry.Event
    if($seen.ContainsKey($id)){throw 'Duplicate sound event snapshot.'};$seen[$id]=$true
  }
  foreach ($value in @($Snapshot.Selector)+@($Snapshot.Events | ForEach-Object {$_.Current})) {
    if($value.Exists -isnot [bool] -or $value.KeyExisted -isnot [bool] -or ($value.Exists -and $value.ValueType -notin @('String','ExpandString','DWord','QWord','Binary','MultiString'))) { throw 'Invalid sound value snapshot.' }
  }
  foreach ($entry in $Snapshot.Events) { Set-RideSoundValue ('AppEvents\Schemes\Apps\{0}\{1}\.Current' -f $entry.Application,$entry.Event) $entry.Current }
  Set-RideSoundValue 'AppEvents\Schemes' $Snapshot.Selector
}
Export-ModuleMember -Function Get-RideSoundSchemeState, Test-RideSoundSchemeMatch, Set-RideSoundSchemeState, Restore-RideSoundSchemeState
