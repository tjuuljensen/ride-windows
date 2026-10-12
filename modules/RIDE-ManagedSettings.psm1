<#
.SYNOPSIS
  Dispatch focused task, adapter, Defender, SMB and power-scheme settings.
.DESCRIPTION
  Uses declared handlers without executing legacy selectors. Captured state is
  serialized by the engine; preview and elevation are owned by that engine.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: The focused Windows modules required by each catalog kind.
  Recovery: Saved-run restore; unavailable resources or policy failures throw.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add focused managed-setting dispatch and power-scheme selection.
#>
Import-Module (Join-Path $PSScriptRoot 'RIDE-ScheduledTasks.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE-AdapterBindings.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE-SystemPreferences.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE-NetworkControls.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE-SoundSchemes.psm1') -Force
function Invoke-RideSchemeCommand {
  <#
  .SYNOPSIS
    Capture a bounded powercfg invocation and its exit code.
  .PARAMETER Arguments
    Separate native argument tokens; GUIDs are validated by the caller.
  .OUTPUTS
    ExitCode and Output.
  #>
  param([string[]] $Arguments)
  # Windows PowerShell promotes redirected native stderr under Stop, even when
  # the process succeeds. Capture both streams and let the native exit code
  # determine success; do not lose recovery after a warning from powercfg.
  $previousPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = @(& (Join-Path $env:SystemRoot 'System32/powercfg.exe') @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $previousPreference }
  [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
}
function Test-RideExistingPowerScheme {
  <#
  .SYNOPSIS
    Query an exact existing scheme GUID without creating or activating it.
  .PARAMETER Guid
    Requested GUID; list visibility alone is insufficient for recovery.
  .OUTPUTS
    Boolean. Requires a successful query naming the requested scheme.
  #>
  param([guid] $Guid)
  $query = Invoke-RideSchemeCommand -Arguments @('/query', $Guid.ToString())
  if ($query.ExitCode -ne 0) { return $false }
  $match = [regex]::Match($query.Output, '(?i)[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')
  return ($match.Success -and $match.Value -eq $Guid.ToString())
}
function Get-RideManagedSettingState {
  <#
  .SYNOPSIS
    Inspect one declared managed setting without writes.
  .PARAMETER Operation
    Catalog metadata for a supported focused kind.
  .OUTPUTS
    Handler-specific literal state, including availability where applicable.
  #>
  param([hashtable] $Operation)
  switch ($Operation.Kind) {
    ScheduledTask { return Get-RideScheduledTaskState $Operation }
    AdapterBinding { return Get-RideAdapterBindingState $Operation }
    DefenderPreference { return Get-RideDefenderPreferenceState $Operation }
    SmbProtocol { return Get-RideSmbProtocolState $Operation }
    SoundScheme { return Get-RideSoundSchemeState $Operation }
    { $_ -in @('NetBios', 'RemoteDesktopFirewall') } { return Get-RideNetworkControlState $Operation }
    PowerScheme {
      $active = Invoke-RideSchemeCommand @('/getactivescheme')
      $list = Invoke-RideSchemeCommand @('/list')
      if ($active.ExitCode -ne 0 -or $list.ExitCode -ne 0) { throw 'Cannot inspect power schemes.' }
      $pattern = '(?i)[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
      $guid = [regex]::Match($active.Output, $pattern)
      if (-not $guid.Success) { throw 'No active power-scheme GUID was returned.' }
      $listed = @($list.Output -split '\r?\n' | ForEach-Object { $first=[regex]::Match($_,$pattern); if($first.Success){$first.Value.ToLowerInvariant()} })
      $candidates = @($listed) + @($Operation.States.Values) + @($guid.Value.ToLowerInvariant())
      $schemes = @($candidates | Sort-Object -Unique | Where-Object { Test-RideExistingPowerScheme -Guid $_ })
      if ($guid.Value -notin $schemes) { throw 'The active power scheme cannot be queried for recovery.' }
      return [pscustomobject]@{ Value = $guid.Value.ToLowerInvariant(); AvailableSchemes = $schemes }
    }
    default { throw 'Unsupported managed setting kind.' }
  }
}
function Set-RideManagedSettingState {
  <#
  .SYNOPSIS
    Apply one declared literal state through its focused handler.
  .PARAMETER Operation
    Catalog metadata.
  .PARAMETER State
    Declared state name.
  .OUTPUTS
    None. Unavailable resources and write failures throw.
  #>
  param([hashtable] $Operation, [string] $State)
  if (-not $Operation.States.ContainsKey($State)) { throw 'Unsupported managed setting state.' }
  if ($Operation.Kind -eq 'SoundScheme') { Set-RideSoundSchemeState $Operation $State; return }
  if ($Operation.Kind -in @('NetBios', 'RemoteDesktopFirewall')) { Set-RideNetworkControlState $Operation $State; return }
  Set-RideManagedSettingValue $Operation $Operation.States[$State]
}
function Set-RideManagedSettingValue {
  <#
  .SYNOPSIS
    Write a validated literal value, including a previously captured value.
  .PARAMETER Operation
    Catalog metadata defines the target; snapshots cannot redirect it.
  .PARAMETER Value
    Typed literal value, not a command.
  .OUTPUTS
    None. Invalid values throw before mutation.
  #>
  param([hashtable] $Operation, $Value)
  switch ($Operation.Kind) {
    ScheduledTask { if ($Value -isnot [bool]) { throw 'Invalid task flag.' }; Set-RideScheduledTaskEnabled $Operation $Value }
    AdapterBinding { if ($Value -isnot [bool]) { throw 'Invalid binding flag.' }; Set-RideAdapterBindingState $Operation $Value }
    DefenderPreference { if ($Value -isnot [int] -or $Value -lt 0 -or $Value -gt 6) { throw 'Invalid Defender mode.' }; Set-RideDefenderPreferenceState $Operation $Value }
    SmbProtocol { if ($Value -isnot [bool]) { throw 'Invalid SMB flag.' }; Set-RideSmbProtocolState $Operation $Value }
    PowerScheme {
      $guid = ([guid]$Value).ToString()
      if (-not (Test-RideExistingPowerScheme -Guid $guid)) { throw "Power scheme is unavailable: $guid" }
      $result = Invoke-RideSchemeCommand -Arguments @('/setactive', $guid)
      if ($result.ExitCode -ne 0) { throw "Cannot activate power scheme: $($result.Output)" }
      $active = Invoke-RideSchemeCommand -Arguments @('/getactivescheme')
      $actual = [regex]::Match($active.Output, '(?i)[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')
      if ($active.ExitCode -ne 0 -or -not $actual.Success -or $actual.Value -ne $guid) { throw 'Windows did not activate the requested power scheme.' }
    }
    default { throw 'Unsupported managed setting kind.' }
  }
}
function Restore-RideManagedSettingState {
  <#
  .SYNOPSIS
    Recover captured literal state using the current catalog target.
  .PARAMETER Operation
    Catalog metadata.
  .PARAMETER Snapshot
    Serialized pre-change state; task and adapter identities are revalidated.
  .OUTPUTS
    None. Invalid snapshots fail before writes.
  #>
  param([hashtable] $Operation, $Snapshot)
  switch ($Operation.Kind) {
    ScheduledTask { Restore-RideScheduledTaskState $Operation $Snapshot }
    AdapterBinding { Restore-RideAdapterBindingState $Operation $Snapshot }
    SoundScheme { Restore-RideSoundSchemeState $Operation $Snapshot }
    { $_ -in @('NetBios', 'RemoteDesktopFirewall') } { Restore-RideNetworkControlState $Operation $Snapshot }
    default { Set-RideManagedSettingValue $Operation $Snapshot.Value }
  }
}
function Test-RideManagedSoundMatch {
  <#
  .SYNOPSIS
    Compare all current event mappings with the selected registered preset.
  .PARAMETER Operation
    Catalog sound metadata.
  .PARAMETER State
    Declared preset state.
  .PARAMETER Current
    Read-only captured sound configuration.
  .OUTPUTS
    Boolean.
  #>
  param([hashtable]$Operation,[string]$State,$Current)
  Test-RideSoundSchemeMatch $Operation $State $Current
}
Export-ModuleMember -Function Get-RideManagedSettingState, Set-RideManagedSettingState, Restore-RideManagedSettingState, Test-RideManagedSoundMatch
