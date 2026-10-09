<#
.SYNOPSIS
  Inspect and manage selected power-plan setting indexes.

.DESCRIPTION
  Reads the active power scheme and changes a single AC or DC index with powercfg. Snapshots retain
  the exact scheme GUID and index for restoration.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.Management.Automation.PSCustomObject. Active scheme and power setting index.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Windows powercfg.exe; machine-scoped settings require elevation.
  Recovery: Restore-RideRun restores the captured scheme/index.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
#>

function Invoke-RidePowercfg {
  <#
  .SYNOPSIS
    Run powercfg and capture its output and exit code.

  .DESCRIPTION
    Internal command wrapper used by the power setting handlers; it does not change behavior by
    itself.

  .PARAMETER Arguments
    Argument tokens passed to powercfg.exe.

  .INPUTS
    None. Arguments are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Native exit code and combined output.

  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Prerequisites: Windows powercfg.exe.
    Author: RIDE-Windows maintainers.
    Version: 0.1.0
  #>

  param([Parameter(Mandatory = $true)][string[]] $Arguments)
  $powercfg = Join-Path $env:SystemRoot 'System32/powercfg.exe'
  $output = @(& $powercfg @Arguments 2>&1 | ForEach-Object { [string]$_ })
  [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join [Environment]::NewLine) }
}

function Get-RidePowerSettingState {
  <#
  .SYNOPSIS
    Read one AC or DC index from a power scheme.

  .DESCRIPTION
    Reads the active scheme unless a scheme GUID is supplied for exact snapshot verification. A
    setting omitted by the active scheme is reported as unavailable.

  .PARAMETER Operation
    Catalog PowerSetting metadata, including scheme subgroup and setting GUIDs.

  .PARAMETER SchemeGuid
    Optional scheme to query instead of the currently active scheme.

  .EXAMPLE
    Get-RidePowerSettingState -Operation $operation

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Availability, scheme GUID, and selected index.

  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Prerequisites: Windows powercfg.exe.
    Author: RIDE-Windows maintainers.
    Version: 0.1.0
  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [string] $SchemeGuid
  )
  if (-not $SchemeGuid) {
    $active = Invoke-RidePowercfg -Arguments @('/getactivescheme')
    if ($active.ExitCode -ne 0) { throw "powercfg could not read the active power scheme: $($active.Output)" }
    $match = [regex]::Match($active.Output, '(?i)([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})')
    if (-not $match.Success) { throw "powercfg returned no active scheme GUID: $($active.Output)" }
    $SchemeGuid = $match.Groups[1].Value
  }
  $query = Invoke-RidePowercfg -Arguments @('/query', $SchemeGuid, $Operation.PowerSubgroupGuid)
  if ($query.ExitCode -ne 0) { throw "powercfg could not query '$($Operation.Id)': $($query.Output)" }
  $settingPattern = '(?is)Power Setting GUID:\s*' + [regex]::Escape($Operation.PowerSettingGuid) + '(.*?)(?=\r?\n\s*Power Setting GUID:|\z)'
  $settingMatch = [regex]::Match($query.Output, $settingPattern)
  if (-not $settingMatch.Success) {
    return [pscustomobject]@{ Exists = $false; Available = $false; SchemeGuid = $SchemeGuid; Index = $null; PowerIndex = $Operation.PowerIndex }
  }
  $indexMatch = [regex]::Match($settingMatch.Groups[1].Value, ('(?im)^\s*Current {0} Power Setting Index:\s*0x([0-9a-f]+)\s*$' -f [regex]::Escape($Operation.PowerIndex)))
  if (-not $indexMatch.Success) { throw "powercfg returned no current $($Operation.PowerIndex) index for '$($Operation.Id)': $($query.Output)" }
  [pscustomobject]@{ Exists = $true; Available = $true; SchemeGuid = $SchemeGuid; Index = [Convert]::ToInt32($indexMatch.Groups[1].Value, 16); PowerIndex = $Operation.PowerIndex }
}

function Set-RidePowerSettingState {
  <#
  .SYNOPSIS
    Set a declared AC or DC power setting state.

  .DESCRIPTION
    Changes the selected index in the active scheme, reactivates that scheme to commit it, and
    verifies the result. The caller must apply ShouldProcess before invoking this handler.

  .PARAMETER Operation
    Catalog PowerSetting metadata.

  .PARAMETER State
    Declared state name from the operation's States map.

  .EXAMPLE
    Set-RidePowerSettingState -Operation $operation -State Sleep

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None on success. Throws when the setting is unavailable or verification fails.

  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Prerequisites: Windows powercfg.exe and an available setting in the active scheme.
    Author: RIDE-Windows maintainers.
    Version: 0.1.0
  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)][string] $State)
  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
  $current = Get-RidePowerSettingState -Operation $Operation
  if (-not $current.Available) { throw "Power setting '$($Operation.Id)' is unavailable in the active power scheme on this device." }
  $verb = if ($Operation.PowerIndex -eq 'AC') { '/setacvalueindex' } else { '/setdcvalueindex' }
  $set = Invoke-RidePowercfg -Arguments @($verb, $current.SchemeGuid, $Operation.PowerSubgroupGuid, $Operation.PowerSettingGuid, [string]$Operation.States[$State])
  if ($set.ExitCode -ne 0) { throw "powercfg could not set '$($Operation.Id)': $($set.Output)" }
  $active = Invoke-RidePowercfg -Arguments @('/setactive', $current.SchemeGuid)
  if ($active.ExitCode -ne 0) { throw "powercfg set the index but could not commit '$($Operation.Id)': $($active.Output)" }
  $verified = Get-RidePowerSettingState -Operation $Operation
  if (-not $verified.Available -or $verified.SchemeGuid -ne $current.SchemeGuid -or $verified.Index -ne [int]$Operation.States[$State]) { throw "Power setting verification failed for '$($Operation.Id)'." }
}

function Restore-RidePowerSettingState {
  <#
  .SYNOPSIS
    Restore an exact power setting snapshot.

  .DESCRIPTION
    Writes the recorded index to its captured scheme and verifies it. Reactivates the scheme only
    when it is still the active scheme.

  .PARAMETER Operation
    Catalog PowerSetting metadata.

  .PARAMETER Snapshot
    Captured SchemeGuid and Index values from the prior state.

  .EXAMPLE
    Restore-RidePowerSettingState -Operation $operation -Snapshot $snapshot

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None on success. Throws if the captured setting cannot be restored exactly.

  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Prerequisites: Windows powercfg.exe and the captured scheme.
    Author: RIDE-Windows maintainers.
    Version: 0.1.0
  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)] $Snapshot)
  $verb = if ($Operation.PowerIndex -eq 'AC') { '/setacvalueindex' } else { '/setdcvalueindex' }
  $set = Invoke-RidePowercfg -Arguments @($verb, [string]$Snapshot.SchemeGuid, $Operation.PowerSubgroupGuid, $Operation.PowerSettingGuid, [string]$Snapshot.Index)
  if ($set.ExitCode -ne 0) { throw "powercfg could not restore '$($Operation.Id)': $($set.Output)" }
  $active = Get-RidePowerSettingState -Operation $Operation
  if ($active.SchemeGuid -eq $Snapshot.SchemeGuid) {
    $commit = Invoke-RidePowercfg -Arguments @('/setactive', [string]$Snapshot.SchemeGuid)
    if ($commit.ExitCode -ne 0) { throw "powercfg could not commit restoration of '$($Operation.Id)': $($commit.Output)" }
  }
  $verified = Get-RidePowerSettingState -Operation $Operation -SchemeGuid ([string]$Snapshot.SchemeGuid)
  if (-not $verified.Available -or $verified.Index -ne [int]$Snapshot.Index) { throw "Power setting restoration verification failed for '$($Operation.Id)'." }
}

Export-ModuleMember -Function Get-RidePowerSettingState, Set-RidePowerSettingState, Restore-RidePowerSettingState
