<#
.SYNOPSIS
  Inspect and manage selected power-plan setting indexes.

.DESCRIPTION
  Reads the active power scheme and changes a single AC or DC index with powercfg. Snapshots retain
  the exact scheme GUID and unsigned index for restoration. Typed PowrProf reads avoid
  localized command output. Native read/backend and unsigned-boundary acceptance remain pending.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.Management.Automation.PSCustomObject. Active scheme and power setting index.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Windows powercfg.exe; machine-scoped settings require elevation.
  Recovery: Restore-RideRun restores the captured scheme/index.
  Author: RIDE-Windows maintainers.
  Version: 0.3.0
  Changelog: 0.3.0: Replace localized reads with GUID-based APIs and detect read-time plan drift.
    0.2.0: Preserve UInt32 indexes and recover legacy signed captures explicitly.
#>

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.PowerRead.psm1') -Force

function ConvertTo-RidePowerIndex {
  param($Value, [switch]$AllowLegacySigned)
  if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or $Value -isnot [ValueType]) { throw 'Power index must be an integral numeric value.' }
  try { $number = [decimal]$Value } catch { throw 'Power index must be a finite integral numeric value.' }
  if ([decimal]::Truncate($number) -ne $number) { throw 'Power index must be an integral numeric value.' }
  if ($AllowLegacySigned -and $number -ge [int32]::MinValue -and $number -lt 0) { $number += [decimal]4294967296 }
  if ($number -lt 0 -or $number -gt [uint32]::MaxValue) { throw 'Power index is outside UInt32 range.' }
  [uint32]$number
}

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
    Prerequisites: Windows powercfg.exe. Only write/commit exit codes are interpreted.
    Author: RIDE-Windows maintainers.
    Version: 0.3.0
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
    missing index is reported as unavailable. Active-plan reads verify the scheme
    again after the index query and refuse drift. No localized text is parsed.

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
    Prerequisites: Windows PowrProf API; native read acceptance remains pending.
    Author: RIDE-Windows maintainers.
    Version: 0.3.0
  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [string] $SchemeGuid
  )
  if ($Operation.PowerIndex -notin @('AC','DC')) { throw 'Power index source must be AC or DC.' }
  $subgroup = [guid]$Operation.PowerSubgroupGuid; $setting = [guid]$Operation.PowerSettingGuid
  if ($subgroup -eq [guid]::Empty -or $setting -eq [guid]::Empty) { throw 'Power setting identities must be nonempty GUIDs.' }
  $readActive = -not $SchemeGuid
  if ($readActive) { $SchemeGuid = Get-RideNativeActivePowerScheme }
  $scheme = [guid]$SchemeGuid
  if ($scheme -eq [guid]::Empty) { throw 'Power scheme identity must be a nonempty GUID.' }
  $query = Get-RideNativePowerIndex -SchemeGuid $scheme -SubgroupGuid $subgroup -SettingGuid $setting -PowerIndex $Operation.PowerIndex
  if ($readActive -and [guid](Get-RideNativeActivePowerScheme) -ne $scheme) { throw 'Active power scheme changed during inspection; retry with fresh state.' }
  if (-not $query.Available) {
    return [pscustomobject]@{ Exists = $false; Available = $false; SchemeGuid = $scheme.ToString('D'); Index = $null; PowerIndex = $Operation.PowerIndex; NativeErrorCode = $query.ErrorCode }
  }
  [pscustomobject]@{ Exists = $true; Available = $true; SchemeGuid = $scheme.ToString('D'); Index = (ConvertTo-RidePowerIndex $query.Index); IndexEncoding = 'UInt32'; PowerIndex = $Operation.PowerIndex; NativeErrorCode = 0 }
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
    Version: 0.3.0
  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)][string] $State)
  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
  $desiredIndex = ConvertTo-RidePowerIndex $Operation.States[$State]
  $current = Get-RidePowerSettingState -Operation $Operation
  if (-not $current.Available) { throw "Power setting '$($Operation.Id)' is unavailable in the active power scheme on this device." }
  $verb = if ($Operation.PowerIndex -eq 'AC') { '/setacvalueindex' } else { '/setdcvalueindex' }
  $set = Invoke-RidePowercfg -Arguments @($verb, $current.SchemeGuid, $Operation.PowerSubgroupGuid, $Operation.PowerSettingGuid, $desiredIndex.ToString([Globalization.CultureInfo]::InvariantCulture))
  if ($set.ExitCode -ne 0) { throw "powercfg could not set '$($Operation.Id)': $($set.Output)" }
  $active = Invoke-RidePowercfg -Arguments @('/setactive', $current.SchemeGuid)
  if ($active.ExitCode -ne 0) { throw "powercfg set the index but could not commit '$($Operation.Id)': $($active.Output)" }
  $verified = Get-RidePowerSettingState -Operation $Operation
  if (-not $verified.Available -or $verified.SchemeGuid -ne $current.SchemeGuid -or $verified.Index -ne $desiredIndex) { throw "Power setting verification failed for '$($Operation.Id)'." }
}

function Restore-RidePowerSettingState {
  <#
  .SYNOPSIS
    Restore an exact power setting snapshot.

  .DESCRIPTION
    Writes the recorded index to its captured scheme and verifies it. Reactivates the scheme only
    when it is still the active scheme. New UInt32 captures preserve all 32 bits.
    Unmarked legacy captures may encode the same bits as a signed Int32; these are
    converted explicitly without changing the stored record. Unknown encodings refuse.

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
    Version: 0.3.0
  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)] $Snapshot)
  $hasEncoding = if ($Snapshot -is [Collections.IDictionary]) { $Snapshot.Contains('IndexEncoding') } else { $Snapshot.PSObject.Properties.Name -contains 'IndexEncoding' }
  $hasVersion = if ($Snapshot -is [Collections.IDictionary]) { $Snapshot.Contains('SnapshotVersion') } else { $Snapshot.PSObject.Properties.Name -contains 'SnapshotVersion' }
  if ($hasVersion -and ($Snapshot.SnapshotVersion -ne 1 -or -not $hasEncoding -or $Snapshot.PowerIndex -cnotin @('AC','DC'))) { throw 'Invalid power snapshot version or required fields.' }
  if ($hasEncoding -and $Snapshot.IndexEncoding -cne 'UInt32') { throw 'Unknown power snapshot index encoding.' }
  $restoreIndex = ConvertTo-RidePowerIndex -Value $Snapshot.Index -AllowLegacySigned:(-not $hasEncoding)
  if ([string]$Snapshot.SchemeGuid -notmatch '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -or [guid]$Snapshot.SchemeGuid -eq [guid]::Empty) { throw 'Invalid power snapshot scheme GUID.' }
  $hasPowerIndex = if ($Snapshot -is [Collections.IDictionary]) { $Snapshot.Contains('PowerIndex') } else { $Snapshot.PSObject.Properties.Name -contains 'PowerIndex' }
  if ($hasPowerIndex -and $Snapshot.PowerIndex -cne $Operation.PowerIndex) { throw 'Power snapshot AC/DC index does not match the operation.' }
  $verb = if ($Operation.PowerIndex -eq 'AC') { '/setacvalueindex' } else { '/setdcvalueindex' }
  $set = Invoke-RidePowercfg -Arguments @($verb, [string]$Snapshot.SchemeGuid, $Operation.PowerSubgroupGuid, $Operation.PowerSettingGuid, $restoreIndex.ToString([Globalization.CultureInfo]::InvariantCulture))
  if ($set.ExitCode -ne 0) { throw "powercfg could not restore '$($Operation.Id)': $($set.Output)" }
  $active = Get-RidePowerSettingState -Operation $Operation
  if ($active.SchemeGuid -eq $Snapshot.SchemeGuid) {
    $commit = Invoke-RidePowercfg -Arguments @('/setactive', [string]$Snapshot.SchemeGuid)
    if ($commit.ExitCode -ne 0) { throw "powercfg could not commit restoration of '$($Operation.Id)': $($commit.Output)" }
  }
  $verified = Get-RidePowerSettingState -Operation $Operation -SchemeGuid ([string]$Snapshot.SchemeGuid)
  if (-not $verified.Available -or $verified.Index -ne $restoreIndex) { throw "Power setting restoration verification failed for '$($Operation.Id)'." }
}

Export-ModuleMember -Function Get-RidePowerSettingState, Set-RidePowerSettingState, Restore-RidePowerSettingState
