<#
.SYNOPSIS
  Inspect and restore current Windows boot configuration elements.

.DESCRIPTION
  Queries bcdedit /enum {current}, applies declared element values or removes overrides, and
  restores captured values. Throws on native-command failures. Boot changes may require a restart;
  import defines commands only.

.EXAMPLE
  Import-Module .\modules\RIDE-BootConfiguration.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: bcdedit.exe and the applicable access/elevation for BCD operations.
  File/environment inputs: Catalog BcdElement/States and captured Exists/Value.
  Recovery: State-changing handlers are engine-internal: use ride.ps1 preview and captured-run
  restoration. Direct calls bypass ShouldProcess and snapshot capture.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish documented module ownership, version, and exported-command help during this
    walkthrough.
  Supported targets are declared per operation in catalog/operations.psd1. This walkthrough
  validates syntax/help, not Windows state transitions.

.LINK
  docs/models/script-repository-model.md

.LINK
  docs/OPERATIONS.md

#>


$script:ModuleVersion = '0.1.0'

function Get-RideBootConfigurationState {
  <#
  .SYNOPSIS
    Read one element from the current BCD entry.

  .DESCRIPTION
    Runs bcdedit /enum {current} /v and matches the declared BcdElement. Nonzero native exit codes
    throw; no BCD changes occur.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideBootConfigurationState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Exists and Value.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $output = (& bcdedit.exe /enum '{current}' /v 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { throw "BCDEdit query failed for '$($Operation.BcdElement)': $($output.Trim())" }
  $pattern = '(?im)^\s*{0}\s+(.+?)\s*$' -f [regex]::Escape($Operation.BcdElement)
  $match = [regex]::Match($output, $pattern)
  [pscustomobject]@{
    Exists = $match.Success
    Value = if ($match.Success) { $match.Groups[1].Value.Trim() } else { $null }
  }
}

function Set-RideBootConfigurationState {
  <#
  .SYNOPSIS
    Set or remove a declared current-entry BCD override.

  .DESCRIPTION
    Uses bcdedit /set or /deletevalue according to the catalog state map. Nonzero exit codes throw.
    Use the engine for snapshot, preview, privilege, and target checks.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER State
    Declared desired state for the selected catalog operation.

  .EXAMPLE
    Get-Help Set-RideBootConfigurationState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $State
  )

  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
  $value = $Operation.States[$State]
  if ($null -eq $value) {
    Invoke-RideBootConfigurationCommand -Arguments @('/deletevalue', '{current}', $Operation.BcdElement)
  }
  else {
    Invoke-RideBootConfigurationCommand -Arguments @('/set', '{current}', $Operation.BcdElement, [string]$value)
  }
}

function Restore-RideBootConfigurationState {
  <#
  .SYNOPSIS
    Restore a captured BCD element value or absence.

  .DESCRIPTION
    Writes the captured value or removes an originally absent override. Boot behavior may require a
    restart; use Restore-RideRun.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER Snapshot
    Captured pre-change state for this operation, read from the matching saved run.

  .EXAMPLE
    Get-Help Restore-RideBootConfigurationState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $Snapshot
  )

  if ($Snapshot.Exists) {
    Invoke-RideBootConfigurationCommand -Arguments @('/set', '{current}', $Operation.BcdElement, [string]$Snapshot.Value)
  }
  else {
    Invoke-RideBootConfigurationCommand -Arguments @('/deletevalue', '{current}', $Operation.BcdElement)
  }
}

function Invoke-RideBootConfigurationCommand {
  param([Parameter(Mandatory = $true)][string[]] $Arguments)

  $output = (& bcdedit.exe @Arguments 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { throw "BCDEdit command failed: $($output.Trim())" }
}

Export-ModuleMember -Function Get-RideBootConfigurationState, Set-RideBootConfigurationState, Restore-RideBootConfigurationState
