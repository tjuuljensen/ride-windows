<#
.SYNOPSIS
  Inspect and manage the catalog Windows Defender path exclusions.

.DESCRIPTION
  Resolves the tools or Downloads/bootstrap path, reads exclusion membership, and adds/removes only
  the selected exclusion. Adding may create the directory; Restore only recovers exclusion
  membership, not folder contents. Engine apply binds writes to its captured path
  and membership. Writes are checked again through the exclusion provider.

.EXAMPLE
  Import-Module .\modules\RIDE-Defender.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Defender cmdlets; elevation for exclusion changes; current-user shell-folder
  metadata.
  File/environment inputs: RIDEVAR-Customization-ToolsFolder, SystemDrive, Downloads shell folder,
  and RIDEVAR-Download-Only affect path/directory resolution.
  Recovery: State-changing handlers are engine-internal: use ride.ps1 preview and captured-run
  restoration. Direct calls bypass ShouldProcess and snapshot capture.
  Author: RIDE-Windows maintainers.
  Version: 0.2.0
  Changelog:
    0.2.0: Bind apply to captured identity/membership and validate versioned recovery.
    0.1.0: Establish documented module ownership, version, and exported-command help during this
    walkthrough.
  Supported targets are declared per operation in catalog/operations.psd1. This walkthrough
  validates syntax/help, not Windows state transitions.

.LINK
  docs/models/script-repository-model.md

.LINK
  docs/OPERATIONS.md

#>


$script:ModuleVersion = '0.2.0'

$ErrorActionPreference = 'Stop'

function ConvertTo-RideDefenderLiteralPath {
  param($Path)
  if ($Path -isnot [string] -or [string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 32767 -or
      $Path -match '[\x00-\x1f*?%]' -or $Path -match '^\\\\[?.]\\' -or
      ($Path -notmatch '^[A-Za-z]:[\\/]' -and $Path -notmatch '^\\\\[^\\/]+\\[^\\/]+\\') -or
      $Path.Substring(2).Contains(':')) {
    throw 'Defender exclusion requires a fully qualified literal directory path; relative, device, wildcard and unresolved-variable paths are not supported.'
  }
  $full = [IO.Path]::GetFullPath($Path)
  $root = [IO.Path]::GetPathRoot($full)
  $full = $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  if ($full -ieq $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)) {
    throw 'A drive or share root is not a supported RIDE directory exclusion.'
  }
  $full
}

function Assert-RideDefenderCapturedMembership {
  param($Capture)
  if ($null -eq $Capture -or $Capture.Present -isnot [bool]) { throw 'Defender capture requires literal Boolean membership and its captured path.' }
  ConvertTo-RideDefenderLiteralPath $Capture.Path
}

function Resolve-RideDefenderExclusionPath {
  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  switch ($Operation.PathResolver) {
    'ToolsDirectory' {
      $path = [Environment]::GetEnvironmentVariable('RIDEVAR-Customization-ToolsFolder', 'Process')
      if (-not $path) {
        $systemDrive = [Environment]::GetEnvironmentVariable('SystemDrive', 'Process')
        if (-not $systemDrive) { throw 'The system drive could not be resolved for the tools exclusion.' }
        $path = Join-Path -Path $systemDrive -ChildPath 'Tools'
      }
    }
    'BootstrapDirectory' {
      $downloadsValueName = '{374DE290-123F-4565-9164-39C4925E467B}'
      $shellFolders = Get-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name $downloadsValueName -ErrorAction Stop
      $downloadsPath = [Environment]::ExpandEnvironmentVariables([string]$shellFolders.$downloadsValueName)
      if (-not $downloadsPath) { throw 'The current user Downloads folder could not be resolved for the bootstrap exclusion.' }
      $path = Join-Path -Path $downloadsPath -ChildPath 'bootstrap'
    }
    default { throw "Unsupported Defender exclusion path resolver: $($Operation.PathResolver)" }
  }

  $path = [Environment]::ExpandEnvironmentVariables([string]$path)
  ConvertTo-RideDefenderLiteralPath $path
}

function Get-RideDefenderPreferenceObservation {
  Get-MpPreference -ErrorAction Stop
}

function Get-RideDefenderExclusionPaths {
  $preferences = Get-RideDefenderPreferenceObservation
  if ($null -eq $preferences -or @($preferences).Count -ne 1 -or
      $preferences.PSObject.Properties.Name -notcontains 'ExclusionPath') {
    throw 'Defender returned no usable exclusion membership observation.'
  }
  @($preferences.ExclusionPath | Where-Object { $_ })
}

function Add-RideDefenderExclusion {
  param([Parameter(Mandatory = $true)][string] $Path)
  Add-MpPreference -ExclusionPath $Path -ErrorAction Stop
}

function Remove-RideDefenderExclusion {
  param([Parameter(Mandatory = $true)][string] $Path)
  Remove-MpPreference -ExclusionPath $Path -ErrorAction Stop
}

function Test-RideDefenderExclusionPresent {
  param(
    [Parameter(Mandatory = $true)][string] $Path,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]] $ExclusionPaths
  )

  $normalizedPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  foreach ($exclusionPath in $ExclusionPaths) {
    try {
      $normalizedExclusionPath = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($exclusionPath)).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
      if ([string]::Equals($normalizedPath, $normalizedExclusionPath, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    catch {
      if ([string]::Equals($Path, $exclusionPath, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
  }
  $false
}

function Get-RideDefenderExclusionState {
  <#
  .SYNOPSIS
    Resolve a declared path and inspect Defender exclusion membership.

  .DESCRIPTION
    Uses the catalog PathResolver and current-user environment/shell-folder inputs. Compares
    normalized paths without changing Defender preferences.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideDefenderExclusionState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Present and Path.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $path = Resolve-RideDefenderExclusionPath -Operation $Operation
  $exclusionPaths = @(Get-RideDefenderExclusionPaths)
  [pscustomobject]@{
    Present = Test-RideDefenderExclusionPresent -Path $path -ExclusionPaths $exclusionPaths
    Path = $path
  }
}

function Ensure-RideDefenderExclusionDirectory {
  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)][string] $Path)

  if ($Operation.PathResolver -eq 'ToolsDirectory' -and [Environment]::GetEnvironmentVariable('RIDEVAR-Download-Only', 'Process')) { return }
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
  }
}

function Set-RideDefenderExclusionState {
  <#
  .SYNOPSIS
    Add or remove the catalog Defender path exclusion.

  .DESCRIPTION
    Present creates the directory if needed and adds a missing exclusion; Absent removes an existing
    exclusion. Directory creation observes RIDEVAR-Download-Only for ToolsDirectory. Direct calls
    bypass engine preview/snapshots.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER State
    Declared desired state for the selected catalog operation.

  .PARAMETER ExpectedState
    Engine pre-change capture. A changed resolved path or membership refuses the
    write before directory creation. Omitted only by internal direct-call callers.

  .EXAMPLE
    Get-Help Set-RideDefenderExclusionState -Full
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
    [Parameter(Mandatory = $true)][ValidateSet('Present', 'Absent')][string] $State,
    $ExpectedState
  )

  $current = Get-RideDefenderExclusionState -Operation $Operation
  $path = Assert-RideDefenderCapturedMembership $current
  if ($PSBoundParameters.ContainsKey('ExpectedState')) {
    $expectedPath = Assert-RideDefenderCapturedMembership $ExpectedState
    if ($path -ine $expectedPath -or $current.Present -ne $ExpectedState.Present) {
      throw 'Defender exclusion path or membership changed after capture; no write was attempted.'
    }
  }
  if ($State -eq 'Present') {
    if ($current.Present) { return }
    Ensure-RideDefenderExclusionDirectory -Operation $Operation -Path $path
    if (Test-RideDefenderExclusionPresent -Path $path -ExclusionPaths @(Get-RideDefenderExclusionPaths)) {
      throw 'Defender exclusion membership changed during directory preparation; no exclusion write was attempted.'
    }
    Add-RideDefenderExclusion -Path $path
  }
  elseif ($current.Present) { Remove-RideDefenderExclusion -Path $path }
  else { return }
  $actual = Test-RideDefenderExclusionPresent -Path $path -ExclusionPaths @(Get-RideDefenderExclusionPaths)
  if ($actual -ne ($State -eq 'Present')) {
    throw 'Defender did not report the requested exclusion membership; retain the saved capture for recovery.'
  }
}

function Restore-RideDefenderExclusionState {
  <#
  .SYNOPSIS
    Restore captured Defender exclusion membership.

  .DESCRIPTION
    Uses the saved literal path and adds/removes only its membership. Version-1
    records bind operation/resolver and intended membership. Older Boolean/path
    records remain readable; malformed or pathless records fail without writes.
    Does not recreate/delete directory contents. Use Restore-RideRun.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER Snapshot
    Captured pre-change state for this operation, read from the matching saved run.

  .EXAMPLE
    Get-Help Restore-RideDefenderExclusionState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)] $Snapshot)

  $path = Assert-RideDefenderCapturedMembership $Snapshot
  $hasVersion = if ($Snapshot -is [Collections.IDictionary]) { $Snapshot.Contains('SnapshotVersion') } else { $Snapshot.PSObject.Properties.Name -contains 'SnapshotVersion' }
  if ($hasVersion) {
    if (($Snapshot.SnapshotVersion -isnot [int] -and $Snapshot.SnapshotVersion -isnot [long]) -or $Snapshot.SnapshotVersion -ne 1 -or
        $Snapshot.OperationId -isnot [string] -or $Snapshot.OperationId -ine $Operation.Id -or
        $Snapshot.PathResolver -isnot [string] -or $Snapshot.PathResolver -cne $Operation.PathResolver -or
        $Snapshot.ExpectedPresent -isnot [bool]) {
      throw 'Invalid or mismatched Defender exclusion recovery version/identity.'
    }
    if ($Snapshot.Present -eq $Snapshot.ExpectedPresent) { return }
  }
  $exclusionPaths = @(Get-RideDefenderExclusionPaths)
  $currentlyPresent = Test-RideDefenderExclusionPresent -Path $path -ExclusionPaths $exclusionPaths
  if ($Snapshot.Present -and -not $currentlyPresent) {
    Add-RideDefenderExclusion -Path $path
  }
  elseif (-not $Snapshot.Present -and $currentlyPresent) {
    Remove-RideDefenderExclusion -Path $path
  }
  else { return }
  $restored = Test-RideDefenderExclusionPresent -Path $path -ExclusionPaths @(Get-RideDefenderExclusionPaths)
  if ($restored -ne $Snapshot.Present) { throw 'Defender exclusion recovery was not observed; retain the saved capture and resolve provider/policy failures before retry.' }
}

Export-ModuleMember -Function Get-RideDefenderExclusionState, Set-RideDefenderExclusionState, Restore-RideDefenderExclusionState
