<#
.SYNOPSIS
  Inspect and manage the catalog Windows Defender path exclusions.

.DESCRIPTION
  Resolves the tools or Downloads/bootstrap path, reads exclusion membership, and adds/removes only
  the selected exclusion. Adding may create the directory; Restore only recovers exclusion
  membership, not folder contents.

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

$ErrorActionPreference = 'Stop'

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
  if (-not [IO.Path]::IsPathRooted($path)) { throw "Defender exclusion path must be rooted: $path" }
  [IO.Path]::GetFullPath($path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Get-RideDefenderExclusionPaths {
  $preferences = Get-MpPreference -ErrorAction Stop
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
    [Parameter(Mandatory = $true)][ValidateSet('Present', 'Absent')][string] $State
  )

  $current = Get-RideDefenderExclusionState -Operation $Operation
  if ($State -eq 'Present') {
    if ($current.Present) { return }
    Ensure-RideDefenderExclusionDirectory -Operation $Operation -Path $current.Path
    Add-RideDefenderExclusion -Path $current.Path
    return
  }
  if ($current.Present) { Remove-RideDefenderExclusion -Path $current.Path }
}

function Restore-RideDefenderExclusionState {
  <#
  .SYNOPSIS
    Restore captured Defender exclusion membership.

  .DESCRIPTION
    Uses the saved resolved path when available and adds/removes only its membership. Does not
    recreate/delete directory contents. Use Restore-RideRun.

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

  $path = [string]$Snapshot.Path
  if (-not $path) { $path = Resolve-RideDefenderExclusionPath -Operation $Operation }
  $exclusionPaths = @(Get-RideDefenderExclusionPaths)
  $currentlyPresent = Test-RideDefenderExclusionPresent -Path $path -ExclusionPaths $exclusionPaths
  if ($Snapshot.Present -and -not $currentlyPresent) {
    Add-RideDefenderExclusion -Path $path
  }
  elseif (-not $Snapshot.Present -and $currentlyPresent) {
    Remove-RideDefenderExclusion -Path $path
  }
}

Export-ModuleMember -Function Get-RideDefenderExclusionState, Set-RideDefenderExclusionState, Restore-RideDefenderExclusionState
