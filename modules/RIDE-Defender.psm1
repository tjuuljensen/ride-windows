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
