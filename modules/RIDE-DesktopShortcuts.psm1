<#
.SYNOPSIS
  Manage catalog-owned current-user desktop shortcuts.
.DESCRIPTION
  Creates and removes a declared Windows shortcut using the current user's
  desktop and the Windows Script Host shortcut COM interface. Existing files
  are never overwritten. Removal refuses a shortcut that no longer matches the
  catalog target, arguments, and working directory.
.EXAMPLE
  Get-Help Get-RideDesktopShortcutState -Full
.INPUTS
  None. Exported commands accept explicit operation metadata.
.OUTPUTS
  Inspection returns shortcut presence and target metadata; changes return none.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Windows Script Host shortcut COM support and a writable user desktop.
  Recovery: Use ride.ps1 restore; a modified shortcut is preserved and reported.
  Version: 0.1.3
  Changelog: 0.1.3: Report unavailable targets without naming a different shortcut product.
    0.1.2: Refuse directory and reparse-point collisions before COM access.
    0.1.1: Resolve declared shortcut paths without mutating catalog metadata.
    0.1.0: Add the optional BitLocker wizard shortcut lifecycle.
#>

$ErrorActionPreference = 'Stop'

function Resolve-RideDesktopShortcutPath {
  param([Parameter(Mandatory = $true)][hashtable] $Operation)
  $definition = switch ([string]$Operation.Id) {
    'windows.bitlocker-wizard-shortcut' {
      @{
        ShortcutName = 'BitLocker Drive Encryption.lnk'
        TargetPath = '%SystemRoot%\System32\BitLockerWizardElev.exe'
        Arguments = ''
        DescriptionText = 'Open Windows BitLocker Drive Encryption'
        WorkingDirectory = '%SystemRoot%\System32'
      }
      break
    }
    'windows.power-options-shortcut' {
      @{
        ShortcutName = 'Power Options.lnk'
        TargetPath = '%SystemRoot%\System32\control.exe'
        Arguments = '/name Microsoft.PowerOptions'
        DescriptionText = 'Open Windows Power Options'
        WorkingDirectory = '%SystemRoot%\System32'
      }
      break
    }
    default { $null }
  }
  if (-not $definition -or $Operation.Scope -ne 'User' -or $Operation.PathResolver -ne 'CurrentUserDesktop' -or
      $Operation.ShortcutName -cne $definition.ShortcutName -or
      $Operation.TargetPath -cne $definition.TargetPath -or
      $Operation.Arguments -cne $definition.Arguments -or
      $Operation.DescriptionText -cne $definition.DescriptionText -or
      $Operation.WorkingDirectory -cne $definition.WorkingDirectory) {
    throw 'Unsupported desktop shortcut metadata.'
  }
  $target = [Environment]::ExpandEnvironmentVariables([string]$Operation.TargetPath)
  $working = [Environment]::ExpandEnvironmentVariables([string]$Operation.WorkingDirectory)
  $targetPath = [IO.Path]::GetFullPath($target)
  $workingDirectory = [IO.Path]::GetFullPath($working)
  $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
  if (-not $desktop -or -not [IO.Path]::IsPathRooted($desktop) -or -not [IO.Directory]::Exists($desktop)) {
    throw 'The current-user desktop directory is unavailable; no shortcut was changed.'
  }
  [pscustomobject]@{
    Path = [IO.Path]::GetFullPath((Join-Path $desktop $Operation.ShortcutName))
    TargetPath = $targetPath
    Arguments = [string]$Operation.Arguments
    DescriptionText = [string]$Operation.DescriptionText
    WorkingDirectory = $workingDirectory
  }
}

function Get-RideDesktopShortcutPathEntry {
  param([Parameter(Mandatory = $true)][string] $Path)
  try { $attributes = [IO.File]::GetAttributes($Path) }
  catch [IO.FileNotFoundException] { return [pscustomobject]@{ Exists = $false; Attributes = $null } }
  catch [IO.DirectoryNotFoundException] { return [pscustomobject]@{ Exists = $false; Attributes = $null } }
  if (($attributes -band [IO.FileAttributes]::Directory) -or ($attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Refusing a directory or reparse point at desktop shortcut path '$Path'."
  }
  [pscustomobject]@{ Exists = $true; Attributes = $attributes }
}

function Get-RideDesktopShortcutState {
  <#
  .SYNOPSIS
    Inspect the declared current-user desktop shortcut.
  .DESCRIPTION
    Reports Present only when the existing shortcut matches the declared target,
    arguments, and working directory. Does not open the target.
  .PARAMETER Operation
    DesktopShortcut catalog metadata.
  .OUTPUTS
    PSCustomObject with path and presence state.
  #>
  param([Parameter(Mandatory = $true)][hashtable] $Operation)
  $shortcutSpec = Resolve-RideDesktopShortcutPath $Operation
  $path = $shortcutSpec.Path
  $pathEntry = Get-RideDesktopShortcutPathEntry -Path $path
  if (-not $pathEntry.Exists) { return [pscustomobject]@{ Path = $path; Present = $false; Matches = $false } }
  $shell = New-Object -ComObject WScript.Shell
  try {
    $shortcut = $shell.CreateShortcut($path)
    $target = [IO.Path]::GetFullPath([string]$shortcut.TargetPath)
    $matches = [string]::Equals($target, $shortcutSpec.TargetPath, [StringComparison]::OrdinalIgnoreCase) -and
      [string]::Equals([string]$shortcut.Arguments, $shortcutSpec.Arguments, [StringComparison]::Ordinal) -and
      [string]::Equals([IO.Path]::GetFullPath([string]$shortcut.WorkingDirectory), $shortcutSpec.WorkingDirectory, [StringComparison]::OrdinalIgnoreCase)
    [pscustomobject]@{ Path = $path; Present = [bool]$matches; Matches = [bool]$matches; ExistingFile = $true }
  }
  finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
}

function Set-RideDesktopShortcutState {
  <#
  .SYNOPSIS
    Create or remove the declared desktop shortcut.
  .DESCRIPTION
    Creates only a missing shortcut. Preserves an unrelated or modified file at
    the owned path. Call through the RIDE engine for ShouldProcess and capture.
  .PARAMETER Operation
    DesktopShortcut catalog metadata.
  .PARAMETER State
    Present or Absent.
  #>
  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)][ValidateSet('Present', 'Absent')][string] $State)
  $current = Get-RideDesktopShortcutState $Operation
  if ($State -eq 'Present') {
    if ($current.Present) { return }
    if ($current.ExistingFile) { throw "A different file already occupies '$($current.Path)'; it was preserved." }
    $shortcutSpec = Resolve-RideDesktopShortcutPath $Operation
    if (-not [IO.File]::Exists($shortcutSpec.TargetPath) -or -not [IO.Directory]::Exists($shortcutSpec.WorkingDirectory)) {
      throw 'The declared desktop shortcut target is unavailable on this device; no shortcut was changed.'
    }
    $shell = New-Object -ComObject WScript.Shell
    try {
      $shortcut = $shell.CreateShortcut($current.Path)
      $shortcut.TargetPath = $shortcutSpec.TargetPath
      $shortcut.Arguments = $shortcutSpec.Arguments
      $shortcut.Description = $shortcutSpec.DescriptionText
      $shortcut.WorkingDirectory = $shortcutSpec.WorkingDirectory
      $shortcut.Save()
    }
    finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
    return
  }
  if (-not $current.Present -and $current.ExistingFile) { throw "The shortcut at '$($current.Path)' no longer matches RIDE metadata; it was preserved." }
  if ($current.Present) { Remove-Item -LiteralPath $current.Path -Force -ErrorAction Stop }
}

function Restore-RideDesktopShortcutState {
  <#
  .SYNOPSIS
    Restore the captured shortcut presence.
  .PARAMETER Operation
    DesktopShortcut catalog metadata.
  .PARAMETER Snapshot
    Versioned saved-run snapshot.
  #>
  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)] $Snapshot)
  if ([bool]$Snapshot.Present) { Set-RideDesktopShortcutState -Operation $Operation -State Present }
  else { Set-RideDesktopShortcutState -Operation $Operation -State Absent }
}

Export-ModuleMember -Function Get-RideDesktopShortcutState, Set-RideDesktopShortcutState, Restore-RideDesktopShortcutState
