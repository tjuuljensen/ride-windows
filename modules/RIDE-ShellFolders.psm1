<#
.SYNOPSIS
  Inspect, create and restore catalog desktop Shell folders.

.DESCRIPTION
  Manages one current-user desktop folder named with a Shell class identifier.
  Import defines commands only. Engine calls provide ShouldProcess and saved-run
  capture. Removal is nonrecursive and refuses files, reparse points and nonempty
  folders. Restore recovers a removed empty folder's attributes, timestamps and ACL.

.EXAMPLE
  Import-Module .\modules\RIDE-ShellFolders.psm1
  Get-Help Get-RideShellFolderState -Full

.INPUTS
  None on import. Exported commands accept explicit parameters.

.OUTPUTS
  None on import. Inspection returns directory state; changes return no objects.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: An existing writable current-user desktop.
  File/environment inputs: Catalog FolderName and the resolved DesktopDirectory.
  Recovery: Use ride.ps1 restore; restoring after desktop redirection requires review.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog: 0.1.0: Add the optional God Mode desktop Shell folder lifecycle.

.LINK
  https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction
#>


$script:ModuleVersion = '0.1.0'
$ErrorActionPreference = 'Stop'

function Get-RideDesktopDirectory {
  [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
}

function Resolve-RideShellFolderPath {
  param([hashtable] $Operation)
  if ($Operation.Scope -ne 'User' -or $Operation.PathResolver -ne 'CurrentUserDesktop' -or
      $Operation.FolderName -cne 'GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}') {
    throw 'Unsupported desktop Shell folder metadata.'
  }
  $desktop = Get-RideDesktopDirectory
  if (-not $desktop -or -not [IO.Path]::IsPathRooted($desktop) -or -not [IO.Directory]::Exists($desktop)) {
    throw 'The current-user desktop directory is unavailable; no folder was changed.'
  }
  [IO.Path]::GetFullPath((Join-Path $desktop $Operation.FolderName))
}

function Get-RideShellFolderState {
  <#
  .SYNOPSIS
    Read desktop Shell folder presence and recoverable directory metadata.
  .DESCRIPTION
    Inspects only the catalog path. Refuses a file or reparse point at that path.
    Does not enumerate the virtual Control Panel view or change Windows settings.
  .PARAMETER Operation
    User-scoped ShellFolder catalog metadata.
  .EXAMPLE
    Get-Help Get-RideShellFolderState -Full
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Path, Present, HasContents and directory metadata.
  .NOTES
    Ownership, compatibility and version follow the module overview.
  #>
  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $path = Resolve-RideShellFolderPath -Operation $Operation
  $item = $null
  try { $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop }
  catch [System.Management.Automation.ItemNotFoundException] { }
  if (-not $item) {
    return [pscustomobject]@{ Path = $path; Present = $false; HasContents = $false }
  }
  if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Refusing a file or reparse point at desktop Shell folder path '$path'."
  }
  $hasContents = $false
  foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($path)) { $hasContents = $true; break }
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
  $sections = [Security.AccessControl.AccessControlSections]::Access -bor
    [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
  [pscustomobject]@{
    Path = $path
    Present = $true
    HasContents = $hasContents
    Attributes = [int]$item.Attributes
    CreationTimeUtc = $item.CreationTimeUtc.ToString('o')
    LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
    SecurityDescriptor = $acl.GetSecurityDescriptorSddlForm($sections)
  }
}

function Set-RideShellFolderState {
  <#
  .SYNOPSIS
    Create or remove the catalog desktop Shell folder.
  .DESCRIPTION
    Present creates a missing directory and leaves existing directories unchanged.
    Absent deletes only an empty directory, without recursion. Call through the
    RIDE engine for preview, target checks and pre-change capture.
  .PARAMETER Operation
    User-scoped ShellFolder catalog metadata.
  .PARAMETER State
    Present or Absent.
  .EXAMPLE
    Get-Help Set-RideShellFolderState -Full
  .INPUTS
    None.
  .OUTPUTS
    None.
  .NOTES
    Ownership, compatibility and version follow the module overview.
  #>
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][ValidateSet('Present', 'Absent')][string] $State
  )
  $current = Get-RideShellFolderState -Operation $Operation
  if ($State -eq 'Present') {
    if (-not $current.Present) { New-Item -Path $current.Path -ItemType Directory -ErrorAction Stop | Out-Null }
    return
  }
  if (-not $current.Present) { return }
  if ($current.HasContents) { throw "Refusing to remove nonempty Shell folder '$($current.Path)'; preserve its files first." }
  # Nonrecursive deletion also protects files added after the presence check.
  [IO.Directory]::Delete($current.Path, $false)
}

function Restore-RideShellFolderState {
  <#
  .SYNOPSIS
    Restore captured desktop Shell folder presence and directory metadata.
  .DESCRIPTION
    Validates the captured path against the current desktop and refuses redirects,
    file/reparse collisions and nonempty directories. Recreates a removed empty
    folder and restores its ACL, attributes, creation time and modification time.
    A previously absent folder is removed only when empty.
  .PARAMETER Operation
    User-scoped ShellFolder catalog metadata.
  .PARAMETER Snapshot
    Versioned saved-run snapshot from the engine.
  .EXAMPLE
    Get-Help Restore-RideShellFolderState -Full
  .INPUTS
    None.
  .OUTPUTS
    None.
  .NOTES
    Ownership, compatibility and version follow the module overview.
  #>
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $Snapshot
  )
  $current = Get-RideShellFolderState -Operation $Operation
  if (-not [string]::Equals($current.Path, [string]$Snapshot.Path, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The saved Shell folder path does not match the current desktop; review desktop redirection before restoring.'
  }
  if (-not $Snapshot.Present) {
    Set-RideShellFolderState -Operation $Operation -State Absent
    return
  }
  if ($Snapshot.HasContents -or $current.HasContents) { throw 'Refusing to restore directory metadata over a nonempty Shell folder.' }
  $attributes = [IO.FileAttributes][int]$Snapshot.Attributes
  if (-not ($attributes -band [IO.FileAttributes]::Directory) -or ($attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Invalid captured Shell folder attributes.'
  }
  # PowerShell 7 may deserialize ISO JSON strings as DateTime. A string cast of
  # that object uses the display format and loses fractional seconds.
  $created = ConvertFrom-RideShellFolderTimestamp -Value $Snapshot.CreationTimeUtc
  $modified = ConvertFrom-RideShellFolderTimestamp -Value $Snapshot.LastWriteTimeUtc
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetSecurityDescriptorSddlForm([string]$Snapshot.SecurityDescriptor)
  if (-not $current.Present) { New-Item -Path $current.Path -ItemType Directory -ErrorAction Stop | Out-Null }
  Set-Acl -LiteralPath $current.Path -AclObject $acl -ErrorAction Stop
  [IO.File]::SetAttributes($current.Path, $attributes)
  [IO.Directory]::SetCreationTimeUtc($current.Path, $created)
  [IO.Directory]::SetLastWriteTimeUtc($current.Path, $modified)
}

function ConvertFrom-RideShellFolderTimestamp {
  param($Value)
  if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
  if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
  [DateTime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}

Export-ModuleMember -Function Get-RideShellFolderState, Set-RideShellFolderState, Restore-RideShellFolderState
