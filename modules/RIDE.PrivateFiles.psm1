<#
.SYNOPSIS
  Create and read private local files for credential-bearing RIDE preparation/state.
.DESCRIPTION
  Creates files with current-user/SYSTEM or machine administrator/SYSTEM access
  and verifies open-handle permissions. Reads require the matching owner and
  protected DACL. Does not change permissions on an existing file or directory.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Local filesystem with Windows ACL support; existing parent directory.
  Recovery: Caller owns disposal and new-file cleanup. No overwrite is permitted.
  Version: 0.2.0.
  Changelog: 0.2.0: Add explicit administrator-owned machine state without changing user defaults.
  0.1.0: Share the validated WLAN private-file boundary with lifecycle state.
#>
$ErrorActionPreference='Stop'

function Resolve-RidePrivateFilePath {
  param([string]$Path)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Private RIDE files require Windows.' }
  $full=[IO.Path]::GetFullPath($Path)
  if ($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':') -or [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full)).DriveType -eq [IO.DriveType]::Network) { throw 'Private output requires a local drive path without alternate streams.' }
  $parent=[IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($full))
  if (-not $parent.Exists) { throw 'Create the private-file parent directory explicitly.' }
  for ($node=$parent;$null -ne $node;$node=$node.Parent) { if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Private-file ancestors must not be reparse points.' } }
  if ([IO.File]::Exists($full) -and ([IO.File]::GetAttributes($full) -band [IO.FileAttributes]::ReparsePoint)) { throw 'Private files must not be reparse points.' }
  $full
}
function New-RidePrivateFileSecurity {
  param([ValidateSet('User','Machine')][string]$Scope='User')
  if($Scope -eq 'Machine'){$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')}
  else{$identity=[Security.Principal.WindowsIdentity]::GetCurrent();try { $sid=$identity.User } finally { $identity.Dispose() }}
  $security=[Security.AccessControl.FileSecurity]::new()
  $security.SetAccessRuleProtection($true,$false);$security.SetOwner($sid)
  foreach ($principal in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
  }
  $security
}

function New-RidePrivateFileStream {
  <#
  .SYNOPSIS
    Create a new private file and return an open stream; no existing file is overwritten.
  .PARAMETER Path
    New local file in an existing directory. No reparse ancestors or network paths.
  .PARAMETER Scope
    User (default) grants current-user/SYSTEM access. Machine grants only local
    Administrators/SYSTEM and sets Administrators as owner; requires existing elevation.
  .OUTPUTS
    FileStream. Caller must dispose it, including on write failure.
  .NOTES
    Internal persistence helper. Caller owns ShouldProcess and data handling.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path,[ValidateSet('User','Machine')][string]$Scope='User')
  $Path=Resolve-RidePrivateFilePath $Path
  $security=New-RidePrivateFileSecurity -Scope $Scope
  $rights=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::ReadPermissions
  $stream=$null
  try {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
      $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,$rights,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$security)
      $actual=$stream.GetAccessControl()
    } else {
      $stream=[IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path),[IO.FileMode]::CreateNew,$rights,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$security)
      $actual=[IO.FileSystemAclExtensions]::GetAccessControl($stream)
    }
    $expectedRules=@($security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {'{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.IsInherited} | Sort-Object)
    $actualRules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {'{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.IsInherited} | Sort-Object)
    if (-not $actual.AreAccessRulesProtected -or ($expectedRules -join ';') -cne ($actualRules -join ';') -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $security.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'Private file permissions could not be verified before writing.' }
    $stream
  } catch {
    if ($stream) { $stream.Dispose() }
    throw
  }
}

function Read-RidePrivateFileBytes {
  <#
  .SYNOPSIS
    Read a bounded private file after checking owner and handle DACL.
  .PARAMETER Path
    Existing private local file with the selected scope's owner and access rules.
  .PARAMETER MaximumBytes
    Bound for the specific caller's record format. Default one MiB.
  .PARAMETER Scope
    User (default) or administrator-owned Machine permissions required before reading.
  .OUTPUTS
    Byte array. May contain credentials; callers must not emit it into logs.
  .NOTES
    Read-only. Uses an exclusive handle and never repairs existing permissions.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path,[ValidateRange(1,16777216)][int]$MaximumBytes=1048576,[ValidateSet('User','Machine')][string]$Scope='User')
  $Path=Resolve-RidePrivateFilePath $Path
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
  try {
    $expected=New-RidePrivateFileSecurity -Scope $Scope
    $actual=if($PSVersionTable.PSEdition -eq 'Desktop'){$stream.GetAccessControl()}else{[IO.FileSystemAclExtensions]::GetAccessControl($stream)}
    $expectedRules=@($expected.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.IsInherited}|Sort-Object)
    $actualRules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.IsInherited}|Sort-Object)
    if(-not $actual.AreAccessRulesProtected -or ($expectedRules -join ';') -cne ($actualRules -join ';') -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $expected.GetOwner([Security.Principal.SecurityIdentifier]).Value){throw 'Private file owner or permissions differ; no content was read.'}
    if($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes){throw 'Private file is empty or exceeds its size bound.'}
    $bytes=New-Object byte[] ([int]$stream.Length)
    $offset=0
    while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -eq 0){throw 'Private file changed or ended during read.'};$offset+=$count}
    ,$bytes
  }finally{$stream.Dispose()}
}

Export-ModuleMember -Function New-RidePrivateFileStream,Read-RidePrivateFileBytes
