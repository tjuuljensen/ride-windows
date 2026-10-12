<#
.SYNOPSIS
  Manage individual current-user PowerShell startup settings without evaluating profiles.
.DESCRIPTION
  Resolves ConsoleHost profiles using each installed runtime with NoProfile. Versioned
  RIDE blocks are rendered from allowlisted settings, inspected as text, and updated
  under an exclusive file lock. Snapshot version 1 captures bytes, owner, runtime,
  path and expected post-change content. Restore preserves unrelated edits or reports
  a conflict. Import defines commands only; no profile is read or executed on import.
.EXAMPLE
  Import-Module .\modules\RIDE-ProfileSettings.psm1
  Get-Help Set-RideProfileSettingState -Full
.INPUTS
  None on import.
.OUTPUTS
  None on import. Inspection and snapshot commands return objects; writers return no data.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Installed selected runtime and writable intended-user profile directory.
  File/environment inputs: Runtime-reported CurrentUserCurrentHost path; current token SID.
  Recovery: ride.ps1 restore; conflicts retain the full original bytes in the saved record.
  Parent directories created for a profile are retained. File ACLs remain in place.
  Author: RIDE-Windows maintainers.
  Version: 0.1.2
  Changelog: 0.1.2: Recover original absence after a RIDE-created profile is unset.
    0.1.1: Allow thirty seconds for cold runtime discovery in disposable guests.
    0.1.0: Add bounded managed-block lifecycle and Terminal color rendering.
.LINK
  ../docs/POWERSHELL-PROFILES.md
.LINK
  https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags
#>


$script:ModuleVersion = '0.1.2'
$ErrorActionPreference = 'Stop'
$script:ProfileLimit = 1MB

function Get-RideProfileOwnerSid {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { $identity.User.Value } finally { $identity.Dispose() }
}

function Get-RideProfileRuntimeExecutable {
  param([string] $Runtime)
  if ($Runtime -eq 'WindowsPowerShell51') {
    $path = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if ([IO.File]::Exists($path)) { return $path }
  }
  elseif ($Runtime -eq 'PowerShell7') {
    if ($PSVersionTable.PSVersion.Major -eq 7 -and [IO.File]::Exists((Join-Path $PSHOME 'pwsh.exe'))) { return (Join-Path $PSHOME 'pwsh.exe') }
    $command = Get-Command pwsh.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
  }
}

function Resolve-RideProfileSettingTarget {
  param([hashtable] $Operation)
  if ($Operation.Kind -ne 'ProfileSetting' -or $Operation.Handler -ne 'ProfileSetting' -or
      $Operation.Scope -ne 'User' -or $Operation.RequiresAdmin -ne $false -or
      $Operation.ProfileRuntime -notin @('WindowsPowerShell51', 'PowerShell7') -or
      $Operation.ProfileSetting -ne 'TerminalColors' -or $Operation.Id -notmatch '^[a-z][a-z0-9.-]+$') {
    throw 'Unsupported PowerShell profile setting metadata.'
  }
  $executable = Get-RideProfileRuntimeExecutable $Operation.ProfileRuntime
  if (-not $executable) { return [pscustomobject]@{ Available = $false; Reason = 'Selected PowerShell runtime is not installed'; Path = $null; OwnerSid = Get-RideProfileOwnerSid } }
  $query = '$ErrorActionPreference = ''Stop''; $ProgressPreference = ''SilentlyContinue''; [pscustomobject]@{ Path = $PROFILE.CurrentUserCurrentHost; Major = $PSVersionTable.PSVersion.Major; Minor = $PSVersionTable.PSVersion.Minor; Edition = $PSVersionTable.PSEdition; HostName = $Host.Name; OwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } | ConvertTo-Json -Compress'
  $start = New-Object Diagnostics.ProcessStartInfo
  $start.FileName = $executable
  $start.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($query))
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $start
  try {
    $null = $process.Start()
    $output = $process.StandardOutput.ReadToEndAsync()
    $errors = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'PowerShell profile discovery timed out.' }
    # Windows PowerShell may send first-use progress/initialization diagnostics
    # to stderr despite a successful query. Require a successful exit AND the
    # complete identity-checked JSON result below rather than empty stderr.
    if ($process.ExitCode -ne 0) { throw 'PowerShell profile discovery failed; no profile was evaluated or changed.' }
    $target = $output.Result | ConvertFrom-Json -ErrorAction Stop
  }
  finally { $process.Dispose() }
  $expectedMajor = if ($Operation.ProfileRuntime -eq 'WindowsPowerShell51') { 5 } else { 7 }
  if ($target.Major -ne $expectedMajor -or ($expectedMajor -eq 5 -and ($target.Minor -ne 1 -or $target.Edition -ne 'Desktop')) -or
      $target.HostName -ne 'ConsoleHost' -or $target.OwnerSid -cne (Get-RideProfileOwnerSid) -or
      -not [IO.Path]::IsPathRooted([string]$target.Path) -or [IO.Path]::GetFileName([string]$target.Path) -cne 'Microsoft.PowerShell_profile.ps1') {
    throw 'PowerShell profile discovery returned an unexpected runtime, user or path.'
  }
  [pscustomobject]@{ Available = $true; Reason = $null; Path = [IO.Path]::GetFullPath($target.Path); OwnerSid = $target.OwnerSid }
}

function Initialize-RideProfileNativeApi {
  if ('Ride.ProfileFiles.Native' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Ride.ProfileFiles {
  [StructLayout(LayoutKind.Sequential)]
  public struct TagInfo { public uint Attributes; public uint Tag; }
  public static class Native {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
      IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind,
      out TagInfo info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind,
      ref byte disposition, uint size);
  }
}
'@
}

function Get-RideProfileReparseTag {
  param([string] $Path)
  Initialize-RideProfileNativeApi
  # Metadata-only OPEN_EXISTING, OPEN_REPARSE_POINT and BACKUP_SEMANTICS; no hydration/write.
  $handle = [Ride.ProfileFiles.Native]::CreateFileW($Path, 0, 7, [IntPtr]::Zero, 3, 35651584, [IntPtr]::Zero)
  try {
    if ($handle.IsInvalid) { throw 'Could not inspect the profile reparse point safely.' }
    $info = New-Object Ride.ProfileFiles.TagInfo
    if (-not [Ride.ProfileFiles.Native]::GetFileInformationByHandleEx($handle, 9, [ref]$info, 8)) { throw 'Could not identify the profile reparse point.' }
    $info.Tag
  }
  finally { $handle.Dispose() }
}

function Assert-RideProfilePath {
  param([string] $Path)
  $candidate = $Path
  while ($candidate) {
    if (Test-Path -LiteralPath $candidate) {
      $item = Get-Item -LiteralPath $candidate -Force
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        $tag = Get-RideProfileReparseTag $candidate
        # Known Microsoft cloud placeholders are not path redirection. All
        # name-surrogate/unknown tags (including symlinks and junctions) fail closed.
        if (($tag -band [Convert]::ToUInt32('FFFF0FFF', 16)) -ne [Convert]::ToUInt32('9000001A', 16)) {
          throw 'Refusing a redirecting or unknown reparse point in the PowerShell profile path.'
        }
      }
      if ($candidate -eq $Path -and $item.PSIsContainer) { throw 'The PowerShell profile path is a directory.' }
    }
    $parent = Split-Path -Parent $candidate
    if ($parent -eq $candidate) { break }
    $candidate = $parent
  }
}

function Get-RideProfileEncoding {
  param([byte[]] $Bytes)
  $offset = 0
  $name = 'Utf8'
  $encoding = New-Object Text.UTF8Encoding($false, $true)
  if ($Bytes.Length -ge 4 -and (($Bytes[0] -eq 255 -and $Bytes[1] -eq 254 -and $Bytes[2] -eq 0 -and $Bytes[3] -eq 0) -or ($Bytes[0] -eq 0 -and $Bytes[1] -eq 0 -and $Bytes[2] -eq 254 -and $Bytes[3] -eq 255))) { throw 'UTF-32 profiles are not supported; preserve the original file.' }
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) { $offset = 3 }
  elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 255 -and $Bytes[1] -eq 254) { $encoding = New-Object Text.UnicodeEncoding($false, $false, $true); $offset = 2; $name = 'Utf16LE' }
  elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 254 -and $Bytes[1] -eq 255) { $encoding = New-Object Text.UnicodeEncoding($true, $false, $true); $offset = 2; $name = 'Utf16BE' }
  try { $content = $encoding.GetString($Bytes, $offset, $Bytes.Length - $offset) }
  catch {
    if ($offset) { throw 'The profile has invalid encoded text.' }
    # ANSI files remain byte-preserving: all generated fragments are ASCII.
    $encoding = [Text.Encoding]::GetEncoding(28591)
    $content = $encoding.GetString($Bytes)
    $name = 'SingleByte'
  }
  if ($content.Contains([string][char]0)) { throw 'The profile contains unsupported binary or BOM-less UTF-16 text.' }
  [pscustomobject]@{ Encoding = $encoding; Offset = $offset; Text = $content; Name = $name }
}

function Get-RideProfileSettingBlock {
  param([hashtable] $Operation, [string] $State, [string] $NewLine = "`n")
  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
  if ($null -eq $Operation.States[$State]) { return '' }
  $schemes = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '../components/profiles/terminal-color-schemes.psd1')
  $normal = $schemes[$Operation.NormalColorScheme]
  $admin = $schemes[$Operation.AdminColorScheme]
  if (-not $normal -or -not $admin) { throw 'Unknown reviewed Terminal color preset.' }
  foreach ($palette in @($normal, $admin)) {
    if ($palette.Count -ne 19 -or @($palette.Values | Where-Object { $_ -cnotmatch '^#[0-9A-Fa-f]{6}$' }).Count) { throw 'Invalid reviewed Terminal palette data.' }
  }
  $lines = New-Object System.Collections.Generic.List[string]
  # The leading separator is owned by this block, even for a profile without a final newline.
  $lines.Add('')
  $lines.Add("# >>> RIDE ProfileSetting v1 $($Operation.Id) $State")
  $lines.Add('# Color values adapted from Microsoft Windows Terminal defaults.json (MIT).')
  $lines.Add('# https://github.com/microsoft/terminal/blob/main/src/cascadia/TerminalSettingsModel/defaults.json')
  foreach ($notice in (Get-Content -LiteralPath (Join-Path $PSScriptRoot '../components/profiles/microsoft-terminal-LICENSE.txt'))) { $lines.Add('# ' + $notice) }
  $lines.Add('& {')
  $lines.Add('  if ($Host.Name -ne ''ConsoleHost'' -or -not $env:WT_SESSION -or $PSSenderInfo -or')
  $lines.Add('      -not [Environment]::UserInteractive -or [Console]::IsOutputRedirected -or')
  $lines.Add('      @([Environment]::GetCommandLineArgs() | Where-Object { $_ -match ''^-noni'' }).Count) { return }')
  $major = if ($Operation.ProfileRuntime -eq 'WindowsPowerShell51') { 5 } else { 7 }
  $lines.Add("  if (`$PSVersionTable.PSVersion.Major -ne $major) { return }")
  $lines.Add('  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()')
  $lines.Add('  try { $principal = [Security.Principal.WindowsPrincipal]::new($identity); $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }')
  $lines.Add('  finally { $identity.Dispose() }')
  if ($State -eq 'AdminBlue') { $lines.Add('  if (-not $admin) { return }') }
  $lines.Add('  $esc = [char]27')
  $paletteNames = @('black','red','green','yellow','blue','purple','cyan','white','brightBlack','brightRed','brightGreen','brightYellow','brightBlue','brightPurple','brightCyan','brightWhite')
  foreach ($branch in @('admin', 'normal')) {
    if ($branch -eq 'normal' -and $State -eq 'AdminBlue') { continue }
    $palette = if ($branch -eq 'admin') { $admin } else { $normal }
    $lines.Add($(if ($branch -eq 'admin') { '  if ($admin) {' } else { '  else {' }))
    $osc = '4'
    for ($index = 0; $index -lt $paletteNames.Count; $index++) { $osc += ';' + $index + ';' + $palette[$paletteNames[$index]] }
    foreach ($sequence in @($osc, ('10;' + $palette.foreground), ('11;' + $palette.background), ('12;' + $palette.cursorColor))) {
      $lines.Add(('    [Console]::Write("${esc}]' + $sequence + '`a")'))
    }
    $lines.Add('  }')
  }
  $lines.Add('}')
  $lines.Add("# <<< RIDE ProfileSetting v1 $($Operation.Id)")
  ($lines -join $NewLine) + $NewLine
}

function Read-RideProfileSettingFile {
  param([hashtable] $Operation, $Target, [byte[]] $SavedBytes, [bool] $SavedExists)
  Assert-RideProfilePath $Target.Path
  $exists = [IO.File]::Exists($Target.Path)
  $bytes = [byte[]]@()
  if ($PSBoundParameters.ContainsKey('SavedBytes')) {
    $bytes = $SavedBytes
    $exists = $SavedExists
    if ($bytes.Length -gt $script:ProfileLimit) { throw 'Saved PowerShell profile exceeds the 1 MiB limit.' }
  }
  elseif ($exists) {
    if ((Get-Item -LiteralPath $Target.Path -Force).Length -gt $script:ProfileLimit) { throw 'PowerShell profile exceeds the 1 MiB inspection limit.' }
    $bytes = [IO.File]::ReadAllBytes($Target.Path)
    if ($bytes.Length -gt $script:ProfileLimit) { throw 'PowerShell profile exceeds the 1 MiB inspection limit.' }
  }
  $decoded = Get-RideProfileEncoding $bytes
  $text = $decoded.Text
  $newline = if ($text.Contains("`r`n")) { "`r`n" } elseif ($text.Contains("`n")) { "`n" } elseif ($text.Contains("`r")) { "`r" } else { "`r`n" }
  $id = [regex]::Escape($Operation.Id)
  $marker = '(?m)^# (?:>>>|<<<) RIDE ProfileSetting [^\r\n]*\b' + $id + '(?: |\r?$|$)'
  $markers = [regex]::Matches($text, $marker)
  $block = ''; $start = $bytes.Length; $length = 0; $state = $Operation.UnsetState
  if ($markers.Count) {
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Profile syntax is invalid; no managed block can be changed safely.' }
    $pattern = '(?s)(?:\r\n|\n|\r)# >>> RIDE ProfileSetting v1 ' + $id + ' (?<state>[A-Za-z][A-Za-z0-9]*)(?:\r\n|\n|\r).*?(?:\r\n|\n|\r)# <<< RIDE ProfileSetting v1 ' + $id + '(?:\r\n|\n|\r)'
    $matches = [regex]::Matches($text, $pattern)
    if ($markers.Count -ne 2 -or $matches.Count -ne 1) { throw 'Ambiguous or unsupported RIDE profile block; preserve the file and resolve the conflict.' }
    $match = $matches[0]
    foreach ($mark in $markers) {
      if (-not @($tokens | Where-Object { $_.Kind -eq 'Comment' -and $_.Extent.StartOffset -eq $mark.Index }).Count) { throw 'RIDE profile markers are embedded in other code or text.' }
      $nested = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.ScriptBlockAst] -and $node -ne $ast -and $node.Extent.StartOffset -lt $mark.Index -and $node.Extent.EndOffset -gt $mark.Index }, $true)
      if (@($nested).Count) { throw 'RIDE profile markers must be at the top level.' }
    }
    $state = $match.Groups['state'].Value
    if (-not $Operation.States.ContainsKey($state) -or $null -eq $Operation.States[$state]) { throw 'Unsupported RIDE profile block state.' }
    $block = $match.Value
    $blockNewline = if ($block.StartsWith("`r`n")) { "`r`n" } elseif ($block.StartsWith("`n")) { "`n" } else { "`r" }
    $newline = $blockNewline
    if ($block -cne (Get-RideProfileSettingBlock $Operation $state $blockNewline)) { throw 'The RIDE profile block was modified; resolve the conflict before changing it.' }
    $start = $decoded.Offset + $decoded.Encoding.GetByteCount($text.Substring(0, $match.Index))
    $length = $decoded.Encoding.GetByteCount($block)
  }
  [pscustomobject]@{
    Available = $true; Path = $Target.Path; OwnerSid = $Target.OwnerSid
    Runtime = $Operation.ProfileRuntime; SnapshotVersion = 1; FileExists = $exists
    FileBase64 = [Convert]::ToBase64String($bytes); Block = $block; State = $state
    BlockStart = $start; BlockLength = $length; EncodingName = $decoded.Name; NewLine = $newline
  }
}

function Merge-RideProfileBlockBytes {
  param($Current, [string] $Block)
  $bytes = [Convert]::FromBase64String($Current.FileBase64)
  $decoded = Get-RideProfileEncoding $bytes
  $fragment = $decoded.Encoding.GetBytes($Block)
  $result = New-Object byte[] ($bytes.Length - $Current.BlockLength + $fragment.Length)
  [Array]::Copy($bytes, 0, $result, 0, $Current.BlockStart)
  [Array]::Copy($fragment, 0, $result, $Current.BlockStart, $fragment.Length)
  [Array]::Copy($bytes, $Current.BlockStart + $Current.BlockLength, $result, $Current.BlockStart + $fragment.Length, $bytes.Length - $Current.BlockStart - $Current.BlockLength)
  if ($result.Length -gt $script:ProfileLimit) { throw 'Resulting PowerShell profile exceeds the 1 MiB limit.' }
  $tokens = $null; $errors = $null
  $null = [Management.Automation.Language.Parser]::ParseInput((Get-RideProfileEncoding $result).Text, [ref]$tokens, [ref]$errors)
  if ($errors.Count) { throw 'Resulting PowerShell profile has syntax errors; no file was changed.' }
  ,$result
}

function Write-RideProfileSettingFile {
  param($Current, [byte[]] $Bytes, [switch] $Delete)
  Assert-RideProfilePath $Current.Path
  $stream = $null
  try {
    if (-not $Current.FileExists) {
      if ($Delete) { return }
      $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $Current.Path))
    }
    $mode = if ($Current.FileExists) { [IO.FileMode]::Open } else { [IO.FileMode]::CreateNew }
    if ($Delete) {
      # Open with DELETE access so deletion can be marked on this locked handle,
      # without a close/reopen race against an editor or another RIDE process.
      Initialize-RideProfileNativeApi
      $handle = [Ride.ProfileFiles.Native]::CreateFileW($Current.Path, 3221291008, 0, [IntPtr]::Zero, 3, 128, [IntPtr]::Zero)
      if ($handle.IsInvalid) { $handle.Dispose(); throw 'Could not exclusively open the profile for bounded removal.' }
      $stream = New-Object IO.FileStream($handle, [IO.FileAccess]::ReadWrite)
    }
    else { $stream = [IO.File]::Open($Current.Path, $mode, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    if ($stream.Length -gt $script:ProfileLimit) { throw 'Profile changed after inspection; no contents were overwritten.' }
    $actual = New-Object byte[] ([int]$stream.Length)
    $read = 0
    while ($read -lt $actual.Length) { $count = $stream.Read($actual, $read, $actual.Length - $read); if (-not $count) { throw 'Could not read the locked profile.' }; $read += $count }
    if ([Convert]::ToBase64String($actual) -cne $Current.FileBase64) { throw 'Profile changed after inspection; no contents were overwritten.' }
    if ($Delete) {
      [byte]$disposition = 1
      if (-not [Ride.ProfileFiles.Native]::SetFileInformationByHandle($stream.SafeFileHandle, 4, [ref]$disposition, 1)) { throw 'Could not remove the unchanged RIDE-created profile.' }
      return
    }
    try { $stream.Position = 0; $stream.Write($Bytes, 0, $Bytes.Length); $stream.SetLength($Bytes.Length); $stream.Flush($true) }
    catch {
      $failure = $_
      try { $stream.Position = 0; $stream.Write($actual, 0, $actual.Length); $stream.SetLength($actual.Length); $stream.Flush($true) } catch { }
      throw $failure
    }
  }
  finally { if ($stream) { $stream.Dispose() } }
}

function Get-RideProfileSettingState {
  <#
  .SYNOPSIS
    Inspect a runtime's managed profile block without running the profile.
  .PARAMETER Operation
    User-scoped ProfileSetting catalog entry.
  .EXAMPLE
    Get-RideProfileSettingState -Operation $operation
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Availability, path, state and captured bytes.
  .NOTES
    Read-only bounded discovery. Version and compatibility follow the module overview.
  #>
  param([Parameter(Mandatory = $true)][hashtable] $Operation)
  $target = Resolve-RideProfileSettingTarget $Operation
  if (-not $target.Available) { return $target }
  Read-RideProfileSettingFile $Operation $target
}

function Get-RideProfileSettingSnapshot {
  <#
  .SYNOPSIS
    Capture versioned profile bytes and the intended post-change block for recovery.
  .PARAMETER Operation
    ProfileSetting catalog entry.
  .PARAMETER CurrentState
    Read-only state captured before the change.
  .PARAMETER State
    Intended catalog state, used to recognize the change during restore.
  .EXAMPLE
    Get-RideProfileSettingSnapshot -Operation $operation -CurrentState $current -State Recommended
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Snapshot contract version 1.
  .NOTES
    No writes. Full original bytes remain available if automatic recovery reports a conflict.
  #>
  param([hashtable] $Operation, $CurrentState, [string] $State)
  if (-not $CurrentState.Available) { throw 'The selected PowerShell runtime is unavailable.' }
  $block = Get-RideProfileSettingBlock $Operation $State $CurrentState.NewLine
  $bytes = Merge-RideProfileBlockBytes $CurrentState $block
  [pscustomobject]@{
    SnapshotVersion = 1; Runtime = $Operation.ProfileRuntime; Setting = $Operation.ProfileSetting
    Path = $CurrentState.Path; OwnerSid = $CurrentState.OwnerSid; FileExists = $CurrentState.FileExists
    FileBase64 = $CurrentState.FileBase64; Block = $CurrentState.Block; BlockStart = $CurrentState.BlockStart
    ExpectedBlock = $block; ExpectedFileBase64 = [Convert]::ToBase64String($bytes)
  }
}

function Set-RideProfileSettingState {
  <#
  .SYNOPSIS
    Set or remove one managed profile setting with preview and conflict detection.
  .DESCRIPTION
    Use the engine for target checks and saved-run capture. Default removes only this
    block. Existing unrelated bytes and file encoding are preserved; profiles are never sourced.
  .PARAMETER Operation
    ProfileSetting catalog entry.
  .PARAMETER State
    Declared Recommended, AdminBlue or Default state.
  .PARAMETER ExpectedState
    Optional engine pre-change state; rejects changes made since snapshot capture.
  .EXAMPLE
    Set-RideProfileSettingState -Operation $operation -State Recommended -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    None.
  .NOTES
    Changes affect new sessions. Version and compatibility follow the module overview.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
  param([Parameter(Mandatory = $true)][hashtable] $Operation, [Parameter(Mandatory = $true)][string] $State, $ExpectedState)
  $current = Get-RideProfileSettingState $Operation
  if (-not $current.Available) { throw 'The selected PowerShell runtime is unavailable.' }
  if ($ExpectedState -and ($current.OwnerSid -cne $ExpectedState.OwnerSid -or $current.Runtime -cne $ExpectedState.Runtime -or
      $current.FileExists -ne $ExpectedState.FileExists -or $current.FileBase64 -cne $ExpectedState.FileBase64 -or
      $current.Path -ine $ExpectedState.Path)) { throw 'Profile identity or content changed after snapshot capture; no contents were overwritten.' }
  $block = Get-RideProfileSettingBlock $Operation $State $current.NewLine
  if ($block -ceq $current.Block) { return }
  $bytes = Merge-RideProfileBlockBytes $current $block
  if ($PSCmdlet.ShouldProcess($current.Path, "Set $($Operation.ProfileSetting) to $State")) { Write-RideProfileSettingFile $current $bytes }
}

function Restore-RideProfileSettingState {
  <#
  .SYNOPSIS
    Restore a captured managed block, preserving unrelated profile changes.
  .DESCRIPTION
    Validates owner, runtime, path and snapshot version before writing. Recognizes the
    original or expected block; conflicting managed edits fail. Removed blocks can be
    reinserted after append-only edits. ValidateOnly performs all checks without writes.
  .PARAMETER Operation
    Original ProfileSetting catalog entry.
  .PARAMETER Snapshot
    Snapshot contract version 1, including expected post-change content.
  .PARAMETER ValidateOnly
    Preflight recovery without changing files.
  .EXAMPLE
    Restore-RideProfileSettingState -Operation $operation -Snapshot $snapshot -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    None.
  .NOTES
    Newly created profiles are deleted only when they still contain exclusively RIDE content.
    Version and compatibility follow the module overview.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
  param([hashtable] $Operation, $Snapshot, [switch] $ValidateOnly)
  $current = Get-RideProfileSettingState $Operation
  if (-not $current.Available -or $Snapshot.SnapshotVersion -ne 1 -or $Snapshot.Runtime -cne $Operation.ProfileRuntime -or
      $Snapshot.Setting -cne $Operation.ProfileSetting -or $Snapshot.OwnerSid -cne $current.OwnerSid -or
      -not [string]::Equals([string]$Snapshot.Path, [string]$current.Path, [StringComparison]::OrdinalIgnoreCase)) { throw 'Profile recovery identity, version or path mismatch; captured state is retained.' }
  $original = [Convert]::FromBase64String([string]$Snapshot.FileBase64)
  $expected = [Convert]::FromBase64String([string]$Snapshot.ExpectedFileBase64)
  if ($original.Length -gt $script:ProfileLimit -or $expected.Length -gt $script:ProfileLimit -or $Snapshot.BlockStart -lt 0 -or $Snapshot.BlockStart -gt $original.Length) { throw 'Invalid profile recovery snapshot.' }
  # Validate both saved blocks and their byte-level relationship without evaluating code.
  $target = [pscustomobject]@{ Path = $current.Path; OwnerSid = $current.OwnerSid }
  $captured = Read-RideProfileSettingFile -Operation $Operation -Target $target -SavedBytes $original -SavedExists ([bool]$Snapshot.FileExists)
  $applied = Read-RideProfileSettingFile -Operation $Operation -Target $target -SavedBytes $expected -SavedExists $true
  if ($captured.Block -cne [string]$Snapshot.Block -or $captured.BlockStart -ne $Snapshot.BlockStart -or
      $applied.Block -cne [string]$Snapshot.ExpectedBlock -or
      [Convert]::ToBase64String((Merge-RideProfileBlockBytes $captured ([string]$Snapshot.ExpectedBlock))) -cne [string]$Snapshot.ExpectedFileBase64) { throw 'Invalid profile recovery snapshot content.' }
  $savedDecoded = Get-RideProfileEncoding $original
  if ($current.Block -ceq [string]$Snapshot.Block -and $current.FileExists -eq [bool]$Snapshot.FileExists) { return }
  $delete = $false
  if ($current.FileBase64 -ceq [string]$Snapshot.ExpectedFileBase64) {
    $bytes = $original
    $delete = -not [bool]$Snapshot.FileExists
  }
  elseif ($current.Block -ceq [string]$Snapshot.ExpectedBlock -and $current.Block) {
    if ((Get-RideProfileEncoding ([Convert]::FromBase64String($current.FileBase64))).Name -cne $savedDecoded.Name) { throw 'Profile encoding changed; review recovery before restoring.' }
    $bytes = Merge-RideProfileBlockBytes $current ([string]$Snapshot.Block)
  }
  elseif (-not $current.Block -and -not $Snapshot.ExpectedBlock -and $Snapshot.Block) {
    $actual = [Convert]::FromBase64String($current.FileBase64)
    if ($actual.Length -lt $expected.Length) { throw 'Profile changed around the removed block; review recovery before restoring.' }
    $prefix = New-Object byte[] $expected.Length
    [Array]::Copy($actual, 0, $prefix, 0, $prefix.Length)
    if ([Convert]::ToBase64String($prefix) -cne [string]$Snapshot.ExpectedFileBase64) { throw 'Profile changed around the removed block; review recovery before restoring.' }
    $insertion = $current.PSObject.Copy(); $insertion.BlockStart = [int]$Snapshot.BlockStart; $insertion.BlockLength = 0
    $bytes = Merge-RideProfileBlockBytes $insertion ([string]$Snapshot.Block)
  }
  elseif ($current.FileBase64 -ceq [string]$Snapshot.FileBase64) {
    $bytes = $original
    $delete = -not [bool]$Snapshot.FileExists
  }
  else { throw 'Profile managed content changed since this run; captured state is retained.' }
  if ($ValidateOnly) { return }
  if ($PSCmdlet.ShouldProcess($current.Path, 'Restore captured PowerShell profile setting')) { Write-RideProfileSettingFile $current $bytes -Delete:$delete }
}

Register-ArgumentCompleter -CommandName Set-RideProfileSettingState, Get-RideProfileSettingSnapshot -ParameterName State -ScriptBlock {
  param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
  try {
    $operation = $fakeBoundParameters.Operation
    if ($operation -isnot [hashtable] -or $operation.States -isnot [hashtable]) { return }
    foreach ($candidate in $operation.States.Keys | Sort-Object -Unique) {
      if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
        [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
      }
    }
  } catch { }
}

Export-ModuleMember -Function Get-RideProfileSettingState, Get-RideProfileSettingSnapshot, Set-RideProfileSettingState, Restore-RideProfileSettingState
