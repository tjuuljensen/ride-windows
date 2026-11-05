<#
.SYNOPSIS
  Install and recover explicitly selected machine-scope TrueType fonts.
.DESCRIPTION
  Preflights an entire hash-pinned batch, preserves existing matching fonts,
  refuses collisions and records private recovery intent before any writer.
  Removal is limited to fonts created by a completed RIDE run. File bytes,
  owner/group/DACL, attributes, timestamps and font registration are checked.
.NOTES
  Compatibility: Candidate native Windows 11 x64, PowerShell 5.1 and PowerShell 7.
  Prerequisites: Existing elevation, existing local state directory and licensed
  single-face TrueType files. No UAC, reboot, font-cache reset or process killing.
  Recovery: Conditional captured file/registration recovery; active font users or
  other sessions can prevent unloading/deletion. Incomplete runs retain intent.
  Runtime references, audit ACLs and other applications' cached fonts are not restored.
  Version: 0.1.2.
  Changelog: 0.1.2: Preserve an exact inherited security descriptor on recreated fonts.
  0.1.1: Identify the failing restore step and differing readback fields.
  0.1.0: Add private, ownership-bound machine-font lifecycle candidate.
.LINK
  ../docs/machine-fonts.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.FontFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop
$script:FontRegistryPath='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'

function Get-RideMachineFontContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{[pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;Revision=[int]$version.UBR;InstallationType=[string]$version.InstallationType;NativeProcess=[Environment]::Is64BitProcess;Architecture=$env:PROCESSOR_ARCHITECTURE;UserSid=$identity.User.Value;SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;FontDirectory=Join-Path ([Environment]::GetFolderPath('Windows')) 'Fonts';Administrator=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}}finally{$identity.Dispose()}
}

function Assert-RideMachineFontContext {
  param($Context,$Expected,[bool]$Mutation)
  if($Context.InstallationType -cne 'Client' -or $Context.Build -cnotmatch '^\d{5,8}$' -or [int]$Context.Build -lt 22000 -or -not $Context.NativeProcess -or $Context.Architecture -cne 'AMD64'){throw 'Machine fonts require the native Windows 11 x64 candidate target.'}
  if($Mutation -and -not $Context.Administrator){throw 'Machine fonts require existing elevation; no UAC prompt is launched.'}
  if($Expected){foreach($field in @('ComputerName','Build','EditionId','Revision','InstallationType','NativeProcess','Architecture','UserSid','SessionId','FontDirectory')){if($Context.$field -cne $Expected.$field){throw "Machine-font context drift ($field); retain recovery state."}}}
  $directory=[IO.DirectoryInfo]::new($Context.FontDirectory)
  if(-not $directory.Exists){throw 'Windows font directory is unavailable.'}
  for($node=$directory;$null -ne $node;$node=$node.Parent){if($node.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Font destination ancestors must not be reparse points.'}}
}

function Get-RideFontHash {
  param([byte[]]$Bytes)
  $sha=[Security.Cryptography.SHA256]::Create()
  try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')}finally{$sha.Dispose()}
}

function Get-RideMachineFontRegistry {
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:FontRegistryPath,$false)
  if(-not $key){throw 'Machine font registry key is unavailable.'}
  try {
    $names=@($key.GetValueNames());if($names.Count -gt 4096){throw 'Font registry inventory exceeds its bound.'}
    [pscustomobject]@{Security=$key.GetAccessControl().GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access');Rows=@($names|Sort-Object|ForEach-Object {[pscustomobject]@{Name=$_;Kind=[string]$key.GetValueKind($_);Value=$key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}})}
  }finally{$key.Dispose()}
}

function Set-RideMachineFontRegistration {
  param([string]$Name,[string]$FileName)
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:FontRegistryPath,$true)
  if(-not $key){throw 'Machine font registry key is unavailable for writing.'}
  try{$key.SetValue($Name,$FileName,[Microsoft.Win32.RegistryValueKind]::String);$key.Flush()}finally{$key.Dispose()}
}

function Remove-RideMachineFontRegistration {
  param([string]$Name)
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:FontRegistryPath,$true)
  if(-not $key){throw 'Machine font registry key is unavailable for writing.'}
  try{$key.DeleteValue($Name,$true);$key.Flush()}finally{$key.Dispose()}
}

function Invoke-RideMachineFontNative {
  param([ValidateSet('Add','Remove','Notify')][string]$Action,[string]$Path)
  if(-not ('Ride.MachineFontsV1.Native' -as [type])){
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Ride.MachineFontsV1 {
 public static class Native {
  [DllImport("gdi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] public static extern int AddFontResourceW(string path);
  [DllImport("gdi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool RemoveFontResourceW(string path);
  [DllImport("user32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool SendNotifyMessageW(IntPtr window,uint message,UIntPtr wParam,IntPtr lParam);
 }
}
'@ -ErrorAction Stop
  }
  switch($Action){
    Add {if([Ride.MachineFontsV1.Native]::AddFontResourceW($Path) -lt 1){throw 'Windows did not load the selected font.'}}
    Remove {if(-not [Ride.MachineFontsV1.Native]::RemoveFontResourceW($Path)){throw 'Font unload was not confirmed in this session; retain state and inspect active consumers.'}}
    Notify {if(-not [Ride.MachineFontsV1.Native]::SendNotifyMessageW([IntPtr]65535,0x001d,[UIntPtr]::Zero,[IntPtr]::Zero)){throw 'Font-change notification was not submitted.'}}
  }
}

function Get-RideMachineFontSnapshot {
  param($Context,$Entry,$Registry)
  if([IO.Path]::GetFileName($Entry.FileName) -cne $Entry.FileName -or [IO.Path]::GetExtension($Entry.FileName) -ine '.ttf'){throw 'Invalid saved font filename.'}
  $path=Join-Path $Context.FontDirectory $Entry.FileName
  if([IO.Directory]::Exists($path)){throw 'A directory collides with the selected font destination.'}
  $file=[IO.FileInfo]::new($path)
  if($file.Exists -and ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Font destination must not be a reparse point.'}
  $state=[ordered]@{Exists=$file.Exists;Sha256=$null;Bytes=0;Security=$null;Attributes=0;CreationUtcTicks=$null;LastWriteUtcTicks=$null}
  if($file.Exists){
    if($file.Length -gt 16777216){throw 'Existing font exceeds the file size bound.'}
    $state.Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;$state.Bytes=$file.Length
    $security=Get-Acl -LiteralPath $path
    $state.Security=$security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access')
    $state.Attributes=[int]$file.Attributes;$state.CreationUtcTicks=$file.CreationTimeUtc.Ticks.ToString();$state.LastWriteUtcTicks=$file.LastWriteTimeUtc.Ticks.ToString()
  }
  $matches=@($Registry.Rows|Where-Object Name -IEQ $Entry.RegistryName)
  if($matches.Count -gt 1){throw 'Ambiguous font registration.'}
  $aliases=@($Registry.Rows|Where-Object {$_.Value -is [string] -and [IO.Path]::GetFileName($_.Value) -ieq $Entry.FileName}|ForEach-Object Name|Sort-Object)
  [pscustomobject]@{File=[pscustomobject]$state;Registration=if($matches.Count){$matches[0]}else{$null};Aliases=$aliases}
}

function Test-RideMachineFontEqual {
  param($Left,$Right)
  (ConvertTo-Json -InputObject $Left -Depth 8 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 8 -Compress)
}

function Assert-RideMachineFontRegistryUnrelated {
  param($Before,$After,[string[]]$Names)
  if($Before.Security -cne $After.Security -or -not (Test-RideMachineFontEqual @($Before.Rows|Where-Object Name -NotIn $Names) @($After.Rows|Where-Object Name -NotIn $Names))){throw 'Unrelated font registration or registry security changed; retain the run for inspection.'}
}

function Get-RideMachineFontRunPath {
  param([string]$StateDirectory,[string]$RunId,[ValidateSet('intent','applied')][string]$Part)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'Font run ID must be 32 lowercase hexadecimal characters.'}
  Join-Path $StateDirectory ($RunId+'.fonts.'+$Part+'.json')
}

function Assert-RideMachineFontStateDirectory {
  param([string]$StateDirectory)
  $full=[IO.Path]::GetFullPath($StateDirectory)
  if($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':') -or -not [IO.Directory]::Exists($full) -or [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full)).DriveType -eq [IO.DriveType]::Network){throw 'Font state requires an existing local directory without alternate streams.'}
  for($node=[IO.DirectoryInfo]::new($full);$null -ne $node;$node=$node.Parent){if($node.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Font state ancestors must not be reparse points.'}}
}

function Save-RideMachineFontRun {
  param([string]$StateDirectory,[string]$RunId,[string]$Part,$Record)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 15 -Compress))
  if($bytes.Length -gt 16777216){throw 'Font recovery record exceeds its bound.'}
  $stream=New-RideMachineFontStateStream -Path (Get-RideMachineFontRunPath $StateDirectory $RunId $Part)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

function New-RideMachineFontStateStream {
  param([string]$Path)
  New-RidePrivateFileStream -Path $Path -Scope Machine
}

function Read-RideMachineFontStateBytes {
  param([string]$Path)
  Read-RidePrivateFileBytes -Path $Path -MaximumBytes 16777216 -Scope Machine
}

function Read-RideMachineFontRun {
  param([string]$StateDirectory,[string]$RunId,[string]$Part)
  $bytes=Read-RideMachineFontStateBytes -Path (Get-RideMachineFontRunPath $StateDirectory $RunId $Part)
  $record=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
  if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'MachineFontLifecycle' -or $record.RunId -cne $RunId -or $record.Part -cne $Part){throw 'Font recovery record identity differs.'}
  $record
}

function Read-RideMachineFontManifest {
  param([string]$ManifestPath)
  $null=Read-RideFontSourceBytes -Path $ManifestPath -MaximumBytes 1048576
  $manifestFile=Get-Item -LiteralPath $ManifestPath -ErrorAction Stop
  if($manifestFile.PSIsContainer -or $manifestFile.Length -gt 1048576 -or $manifestFile.Extension -ine '.psd1' -or ($manifestFile.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'A bounded ordinary font PSD1 manifest is required.'}
  $manifest=Import-PowerShellDataFile -LiteralPath $manifestFile.FullName
  if(@($manifest.Keys|Where-Object {$_ -notin @('SchemaVersion','Fonts','License')}).Count -or $manifest.SchemaVersion -ne 1 -or @($manifest.Fonts).Count -lt 1 -or @($manifest.Fonts).Count -gt 32 -or $manifest.License -isnot [hashtable] -or @($manifest.License.Keys|Where-Object {$_ -notin @('Path','Sha256')}).Count -or $manifest.License.Path -isnot [string] -or -not $manifest.License.Path -or $manifest.License.Sha256 -isnot [string] -or $manifest.License.Sha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Font manifest schema, batch size or license identity is invalid.'}
  $entries=[Collections.Generic.List[object]]::new();$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$files=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$postscript=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
  foreach($font in @($manifest.Fonts)){
    if($font -isnot [hashtable] -or @($font.Keys|Where-Object {$_ -notin @('Path','Sha256')}).Count -or $font.Path -isnot [string] -or -not $font.Path -or $font.Sha256 -isnot [string] -or $font.Sha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Each selected font requires only an exact path and SHA-256.'}
    $path=if([IO.Path]::IsPathRooted($font.Path)){$font.Path}else{Join-Path $manifestFile.DirectoryName $font.Path}
    $metadata=Get-RideTrueTypeMetadata -Path $path -ExpectedSha256 $font.Sha256
    if(-not $names.Add($metadata.RegistryName) -or -not $files.Add($metadata.FileName) -or -not $postscript.Add($metadata.PostScriptName)){throw 'The selected batch contains duplicate font identities or filenames.'}
    $bytes=Read-RideFontSourceBytes -Path $metadata.Path
    if((Get-RideFontHash $bytes) -ine $metadata.Sha256){throw 'Font source changed during capture.'}
    $total+=$bytes.Length;if($total -gt 8388608){throw 'Font batch exceeds eight MiB of source payload.'}
    $entries.Add([pscustomobject]@{FileName=$metadata.FileName;RegistryName=$metadata.RegistryName;FullName=$metadata.FullName;Sha256=$metadata.Sha256;Payload=[Convert]::ToBase64String($bytes);Created=$false;Before=$null})
  }
  $licensePath=if([IO.Path]::IsPathRooted($manifest.License.Path)){$manifest.License.Path}else{Join-Path $manifestFile.DirectoryName $manifest.License.Path}
  $license=Read-RideFontSourceBytes -Path $licensePath -MaximumBytes 1048576
  $licenseFile=Get-Item -LiteralPath $licensePath -ErrorAction Stop
  if($licenseFile.PSIsContainer -or $licenseFile.Length -lt 1 -or $licenseFile.Length -gt 1048576 -or ($licenseFile.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'License must be an ordinary bounded local file.'}
  if((Get-RideFontHash $license) -ine $manifest.License.Sha256){throw 'License source hash differs from the selected input.'}
  [pscustomobject]@{Entries=$entries.ToArray();License=[pscustomobject]@{FileName=$licenseFile.Name;Sha256=(Get-RideFontHash $license);Payload=[Convert]::ToBase64String($license)}}
}

function Write-RideMachineFontFile {
  param($Context,$Entry,$RestoreFile)
  $bytes=[Convert]::FromBase64String($Entry.Payload)
  if($bytes.Length -gt 16777216 -or (Get-RideFontHash $bytes) -cne $Entry.Sha256){throw 'Saved font payload identity differs.'}
  $path=Join-Path $Context.FontDirectory $Entry.FileName
  $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  if($RestoreFile){
    $sections=[Security.AccessControl.AccessControlSections]'Owner,Group,Access'
    $inherited=(Get-Acl -LiteralPath $path -ErrorAction Stop).GetSecurityDescriptorSddlForm($sections)
    if($inherited -cne $RestoreFile.Security){
      $security=[Security.AccessControl.FileSecurity]::new()
      $security.SetSecurityDescriptorSddlForm($RestoreFile.Security,$sections)
      Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop
    }
    [IO.File]::SetCreationTimeUtc($path,[datetime]::new([long]$RestoreFile.CreationUtcTicks,[DateTimeKind]::Utc))
    [IO.File]::SetLastWriteTimeUtc($path,[datetime]::new([long]$RestoreFile.LastWriteUtcTicks,[DateTimeKind]::Utc))
    [IO.File]::SetAttributes($path,[IO.FileAttributes][int]$RestoreFile.Attributes)
  }
  Set-RideMachineFontRegistration $Entry.RegistryName $Entry.FileName
  Invoke-RideMachineFontNative Add $path
}

function Remove-RideMachineFontFile {
  param($Context,$Entry)
  $path=Join-Path $Context.FontDirectory $Entry.FileName
  Invoke-RideMachineFontNative Remove $path
  Remove-RideMachineFontRegistration $Entry.RegistryName
  [IO.File]::Delete($path)
}

function Complete-RideMachineFontRun {
  param([string]$StateDirectory,$Intent,$Context,$BeforeRegistry)
  $registry=Get-RideMachineFontRegistry
  Assert-RideMachineFontRegistryUnrelated $BeforeRegistry $registry @($Intent.Entries.RegistryName)
  $after=@(foreach($entry in $Intent.Entries){Get-RideMachineFontSnapshot $Context $entry $registry})
  for($i=0;$i -lt $after.Count;$i++){
    $entry=$Intent.Entries[$i];$state=$after[$i]
    if($Intent.Action -ceq 'Install'){
      if(-not $state.File.Exists -or $state.File.Sha256 -cne $entry.Sha256 -or $null -eq $state.Registration -or $state.Registration.Kind -cne 'String' -or $state.Registration.Value -cne $entry.FileName -or @($state.Aliases).Count -ne 1){throw 'Installed font readback differs.'}
      if(-not $entry.Created -and -not (Test-RideMachineFontEqual $state $entry.Before)){throw 'An existing font changed.'}
    }elseif($state.File.Exists -or $null -ne $state.Registration -or @($state.Aliases).Count){throw 'Removed font remained in native file/registration state.'}
  }
  Save-RideMachineFontRun $StateDirectory $Intent.RunId applied ([pscustomobject]@{SchemaVersion=1;Kind='MachineFontLifecycle';RunId=$Intent.RunId;Part='applied';After=$after})
  [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$Intent.RunId;Action=$Intent.Action;Scope='Machine';ChangedFonts=@($Intent.Entries|Where-Object Created).Count;NativeAcceptancePassed=$false}
}

function Install-RideMachineFonts {
  <#
  .SYNOPSIS
    Install a hash-pinned font batch without overwriting existing files or registrations.
  .PARAMETER ManifestPath
    Schema-1 PSD1 with Fonts (Path/Sha256) and License (Path/Sha256).
  .PARAMETER StateDirectory
    Existing local private machine-font recovery directory; records preserve the license.
  .PARAMETER ExpectedComputerName
    Exact selected target name.
  .PARAMETER ExpectedBuild
    Exact expected Windows build number.
  .PARAMETER ExpectedEditionId
    Exact expected Windows edition.
  .PARAMETER AllowCandidate
    Per-invocation opt-in for actual changes while native acceptance is pending.
  .EXAMPLE
    Install-RideMachineFonts -ManifestPath C:\Inputs\fonts.psd1 -StateDirectory C:\Private\FontState -ExpectedComputerName '<vm>' -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Applied or AlreadyDesired result, without payload bytes.
  .NOTES
    Existing matching fonts are preserved, not adopted. Preview writes no files/state.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$ManifestPath,[Parameter(Mandatory)][string]$StateDirectory,
    [Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedBuild,
    [Parameter(Mandatory)][string]$ExpectedEditionId,[switch]$AllowCandidate)
  $context=Get-RideMachineFontContext;Assert-RideMachineFontContext $context $null (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Selected machine-font target differs.'}
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Machine-font native acceptance is pending; use -AllowCandidate for actual changes.'}
  Assert-RideMachineFontStateDirectory $StateDirectory
  $source=Read-RideMachineFontManifest $ManifestPath;$registry=Get-RideMachineFontRegistry
  foreach($entry in $source.Entries){
    $entry.Before=Get-RideMachineFontSnapshot $context $entry $registry
    $state=$entry.Before
    if(-not $state.File.Exists -and $null -eq $state.Registration -and @($state.Aliases).Count -eq 0){$entry.Created=$true;continue}
    if($state.File.Exists -and $state.File.Sha256 -ceq $entry.Sha256 -and $state.Registration.Kind -ceq 'String' -and $state.Registration.Value -ceq $entry.FileName -and @($state.Aliases).Count -eq 1){continue}
    throw 'Font file/registration collision or incomplete existing state; the whole batch is refused.'
  }
  if(-not @($source.Entries|Where-Object Created).Count){return [pscustomobject]@{SchemaVersion=1;Status='AlreadyDesired';RunId=$null;Scope='Machine';ChangedFonts=0}}
  $intent=[pscustomobject]@{SchemaVersion=1;Kind='MachineFontLifecycle';RunId=[guid]::NewGuid().ToString('N');Part='intent';Action='Install';Context=$context;Entries=$source.Entries;License=$source.License}
  if($PSCmdlet.ShouldProcess($context.ComputerName,'Install the preflighted machine-font batch after private recovery capture')){
    Save-RideMachineFontRun $StateDirectory $intent.RunId intent $intent
    try{
      Assert-RideMachineFontContext (Get-RideMachineFontContext) $context $true
      if(-not (Test-RideMachineFontEqual $registry (Get-RideMachineFontRegistry))){throw 'Font registry changed during preflight.'}
      foreach($entry in $intent.Entries){if(-not (Test-RideMachineFontEqual $entry.Before (Get-RideMachineFontSnapshot $context $entry $registry))){throw 'Font file changed during preflight.'}}
      foreach($entry in $intent.Entries){if($entry.Created){Write-RideMachineFontFile $context $entry $null}}
      Invoke-RideMachineFontNative Notify
      Complete-RideMachineFontRun $StateDirectory $intent $context $registry
    }catch{throw "Machine-font import did not complete. Run ID: $($intent.RunId). Retain private state and inspect files/registration before recovery."}
  }
}

function Remove-RideMachineFonts {
  <#
  .SYNOPSIS
    Remove only unchanged fonts created by a completed RIDE install run.
  .PARAMETER OwnerRunId
    Completed font install run whose Created entries identify owned fonts.
  .PARAMETER StateDirectory
    Existing private machine-font state directory.
  .PARAMETER AllowCandidate
    Fresh opt-in for candidate removal.
  .EXAMPLE
    Remove-RideMachineFonts -OwnerRunId '<run-id>' -StateDirectory C:\Private\FontState -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 result with the new removal run ID.
  .NOTES
    Active consumers can prevent unloading/deletion. No reboot or process termination.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$OwnerRunId,[Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  $owner=Read-RideMachineFontRun $StateDirectory $OwnerRunId intent;$applied=Read-RideMachineFontRun $StateDirectory $OwnerRunId applied
  if($owner.Action -cne 'Install' -or @($owner.Entries).Count -ne @($applied.After).Count){throw 'Removal requires a completed font install run.'}
  $context=Get-RideMachineFontContext;Assert-RideMachineFontContext $context $owner.Context (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Candidate font removal requires -AllowCandidate.'}
  $registry=Get-RideMachineFontRegistry;$entries=[Collections.Generic.List[object]]::new();$absent=0
  for($i=0;$i -lt $owner.Entries.Count;$i++){
    $entry=$owner.Entries[$i];if(-not $entry.Created){continue}
    if($entry.Before.File.Exists -or $null -ne $entry.Before.Registration){throw 'Saved font ownership is inconsistent.'}
    $current=Get-RideMachineFontSnapshot $context $entry $registry
    if(-not $current.File.Exists -and $null -eq $current.Registration -and @($current.Aliases).Count -eq 0){$absent++}
    elseif(-not (Test-RideMachineFontEqual $current $applied.After[$i])){throw 'Owned font content, permissions or registration changed; refusing removal.'}
    $entry.Before=$current;$entries.Add($entry)
  }
  if($entries.Count -eq 0){throw 'The run owns no removable font.'}
  if($absent -eq $entries.Count){return [pscustomobject]@{SchemaVersion=1;Status='AlreadyAbsent';RunId=$null;Scope='Machine';ChangedFonts=0}}
  if($absent){throw 'Owned font batch is partly absent; inspect recovery before removal.'}
  $intent=[pscustomobject]@{SchemaVersion=1;Kind='MachineFontLifecycle';RunId=[guid]::NewGuid().ToString('N');Part='intent';Action='Remove';Context=$context;Entries=$entries.ToArray();License=$owner.License}
  if($PSCmdlet.ShouldProcess($context.ComputerName,'Remove the exact RIDE-created font batch after private recovery capture')){
    Save-RideMachineFontRun $StateDirectory $intent.RunId intent $intent
    try{
      Assert-RideMachineFontContext (Get-RideMachineFontContext) $context $true
      if(-not (Test-RideMachineFontEqual $registry (Get-RideMachineFontRegistry))){throw 'Font registry changed during preflight.'}
      foreach($entry in $intent.Entries){if(-not (Test-RideMachineFontEqual $entry.Before (Get-RideMachineFontSnapshot $context $entry $registry))){throw 'Font state changed during preflight.'}}
      foreach($entry in $intent.Entries){Remove-RideMachineFontFile $context $entry}
      Invoke-RideMachineFontNative Notify
      Complete-RideMachineFontRun $StateDirectory $intent $context $registry
    }catch{throw "Machine-font removal did not complete. Run ID: $($intent.RunId). Retain private state and inspect active font consumers before recovery."}
  }
}

function Restore-RideMachineFontRun {
  <#
  .SYNOPSIS
    Restore a completed font run's captured file and registration state.
  .PARAMETER RunId
    Completed install or removal run to undo.
  .PARAMETER StateDirectory
    Existing private machine-font state directory from the original account.
  .PARAMETER AllowCandidate
    Fresh opt-in for actual candidate restore.
  .EXAMPLE
    Restore-RideMachineFontRun -RunId '<run-id>' -StateDirectory C:\Private\FontState -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Restored or AlreadyRestored result.
  .NOTES
    Captures no process font-cache or SACL state. Incomplete records refuse automatic restore.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  $intent=Read-RideMachineFontRun $StateDirectory $RunId intent;$applied=Read-RideMachineFontRun $StateDirectory $RunId applied
  if($intent.Action -cnotin @('Install','Remove') -or @($intent.Entries).Count -lt 1 -or @($intent.Entries).Count -gt 32 -or @($intent.Entries).Count -ne @($applied.After).Count){throw 'Invalid saved font action or batch.'}
  $context=Get-RideMachineFontContext;Assert-RideMachineFontContext $context $intent.Context (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Candidate font restore requires fresh -AllowCandidate.'}
  $registry=Get-RideMachineFontRegistry;$current=@(foreach($entry in $intent.Entries){Get-RideMachineFontSnapshot $context $entry $registry})
  if(Test-RideMachineFontEqual $current @($intent.Entries.Before)){return [pscustomobject]@{SchemaVersion=1;Status='AlreadyRestored';RunId=$RunId;Scope='Machine'}}
  if(-not (Test-RideMachineFontEqual $current @($applied.After))){throw 'Font recovery conflict: files, permissions or registration changed.'}
  if($PSCmdlet.ShouldProcess($context.ComputerName,'Restore captured machine-font files and registration')){
    try{
      Assert-RideMachineFontContext (Get-RideMachineFontContext) $intent.Context $true
      if(-not (Test-RideMachineFontEqual $registry (Get-RideMachineFontRegistry))){throw 'Font registry changed during recovery preflight.'}
      for($i=0;$i -lt $intent.Entries.Count;$i++){if(-not (Test-RideMachineFontEqual $current[$i] (Get-RideMachineFontSnapshot $context $intent.Entries[$i] $registry))){throw 'Font file changed during recovery preflight.'}}
      foreach($entry in $intent.Entries){
        if($intent.Action -ceq 'Install'){if($entry.Created){Remove-RideMachineFontFile $context $entry}}
        else{Write-RideMachineFontFile $context $entry $entry.Before.File}
      }
      Invoke-RideMachineFontNative Notify
      $afterRegistry=Get-RideMachineFontRegistry;Assert-RideMachineFontRegistryUnrelated $registry $afterRegistry @($intent.Entries.RegistryName)
      $after=@(foreach($entry in $intent.Entries){Get-RideMachineFontSnapshot $context $entry $afterRegistry})
      if(-not (Test-RideMachineFontEqual $after @($intent.Entries.Before))){
        $differences=foreach($i in 0..($intent.Entries.Count-1)){
          $entry=$intent.Entries[$i]
          foreach($field in $entry.Before.File.PSObject.Properties.Name){
            if(-not (Test-RideMachineFontEqual $after[$i].File.$field $entry.Before.File.$field)){ "$($entry.FileName) File.$field" }
          }
          foreach($field in @('Registration','Aliases')){
            if(-not (Test-RideMachineFontEqual $after[$i].$field $entry.Before.$field)){ "$($entry.FileName) $field" }
          }
        }
        throw "Font recovery readback differs ($($differences -join ', '))."
      }
      [pscustomobject]@{SchemaVersion=1;Status='Restored';RunId=$RunId;Scope='Machine';NativeAcceptancePassed=$false}
    }catch{
      $cause=$_.Exception.Message
      throw "Machine-font recovery did not complete. Run ID: $RunId. Retain private records. Cause: $($cause.Substring(0,[Math]::Min(1000,$cause.Length)))"
    }
  }
}

$script:FontRunCompleter={param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{if(-not $fakeBoundParameters.ContainsKey('StateDirectory')){return};Get-ChildItem -LiteralPath $fakeBoundParameters.StateDirectory -Filter '*.fonts.applied.json' -File -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.fonts\.applied\.json$'){$id=$Matches[1];if($id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($id,$id,'ParameterValue','Saved machine-font run')}}}}catch{}
}
Register-ArgumentCompleter -CommandName Remove-RideMachineFonts -ParameterName OwnerRunId -ScriptBlock $script:FontRunCompleter
Register-ArgumentCompleter -CommandName Restore-RideMachineFontRun -ParameterName RunId -ScriptBlock $script:FontRunCompleter
Export-ModuleMember -Function Install-RideMachineFonts,Remove-RideMachineFonts,Restore-RideMachineFontRun
