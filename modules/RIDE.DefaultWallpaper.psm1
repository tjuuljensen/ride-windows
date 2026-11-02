<#
.SYNOPSIS
  Apply and recover a machine first-logon wallpaper image on a disposable candidate.
.DESCRIPTION
  Uses the documented ThemeFile policy and a new owned public-readable
  PNG and generated theme. Captures private machine intent before changes and verifies completed
  state before recovery. Preserves inbox/default-profile/source files. This policy
  applies at first logon only and permits later user personalization. Native
  behavior is unverified; profile changes prevent automatic asset recovery.
.NOTES
  Compatibility: Candidate Windows 11 x64 Enterprise/Education, PowerShell 5.1/7.
  Requires an explicitly matched Hyper-V test guest and existing elevation.
  Image and state directories must exist. No UAC, sign-out or reboot is launched.
  Recovery restores captured machine policy/assets, not already-created users,
  Windows caches or visible UI. New profile identities require inspection before
  removal. The native scenario must remove only its owned test user/profile first.
  Incomplete apply retains evidence and requires inspection; no blind cleanup.
  Version: 0.1.0.
  Changelog: 0.1.0: Add first-logon ThemeFile policy and owned theme/image candidate.
  Reference: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_settheme
.LINK
  ../docs/image-personalization.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ImageFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop
$script:PolicyParent='SOFTWARE\Policies\Microsoft\Windows'
$script:PolicyChild='Personalization'

function New-RideDefaultWallpaperTheme {
  param([string]$ImagePath)
  # The owned image path is embedded as INI data, never a caller-supplied theme.
  if($ImagePath -cnotmatch '^[A-Za-z]:\\' -or $ImagePath.Length -gt 240 -or $ImagePath -match '[\x00-\x1f%\[\]=";<>|?*]' -or $ImagePath.Substring(2).Contains(':') -or [IO.Path]::GetExtension($ImagePath) -ine '.png' -or [IO.Path]::GetFullPath($ImagePath) -cne $ImagePath){throw 'Theme image requires a canonical local PNG path without INI/environment syntax.'}
  $body=@('[Theme]','DisplayName=RIDE first-logon wallpaper','','[Control Panel\Desktop]',('Wallpaper='+$ImagePath),'TileWallpaper=0','WallpaperStyle=10','','[VisualStyles]','Path=%ResourceDir%\Themes\Aero\Aero.msstyles','ColorStyle=NormalColor','Size=NormalSize','','[MasterThemeSelector]','MTSM=DABJDKT','') -join "`r`n"
  # Windows theme INI is emitted as UTF-16LE with BOM for non-ASCII local paths.
  $encoding=[Text.UnicodeEncoding]::new($false,$true,$true)
  $bytes=[byte[]]($encoding.GetPreamble()+$encoding.GetBytes($body))
  $sha=[Security.Cryptography.SHA256]::Create()
  try{[pscustomobject]@{Content=$bytes;Bytes=$bytes.Length;Sha256=([BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-',''))}}finally{$sha.Dispose()}
}
function Get-RideDefaultWallpaperProfiles {
  $profiles=@(Get-CimInstance Win32_UserProfile -ErrorAction Stop)
  if($profiles.Count -gt 256){throw 'User-profile inventory exceeds its bound.'}
  @($profiles|Sort-Object SID|ForEach-Object {
    if($_.SID -notmatch '^S-1-[0-9-]+$' -or -not $_.LocalPath){throw 'User-profile identity is incomplete.'}
    [pscustomobject]@{Sid=[string]$_.SID;Path=[string]$_.LocalPath}
  })
}

function Get-RideDefaultWallpaperContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $system=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{[pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;Revision=[int]$version.UBR;InstallationType=[string]$version.InstallationType;NativeProcess=[Environment]::Is64BitProcess;Architecture=$env:PROCESSOR_ARCHITECTURE;Administrator=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);Guest=($env:RIDE_TEST_GUEST -ceq '1' -and $env:RIDE_INTEGRATION_VM -ceq '1' -and $system.Manufacturer -ceq 'Microsoft Corporation' -and $system.Model -ceq 'Virtual Machine')}}finally{$identity.Dispose()}
}
function Assert-RideDefaultWallpaperContext {
  param($Context,$Expected,[bool]$Mutation)
  if(-not $Context.Guest -or $Context.InstallationType -cne 'Client' -or $Context.Build -cnotmatch '^\d{5,8}$' -or [int]$Context.Build -lt 22000 -or -not $Context.NativeProcess -or $Context.Architecture -cne 'AMD64' -or $Context.EditionId -cnotin @('Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')){throw 'First-logon wallpaper candidate requires a marked Windows 11 x64 Enterprise/Education Hyper-V guest.'}
  if($Mutation -and -not $Context.Administrator){throw 'Existing elevation is required; no UAC is launched.'}
  if($Expected){foreach($field in @('ComputerName','Build','EditionId','Revision','InstallationType','NativeProcess','Architecture','Guest')){if($Context.$field -cne $Expected.$field){throw "First-logon wallpaper target changed ($field)."}}}
}
function Test-RideDefaultWallpaperEqual {
  param($Left,$Right)
  (ConvertTo-Json -InputObject $Left -Depth 12 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 12 -Compress)
}
function Resolve-RideDefaultWallpaperDirectory {
  param([string]$Path)
  $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
  if($full -cmatch '^[A-Za-z]:$'){throw 'Select a directory below the drive root.'}
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} (Join-Path $full 'path-check-only')
  $full
}
function Assert-RideDefaultWallpaperAssetDirectory {
  param([string]$Path)
  $full=Resolve-RideDefaultWallpaperDirectory $Path
  $directory=[IO.DirectoryInfo]::new($full)
  if(-not $directory.Parent -or -not $directory.Parent.Parent){throw 'Select an owned asset directory below an administrator-controlled parent.'}
  foreach($node in @($directory,$directory.Parent)){
    $acl=Get-Acl -LiteralPath $node.FullName
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Asset directory and parent must be administrator/SYSTEM owned.'}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
      $writeMask=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
      if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeMask) -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Asset directory or parent grants modification to another principal.'}
      if($rule.AccessControlType -eq 'Deny' -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute)){throw 'Asset directory or parent has a conflicting read/execute deny rule.'}
    }
  }
  $acl=Get-Acl -LiteralPath $full
  $readRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -ceq 'S-1-5-32-545' -and $_.AccessControlType -eq 'Allow' -and -not ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [Security.AccessControl.FileSystemRights]::ReadAndExecute})
  if(-not $readRules.Count){throw 'Asset directory requires Builtin Users read/execute access.'}
  $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access')
}
function New-RideDefaultWallpaperAssetSecurity {
  $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  foreach($sid in @('S-1-5-32-544','S-1-5-18','S-1-5-32-545')){
    $rights=if($sid -ceq 'S-1-5-32-545'){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,[Security.AccessControl.AccessControlType]::Allow))
  }
  $acl
}
function Assert-RideDefaultWallpaperAssetSecurity {
  param($Security)
  $expected=New-RideDefaultWallpaperAssetSecurity
  $rows=@($Security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.IsInherited}|Sort-Object)
  $expectedRows=@($expected.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.IsInherited}|Sort-Object)
  if(-not $Security.AreAccessRulesProtected -or $Security.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or ($rows -join ';') -cne ($expectedRows -join ';')){throw 'Owned image permissions differ.'}
}
function New-RideDefaultWallpaperAssetStream {
  param([string]$Path)
  $acl=New-RideDefaultWallpaperAssetSecurity
  $rights=[Security.AccessControl.FileSystemRights]'Write,ReadPermissions'
  $stream=$null
  try{
    if($PSVersionTable.PSEdition -eq 'Desktop'){$stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,$rights,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl);$actual=$stream.GetAccessControl()}
    else{$stream=[IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path),[IO.FileMode]::CreateNew,$rights,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl);$actual=[IO.FileSystemAclExtensions]::GetAccessControl($stream)}
    Assert-RideDefaultWallpaperAssetSecurity $actual
    $stream
  }catch{if($stream){$stream.Dispose()};throw}
}
function Get-RideDefaultWallpaperAsset {
  param([string]$Path)
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $Path
  try{$file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop}catch [Management.Automation.ItemNotFoundException]{return $null}
  if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Owned image must not be a reparse point.'}
  if($file.PSIsContainer){throw 'A directory collides with the owned image.'}
  if($file.Length -lt 57 -or $file.Length -gt 16777216){throw 'Owned image length is invalid.'}
  $acl=Get-Acl -LiteralPath $Path;Assert-RideDefaultWallpaperAssetSecurity $acl
  [pscustomobject]@{Sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;Bytes=$file.Length;Security=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access');Attributes=[int]$file.Attributes;CreationUtcTicks=$file.CreationTimeUtc.Ticks.ToString();LastWriteUtcTicks=$file.LastWriteTimeUtc.Ticks.ToString()}
}
function Get-RideDefaultWallpaperRegistry {
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:PolicyParent+'\'+$script:PolicyChild,$false)
  if(-not $key){return [pscustomobject]@{Exists=$false;Security=$null;Rows=@();SubKeys=@()}}
  try{
    $names=@($key.GetValueNames());$subKeys=@($key.GetSubKeyNames()|Sort-Object)
    if($names.Count -gt 128 -or $subKeys.Count -gt 128){throw 'Personalization policy inventory exceeds its bound.'}
    $acl=Get-Acl -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\'+$script:PolicyParent+'\'+$script:PolicyChild)
    [pscustomobject]@{Exists=$true;Security=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access');Rows=@($names|Sort-Object|ForEach-Object {[pscustomobject]@{Name=$_;Kind=[string]$key.GetValueKind($_);Value=$key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}});SubKeys=$subKeys}
  }finally{$key.Dispose()}
}
function Set-RideDefaultWallpaperRegistry {
  param($Row,[bool]$RemoveCreatedKey=$false)
  $parent=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:PolicyParent,$true)
  if(-not $parent){throw 'Windows policy parent is unavailable.'}
  try{
    if($RemoveCreatedKey){
      $key=$parent.OpenSubKey($script:PolicyChild,$true)
      if(-not $key){throw 'Created personalization key is missing.'}
      try{$key.DeleteValue('ThemeFile',$true);$key.Flush();if($key.ValueCount -ne 0 -or $key.SubKeyCount -ne 0){throw 'Created personalization key is no longer empty.'}}finally{$key.Dispose()}
      $parent.DeleteSubKey($script:PolicyChild,$true);return
    }
    $key=$parent.CreateSubKey($script:PolicyChild)
    try{if($null -eq $Row){$key.DeleteValue('ThemeFile',$true)}else{$key.SetValue('ThemeFile',[string]$Row.Value,[Microsoft.Win32.RegistryValueKind]$Row.Kind)};$key.Flush()}finally{$key.Dispose()}
  }finally{$parent.Dispose()}
}
function Get-RideDefaultWallpaperRow {
  param($Registry)
  $rows=@($Registry.Rows|Where-Object Name -IEQ 'ThemeFile')
  if($rows.Count -gt 1 -or ($rows.Count -and $rows[0].Kind -cnotin @('String','ExpandString'))){throw 'Prior ThemeFile must be absent or a string policy.'}
  if($rows.Count){$rows[0]}
}
function Assert-RideDefaultWallpaperRegistryChange {
  param($Before,$After,[string]$AssetPath)
  if(-not $After.Exists -or -not (Test-RideDefaultWallpaperEqual @($Before.Rows|Where-Object Name -INE 'ThemeFile') @($After.Rows|Where-Object Name -INE 'ThemeFile')) -or -not (Test-RideDefaultWallpaperEqual @($Before.SubKeys) @($After.SubKeys)) -or ($Before.Exists -and $Before.Security -cne $After.Security)){throw 'Unrelated personalization policy state changed.'}
  $row=Get-RideDefaultWallpaperRow $After
  if($null -eq $row -or $row.Kind -cne 'String' -or $row.Value -cne $AssetPath){throw 'First-logon wallpaper policy readback differs.'}
}
function Get-RideDefaultWallpaperRunPath {
  param([string]$StateDirectory,[string]$RunId,[ValidateSet('intent','applied')][string]$Part)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'First-logon wallpaper run ID must be 32 lowercase hexadecimal characters.'}
  Join-Path $StateDirectory ($RunId+'.default-wallpaper.'+$Part+'.json')
}
function Save-RideDefaultWallpaperRun {
  param([string]$StateDirectory,[string]$RunId,[string]$Part,$Record)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 15 -Compress))
  if($bytes.Length -gt 1048576){throw 'First-logon wallpaper state exceeds its bound.'}
  $stream=New-RidePrivateFileStream -Path (Get-RideDefaultWallpaperRunPath $StateDirectory $RunId $Part) -Scope Machine
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Read-RideDefaultWallpaperRun {
  param([string]$StateDirectory,[string]$RunId,[string]$Part)
  $bytes=Read-RidePrivateFileBytes -Path (Get-RideDefaultWallpaperRunPath $StateDirectory $RunId $Part) -MaximumBytes 1048576 -Scope Machine
  $record=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
  if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'DefaultWallpaper' -or $record.RunId -cne $RunId -or $record.Part -cne $Part){throw 'First-logon wallpaper recovery identity differs.'}
  $record
}
function Assert-RideDefaultWallpaperRun {
  param($Intent,$Applied)
  if($Intent.AssetDirectory -cne (Resolve-RideDefaultWallpaperDirectory $Intent.AssetDirectory) -or $Intent.SourceSha256 -cnotmatch '^[A-F0-9]{64}$' -or $Intent.AssetPath -cne (Join-Path $Intent.AssetDirectory ($Intent.RunId+'.png')) -or $Intent.ThemePath -cne (Join-Path $Intent.AssetDirectory ($Intent.RunId+'.theme')) -or $Applied.File.Sha256 -cne $Intent.SourceSha256 -or $Applied.File.Bytes -ne $Intent.SourceBytes -or $null -eq $Intent.Profiles){throw 'Saved image/theme identity or ownership is invalid.'}
  $theme=New-RideDefaultWallpaperTheme $Intent.AssetPath
  if($Applied.Theme.Sha256 -cne $theme.Sha256 -or $Applied.Theme.Bytes -ne $theme.Bytes){throw 'Saved theme bytes differ from the owned image binding.'}
  Assert-RideDefaultWallpaperRegistryChange $Intent.Before $Applied.After $Intent.ThemePath
}

function Set-RideDefaultWallpaperImage {
  <#
  .SYNOPSIS
    Apply a pinned PNG through a machine first-logon theme policy in a test guest.
  .PARAMETER Path
    Selected local PNG source; original bytes are never changed.
  .PARAMETER ExpectedSha256
    Reviewed source hash; required before decoding or writing.
  .PARAMETER AssetDirectory
    Existing administrator-controlled directory with Users read/execute access.
  .PARAMETER StateDirectory
    Existing local directory for private administrator/SYSTEM recovery records.
  .PARAMETER ExpectedComputerName
    Exact intended disposable computer name.
  .PARAMETER ExpectedBuild
    Exact intended Windows 11 build number.
  .PARAMETER ExpectedEditionId
    Exact supported candidate Enterprise/Education edition identifier.
  .PARAMETER AllowCandidate
    Explicitly permit unaccepted native candidate behavior; required for mutation.
  .EXAMPLE
    Set-RideDefaultWallpaperImage -Path C:\Inputs\lock.png -ExpectedSha256 $hash -AssetDirectory C:\RIDE-Test\Images -StateDirectory C:\RIDE-Test\State -ExpectedComputerName RIDE-Test -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Applied, AlreadyDesired or Preview result. Native visual acceptance is false.
  .NOTES
    Existing elevation and marked Hyper-V guest required. Captures before mutation.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][string]$AssetDirectory,[Parameter(Mandatory)][string]$StateDirectory,
    [Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateSet('Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId,[switch]$AllowCandidate)
  $context=Get-RideDefaultWallpaperContext;Assert-RideDefaultWallpaperContext $context $null (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Selected first-logon wallpaper target differs.'}
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'First-logon wallpaper native acceptance is pending; specify -AllowCandidate.'}
  $AssetDirectory=Resolve-RideDefaultWallpaperDirectory $AssetDirectory;$StateDirectory=Resolve-RideDefaultWallpaperDirectory $StateDirectory
  $directorySecurity=Assert-RideDefaultWallpaperAssetDirectory $AssetDirectory
  $source=Get-RidePngSource -Path $Path -ExpectedSha256 $ExpectedSha256 -IncludeContent
  $before=Get-RideDefaultWallpaperRegistry;$prior=Get-RideDefaultWallpaperRow $before
  if($prior -and $prior.Kind -ceq 'String' -and [IO.Path]::GetDirectoryName([string]$prior.Value) -ieq $AssetDirectory -and [IO.Path]::GetFileName([string]$prior.Value) -cmatch '^([a-f0-9]{32})\.theme$'){
    $ownerId=$Matches[1];$owner=Read-RideDefaultWallpaperRun $StateDirectory $ownerId intent;$done=Read-RideDefaultWallpaperRun $StateDirectory $ownerId applied
    Assert-RideDefaultWallpaperRun $owner $done
    if($owner.SourceSha256 -ceq $source.Sha256){
      Assert-RideDefaultWallpaperContext $context $owner.Context $false
      if($owner.ThemePath -cne $prior.Value -or $owner.DirectorySecurity -cne $directorySecurity -or -not (Test-RideDefaultWallpaperEqual $done.After $before) -or -not (Test-RideDefaultWallpaperEqual $done.File (Get-RideDefaultWallpaperAsset $owner.AssetPath)) -or -not (Test-RideDefaultWallpaperEqual $done.Theme (Get-RideDefaultWallpaperAsset $owner.ThemePath))){throw 'Previously owned image or policy changed.'}
      return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='AlreadyDesired';RunId=$ownerId;NativeVisualAcceptance=$false}
    }
  }
  $runId=[guid]::NewGuid().ToString('N');$assetPath=Join-Path $AssetDirectory ($runId+'.png');$themePath=Join-Path $AssetDirectory ($runId+'.theme')
  $themeSource=New-RideDefaultWallpaperTheme $assetPath;$profiles=@(Get-RideDefaultWallpaperProfiles)
  if($null -ne (Get-RideDefaultWallpaperAsset $assetPath) -or $null -ne (Get-RideDefaultWallpaperAsset $themePath)){throw 'New image/theme destination already exists.'}
  $intent=[pscustomobject]@{SchemaVersion=1;Kind='DefaultWallpaper';RunId=$runId;Part='intent';Context=$context;AssetDirectory=$AssetDirectory;AssetPath=$assetPath;ThemePath=$themePath;Profiles=$profiles;DirectorySecurity=$directorySecurity;SourceSha256=$source.Sha256;SourceBytes=$source.Bytes;Before=$before}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,'Capture machine recovery, create owned image and set first-logon wallpaper policy')){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Preview';RunId=$null;NativeVisualAcceptance=$false}}
  Save-RideDefaultWallpaperRun $StateDirectory $runId intent $intent
  try{
    Assert-RideDefaultWallpaperContext (Get-RideDefaultWallpaperContext) $context $true
    if((Assert-RideDefaultWallpaperAssetDirectory $AssetDirectory) -cne $directorySecurity -or -not (Test-RideDefaultWallpaperEqual $before (Get-RideDefaultWallpaperRegistry))){throw 'Destination or policy changed during preflight.'}
    if(-not (Test-RideDefaultWallpaperEqual $profiles @(Get-RideDefaultWallpaperProfiles))){throw 'User profiles changed during preflight.'}
    $stream=New-RideDefaultWallpaperAssetStream $assetPath
    try{$stream.Write($source.Content,0,$source.Content.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $file=Get-RideDefaultWallpaperAsset $assetPath
    if($file.Sha256 -cne $source.Sha256 -or $file.Bytes -ne $source.Bytes){throw 'Owned image readback differs.'}
    $stream=New-RideDefaultWallpaperAssetStream $themePath
    try{$stream.Write($themeSource.Content,0,$themeSource.Content.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $themeFile=Get-RideDefaultWallpaperAsset $themePath
    if($themeFile.Sha256 -cne $themeSource.Sha256 -or $themeFile.Bytes -ne $themeSource.Bytes){throw 'Owned theme readback differs.'}
    if(-not (Test-RideDefaultWallpaperEqual $before (Get-RideDefaultWallpaperRegistry)) -or -not (Test-RideDefaultWallpaperEqual $profiles @(Get-RideDefaultWallpaperProfiles))){throw 'Policy or user profiles changed before policy write.'}
    Set-RideDefaultWallpaperRegistry ([pscustomobject]@{Kind='String';Value=$themePath})
    $after=Get-RideDefaultWallpaperRegistry;Assert-RideDefaultWallpaperRegistryChange $before $after $themePath
    if(-not (Test-RideDefaultWallpaperEqual $file (Get-RideDefaultWallpaperAsset $assetPath))){throw 'Owned image changed after policy write.'}
    if(-not (Test-RideDefaultWallpaperEqual $themeFile (Get-RideDefaultWallpaperAsset $themePath)) -or -not (Test-RideDefaultWallpaperEqual $profiles @(Get-RideDefaultWallpaperProfiles))){throw 'Theme or user profiles changed after policy write.'}
    Save-RideDefaultWallpaperRun $StateDirectory $runId applied ([pscustomobject]@{SchemaVersion=1;Kind='DefaultWallpaper';RunId=$runId;Part='applied';After=$after;File=$file;Theme=$themeFile})
    [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Applied';RunId=$runId;AssetPath=$assetPath;ThemePath=$themePath;NativeVisualAcceptance=$false}
  }catch{throw "First-logon wallpaper apply incomplete. Run ID: $runId. Retain private intent and inspect policy/image before recovery. Cause: $($_.Exception.Message)"}
}

function Restore-RideDefaultWallpaperRun {
  <#
  .SYNOPSIS
    Restore captured first-logon theme policy and remove unchanged owned theme/image.
  .PARAMETER RunId
    Completed apply run ID. Incomplete runs refuse automatic recovery.
  .PARAMETER StateDirectory
    Existing directory containing the private intent and applied records.
  .PARAMETER AllowCandidate
    Required for actual recovery while native acceptance remains pending.
  .EXAMPLE
    Restore-RideDefaultWallpaperRun -RunId '<run-id>' -StateDirectory C:\RIDE-Test\State -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Restored, AlreadyRestored or Preview result; no visual acceptance claim.
  .NOTES
    Refuses target, image/theme, directory, profile or policy drift. Retains records.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  $StateDirectory=Resolve-RideDefaultWallpaperDirectory $StateDirectory
  $intent=Read-RideDefaultWallpaperRun $StateDirectory $RunId intent;$applied=Read-RideDefaultWallpaperRun $StateDirectory $RunId applied
  Assert-RideDefaultWallpaperRun $intent $applied
  $context=Get-RideDefaultWallpaperContext;Assert-RideDefaultWallpaperContext $context $intent.Context (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'First-logon wallpaper native acceptance is pending; specify -AllowCandidate.'}
  if((Assert-RideDefaultWallpaperAssetDirectory $intent.AssetDirectory) -cne $intent.DirectorySecurity){throw 'Owned image directory changed.'}
  $current=Get-RideDefaultWallpaperRegistry;$file=Get-RideDefaultWallpaperAsset $intent.AssetPath;$theme=Get-RideDefaultWallpaperAsset $intent.ThemePath
  $policyRestored=Test-RideDefaultWallpaperEqual $current $intent.Before
  if($policyRestored -and $null -eq $file -and $null -eq $theme){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='AlreadyRestored';RunId=$RunId;NativeVisualAcceptance=$false}}
  if(-not (Test-RideDefaultWallpaperEqual @($intent.Profiles) @(Get-RideDefaultWallpaperProfiles))){throw 'User profiles changed since apply; preserve assets and inspect first-logon consumers before recovery.'}
  if((-not $policyRestored -and -not (Test-RideDefaultWallpaperEqual $current $applied.After)) -or
    ($null -ne $file -and -not (Test-RideDefaultWallpaperEqual $file $applied.File)) -or ($null -ne $theme -and -not (Test-RideDefaultWallpaperEqual $theme $applied.Theme)) -or
    (-not $policyRestored -and ($null -eq $file -or $null -eq $theme))){throw 'Policy or owned image/theme conflicts with captured recovery.'}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,'Restore captured first-logon theme policy and remove the unchanged run-owned theme/image')){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Preview';RunId=$RunId;NativeVisualAcceptance=$false}}
  try{
    Assert-RideDefaultWallpaperContext (Get-RideDefaultWallpaperContext) $intent.Context $true
    if((Assert-RideDefaultWallpaperAssetDirectory $intent.AssetDirectory) -cne $intent.DirectorySecurity -or -not (Test-RideDefaultWallpaperEqual $current (Get-RideDefaultWallpaperRegistry)) -or -not (Test-RideDefaultWallpaperEqual $file (Get-RideDefaultWallpaperAsset $intent.AssetPath)) -or -not (Test-RideDefaultWallpaperEqual $theme (Get-RideDefaultWallpaperAsset $intent.ThemePath)) -or -not (Test-RideDefaultWallpaperEqual @($intent.Profiles) @(Get-RideDefaultWallpaperProfiles))){throw 'Recovery target changed during preflight.'}
    if(-not $policyRestored){Set-RideDefaultWallpaperRegistry (Get-RideDefaultWallpaperRow $intent.Before) (-not $intent.Before.Exists)}
    if(-not (Test-RideDefaultWallpaperEqual $intent.Before (Get-RideDefaultWallpaperRegistry))){throw 'Captured policy recovery did not verify.'}
    foreach($entry in @(@{Path=$intent.ThemePath;Expected=$applied.Theme},@{Path=$intent.AssetPath;Expected=$applied.File})){
      $live=Get-RideDefaultWallpaperAsset $entry.Path
      if($null -eq $live){continue}
      if(-not (Test-RideDefaultWallpaperEqual $live $entry.Expected) -or -not (Test-RideDefaultWallpaperEqual @($intent.Profiles) @(Get-RideDefaultWallpaperProfiles))){throw 'Owned asset or user profiles changed before removal.'}
      Remove-Item -LiteralPath $entry.Path -ErrorAction Stop
    }
    if($null -ne (Get-RideDefaultWallpaperAsset $intent.AssetPath) -or $null -ne (Get-RideDefaultWallpaperAsset $intent.ThemePath) -or -not (Test-RideDefaultWallpaperEqual $intent.Before (Get-RideDefaultWallpaperRegistry))){throw 'Final recovery readback differs.'}
    [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Restored';RunId=$RunId;NativeVisualAcceptance=$false}
  }catch{throw "First-logon wallpaper recovery incomplete. Run ID: $RunId. Retain private state. Cause: $($_.Exception.Message)"}
}
$script:DefaultWallpaperRunCompleter={
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{if(-not $fakeBoundParameters.ContainsKey('StateDirectory')){return};Get-ChildItem -LiteralPath $fakeBoundParameters.StateDirectory -Filter '*.default-wallpaper.applied.json' -File -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.default-wallpaper\.applied\.json$'){$id=$Matches[1];if($id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($id,$id,'ParameterValue','Completed first-logon wallpaper run')}}}}catch{}
}
Register-ArgumentCompleter -CommandName Restore-RideDefaultWallpaperRun -ParameterName RunId -ScriptBlock $script:DefaultWallpaperRunCompleter
Export-ModuleMember -Function Set-RideDefaultWallpaperImage,Restore-RideDefaultWallpaperRun
