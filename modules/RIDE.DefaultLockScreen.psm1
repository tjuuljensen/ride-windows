<#
.SYNOPSIS
  Apply and recover a machine default lock-screen image on a supported Windows target.
.DESCRIPTION
  Uses the documented LockScreenImage policy and a new owned public-readable
  PNG. Captures private machine intent and, on Pro, a private bounded backup of
  Windows Web Screen img0.jpg when present; otherwise records its prior absence.
  Preserves source images and user-choice policies; does not recursively reset
  SystemData ACLs.
.NOTES
  Compatibility: Windows 11 x64 Pro, Enterprise or Education, PowerShell 5.1/7.
  Requires an explicitly matched Windows target and existing elevation.
  Image and state directories must exist. No UAC, sign-out or reboot is launched.
  Recovery restores captured policy and img0.jpg bytes/metadata, not Windows
  caches or visible UI.
  Apply attempts automatic rollback only for exact captured or RIDE-written
  values. Restore can recover an interrupted intent-only transaction when all
  current values still match that transaction; conflicting state is retained.
  Version: 0.6.0.
  Changelog: 0.6.0: Create a missing Pro img0.jpg target and recover its prior absence; safely no-op failed runs with no child intent.
  Changelog: 0.5.0: Back up and replace Pro img0.jpg with bounded exact file recovery.
  0.4.0: Restore the Pro CSP route with v2-compatible image naming and exact tuple recovery.
  0.2.0: Integrate catalog run IDs, accepted target gating and sibling-image idempotence.
  0.1.1: Read policy permissions from the same opened registry handle.
  0.1.0: Add owned image and default policy lifecycle candidate.
.LINK
  ../docs/image-personalization.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ImageFiles.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop
$script:PolicyParent='SOFTWARE\Policies\Microsoft\Windows'
$script:PolicyChild='Personalization'
$script:CspParent='SOFTWARE\Microsoft\Windows\CurrentVersion'
$script:CspChild='PersonalizationCSP'
$script:CspValueNames=@('LockScreenImagePath','LockScreenImageUrl','LockScreenImageStatus')
function Get-RideDefaultLockBackend {
  param([Parameter(Mandatory)][string]$EditionId)
  if($EditionId -ceq 'Professional'){
    return [pscustomobject]@{Parent=$script:CspParent;Child=$script:CspChild;Names=$script:CspValueNames;Kind='PersonalizationCSP'}
  }
  [pscustomobject]@{Parent=$script:PolicyParent;Child=$script:PolicyChild;Names=@('LockScreenImage');Kind='Policy'}
}
function Get-RideDefaultLockAssetExtension {
  param([Parameter(Mandatory)][string]$EditionId)
  if($EditionId -ceq 'Professional'){return '.jpg'}
  '.png'
}
function Get-RideDefaultLockPlatformPath {
  param([Parameter(Mandatory)][string]$EditionId)
  if($EditionId -ceq 'Professional'){return Join-Path $env:SystemRoot 'Web\Screen\img0.jpg'}
  $null
}
function Get-RideDefaultLockPlatformFile {
  param([Parameter(Mandatory)][string]$Path)
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return $null}
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'The Windows inbox lock-screen image must not be a reparse point.'}
  if($item.Length -lt 1 -or $item.Length -gt 16777216){throw 'The Windows inbox lock-screen image exceeds the 16 MiB recovery bound.'}
  $acl=Get-Acl -LiteralPath $Path
  [pscustomobject]@{Path=[IO.Path]::GetFullPath($Path);Sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;Bytes=$item.Length;Security=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access');Attributes=[int]$item.Attributes;CreationUtcTicks=$item.CreationTimeUtc.Ticks.ToString();LastWriteUtcTicks=$item.LastWriteTimeUtc.Ticks.ToString()}
}
function Write-RideDefaultLockPlatformBytes {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][byte[]]$Bytes,[Parameter(Mandatory)][string]$ExpectedSha256,$Metadata)
  if($Metadata){
    $before=Get-RideDefaultLockPlatformFile $Path
    if(-not $before -or $before.Security -cne $Metadata.Security){throw 'Windows inbox lock-screen file permissions changed.'}
    [IO.File]::SetAttributes($Path,[IO.FileAttributes]::Normal)
    [IO.File]::WriteAllBytes($Path,$Bytes)
    [IO.File]::SetCreationTimeUtc($Path,[DateTime]::new([int64]$Metadata.CreationUtcTicks,[DateTimeKind]::Utc))
  }else{
    if(Test-Path -LiteralPath $Path){throw 'Windows inbox lock-screen image appeared after preflight.'}
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  }
  [IO.File]::SetLastWriteTimeUtc($Path,[DateTime]::UtcNow)
  [IO.File]::SetAttributes($Path,[IO.FileAttributes]::Normal)
  $current=Get-RideDefaultLockPlatformFile $Path
  if(-not $current -or ($Metadata -and $current.Security -cne $Metadata.Security) -or $current.Sha256 -cne $ExpectedSha256){throw 'Windows inbox lock-screen file write or permissions did not verify.'}
  $current
}

function Get-RideDefaultLockContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $system=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{[pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;Revision=[int]$version.UBR;InstallationType=[string]$version.InstallationType;NativeProcess=[Environment]::Is64BitProcess;Architecture=$env:PROCESSOR_ARCHITECTURE;Administrator=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);Guest=($env:RIDE_TEST_GUEST -ceq '1' -and $env:RIDE_INTEGRATION_VM -ceq '1' -and $system.Manufacturer -ceq 'Microsoft Corporation' -and $system.Model -ceq 'Virtual Machine')}}finally{$identity.Dispose()}
}
function Assert-RideDefaultLockContext {
  param($Context,$Expected,[bool]$Mutation)
  if($Context.InstallationType -cne 'Client' -or $Context.Build -cnotmatch '^\d{5,8}$' -or [int]$Context.Build -lt 22000 -or -not $Context.NativeProcess -or $Context.Architecture -cne 'AMD64' -or $Context.EditionId -cnotin @('Professional','Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')){throw 'Default lock-screen candidate requires Windows 11 x64 Pro, Enterprise or Education.'}
  if($Mutation -and -not $Context.Administrator){throw 'Existing elevation is required; no UAC is launched.'}
  if($Expected){foreach($field in @('ComputerName','Build','EditionId','Revision','InstallationType','NativeProcess','Architecture','Guest')){if($Context.$field -cne $Expected.$field){throw "Default lock-screen target changed ($field)."}}}
}
function Test-RideDefaultLockEqual {
  param($Left,$Right)
  (ConvertTo-Json -InputObject $Left -Depth 12 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 12 -Compress)
}
function Resolve-RideDefaultLockDirectory {
  param([string]$Path)
  $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
  if($full -cmatch '^[A-Za-z]:$'){throw 'Select a directory below the drive root.'}
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} (Join-Path $full 'path-check-only')
  $full
}
function Assert-RideDefaultLockAssetDirectory {
  param([string]$Path)
  $full=Resolve-RideDefaultLockDirectory $Path
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
function New-RideDefaultLockAssetSecurity {
  $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  foreach($sid in @('S-1-5-32-544','S-1-5-18','S-1-5-32-545')){
    $rights=if($sid -ceq 'S-1-5-32-545'){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,[Security.AccessControl.AccessControlType]::Allow))
  }
  $acl
}
function Assert-RideDefaultLockAssetSecurity {
  param($Security)
  $expected=New-RideDefaultLockAssetSecurity
  $rows=@($Security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.IsInherited}|Sort-Object)
  $expectedRows=@($expected.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.IsInherited}|Sort-Object)
  if(-not $Security.AreAccessRulesProtected -or $Security.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or ($rows -join ';') -cne ($expectedRows -join ';')){throw 'Owned image permissions differ.'}
}
function New-RideDefaultLockAssetStream {
  param([string]$Path)
  $acl=New-RideDefaultLockAssetSecurity
  $rights=[Security.AccessControl.FileSystemRights]'Write,ReadPermissions'
  $stream=$null
  try{
    if($PSVersionTable.PSEdition -eq 'Desktop'){$stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,$rights,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl);$actual=$stream.GetAccessControl()}
    else{$stream=[IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path),[IO.FileMode]::CreateNew,$rights,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl);$actual=[IO.FileSystemAclExtensions]::GetAccessControl($stream)}
    Assert-RideDefaultLockAssetSecurity $actual
    $stream
  }catch{if($stream){$stream.Dispose()};throw}
}
function Get-RideDefaultLockAsset {
  param([string]$Path)
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $Path
  try{$file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop}catch [Management.Automation.ItemNotFoundException]{return $null}
  if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Owned image must not be a reparse point.'}
  if($file.PSIsContainer){throw 'A directory collides with the owned image.'}
  if($file.Length -lt 57 -or $file.Length -gt 16777216){throw 'Owned image length is invalid.'}
  $acl=Get-Acl -LiteralPath $Path;Assert-RideDefaultLockAssetSecurity $acl
  [pscustomobject]@{Sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;Bytes=$file.Length;Security=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access');Attributes=[int]$file.Attributes;CreationUtcTicks=$file.CreationTimeUtc.Ticks.ToString();LastWriteUtcTicks=$file.LastWriteTimeUtc.Ticks.ToString()}
}
function Open-RideDefaultLockPolicyKey {
  param([string]$EditionId)
  $backend=Get-RideDefaultLockBackend $EditionId
  [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backend.Parent+'\'+$backend.Child,$false)
}
function Test-RideDefaultLockRegistryEqual {
  param($Left,$Right)
  # The sibling default-image operation owns its own value. Preserve all other guards.
  $views=@(foreach($v in @($Left,$Right)){[pscustomobject]@{Exists=$v.Exists;Security=$v.Security;Rows=@($v.Rows|Where-Object Name -INE 'ThemeFile');SubKeys=@($v.SubKeys)}})
  Test-RideDefaultLockEqual $views[0] $views[1]
}
function Get-RideDefaultLockRegistry {
  param([string]$EditionId=(Get-RideDefaultLockContext).EditionId)
  $key=Open-RideDefaultLockPolicyKey $EditionId
  if(-not $key){return [pscustomobject]@{Exists=$false;Security=$null;Rows=@();SubKeys=@()}}
  try{
    $names=@($key.GetValueNames());$subKeys=@($key.GetSubKeyNames()|Sort-Object)
    if($names.Count -gt 128 -or $subKeys.Count -gt 128){throw 'Personalization policy inventory exceeds its bound.'}
    $acl=$key.GetAccessControl()
    [pscustomobject]@{Exists=$true;Security=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access');Rows=@($names|Sort-Object|ForEach-Object {[pscustomobject]@{Name=$_;Kind=[string]$key.GetValueKind($_);Value=$key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}});SubKeys=$subKeys}
  }finally{$key.Dispose()}
}
function Set-RideDefaultLockRegistry {
  param($Row,[bool]$RemoveCreatedKey=$false,[Parameter(Mandatory)][string]$EditionId,[object[]]$RestoreRows)
  $backend=Get-RideDefaultLockBackend $EditionId
  $parent=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backend.Parent,$true)
  if(-not $parent){throw 'Windows lock-screen registry parent is unavailable.'}
  try{
    if($RemoveCreatedKey){
      $key=$parent.OpenSubKey($backend.Child,$true)
      if(-not $key){throw 'Created lock-screen key is missing.'}
      try{foreach($name in $backend.Names){$key.DeleteValue($name,$true)};$key.Flush();if($key.ValueCount -ne 0 -or $key.SubKeyCount -ne 0){throw 'Created lock-screen key is no longer empty.'}}finally{$key.Dispose()}
      $parent.DeleteSubKey($backend.Child,$true);return
    }
    $key=$parent.CreateSubKey($backend.Child)
    try{
      if($PSBoundParameters.ContainsKey('RestoreRows')){
        foreach($name in $backend.Names){$key.DeleteValue($name,$true)}
        foreach($saved in @($RestoreRows)){$key.SetValue([string]$saved.Name,$saved.Value,[Microsoft.Win32.RegistryValueKind]$saved.Kind)}
      }elseif($backend.Kind -ceq 'PersonalizationCSP'){
        if($null -eq $Row){foreach($name in $backend.Names){$key.DeleteValue($name,$true)}}
        else{$path=[string]$Row.Value;$key.SetValue('LockScreenImagePath',$path,[Microsoft.Win32.RegistryValueKind]::String);$key.SetValue('LockScreenImageUrl',$path,[Microsoft.Win32.RegistryValueKind]::String);$key.SetValue('LockScreenImageStatus',1,[Microsoft.Win32.RegistryValueKind]::DWord)}
      }elseif($null -eq $Row){$key.DeleteValue('LockScreenImage',$true)}else{$key.SetValue('LockScreenImage',[string]$Row.Value,[Microsoft.Win32.RegistryValueKind]$Row.Kind)}
      $key.Flush()
    }finally{$key.Dispose()}
  }finally{$parent.Dispose()}
}
function Get-RideDefaultLockRow {
  param($Registry,[string]$EditionId=(Get-RideDefaultLockContext).EditionId)
  $backend=Get-RideDefaultLockBackend $EditionId
  $rows=@($Registry.Rows|Where-Object {$_.Name -in $backend.Names})
  if($backend.Kind -ceq 'PersonalizationCSP'){
    if(-not $rows.Count){return $null}
    $path=@($rows|Where-Object {$_.Name -ieq 'LockScreenImagePath' -and $_.Kind -ceq 'String'})
    $url=@($rows|Where-Object {$_.Name -ieq 'LockScreenImageUrl' -and $_.Kind -ceq 'String'})
    $status=@($rows|Where-Object {$_.Name -ieq 'LockScreenImageStatus' -and $_.Kind -ceq 'DWord'})
    if($rows.Count -ne 3 -or $path.Count -ne 1 -or $url.Count -ne 1 -or $status.Count -ne 1 -or $status[0].Value -ne 1 -or [string]$path[0].Value -cne [string]$url[0].Value){throw 'Prior Pro PersonalizationCSP lock-screen values are partial or inconsistent; refusing to overwrite them.'}
    return [pscustomobject]@{Name='LockScreenImage';Kind='PersonalizationCSP';Value=[string]$path[0].Value}
  }
  if($rows.Count -gt 1 -or ($rows.Count -and $rows[0].Kind -cnotin @('String','ExpandString'))){throw 'Prior LockScreenImage must be absent or a string policy.'}
  if($rows.Count){$rows[0]}
}
function Assert-RideDefaultLockRegistryChange {
  param($Before,$After,[string]$AssetPath,[string]$EditionId)
  $names=(Get-RideDefaultLockBackend $EditionId).Names
  if(-not $After.Exists -or -not (Test-RideDefaultLockEqual @($Before.Rows|Where-Object {$_.Name -notin $names}) @($After.Rows|Where-Object {$_.Name -notin $names})) -or -not (Test-RideDefaultLockEqual @($Before.SubKeys) @($After.SubKeys)) -or ($Before.Exists -and $Before.Security -cne $After.Security)){throw 'Unrelated lock-screen registry state changed.'}
  $row=Get-RideDefaultLockRow $After $EditionId
  if($null -eq $row -or $row.Value -cne $AssetPath){throw 'Default lock-screen registry readback differs.'}
}
function Get-RideDefaultLockRunPath {
  param([string]$StateDirectory,[string]$RunId,[ValidateSet('intent','applied')][string]$Part)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'Default lock-screen run ID must be 32 lowercase hexadecimal characters.'}
  Join-Path $StateDirectory ($RunId+'.default-lock.'+$Part+'.json')
}
function Save-RideDefaultLockRun {
  param([string]$StateDirectory,[string]$RunId,[string]$Part,$Record)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 15 -Compress))
  if($bytes.Length -gt 1048576){throw 'Default lock-screen state exceeds its bound.'}
  $stream=New-RidePrivateFileStream -Path (Get-RideDefaultLockRunPath $StateDirectory $RunId $Part) -Scope Machine
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Read-RideDefaultLockRun {
  param([string]$StateDirectory,[string]$RunId,[string]$Part)
  $bytes=Read-RidePrivateFileBytes -Path (Get-RideDefaultLockRunPath $StateDirectory $RunId $Part) -MaximumBytes 1048576 -Scope Machine
  $record=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
  if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'DefaultLockScreen' -or $record.RunId -cne $RunId -or $record.Part -cne $Part){throw 'Default lock-screen recovery identity differs.'}
  $record
}
function Assert-RideDefaultLockRun {
  param($Intent,$Applied)
  $extension=Get-RideDefaultLockAssetExtension $Intent.Context.EditionId
  $platformPath=if($Intent.PSObject.Properties.Name -contains 'PlatformPath'){[string]$Intent.PlatformPath}else{$Intent.AssetPath}
  if('PlatformPath' -notin $Intent.PSObject.Properties.Name){$expectedPlatformPath=$Intent.AssetPath}else{$expectedPlatformPath=Get-RideDefaultLockPlatformPath $Intent.Context.EditionId;if(-not $expectedPlatformPath){$expectedPlatformPath=$Intent.AssetPath}}
  if($Intent.AssetDirectory -cne (Resolve-RideDefaultLockDirectory $Intent.AssetDirectory) -or $Intent.SourceSha256 -cnotmatch '^[A-F0-9]{64}$' -or $Intent.AssetPath -cne (Join-Path $Intent.AssetDirectory ($Intent.RunId+$extension)) -or $platformPath -cne $expectedPlatformPath -or $Applied.File.Sha256 -cne $Intent.SourceSha256 -or $Applied.File.Bytes -ne $Intent.SourceBytes -or ($Applied.PSObject.Properties.Name -contains 'PlatformPath' -and $Applied.PlatformPath -cne $platformPath)){throw 'Saved image identity or ownership is invalid.'}
  if($Intent.Context.EditionId -ceq 'Professional' -and (-not $Applied.PlatformFile -or $Applied.PlatformFile.Path -cne $Intent.PlatformPath -or $Applied.PlatformFile.Sha256 -cne $Intent.SourceSha256 -or $Applied.PlatformFile.Bytes -ne $Intent.SourceBytes)){throw 'Saved Pro inbox image recovery identity is invalid.'}
  if($Intent.Context.EditionId -ceq 'Professional' -and [bool]$Intent.PlatformCreated -ne [bool](-not $Intent.PriorPlatformFile)){throw 'Saved Pro inbox image creation identity is invalid.'}
  if($Intent.PriorPlatformFile -and ($Intent.PriorPlatformFile.Path -cne $Intent.PlatformPath -or $Intent.PriorPlatformFile.Sha256 -notmatch '^[A-F0-9]{64}$' -or $Intent.PriorPlatformFile.Bytes -lt 1 -or $Intent.PriorPlatformFile.Bytes -gt 16777216 -or $Intent.PlatformBackupPath -cne (Join-Path $Intent.StateDirectory ($Intent.RunId+'.prior.img0.bin')) -or -not $Applied.PlatformFile -or $Applied.PlatformFile.Path -cne $Intent.PlatformPath -or $Applied.PlatformFile.Sha256 -cne $Intent.SourceSha256 -or $Applied.PlatformFile.Bytes -ne $Intent.SourceBytes -or $Applied.PlatformFile.Security -cne $Intent.PriorPlatformFile.Security)){throw 'Saved Windows inbox image recovery identity is invalid.'}
  Assert-RideDefaultLockRegistryChange $Intent.Before $Applied.After $platformPath $Intent.Context.EditionId
}
function Get-RideDefaultLockActiveRun {
  param([string]$StateDirectory,[string]$AssetDirectory,$Registry,$Context)
  if($Context.EditionId -cne 'Professional'){return $null}
  $row=Get-RideDefaultLockRow $Registry $Context.EditionId;$platformPath=Get-RideDefaultLockPlatformPath $Context.EditionId
  if(-not $row -or $row.Value -cne $platformPath){return $null}
  $platformFile=Get-RideDefaultLockPlatformFile $platformPath
  $files=@(Get-ChildItem -LiteralPath $StateDirectory -Filter '*.default-lock.applied.json' -File -ErrorAction Stop|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1000)
  foreach($file in $files){
    if($file.Name -cnotmatch '^([a-f0-9]{32})\.default-lock\.applied\.json$'){continue}
    $id=$Matches[1]
    try{$intent=Read-RideDefaultLockRun $StateDirectory $id intent;$done=Read-RideDefaultLockRun $StateDirectory $id applied;Assert-RideDefaultLockRun $intent $done}catch{continue}
    if($intent.AssetDirectory -ieq $AssetDirectory -and $intent.PlatformPath -ceq $platformPath -and (Test-RideDefaultLockRegistryEqual $done.After $Registry) -and (Test-RideDefaultLockEqual $done.PlatformFile $platformFile) -and (Test-RideDefaultLockEqual $done.File (Get-RideDefaultLockAsset $intent.AssetPath))){return [pscustomobject]@{Intent=$intent;Applied=$done}}
  }
  $null
}

function Set-RideDefaultLockScreenImage {
  <#
  .SYNOPSIS
    Apply a pinned PNG as the machine default lock-screen image on the selected Windows target.
  .PARAMETER Path
    Selected local PNG source; original bytes are never changed.
  .PARAMETER ExpectedSha256
    Reviewed source hash; required before decoding or writing.
  .PARAMETER AssetDirectory
    Existing administrator-controlled directory with Users read/execute access.
  .PARAMETER StateDirectory
    Existing local directory for private administrator/SYSTEM recovery records.
  .PARAMETER RunId
    Optional engine-owned 32-digit run identity; generated when omitted.
  .PARAMETER ExpectedComputerName
    Exact intended computer name.
  .PARAMETER ExpectedBuild
    Exact intended Windows 11 build number.
  .PARAMETER ExpectedEditionId
    Exact Pro, Enterprise or Education edition identifier.
  .PARAMETER AllowCandidate
    Permit mutation on declared targets other than accepted EnterpriseEval 26300.9711.
  .EXAMPLE
    Set-RideDefaultLockScreenImage -Path C:\Inputs\lock.png -ExpectedSha256 $hash -AssetDirectory C:\RIDE-Test\Images -StateDirectory C:\RIDE-Test\State -ExpectedComputerName RIDE-Test -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Applied, AlreadyDesired or Preview result. Native visual acceptance is false.
  .NOTES
    Existing elevation and matching Windows target required. Captures before mutation.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][string]$AssetDirectory,[Parameter(Mandatory)][string]$StateDirectory,
    [Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateSet('Professional','Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId,[switch]$AllowCandidate,[ValidatePattern('^[a-f0-9]{32}$')][string]$RunId)
  $context=Get-RideDefaultLockContext;Assert-RideDefaultLockContext $context $null (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Selected default lock-screen target differs.'}
  if(-not $WhatIfPreference -and -not $AllowCandidate -and ($context.Build -cne '26300' -or $context.EditionId -cne 'EnterpriseEval' -or $context.Revision -ne 9711)){throw 'Default lock-screen native acceptance is pending; specify -AllowCandidate.'}
  $AssetDirectory=Resolve-RideDefaultLockDirectory $AssetDirectory;$StateDirectory=Resolve-RideDefaultLockDirectory $StateDirectory
  $directorySecurity=Assert-RideDefaultLockAssetDirectory $AssetDirectory
  $source=Get-RidePngSource -Path $Path -ExpectedSha256 $ExpectedSha256 -IncludeContent
  $before=Get-RideDefaultLockRegistry -EditionId $context.EditionId;$prior=Get-RideDefaultLockRow $before $context.EditionId
  $platformPath=Get-RideDefaultLockPlatformPath $context.EditionId
  if($platformPath){
    $active=Get-RideDefaultLockActiveRun $StateDirectory $AssetDirectory $before $context
    if($active -and $active.Intent.SourceSha256 -ceq $source.Sha256){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='AlreadyDesired';RunId=$active.Intent.RunId;NativeVisualAcceptance=$false}}
  }
  if($prior -and $prior.Kind -cin @('String','ExpandString','PersonalizationCSP') -and [IO.Path]::GetDirectoryName([string]$prior.Value) -ieq $AssetDirectory -and [IO.Path]::GetFileName([string]$prior.Value) -cmatch '^([a-f0-9]{32})\.(png|jpg)$'){
    $ownerId=$Matches[1];$owner=Read-RideDefaultLockRun $StateDirectory $ownerId intent;$done=Read-RideDefaultLockRun $StateDirectory $ownerId applied
    Assert-RideDefaultLockRun $owner $done
    if($owner.SourceSha256 -ceq $source.Sha256){
      Assert-RideDefaultLockContext $context $owner.Context $false
      if($owner.AssetPath -cne $prior.Value -or $owner.DirectorySecurity -cne $directorySecurity -or -not (Test-RideDefaultLockRegistryEqual $done.After $before) -or -not (Test-RideDefaultLockEqual $done.File (Get-RideDefaultLockAsset $owner.AssetPath))){throw 'Previously owned image or policy changed.'}
      return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='AlreadyDesired';RunId=$ownerId;NativeVisualAcceptance=$false}
    }
  }
  $runId=if($RunId){$RunId}else{[guid]::NewGuid().ToString('N')};$assetPath=Join-Path $AssetDirectory ($runId+(Get-RideDefaultLockAssetExtension $context.EditionId));$policyPath=if($platformPath){$platformPath}else{$assetPath}
  if($null -ne (Get-RideDefaultLockAsset $assetPath)){throw 'New image destination already exists.'}
  $priorPlatformFile=if($platformPath){Get-RideDefaultLockPlatformFile $platformPath}else{$null};$platformBackupPath=if($priorPlatformFile){Join-Path $StateDirectory ($runId+'.prior.img0.bin')}else{$null}
  $intent=[pscustomobject]@{SchemaVersion=1;Kind='DefaultLockScreen';RunId=$runId;Part='intent';Context=$context;AssetDirectory=$AssetDirectory;StateDirectory=$StateDirectory;AssetPath=$assetPath;PlatformPath=$policyPath;PlatformBackupPath=$platformBackupPath;PlatformCreated=[bool]($platformPath -and -not $priorPlatformFile);PriorPlatformFile=$priorPlatformFile;DirectorySecurity=$directorySecurity;SourceSha256=$source.Sha256;SourceBytes=$source.Bytes;Before=$before}
  $action=if($platformPath){'Capture recovery, replace Windows img0.jpg, and set the Pro lock-screen CSP tuple'}else{'Capture machine recovery, create owned image and set default lock-screen policy'}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,$action)){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Preview';RunId=$null;NativeVisualAcceptance=$false}}
  Save-RideDefaultLockRun $StateDirectory $runId intent $intent
  try{
    Assert-RideDefaultLockContext (Get-RideDefaultLockContext) $context $true
    if((Assert-RideDefaultLockAssetDirectory $AssetDirectory) -cne $directorySecurity -or -not (Test-RideDefaultLockEqual $before (Get-RideDefaultLockRegistry -EditionId $context.EditionId))){throw 'Destination or policy changed during preflight.'}
    if($platformPath -and -not (Test-RideDefaultLockEqual $priorPlatformFile (Get-RideDefaultLockPlatformFile $platformPath))){throw 'Windows inbox lock-screen image changed during preflight.'}
    if($priorPlatformFile){$backupBytes=[IO.File]::ReadAllBytes($platformPath);if($backupBytes.Length -ne $priorPlatformFile.Bytes -or (Get-FileHash -LiteralPath $platformPath -Algorithm SHA256).Hash -cne $priorPlatformFile.Sha256){throw 'Windows inbox lock-screen image changed while capturing recovery.'};$backupStream=New-RidePrivateFileStream -Path $platformBackupPath -Scope Machine;try{$backupStream.Write($backupBytes,0,$backupBytes.Length);$backupStream.Flush($true)}finally{$backupStream.Dispose()}}
    $stream=New-RideDefaultLockAssetStream $assetPath
    try{$stream.Write($source.Content,0,$source.Content.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $file=Get-RideDefaultLockAsset $assetPath
    if($file.Sha256 -cne $source.Sha256 -or $file.Bytes -ne $source.Bytes){throw 'Owned image readback differs.'}
    if(-not (Test-RideDefaultLockEqual $before (Get-RideDefaultLockRegistry -EditionId $context.EditionId))){throw 'Lock-screen registry state changed before its write.'}
    if($platformPath){
      Set-RideDefaultLockRegistry ([pscustomobject]@{Kind='PersonalizationCSP';Value=$policyPath}) -EditionId $context.EditionId
      $policyAfter=Get-RideDefaultLockRegistry -EditionId $context.EditionId;Assert-RideDefaultLockRegistryChange $before $policyAfter $policyPath $context.EditionId
      Write-RideDefaultLockPlatformBytes -Path $platformPath -Bytes $source.Content -ExpectedSha256 $source.Sha256 -Metadata $priorPlatformFile|Out-Null
      $after=Get-RideDefaultLockRegistry -EditionId $context.EditionId
    }else{
      Set-RideDefaultLockRegistry ([pscustomobject]@{Kind='String';Value=$policyPath}) -EditionId $context.EditionId
      $after=Get-RideDefaultLockRegistry -EditionId $context.EditionId;Assert-RideDefaultLockRegistryChange $before $after $policyPath $context.EditionId
    }
    Assert-RideDefaultLockRegistryChange $before $after $policyPath $context.EditionId
    if(-not (Test-RideDefaultLockEqual $file (Get-RideDefaultLockAsset $assetPath))){throw 'Owned image changed after policy write.'}
    $platformFile=if($platformPath){Get-RideDefaultLockPlatformFile $platformPath}else{$null}
    Save-RideDefaultLockRun $StateDirectory $runId applied ([pscustomobject]@{SchemaVersion=1;Kind='DefaultLockScreen';RunId=$runId;Part='applied';After=$after;File=$file;PlatformPath=$policyPath;PlatformFile=$platformFile})
    [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Applied';RunId=$runId;AssetPath=$assetPath;NativeVisualAcceptance=$false}
  }catch{
    $cause=$_.Exception.Message
    if($platformPath -and ($backupBytes -or -not $priorPlatformFile)){
      try{
        $currentRegistry=Get-RideDefaultLockRegistry -EditionId $context.EditionId
        $currentPlatform=Get-RideDefaultLockPlatformFile $platformPath
        $row=Get-RideDefaultLockRow $currentRegistry $context.EditionId
        $targetTuple=($row -and $row.Value -ceq $platformPath)
        if($targetTuple -and (($priorPlatformFile -and $currentPlatform -and $currentPlatform.Security -ceq $priorPlatformFile.Security -and $currentPlatform.Sha256 -cin @($source.Sha256,$priorPlatformFile.Sha256)) -or (-not $priorPlatformFile -and (-not $currentPlatform -or $currentPlatform.Sha256 -ceq $source.Sha256)))){
          if($priorPlatformFile -and $currentPlatform.Sha256 -ceq $source.Sha256){Write-RideDefaultLockPlatformBytes -Path $platformPath -Bytes $backupBytes -ExpectedSha256 $priorPlatformFile.Sha256 -Metadata $priorPlatformFile|Out-Null;[IO.File]::SetLastWriteTimeUtc($platformPath,[DateTime]::new([int64]$priorPlatformFile.LastWriteUtcTicks,[DateTimeKind]::Utc));[IO.File]::SetAttributes($platformPath,[IO.FileAttributes][int]$priorPlatformFile.Attributes)}
          elseif(-not $priorPlatformFile){Remove-Item -LiteralPath $platformPath -Force -ErrorAction Stop}
          $backend=(Get-RideDefaultLockBackend $context.EditionId);$rows=@($before.Rows|Where-Object {$_.Name -in $backend.Names})
          Set-RideDefaultLockRegistry -RestoreRows $rows -RemoveCreatedKey:(-not $before.Exists) -EditionId $context.EditionId
        }
      }catch{}
    }
    throw "Default lock-screen apply incomplete. Run ID: $runId. Retain private intent and inspect policy/image before recovery. Cause: $cause"
  }
}

function Restore-RideDefaultLockIncompleteRun {
  param([Parameter(Mandatory)]$Intent,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  $context=Get-RideDefaultLockContext
  Assert-RideDefaultLockContext $context $Intent.Context (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate -and ($context.Build -cne '26300' -or $context.EditionId -cne 'EnterpriseEval' -or $context.Revision -ne 9711)){throw 'Default lock-screen native acceptance is pending; specify -AllowCandidate.'}
  $expectedPlatformPath=Get-RideDefaultLockPlatformPath $context.EditionId
  if(-not $expectedPlatformPath){$expectedPlatformPath=$Intent.AssetPath}
  $expectedBackupPath=if($Intent.PriorPlatformFile){Join-Path $StateDirectory ($RunId+'.prior.img0.bin')}else{$null}
  if($Intent.StateDirectory -cne $StateDirectory -or $Intent.RunId -cne $RunId -or $Intent.AssetDirectory -cne (Resolve-RideDefaultLockDirectory $Intent.AssetDirectory) -or $Intent.AssetPath -cne (Join-Path $Intent.AssetDirectory ($RunId+(Get-RideDefaultLockAssetExtension $context.EditionId))) -or $Intent.PlatformPath -cne $expectedPlatformPath -or $Intent.SourceSha256 -cnotmatch '^[A-F0-9]{64}$' -or $Intent.SourceBytes -lt 1 -or $Intent.SourceBytes -gt 16777216 -or $Intent.PlatformBackupPath -cne $expectedBackupPath -or ($Intent.PriorPlatformFile -and ($Intent.PriorPlatformFile.Path -cne $expectedPlatformPath -or $Intent.PriorPlatformFile.Sha256 -cnotmatch '^[A-F0-9]{64}$'))){throw 'Incomplete lock-screen intent identity is invalid.'}
  if((Assert-RideDefaultLockAssetDirectory $Intent.AssetDirectory) -cne $Intent.DirectorySecurity){throw 'Owned image directory changed.'}
  $current=Get-RideDefaultLockRegistry -EditionId $context.EditionId
  $registryRestored=Test-RideDefaultLockEqual $current $Intent.Before
  $registryApplied=$false
  if(-not $registryRestored){try{Assert-RideDefaultLockRegistryChange $Intent.Before $current $Intent.PlatformPath $context.EditionId;$registryApplied=$true}catch{throw 'Lock-screen policy changed to a value that does not match the incomplete RIDE transaction.'}}
  $asset=Get-RideDefaultLockAsset $Intent.AssetPath
  if($asset -and ($asset.Sha256 -cne $Intent.SourceSha256 -or $asset.Bytes -ne $Intent.SourceBytes)){throw 'Incomplete RIDE-owned image conflicts with the captured source.'}
  $platformRestored=$true;$platformApplied=$false;$platformCurrent=$null;$backupBytes=$null
  if($context.EditionId -ceq 'Professional'){
    $platformCurrent=Get-RideDefaultLockPlatformFile $Intent.PlatformPath
    if($Intent.PriorPlatformFile){$platformRestored=Test-RideDefaultLockEqual $platformCurrent $Intent.PriorPlatformFile;$platformApplied=$platformCurrent -and $platformCurrent.Security -ceq $Intent.PriorPlatformFile.Security -and $platformCurrent.Sha256 -ceq $Intent.SourceSha256 -and $platformCurrent.Bytes -eq $Intent.SourceBytes}
    else{$platformRestored=$null -eq $platformCurrent;$platformApplied=$platformCurrent -and $platformCurrent.Sha256 -ceq $Intent.SourceSha256 -and $platformCurrent.Bytes -eq $Intent.SourceBytes}
    if(-not $platformRestored -and -not $platformApplied){throw 'Windows inbox image changed to a value that does not match the incomplete RIDE transaction.'}
    if($platformApplied -and $Intent.PriorPlatformFile){$backupBytes=Read-RidePrivateFileBytes -Path $Intent.PlatformBackupPath -MaximumBytes 16777216 -Scope Machine;if($backupBytes.Length -ne $Intent.PriorPlatformFile.Bytes -or (Get-FileHash -LiteralPath $Intent.PlatformBackupPath -Algorithm SHA256).Hash -cne $Intent.PriorPlatformFile.Sha256){throw 'Captured Windows inbox image backup does not verify.'}}
  }
  if($registryRestored -and $platformRestored -and -not $asset){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='AlreadyRestored';RunId=$RunId;NativeVisualAcceptance=$false}}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,'Recover an incomplete default lock-screen transaction from its private intent record')){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Preview';RunId=$RunId;NativeVisualAcceptance=$false}}
  Assert-RideDefaultLockContext (Get-RideDefaultLockContext) $Intent.Context $true
  if(-not (Test-RideDefaultLockEqual $current (Get-RideDefaultLockRegistry -EditionId $context.EditionId)) -or ($asset -and -not (Test-RideDefaultLockEqual $asset (Get-RideDefaultLockAsset $Intent.AssetPath))) -or ($context.EditionId -ceq 'Professional' -and -not (Test-RideDefaultLockEqual $platformCurrent (Get-RideDefaultLockPlatformFile $Intent.PlatformPath)))){throw 'Incomplete recovery target changed during preflight.'}
  if($platformApplied -and $Intent.PriorPlatformFile){
    Write-RideDefaultLockPlatformBytes -Path $Intent.PlatformPath -Bytes $backupBytes -ExpectedSha256 $Intent.PriorPlatformFile.Sha256 -Metadata $Intent.PriorPlatformFile|Out-Null
    [IO.File]::SetLastWriteTimeUtc($Intent.PlatformPath,[DateTime]::new([int64]$Intent.PriorPlatformFile.LastWriteUtcTicks,[DateTimeKind]::Utc))
    [IO.File]::SetAttributes($Intent.PlatformPath,[IO.FileAttributes][int]$Intent.PriorPlatformFile.Attributes)
  }elseif($platformApplied){Remove-Item -LiteralPath $Intent.PlatformPath -Force -ErrorAction Stop}
  if($registryApplied){$backend=Get-RideDefaultLockBackend $context.EditionId;$rows=@($Intent.Before.Rows|Where-Object {$_.Name -in $backend.Names});Set-RideDefaultLockRegistry -RestoreRows $rows -RemoveCreatedKey:(-not $Intent.Before.Exists) -EditionId $context.EditionId}
  if($asset){Remove-Item -LiteralPath $Intent.AssetPath -ErrorAction Stop}
  if($Intent.PriorPlatformFile -and (Test-Path -LiteralPath $Intent.PlatformBackupPath -PathType Leaf)){Remove-Item -LiteralPath $Intent.PlatformBackupPath -ErrorAction Stop}
  if(-not (Test-RideDefaultLockEqual $Intent.Before (Get-RideDefaultLockRegistry -EditionId $context.EditionId)) -or ($Intent.PriorPlatformFile -and -not (Test-RideDefaultLockEqual $Intent.PriorPlatformFile (Get-RideDefaultLockPlatformFile $Intent.PlatformPath))) -or ($context.EditionId -ceq 'Professional' -and $Intent.PlatformCreated -and $null -ne (Get-RideDefaultLockPlatformFile $Intent.PlatformPath)) -or (Get-RideDefaultLockAsset $Intent.AssetPath)){throw 'Incomplete lock-screen recovery readback differs.'}
  [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='RecoveredIncomplete';RunId=$RunId;NativeVisualAcceptance=$false}
}

function Restore-RideDefaultLockScreenRun {
  <#
  .SYNOPSIS
    Restore captured default lock-screen policy and remove only its unchanged owned image.
  .PARAMETER RunId
    Apply run ID. Incomplete intent-only runs are recovered only when all current
    state still matches the captured prior state or exact RIDE-written values.
  .PARAMETER StateDirectory
    Existing directory containing the private intent and applied records.
  .PARAMETER AllowCandidate
    Required for actual recovery while native acceptance remains pending.
  .EXAMPLE
    Restore-RideDefaultLockScreenRun -RunId '<run-id>' -StateDirectory C:\RIDE-Test\State -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Restored, AlreadyRestored or Preview result; no visual acceptance claim.
  .NOTES
    Refuses target, image, directory or policy drift. Retains recovery records.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  $StateDirectory=Resolve-RideDefaultLockDirectory $StateDirectory
  $intent=Read-RideDefaultLockRun $StateDirectory $RunId intent
  $appliedPath=Get-RideDefaultLockRunPath $StateDirectory $RunId applied
  if(-not (Test-Path -LiteralPath $appliedPath -PathType Leaf)){return Restore-RideDefaultLockIncompleteRun -Intent $intent -RunId $RunId -StateDirectory $StateDirectory -AllowCandidate:$AllowCandidate}
  $applied=Read-RideDefaultLockRun $StateDirectory $RunId applied
  Assert-RideDefaultLockRun $intent $applied
  $context=Get-RideDefaultLockContext;Assert-RideDefaultLockContext $context $intent.Context (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate -and ($context.Build -cne '26300' -or $context.EditionId -cne 'EnterpriseEval' -or $context.Revision -ne 9711)){throw 'Default lock-screen native acceptance is pending; specify -AllowCandidate.'}
  if((Assert-RideDefaultLockAssetDirectory $intent.AssetDirectory) -cne $intent.DirectorySecurity){throw 'Owned image directory changed.'}
  $current=Get-RideDefaultLockRegistry -EditionId $context.EditionId;$file=Get-RideDefaultLockAsset $intent.AssetPath
  $registryRestored=Test-RideDefaultLockEqual $current $intent.Before
  $platformRestored=$true;$platformCurrent=$null;$backupBytes=$null
  if($context.EditionId -ceq 'Professional'){
    $platformCurrent=Get-RideDefaultLockPlatformFile $intent.PlatformPath
    if($intent.PriorPlatformFile){$platformRestored=Test-RideDefaultLockEqual $platformCurrent $intent.PriorPlatformFile}
    else{$platformRestored=$null -eq $platformCurrent}
    $platformApplied=($applied.PSObject.Properties.Name -contains 'PlatformFile') -and (Test-RideDefaultLockEqual $platformCurrent $applied.PlatformFile)
    if(-not $platformRestored -and -not $platformApplied){throw 'Windows inbox lock-screen image conflicts with captured recovery.'}
  }
  if($registryRestored -and $platformRestored -and $null -eq $file){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='AlreadyRestored';RunId=$RunId;NativeVisualAcceptance=$false}}
  if($intent.PriorPlatformFile -and -not $platformRestored){$backupBytes=Read-RidePrivateFileBytes -Path $intent.PlatformBackupPath -MaximumBytes 16777216 -Scope Machine;if($backupBytes.Length -ne $intent.PriorPlatformFile.Bytes -or (Get-FileHash -LiteralPath $intent.PlatformBackupPath -Algorithm SHA256).Hash -cne $intent.PriorPlatformFile.Sha256){throw 'Captured Windows inbox image backup does not verify.'}}
  if((-not $registryRestored -and -not (Test-RideDefaultLockRegistryEqual $current $applied.After)) -or ($file -and -not (Test-RideDefaultLockEqual $file $applied.File))){throw 'Lock-screen registry state or owned image conflicts with captured recovery.'}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,'Restore captured default lock-screen policy and remove the unchanged run-owned image')){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Preview';RunId=$RunId;NativeVisualAcceptance=$false}}
  try{
    Assert-RideDefaultLockContext (Get-RideDefaultLockContext) $intent.Context $true
    if((Assert-RideDefaultLockAssetDirectory $intent.AssetDirectory) -cne $intent.DirectorySecurity -or -not (Test-RideDefaultLockEqual $current (Get-RideDefaultLockRegistry -EditionId $context.EditionId)) -or ($file -and -not (Test-RideDefaultLockEqual $file (Get-RideDefaultLockAsset $intent.AssetPath))) -or ($context.EditionId -ceq 'Professional' -and -not (Test-RideDefaultLockEqual $platformCurrent (Get-RideDefaultLockPlatformFile $intent.PlatformPath)))){throw 'Recovery target changed during preflight.'}
    if($intent.PriorPlatformFile -and -not $platformRestored){
      Write-RideDefaultLockPlatformBytes -Path $intent.PlatformPath -Bytes $backupBytes -ExpectedSha256 $intent.PriorPlatformFile.Sha256 -Metadata $intent.PriorPlatformFile|Out-Null
      [IO.File]::SetLastWriteTimeUtc($intent.PlatformPath,[DateTime]::new([int64]$intent.PriorPlatformFile.LastWriteUtcTicks,[DateTimeKind]::Utc))
      [IO.File]::SetAttributes($intent.PlatformPath,[IO.FileAttributes][int]$intent.PriorPlatformFile.Attributes)
      if(-not (Test-RideDefaultLockEqual $intent.PriorPlatformFile (Get-RideDefaultLockPlatformFile $intent.PlatformPath))){throw 'Windows inbox lock-screen image recovery did not verify.'}
    }elseif($context.EditionId -ceq 'Professional' -and -not $platformRestored){Remove-Item -LiteralPath $intent.PlatformPath -Force -ErrorAction Stop}
    if(-not $registryRestored){
      $backend=(Get-RideDefaultLockBackend $intent.Context.EditionId)
      $restoreRows=@($intent.Before.Rows|Where-Object {$_.Name -in $backend.Names})
      Set-RideDefaultLockRegistry -RestoreRows $restoreRows -RemoveCreatedKey:(-not $intent.Before.Exists) -EditionId $intent.Context.EditionId
    }
    if(-not (Test-RideDefaultLockEqual $intent.Before (Get-RideDefaultLockRegistry -EditionId $context.EditionId))){throw 'Captured lock-screen registry recovery did not verify.'}
    if($file -and -not (Test-RideDefaultLockEqual $applied.File (Get-RideDefaultLockAsset $intent.AssetPath))){throw 'Owned image changed before removal.'}
    Remove-Item -LiteralPath $intent.AssetPath -ErrorAction Stop
    if($intent.PriorPlatformFile -and (Test-Path -LiteralPath $intent.PlatformBackupPath -PathType Leaf)){Remove-Item -LiteralPath $intent.PlatformBackupPath -ErrorAction Stop}
    if($null -ne (Get-RideDefaultLockAsset $intent.AssetPath) -or -not (Test-RideDefaultLockEqual $intent.Before (Get-RideDefaultLockRegistry -EditionId $context.EditionId)) -or ($context.EditionId -ceq 'Professional' -and $null -ne (Get-RideDefaultLockPlatformFile $intent.PlatformPath) -and -not $intent.PriorPlatformFile)){throw 'Final recovery readback differs.'}
    [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Restored';RunId=$RunId;NativeVisualAcceptance=$false}
  }catch{throw "Default lock-screen recovery incomplete. Run ID: $RunId. Retain private state. Cause: $($_.Exception.Message)"}
}
$script:DefaultLockRunCompleter={
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{if(-not $fakeBoundParameters.ContainsKey('StateDirectory')){return};Get-ChildItem -LiteralPath $fakeBoundParameters.StateDirectory -Filter '*.default-lock.applied.json' -File -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.default-lock\.applied\.json$'){$id=$Matches[1];if($id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($id,$id,'ParameterValue','Completed default lock-screen run')}}}}catch{}
}
Register-ArgumentCompleter -CommandName Restore-RideDefaultLockScreenRun -ParameterName RunId -ScriptBlock $script:DefaultLockRunCompleter
Export-ModuleMember -Function Set-RideDefaultLockScreenImage,Restore-RideDefaultLockScreenRun
