<#
.SYNOPSIS
  Apply and recover a machine default lock-screen image on a disposable candidate.
.DESCRIPTION
  Uses the documented LockScreenImage policy and a new owned public-readable
  PNG. Captures private machine intent before changes and verifies completed
  state before recovery. Preserves inbox/source images and user-choice policies.
.NOTES
  Compatibility: Candidate Windows 11 x64 Enterprise/Education, PowerShell 5.1/7.
  Requires an explicitly matched Hyper-V test guest and existing elevation.
  Image and state directories must exist. No UAC, sign-out or reboot is launched.
  Recovery restores captured policy/file state, not Windows caches or visible UI.
  Incomplete apply retains evidence and requires inspection; no blind cleanup.
  Version: 0.1.1.
  Changelog: 0.1.1: Read policy permissions from the same opened registry handle.
  0.1.0: Add owned image and default policy lifecycle candidate.
.LINK
  ../docs/image-personalization.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ImageFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop
$script:PolicyParent='SOFTWARE\Policies\Microsoft\Windows'
$script:PolicyChild='Personalization'

function Get-RideDefaultLockContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $system=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{[pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;Revision=[int]$version.UBR;InstallationType=[string]$version.InstallationType;NativeProcess=[Environment]::Is64BitProcess;Architecture=$env:PROCESSOR_ARCHITECTURE;Administrator=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);Guest=($env:RIDE_TEST_GUEST -ceq '1' -and $env:RIDE_INTEGRATION_VM -ceq '1' -and $system.Manufacturer -ceq 'Microsoft Corporation' -and $system.Model -ceq 'Virtual Machine')}}finally{$identity.Dispose()}
}
function Assert-RideDefaultLockContext {
  param($Context,$Expected,[bool]$Mutation)
  if(-not $Context.Guest -or $Context.InstallationType -cne 'Client' -or $Context.Build -cnotmatch '^\d{5,8}$' -or [int]$Context.Build -lt 22000 -or -not $Context.NativeProcess -or $Context.Architecture -cne 'AMD64' -or $Context.EditionId -cnotin @('Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')){throw 'Default lock-screen candidate requires a marked Windows 11 x64 Enterprise/Education Hyper-V guest.'}
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
  [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:PolicyParent+'\'+$script:PolicyChild,$false)
}
function Get-RideDefaultLockRegistry {
  $key=Open-RideDefaultLockPolicyKey
  if(-not $key){return [pscustomobject]@{Exists=$false;Security=$null;Rows=@();SubKeys=@()}}
  try{
    $names=@($key.GetValueNames());$subKeys=@($key.GetSubKeyNames()|Sort-Object)
    if($names.Count -gt 128 -or $subKeys.Count -gt 128){throw 'Personalization policy inventory exceeds its bound.'}
    $acl=$key.GetAccessControl()
    [pscustomobject]@{Exists=$true;Security=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner,Group,Access');Rows=@($names|Sort-Object|ForEach-Object {[pscustomobject]@{Name=$_;Kind=[string]$key.GetValueKind($_);Value=$key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}});SubKeys=$subKeys}
  }finally{$key.Dispose()}
}
function Set-RideDefaultLockRegistry {
  param($Row,[bool]$RemoveCreatedKey=$false)
  $parent=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:PolicyParent,$true)
  if(-not $parent){throw 'Windows policy parent is unavailable.'}
  try{
    if($RemoveCreatedKey){
      $key=$parent.OpenSubKey($script:PolicyChild,$true)
      if(-not $key){throw 'Created personalization key is missing.'}
      try{$key.DeleteValue('LockScreenImage',$true);$key.Flush();if($key.ValueCount -ne 0 -or $key.SubKeyCount -ne 0){throw 'Created personalization key is no longer empty.'}}finally{$key.Dispose()}
      $parent.DeleteSubKey($script:PolicyChild,$true);return
    }
    $key=$parent.CreateSubKey($script:PolicyChild)
    try{if($null -eq $Row){$key.DeleteValue('LockScreenImage',$true)}else{$key.SetValue('LockScreenImage',[string]$Row.Value,[Microsoft.Win32.RegistryValueKind]$Row.Kind)};$key.Flush()}finally{$key.Dispose()}
  }finally{$parent.Dispose()}
}
function Get-RideDefaultLockRow {
  param($Registry)
  $rows=@($Registry.Rows|Where-Object Name -IEQ 'LockScreenImage')
  if($rows.Count -gt 1 -or ($rows.Count -and $rows[0].Kind -cnotin @('String','ExpandString'))){throw 'Prior LockScreenImage must be absent or a string policy.'}
  if($rows.Count){$rows[0]}
}
function Assert-RideDefaultLockRegistryChange {
  param($Before,$After,[string]$AssetPath)
  if(-not $After.Exists -or -not (Test-RideDefaultLockEqual @($Before.Rows|Where-Object Name -INE 'LockScreenImage') @($After.Rows|Where-Object Name -INE 'LockScreenImage')) -or -not (Test-RideDefaultLockEqual @($Before.SubKeys) @($After.SubKeys)) -or ($Before.Exists -and $Before.Security -cne $After.Security)){throw 'Unrelated personalization policy state changed.'}
  $row=Get-RideDefaultLockRow $After
  if($null -eq $row -or $row.Kind -cne 'String' -or $row.Value -cne $AssetPath){throw 'Default lock-screen policy readback differs.'}
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
  if($Intent.AssetDirectory -cne (Resolve-RideDefaultLockDirectory $Intent.AssetDirectory) -or $Intent.SourceSha256 -cnotmatch '^[A-F0-9]{64}$' -or $Intent.AssetPath -cne (Join-Path $Intent.AssetDirectory ($Intent.RunId+'.png')) -or $Applied.File.Sha256 -cne $Intent.SourceSha256 -or $Applied.File.Bytes -ne $Intent.SourceBytes){throw 'Saved image identity or ownership is invalid.'}
  Assert-RideDefaultLockRegistryChange $Intent.Before $Applied.After $Intent.AssetPath
}

function Set-RideDefaultLockScreenImage {
  <#
  .SYNOPSIS
    Apply a pinned PNG as the machine default lock-screen image in a test guest.
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
    Set-RideDefaultLockScreenImage -Path C:\Inputs\lock.png -ExpectedSha256 $hash -AssetDirectory C:\RIDE-Test\Images -StateDirectory C:\RIDE-Test\State -ExpectedComputerName RIDE-Test -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -WhatIf
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
  $context=Get-RideDefaultLockContext;Assert-RideDefaultLockContext $context $null (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Selected default lock-screen target differs.'}
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Default lock-screen native acceptance is pending; specify -AllowCandidate.'}
  $AssetDirectory=Resolve-RideDefaultLockDirectory $AssetDirectory;$StateDirectory=Resolve-RideDefaultLockDirectory $StateDirectory
  $directorySecurity=Assert-RideDefaultLockAssetDirectory $AssetDirectory
  $source=Get-RidePngSource -Path $Path -ExpectedSha256 $ExpectedSha256 -IncludeContent
  $before=Get-RideDefaultLockRegistry;$prior=Get-RideDefaultLockRow $before
  if($prior -and $prior.Kind -ceq 'String' -and [IO.Path]::GetDirectoryName([string]$prior.Value) -ieq $AssetDirectory -and [IO.Path]::GetFileName([string]$prior.Value) -cmatch '^([a-f0-9]{32})\.png$'){
    $ownerId=$Matches[1];$owner=Read-RideDefaultLockRun $StateDirectory $ownerId intent;$done=Read-RideDefaultLockRun $StateDirectory $ownerId applied
    Assert-RideDefaultLockRun $owner $done
    if($owner.SourceSha256 -ceq $source.Sha256){
      Assert-RideDefaultLockContext $context $owner.Context $false
      if($owner.AssetPath -cne $prior.Value -or $owner.DirectorySecurity -cne $directorySecurity -or -not (Test-RideDefaultLockEqual $done.After $before) -or -not (Test-RideDefaultLockEqual $done.File (Get-RideDefaultLockAsset $owner.AssetPath))){throw 'Previously owned image or policy changed.'}
      return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='AlreadyDesired';RunId=$ownerId;NativeVisualAcceptance=$false}
    }
  }
  $runId=[guid]::NewGuid().ToString('N');$assetPath=Join-Path $AssetDirectory ($runId+'.png')
  if($null -ne (Get-RideDefaultLockAsset $assetPath)){throw 'New image destination already exists.'}
  $intent=[pscustomobject]@{SchemaVersion=1;Kind='DefaultLockScreen';RunId=$runId;Part='intent';Context=$context;AssetDirectory=$AssetDirectory;AssetPath=$assetPath;DirectorySecurity=$directorySecurity;SourceSha256=$source.Sha256;SourceBytes=$source.Bytes;Before=$before}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,'Capture machine recovery, create owned image and set default lock-screen policy')){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Preview';RunId=$null;NativeVisualAcceptance=$false}}
  Save-RideDefaultLockRun $StateDirectory $runId intent $intent
  try{
    Assert-RideDefaultLockContext (Get-RideDefaultLockContext) $context $true
    if((Assert-RideDefaultLockAssetDirectory $AssetDirectory) -cne $directorySecurity -or -not (Test-RideDefaultLockEqual $before (Get-RideDefaultLockRegistry))){throw 'Destination or policy changed during preflight.'}
    $stream=New-RideDefaultLockAssetStream $assetPath
    try{$stream.Write($source.Content,0,$source.Content.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $file=Get-RideDefaultLockAsset $assetPath
    if($file.Sha256 -cne $source.Sha256 -or $file.Bytes -ne $source.Bytes){throw 'Owned image readback differs.'}
    if(-not (Test-RideDefaultLockEqual $before (Get-RideDefaultLockRegistry))){throw 'Policy changed before its write.'}
    Set-RideDefaultLockRegistry ([pscustomobject]@{Kind='String';Value=$assetPath})
    $after=Get-RideDefaultLockRegistry;Assert-RideDefaultLockRegistryChange $before $after $assetPath
    if(-not (Test-RideDefaultLockEqual $file (Get-RideDefaultLockAsset $assetPath))){throw 'Owned image changed after policy write.'}
    Save-RideDefaultLockRun $StateDirectory $runId applied ([pscustomobject]@{SchemaVersion=1;Kind='DefaultLockScreen';RunId=$runId;Part='applied';After=$after;File=$file})
    [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Applied';RunId=$runId;AssetPath=$assetPath;NativeVisualAcceptance=$false}
  }catch{throw "Default lock-screen apply incomplete. Run ID: $runId. Retain private intent and inspect policy/image before recovery. Cause: $($_.Exception.Message)"}
}

function Restore-RideDefaultLockScreenRun {
  <#
  .SYNOPSIS
    Restore captured default lock-screen policy and remove only its unchanged owned image.
  .PARAMETER RunId
    Completed apply run ID. Incomplete runs refuse automatic recovery.
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
  $intent=Read-RideDefaultLockRun $StateDirectory $RunId intent;$applied=Read-RideDefaultLockRun $StateDirectory $RunId applied
  Assert-RideDefaultLockRun $intent $applied
  $context=Get-RideDefaultLockContext;Assert-RideDefaultLockContext $context $intent.Context (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Default lock-screen native acceptance is pending; specify -AllowCandidate.'}
  if((Assert-RideDefaultLockAssetDirectory $intent.AssetDirectory) -cne $intent.DirectorySecurity){throw 'Owned image directory changed.'}
  $current=Get-RideDefaultLockRegistry;$file=Get-RideDefaultLockAsset $intent.AssetPath
  $policyRestored=Test-RideDefaultLockEqual $current $intent.Before
  if($policyRestored -and $null -eq $file){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='AlreadyRestored';RunId=$RunId;NativeVisualAcceptance=$false}}
  if((-not $policyRestored -and -not (Test-RideDefaultLockEqual $current $applied.After)) -or -not (Test-RideDefaultLockEqual $file $applied.File)){throw 'Policy or owned image conflicts with captured recovery.'}
  if(-not $PSCmdlet.ShouldProcess($context.ComputerName,'Restore captured default lock-screen policy and remove the unchanged run-owned image')){return [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Preview';RunId=$RunId;NativeVisualAcceptance=$false}}
  try{
    Assert-RideDefaultLockContext (Get-RideDefaultLockContext) $intent.Context $true
    if((Assert-RideDefaultLockAssetDirectory $intent.AssetDirectory) -cne $intent.DirectorySecurity -or -not (Test-RideDefaultLockEqual $current (Get-RideDefaultLockRegistry)) -or -not (Test-RideDefaultLockEqual $file (Get-RideDefaultLockAsset $intent.AssetPath))){throw 'Recovery target changed during preflight.'}
    if(-not $policyRestored){Set-RideDefaultLockRegistry (Get-RideDefaultLockRow $intent.Before) (-not $intent.Before.Exists)}
    if(-not (Test-RideDefaultLockEqual $intent.Before (Get-RideDefaultLockRegistry))){throw 'Captured policy recovery did not verify.'}
    if(-not (Test-RideDefaultLockEqual $applied.File (Get-RideDefaultLockAsset $intent.AssetPath))){throw 'Owned image changed before removal.'}
    Remove-Item -LiteralPath $intent.AssetPath -ErrorAction Stop
    if($null -ne (Get-RideDefaultLockAsset $intent.AssetPath) -or -not (Test-RideDefaultLockEqual $intent.Before (Get-RideDefaultLockRegistry))){throw 'Final recovery readback differs.'}
    [pscustomobject]@{SchemaVersion=1;Scope='Machine';Status='Restored';RunId=$RunId;NativeVisualAcceptance=$false}
  }catch{throw "Default lock-screen recovery incomplete. Run ID: $RunId. Retain private state. Cause: $($_.Exception.Message)"}
}
$script:DefaultLockRunCompleter={
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{if(-not $fakeBoundParameters.ContainsKey('StateDirectory')){return};Get-ChildItem -LiteralPath $fakeBoundParameters.StateDirectory -Filter '*.default-lock.applied.json' -File -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.default-lock\.applied\.json$'){$id=$Matches[1];if($id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($id,$id,'ParameterValue','Completed default lock-screen run')}}}}catch{}
}
Register-ArgumentCompleter -CommandName Restore-RideDefaultLockScreenRun -ParameterName RunId -ScriptBlock $script:DefaultLockRunCompleter
Export-ModuleMember -Function Set-RideDefaultLockScreenImage,Restore-RideDefaultLockScreenRun
