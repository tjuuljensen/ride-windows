<#
.SYNOPSIS
  Adapt default-image lifecycles to catalog planning and saved-run recovery.
.DESCRIPTION
  Calculates local PNG hashes when omitted, or retains explicit pins, for the guarded image handlers.
  Discovery is read-only. Owned public images and private receipts are separated.
.NOTES
  Version: 0.6.0. Windows PowerShell 5.1/7. Supports machine wallpaper,
  machine lock-screen, and recoverable static per-user wallpaper/lock-screen images.
  Changelog: 0.6.0: Add recoverable current-user desktop wallpaper.
    0.5.0: Restore failed lock-screen runs that never wrote child intent as unchanged.
  0.4.0: Add the per-user static lock-screen lifecycle.
  0.2.0: Resolve omitted image hashes from validated local files during selection.
  Accepted image behavior: EnterpriseEval 26300.9711. Other builds require
  AllowCandidate; this does not bypass edition, privilege or recovery checks.
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ImageFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.DefaultWallpaper.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.DefaultLockScreen.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.UserLockScreen.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.UserWallpaper.psm1') -ErrorAction Stop
function Get-RideDefaultImageAdapter {
 param($Operation,[string]$StateRoot)
 if($Operation.ImageType -cnotin @('Wallpaper','LockScreen','UserLockScreen','UserWallpaper')){throw 'Invalid default-image type.'}
 if($Operation.ImageType -ceq 'UserWallpaper'){
  return [pscustomobject]@{Module=Get-Module RIDE.UserWallpaper;Prefix='UserWallpaper';Set='Set-RideUserWallpaperImage';Restore='Restore-RideUserWallpaperImage';Root=(Join-Path $StateRoot 'Images/UserWallpaper');State=(Join-Path $StateRoot 'ImageState/UserWallpaper')}
 }
 if($Operation.ImageType -ceq 'UserLockScreen'){
  return [pscustomobject]@{Module=Get-Module RIDE.UserLockScreen;Prefix='UserLockScreen';Set='Set-RideUserLockScreenImage';Restore='Restore-RideUserLockScreenImage';Root=(Join-Path $StateRoot 'Images/UserLockScreen');State=(Join-Path $StateRoot 'ImageState/UserLockScreen')}
 }
 $wall=$Operation.ImageType -ceq 'Wallpaper'
 [pscustomobject]@{Module=if($wall){Get-Module RIDE.DefaultWallpaper}else{Get-Module RIDE.DefaultLockScreen};Prefix=if($wall){'DefaultWallpaper'}else{'DefaultLock'};Set=if($wall){'Set-RideDefaultWallpaperImage'}else{'Set-RideDefaultLockScreenImage'};Restore=if($wall){'Restore-RideDefaultWallpaperRun'}else{'Restore-RideDefaultLockScreenRun'};Root=(Join-Path $StateRoot ('Images/'+$Operation.ImageType));State=(Join-Path $StateRoot ('ImageState/'+$Operation.ImageType))}
}
function Set-RideDefaultImageSelection {
 <#
 .SYNOPSIS
  Copy a catalog image operation with validated local input selection.
 .DESCRIPTION
  Returns a selected operation without modifying the catalog. An omitted hash is
  calculated from the validated source; execution rechecks that resolved hash.
 .INPUTS
  None. Engine supplies explicit operation, storage and run parameters.
 .OUTPUTS
  Hashtable.
 .NOTES
  Compatibility and target limits follow the module overview. See docs/image-personalization.md.
 #>
 [CmdletBinding()]
 param([hashtable]$Operation,[string]$ImagePath,[string]$ImageSha256)
 if([string]::IsNullOrWhiteSpace($ImagePath) -or $ImagePath -cnotmatch '^[A-Za-z]:[\\/]' -or [IO.Path]::GetExtension($ImagePath) -ine '.png'){throw 'Default image requires an absolute local PNG ImagePath.'}
 if($ImageSha256 -and $ImageSha256 -cnotmatch '^[a-fA-F0-9]{64}$'){throw 'Optional ImageSha256 must contain 64 hexadecimal digits.'}
 if(-not $ImageSha256){$ImageSha256=(Get-RidePngSource -Path $ImagePath).Sha256}
 $copy=@{};foreach($key in $Operation.Keys){$copy[$key]=$Operation[$key]}
 $copy.ImagePath=[IO.Path]::GetFullPath($ImagePath);$copy.ImageSha256=$ImageSha256.ToUpperInvariant();$copy
}
function Get-RideDefaultImageState {
 <#
 .SYNOPSIS
  Inspect image policy and verified owned payload state without mutation.
 .DESCRIPTION
  Private receipts require read permission; unreadable or changed ownership is not reported as desired.
 .INPUTS
  None. Engine supplies explicit operation, storage and run parameters.
 .OUTPUTS
  PSCustomObject.
 .NOTES
  Compatibility and target limits follow the module overview. See docs/image-personalization.md.
 #>
 [CmdletBinding()]
 param($Operation,[string]$StateRoot)
 $a=Get-RideDefaultImageAdapter $Operation $StateRoot
 if($Operation.ImageType -ceq 'UserLockScreen'){return Get-RideUserLockScreenState -AssetDirectory $a.Root -StateDirectory $a.State}
 if($Operation.ImageType -ceq 'UserWallpaper'){return Get-RideUserWallpaperState -AssetDirectory $a.Root -StateDirectory $a.State}
 if($Operation.ImageType -ceq 'LockScreen'){
  $ctx=& $a.Module {Get-RideDefaultLockContext}
  if($ctx.EditionId -ceq 'Professional'){
   $reg=& $a.Module {param($edition)Get-RideDefaultLockRegistry -EditionId $edition} $ctx.EditionId
   $active=& $a.Module {param($state,$asset,$registry,$context)Get-RideDefaultLockActiveRun $state $asset $registry $context} $a.State $a.Root $reg $ctx
   if($active){return [pscustomobject]@{Available=$true;PolicyPath=$active.Intent.PlatformPath;SourceSha256=$active.Intent.SourceSha256;Owned=$true;Registry=$reg;Context=$ctx}}
  }
 }
 & $a.Module {
  param($a,$op)
  $context=& ('Get-Ride'+$a.Prefix+'Context')
  $registry=& ('Get-Ride'+$a.Prefix+'Registry');$row=& ('Get-Ride'+$a.Prefix+'Row') $registry
  $path=if($row){[string]$row.Value}else{$null};$hash=$null;$owned=$false
  if($row -and $row.Kind -ceq 'String' -and [IO.Path]::GetDirectoryName($path) -ieq $a.Root -and [IO.Path]::GetFileNameWithoutExtension($path) -cmatch '^[a-f0-9]{32}$'){
   $id=[IO.Path]::GetFileNameWithoutExtension($path)
   try{
    $intent=& ('Read-Ride'+$a.Prefix+'Run') $a.State $id intent;$done=& ('Read-Ride'+$a.Prefix+'Run') $a.State $id applied
    & ('Assert-Ride'+$a.Prefix+'Run') $intent $done
    & ('Assert-Ride'+$a.Prefix+'Context') $context $intent.Context $false
    if($intent.AssetDirectory -ine $a.Root -or (& ('Assert-Ride'+$a.Prefix+'AssetDirectory') $intent.AssetDirectory) -cne $intent.DirectorySecurity){throw 'Owned image directory changed.'}
    $equal='Test-Ride'+$a.Prefix+'Equal';$asset='Get-Ride'+$a.Prefix+'Asset'
    $owned=(& ('Test-Ride'+$a.Prefix+'RegistryEqual') $registry $done.After) -and (& $equal (& $asset $intent.AssetPath) $done.File)
    if($op.ImageType -ceq 'Wallpaper'){$owned=$owned -and (& $equal (& $asset $intent.ThemePath) $done.Theme)}
    if($owned){$hash=$intent.SourceSha256}
   }catch{$owned=$false}
  }
  [pscustomobject]@{Available=$true;PolicyPath=$path;SourceSha256=$hash;Owned=$owned;Registry=$registry;Context=$context}
 } $a $Operation
}
function Assert-RideDefaultImageTarget {
 <#
 .SYNOPSIS
  Check native image target and explicit candidate boundaries.
 .DESCRIPTION
  Preview skips privilege and acceptance opt-in, while retaining edition and architecture checks.
 .INPUTS
  None. Engine supplies explicit operation, storage and run parameters.
 .OUTPUTS
  None.
 .NOTES
  Compatibility and target limits follow the module overview. See docs/image-personalization.md.
 #>
 [CmdletBinding()]
 param($Operation,$CurrentState,[switch]$AllowCandidate,[switch]$Preview)
 $a=Get-RideDefaultImageAdapter $Operation 'C:\Unused'
 if($Operation.ImageType -cin @('UserLockScreen','UserWallpaper')){
  if(-not $CurrentState.Available){throw "Current user lock-screen image is unavailable: $($CurrentState.Reason)"}
  if($Operation.ImageType -ceq 'UserLockScreen'){
   & $a.Module {param($state,$preview) Assert-RideUserLockScreenContext $state.Context $null (-not $preview)} $CurrentState ([bool]$Preview)
   if(-not $CurrentState.CurrentLocalPath -or -not (Test-Path -LiteralPath $CurrentState.CurrentLocalPath -PathType Leaf)){throw 'Current user lock-screen mode is dynamic or opaque; exact recovery cannot be captured, so the selected plan is refused before mutation.'}
  } else {
   & $a.Module {param($state) Assert-RideUserWallpaperContext $state.Context $null} $CurrentState
   if(-not $CurrentState.CurrentPath -or -not (Test-Path -LiteralPath $CurrentState.CurrentPath -PathType Leaf)){throw 'Current user wallpaper is dynamic, missing or opaque; exact recovery cannot be captured.'}
  }
  return
 }
 & $a.Module {param($a,$c,$mutation) & ('Assert-Ride'+$a.Prefix+'Context') $c $null $mutation} $a $CurrentState.Context (-not $Preview)
 $c=$CurrentState.Context
 if(-not $Preview -and -not $AllowCandidate -and ($c.Build -cne '26300' -or $c.EditionId -cne 'EnterpriseEval' -or $c.Revision -ne 9711)){throw 'Default-image acceptance is limited to EnterpriseEval 26300.9711; other declared editions/builds require -AllowCandidate.'}
}
function Initialize-RideDefaultImageDirectory {
 param([string]$Path,[bool]$Public)
 if(Test-Path -LiteralPath $Path){return}
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 foreach($sid in @('S-1-5-32-544','S-1-5-18')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 if($Public){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))}
 $directory=[IO.DirectoryInfo]::new($Path)
 if($PSVersionTable.PSEdition -eq 'Desktop'){$directory.Create($acl)}else{[IO.FileSystemAclExtensions]::Create($directory,$acl)}
}
function Initialize-RideUserImageDirectory {
 param([Parameter(Mandatory)][string]$Path)
 if(Test-Path -LiteralPath $Path -PathType Container){return}
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($identity.User)
 foreach($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 $directory=[IO.DirectoryInfo]::new($Path);if($PSVersionTable.PSEdition -eq 'Desktop'){$directory.Create($acl)}else{[IO.FileSystemAclExtensions]::Create($directory,$acl)}
}
function Set-RideDefaultImageState {
 <#
 .SYNOPSIS
  Apply a selected image under the engine saved-run identity.
 .DESCRIPTION
  Requires existing elevation and verified local input. Creates controlled storage only after ShouldProcess.
 .INPUTS
  None. Engine supplies explicit operation, storage and run parameters.
 .OUTPUTS
  None.
 .NOTES
  Compatibility and target limits follow the module overview. See docs/image-personalization.md.
 #>
 [CmdletBinding(SupportsShouldProcess)]
 param($Operation,[string]$StateRoot,[string]$RunId,[switch]$AllowCandidate)
 $state=Get-RideDefaultImageState $Operation $StateRoot
 Assert-RideDefaultImageTarget $Operation $state -AllowCandidate:$AllowCandidate -Preview:$WhatIfPreference
 $null=Get-RidePngSource -Path $Operation.ImagePath -ExpectedSha256 $Operation.ImageSha256
 if(-not $PSCmdlet.ShouldProcess($Operation.Id,'Apply selected default image')){return}
 $a=Get-RideDefaultImageAdapter $Operation $StateRoot
 if($Operation.ImageType -cin @('UserLockScreen','UserWallpaper')){
  foreach($path in @((Split-Path $a.Root),$a.Root)){Initialize-RideUserImageDirectory $path}
  foreach($path in @((Split-Path $a.State),$a.State)){Initialize-RideUserImageDirectory $path}
  $parameters=@{Path=$Operation.ImagePath;ExpectedSha256=$Operation.ImageSha256;AssetDirectory=$a.Root;StateDirectory=$a.State;RunId=$RunId;ExpectedComputerName=$state.Context.ComputerName;ExpectedUserSid=$state.Context.UserSid;ExpectedBuild=$state.Context.Build;Confirm=$false}
  if($Operation.ImageType -ceq 'UserLockScreen'){$result=Set-RideUserLockScreenImage @parameters}
  else {$result=Set-RideUserWallpaperImage @parameters}
  if($result.Status -ne 'Applied'){throw 'Concurrent user image state changed; no user image run was applied.'}
  return
 }
 foreach($path in @((Split-Path $a.Root),$a.Root)){Initialize-RideDefaultImageDirectory $path $true}
 foreach($path in @((Split-Path $a.State),$a.State)){Initialize-RideDefaultImageDirectory $path $false}
 $parameters=@{Path=$Operation.ImagePath;ExpectedSha256=$Operation.ImageSha256;AssetDirectory=$a.Root;StateDirectory=$a.State;RunId=$RunId;ExpectedComputerName=$state.Context.ComputerName;ExpectedBuild=$state.Context.Build;ExpectedEditionId=$state.Context.EditionId;AllowCandidate=$AllowCandidate;Confirm=$false}
 $result=& $a.Set @parameters
 if($result.Status -ne 'Applied'){throw 'Concurrent image state changed; no new image run was applied. Inspect the saved outer run.'}
}
function Restore-RideDefaultImageState {
 <#
 .SYNOPSIS
  Validate or restore captured default-image state.
 .DESCRIPTION
  ValidateOnly performs no writes; actual recovery retains child policy, file, ownership and consumer guards.
 .INPUTS
  None. Engine supplies explicit operation, storage and run parameters.
 .OUTPUTS
  None.
 .NOTES
  Compatibility and target limits follow the module overview. See docs/image-personalization.md.
 #>
 [CmdletBinding(SupportsShouldProcess)]
 param($Operation,$Snapshot,[string]$RunId,[string]$StateRoot,[switch]$AllowCandidate,[switch]$ValidateOnly,[switch]$FailedApplyWithoutChildIntent)
 if($Snapshot.SnapshotVersion -ne 1 -or $Snapshot.OperationId -cne $Operation.Id -or $Snapshot.ImageType -cne $Operation.ImageType -or $Snapshot.ImageRunId -cne $RunId -or $RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'Invalid saved default-image identity.'}
 $a=Get-RideDefaultImageAdapter $Operation $StateRoot
 if($FailedApplyWithoutChildIntent -and $Operation.ImageType -ceq 'LockScreen'){
  $childStateExists=$false
  & $a.Module {
   param($state,$asset,$run,$edition)
   $intent=Get-RideDefaultLockRunPath $state $run intent;$applied=Get-RideDefaultLockRunPath $state $run applied
   $extension=Get-RideDefaultLockAssetExtension $edition
   $owned=Join-Path $asset ($run+$extension);$backup=Join-Path $state ($run+'.prior.img0.bin')
   (Test-Path -LiteralPath $intent) -or (Test-Path -LiteralPath $applied) -or (Test-Path -LiteralPath $owned) -or (Test-Path -LiteralPath $backup)
  } $a.State $a.Root $RunId ((& $a.Module { (Get-RideDefaultLockContext).EditionId })) | ForEach-Object { $childStateExists=[bool]$_ }
  if(-not $childStateExists){return}
 }
 if($Operation.ImageType -cin @('UserLockScreen','UserWallpaper')){
  $verb=if($Operation.ImageType -ceq 'UserLockScreen'){'lock-screen'}else{'wallpaper'}
  $restore=if($Operation.ImageType -ceq 'UserLockScreen'){'Restore-RideUserLockScreenImage'}else{'Restore-RideUserWallpaperImage'}
  if($ValidateOnly){
   & $restore -RunId $RunId -AssetDirectory $a.Root -StateDirectory $a.State -WhatIf -Confirm:$false|Out-Null
   return
  }
  if($PSCmdlet.ShouldProcess($Operation.Id,"Restore captured per-user $verb state")){& $restore -RunId $RunId -AssetDirectory $a.Root -StateDirectory $a.State -Confirm:$false|Out-Null}
  return
 }
 if($ValidateOnly){
  # Validate all image-owned values/files before any write. The sibling value
  # is restored separately, in reverse capture order, by the engine.
  & $a.Module {
   param($a,$run,$allow)
   $intent=& ('Read-Ride'+$a.Prefix+'Run') $a.State $run intent
   $done=& ('Read-Ride'+$a.Prefix+'Run') $a.State $run applied
   & ('Assert-Ride'+$a.Prefix+'Run') $intent $done
   $c=& ('Get-Ride'+$a.Prefix+'Context'); & ('Assert-Ride'+$a.Prefix+'Context') $c $intent.Context $false
   $equal='Test-Ride'+$a.Prefix+'Equal';$asset='Get-Ride'+$a.Prefix+'Asset';$reg=& ('Get-Ride'+$a.Prefix+'Registry')
   $row=& ('Get-Ride'+$a.Prefix+'Row') $reg;$expected=& ('Get-Ride'+$a.Prefix+'Row') $done.After;$prior=& ('Get-Ride'+$a.Prefix+'Row') $intent.Before
   $file=& $asset $intent.AssetPath
   if((& $equal $row $prior) -and $null -eq $file){
    if($a.Prefix -ne 'DefaultWallpaper' -or $null -eq (& $asset $intent.ThemePath)){return}
   }
   if((-not (& $equal $row $expected) -and -not (& $equal $row $prior)) -or ($null -ne $file -and -not (& $equal $file $done.File))){throw 'Image policy/file conflicts with captured recovery.'}
   if((-not (& $equal $row $prior)) -and $null -eq $file){throw 'Active image file is missing.'}
   if($a.Prefix -eq 'DefaultWallpaper'){
    $theme=& $asset $intent.ThemePath
    if(($null -ne $theme -and -not (& $equal $theme $done.Theme)) -or (-not (& $equal $row $prior) -and $null -eq $theme)){throw 'Theme conflicts with captured recovery.'}
    if(-not (& $equal @($intent.Profiles) @((Get-RideDefaultWallpaperProfiles)))){throw 'User profiles changed since apply; inspect first-logon consumers before recovery.'}
   }
   if((& ('Assert-Ride'+$a.Prefix+'AssetDirectory') $intent.AssetDirectory) -cne $intent.DirectorySecurity){throw 'Image directory changed.'}
  } $a $RunId ([bool]$AllowCandidate)
  return
 }
 if($PSCmdlet.ShouldProcess($Operation.Id,'Restore captured default-image state')){& $a.Restore -RunId $RunId -StateDirectory $a.State -AllowCandidate:$AllowCandidate -Confirm:$false|Out-Null}
}
Export-ModuleMember -Function Set-RideDefaultImageSelection,Get-RideDefaultImageState,Assert-RideDefaultImageTarget,Set-RideDefaultImageState,Restore-RideDefaultImageState
