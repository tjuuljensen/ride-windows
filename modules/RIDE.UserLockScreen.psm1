<#
.SYNOPSIS
  Set and restore the signed-in user's lock-screen image.
.DESCRIPTION
  Uses the Windows user-profile personalization API. Recovery is limited to a
  current static image exposed as a readable local file URI; dynamic or opaque
  Windows/Spotlight states are refused before mutation.
.NOTES
  Compatibility: Windows 11 x64, Windows PowerShell 5.1 or PowerShell 7.
  Runs only in the intended interactive user's context; no elevation required.
  Version: 0.1.0.
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ImageFiles.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop

function Get-RideUserLockScreenContext {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $profile=[IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
  [pscustomobject]@{ComputerName=[Environment]::MachineName;UserSid=$identity.User.Value;UserProfile=$profile;Build=[string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber;Architecture=$env:PROCESSOR_ARCHITECTURE;Interactive=[Environment]::UserInteractive}
}
function Assert-RideUserLockScreenContext {
  param($Context,$Expected,[bool]$Mutation)
  if(-not $Context.Interactive -or $Context.Architecture -cne 'AMD64' -or [int]$Context.Build -lt 22000){throw 'User lock-screen images require an interactive Windows 11 x64 session.'}
  if($Expected -and ($Context.ComputerName -cne $Expected.ComputerName -or $Context.UserSid -cne $Expected.UserSid -or $Context.UserProfile -cne $Expected.UserProfile -or $Context.Build -cne $Expected.Build)){throw 'The current user or Windows target differs from the captured image run.'}
}
function Get-RideUserLockScreenImageUri {
  try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
    $type=[type]::GetType('Windows.System.UserProfile.LockScreen, Windows.System.UserProfile, ContentType=WindowsRuntime',$true)
    $uri=$type.GetProperty('OriginalImageFile').GetValue($null,$null)
    if($null -eq $uri){return $null}
    [string]$uri.AbsoluteUri
  } catch { throw "Windows could not inspect the current user's lock-screen image: $($_.Exception.Message)" }
}
function Invoke-RideUserLockScreenSet {
  param([Parameter(Mandatory)][string]$Path)
  try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
    $storageType=[type]::GetType('Windows.Storage.StorageFile, Windows.Storage, ContentType=WindowsRuntime',$true)
    $personalizationType=[type]::GetType('Windows.System.UserProfile.UserProfilePersonalizationSettings, Windows.System.UserProfile, ContentType=WindowsRuntime',$true)
    $getFile=$storageType.GetMethod('GetFileFromPathAsync',[Reflection.BindingFlags]'Public,Static')
    $fileOperation=$getFile.Invoke($null,@($Path))
    $fileTask=[System.WindowsRuntimeSystemExtensions]::AsTask($fileOperation)
    $file=$fileTask.GetAwaiter().GetResult()
    $settings=$personalizationType.GetProperty('Current',[Reflection.BindingFlags]'Public,Static').GetValue($null,$null)
    $setOperation=$personalizationType.GetMethod('TrySetLockScreenImageAsync').Invoke($settings,@($file))
    $result=[System.WindowsRuntimeSystemExtensions]::AsTask($setOperation).GetAwaiter().GetResult()
    if(-not $result){throw 'Windows rejected the user lock-screen image.'}
  } catch { throw "Windows user lock-screen API failed: $($_.Exception.Message)" }
}
function Get-RideUserLockScreenFile {
  param([string]$Path)
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return $null}
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'User lock-screen image is a reparse point.'}
  [pscustomobject]@{Path=[IO.Path]::GetFullPath($Path);Sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;Bytes=$item.Length}
}
function Read-RideUserLockScreenRecord {
  param([Parameter(Mandatory)][string]$Path)
  $bytes=Read-RidePrivateFileBytes -Path $Path -MaximumBytes 1048576 -Scope User
  [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
}
function Get-RideUserLockScreenState {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$AssetDirectory,[Parameter(Mandatory)][string]$StateDirectory)
  $context=Get-RideUserLockScreenContext;Assert-RideUserLockScreenContext $context $null $false
  try{$uri=Get-RideUserLockScreenImageUri}catch{return [pscustomobject]@{Available=$false;Reason=$_.Exception.Message;PolicyPath=$null;SourceSha256=$null;Owned=$false;Context=$context;CurrentLocalPath=$null}}
  $path=$null;$owned=$false;$hash=$null
  if($uri){
    $parsed=[uri]$uri
    if($parsed.IsFile){$path=[IO.Path]::GetFullPath($parsed.LocalPath);$file=Get-RideUserLockScreenFile $path
      if($file -and [IO.Path]::GetDirectoryName($path) -ieq [IO.Path]::GetFullPath($AssetDirectory).TrimEnd('\')){$id=[IO.Path]::GetFileNameWithoutExtension($path);$intentPath=Join-Path $StateDirectory ($id+'.user-lock.intent.json');$donePath=Join-Path $StateDirectory ($id+'.user-lock.applied.json')
        if((Test-Path -LiteralPath $intentPath) -and (Test-Path -LiteralPath $donePath)){$intent=Read-RideUserLockScreenRecord $intentPath;$done=Read-RideUserLockScreenRecord $donePath;if($intent.RunId -ceq $id -and $intent.Context.UserSid -ceq $context.UserSid -and $done.Image.Sha256 -ceq $file.Sha256){$owned=$true;$hash=$intent.SourceSha256}}
      }
    }
  }
  [pscustomobject]@{Available=$true;PolicyPath=$uri;SourceSha256=$hash;Owned=$owned;Context=$context;CurrentLocalPath=$path;Reason=$null}
}
function Set-RideUserLockScreenImage {
  [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,[Parameter(Mandatory)][string]$AssetDirectory,[Parameter(Mandatory)][string]$StateDirectory,[Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedUserSid,[Parameter(Mandatory)][string]$ExpectedBuild,[ValidatePattern('^[a-f0-9]{32}$')][string]$RunId)
  $context=Get-RideUserLockScreenContext;Assert-RideUserLockScreenContext $context $null (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.UserSid -cne $ExpectedUserSid -or $context.Build -cne $ExpectedBuild){throw 'Selected signed-in user or Windows target differs.'}
  $AssetDirectory=[IO.Path]::GetFullPath($AssetDirectory);$StateDirectory=[IO.Path]::GetFullPath($StateDirectory)
  if(-not (Test-Path -LiteralPath $AssetDirectory -PathType Container) -or -not (Test-Path -LiteralPath $StateDirectory -PathType Container)){throw 'User image and state directories must already exist.'}
  $source=Get-RidePngSource -Path $Path -ExpectedSha256 $ExpectedSha256 -IncludeContent
  $beforeUri=Get-RideUserLockScreenImageUri
  if(-not $beforeUri){throw 'Windows did not expose a current user lock-screen image; exact recovery cannot be captured.'}
  $beforeParsed=[uri]$beforeUri
  if(-not $beforeParsed.IsFile -or -not (Test-Path -LiteralPath $beforeParsed.LocalPath -PathType Leaf)){throw 'Current lock-screen mode is dynamic or opaque; exact recovery is unavailable. Select a static local image first.'}
  $runId=if($RunId){$RunId}else{[guid]::NewGuid().ToString('N')}
  $asset=Join-Path $AssetDirectory ($runId+'.png');$prior=Join-Path $AssetDirectory ($runId+'.prior'+[IO.Path]::GetExtension($beforeParsed.LocalPath))
  if((Test-Path -LiteralPath $asset) -or (Test-Path -LiteralPath $prior)){throw 'User lock-screen destination already exists.'}
  if(-not $PSCmdlet.ShouldProcess($context.UserSid,'Capture current static image, install selected image and set this user lock screen')){return [pscustomobject]@{Scope='User';Status='Preview';RunId=$null}}
  $intentPath=Join-Path $StateDirectory ($runId+'.user-lock.intent.json');$donePath=Join-Path $StateDirectory ($runId+'.user-lock.applied.json')
  $priorBytes=[IO.File]::ReadAllBytes($beforeParsed.LocalPath)
  if($priorBytes.Length -gt 16777216){throw 'Current user lock-screen image exceeds the 16 MiB recovery bound.'}
  $priorHash=(Get-FileHash -LiteralPath $beforeParsed.LocalPath -Algorithm SHA256).Hash
  $intent=[pscustomobject]@{SchemaVersion=1;RunId=$runId;Context=$context;BeforeUri=$beforeUri;OriginalPriorPath=[IO.Path]::GetFullPath($beforeParsed.LocalPath);PriorPath=$prior;PriorSha256=$priorHash;PriorBytes=$priorBytes.Length;AssetPath=$asset;SourceSha256=$source.Sha256;SourceBytes=$source.Bytes}
  $json=[Text.UTF8Encoding]::new($false).GetBytes(($intent|ConvertTo-Json -Depth 8 -Compress))
  $stream=New-RidePrivateFileStream -Path $intentPath -Scope User;try{$stream.Write($json,0,$json.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  try {
    [IO.File]::WriteAllBytes($prior,$priorBytes);[IO.File]::WriteAllBytes($asset,$source.Content)
    if((Get-FileHash -LiteralPath $prior -Algorithm SHA256).Hash -cne $priorHash -or (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash -cne $source.Sha256){throw 'Captured or selected image bytes failed readback.'}
    Invoke-RideUserLockScreenSet $asset
    $afterUri=Get-RideUserLockScreenImageUri
    $expectedUri=([uri]$asset).AbsoluteUri
    if($afterUri -cne $expectedUri){throw 'Windows lock-screen image URI readback differs.'}
    $done=[pscustomobject]@{SchemaVersion=1;RunId=$runId;Image=(Get-RideUserLockScreenFile $asset);AfterUri=$afterUri}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($done|ConvertTo-Json -Depth 5 -Compress));$stream=New-RidePrivateFileStream -Path $donePath -Scope User;try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    [pscustomobject]@{Scope='User';Status='Applied';RunId=$runId;AssetPath=$asset}
  } catch {
    $cause=$_.Exception.Message
    try {
      $currentUri=Get-RideUserLockScreenImageUri
      $assetFile=Get-RideUserLockScreenFile $asset
      $originalFile=Get-RideUserLockScreenFile $intent.OriginalPriorPath
      $backupFile=Get-RideUserLockScreenFile $prior
      if($currentUri -ceq ([uri]$asset).AbsoluteUri -and $assetFile -and $assetFile.Sha256 -ceq $source.Sha256 -and $originalFile -and $originalFile.Sha256 -ceq $priorHash -and $backupFile -and $backupFile.Sha256 -ceq $priorHash){
        Invoke-RideUserLockScreenSet $intent.OriginalPriorPath
        if((Get-RideUserLockScreenImageUri) -cne $beforeUri){throw 'The original user lock-screen URI did not verify during automatic rollback.'}
        Remove-Item -LiteralPath $asset -ErrorAction Stop
        Remove-Item -LiteralPath $prior -ErrorAction Stop
      }
    } catch { $cause += " Automatic rollback also needs recovery: $($_.Exception.Message)" }
    throw "User lock-screen apply failed. Run ID: $runId. Automatic rollback was attempted only when the current URI and captured files matched. Preserve the private intent record. Cause: $cause"
  }
}
function Restore-RideUserLockScreenImage {
  [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$AssetDirectory,[Parameter(Mandatory)][string]$StateDirectory)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'Invalid user lock-screen run ID.'}
  $context=Get-RideUserLockScreenContext;Assert-RideUserLockScreenContext $context $null (-not $WhatIfPreference)
  $intent=Read-RideUserLockScreenRecord (Join-Path $StateDirectory ($RunId+'.user-lock.intent.json'))
  $done=Read-RideUserLockScreenRecord (Join-Path $StateDirectory ($RunId+'.user-lock.applied.json'))
  if($intent.SchemaVersion -ne 1 -or $done.SchemaVersion -ne 1 -or $intent.RunId -cne $RunId -or $done.RunId -cne $RunId -or $intent.Context.UserSid -cne $context.UserSid){throw 'Saved user lock-screen recovery identity differs.'}
  $current=Get-RideUserLockScreenImageUri
  if($current -ceq $intent.BeforeUri -and -not (Test-Path -LiteralPath $intent.AssetPath)){return [pscustomobject]@{Scope='User';Status='AlreadyRestored';RunId=$RunId}}
  $active=Get-RideUserLockScreenFile $intent.AssetPath;$prior=Get-RideUserLockScreenFile $intent.PriorPath
  if($current -cne $done.AfterUri -or -not $active -or $active.Sha256 -cne $done.Image.Sha256 -or -not $prior -or $prior.Sha256 -cne $intent.PriorSha256){throw 'User lock-screen image changed; captured recovery conflicts, so nothing was changed.'}
  if(-not $PSCmdlet.ShouldProcess($context.UserSid,'Restore captured static user lock-screen image')){return [pscustomobject]@{Scope='User';Status='Preview';RunId=$RunId}}
  $original=Get-RideUserLockScreenFile $intent.OriginalPriorPath
  if(-not $original -or $original.Sha256 -cne $intent.PriorSha256){throw 'Original user image source changed or disappeared; preserve the captured backup and resolve the file conflict before recovery.'}
  Invoke-RideUserLockScreenSet $intent.OriginalPriorPath
  $after=Get-RideUserLockScreenImageUri
  if($after -cne $intent.BeforeUri){throw 'Restored user lock-screen URI did not verify; retain both image files and recovery records.'}
  Remove-Item -LiteralPath $intent.AssetPath -ErrorAction Stop
  Remove-Item -LiteralPath $intent.PriorPath -ErrorAction Stop
  [pscustomobject]@{Scope='User';Status='Restored';RunId=$RunId}
}
Export-ModuleMember -Function Get-RideUserLockScreenState,Set-RideUserLockScreenImage,Restore-RideUserLockScreenImage
