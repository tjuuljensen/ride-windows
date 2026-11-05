<#
.SYNOPSIS
  Set and restore the current user's desktop wallpaper.
.DESCRIPTION
  Uses the Windows IDesktopWallpaper API for one static image shared across
  displays. Slideshow, per-display images, and solid-color backgrounds are
  refused because the API cannot capture them as one recoverable image path.
.NOTES
  Compatibility: Windows 11 x64, Windows PowerShell 5.1 or PowerShell 7.
  Runs in the intended interactive user's context; no elevation required.
  Version: 0.1.0.
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.ImageFiles.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop

function Initialize-RideUserWallpaperInterop {
  if('RIDE.UserWallpaperInterop.IDesktopWallpaper' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace RIDE.UserWallpaperInterop {
  public enum WallpaperPosition { Center=0, Tile=1, Stretch=2, Fit=3, Fill=4, Span=5 }
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
  [ComImport, Guid("B92B56A9-8B55-4E14-9A89-0199BBB6F93B"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IDesktopWallpaper {
    [PreserveSig] int SetWallpaper([MarshalAs(UnmanagedType.LPWStr)] string monitorId, [MarshalAs(UnmanagedType.LPWStr)] string wallpaper);
    [PreserveSig] int GetWallpaper([MarshalAs(UnmanagedType.LPWStr)] string monitorId, [MarshalAs(UnmanagedType.LPWStr)] out string wallpaper);
    [PreserveSig] int GetMonitorDevicePathAt(uint monitorIndex, [MarshalAs(UnmanagedType.LPWStr)] out string monitorId);
    [PreserveSig] int GetMonitorDevicePathCount(out uint count);
    [PreserveSig] int GetMonitorRECT([MarshalAs(UnmanagedType.LPWStr)] string monitorId, out RECT displayRect);
    [PreserveSig] int SetPosition(WallpaperPosition position);
    [PreserveSig] int GetPosition(out WallpaperPosition position);
  }
}
'@ -ErrorAction Stop
}
function New-RideUserWallpaperApi {
  Initialize-RideUserWallpaperInterop
  $class=[type]::GetTypeFromCLSID([guid]'C2CF3110-460E-4FC1-B9D0-8A1C0C9CC4BD')
  [Activator]::CreateInstance($class)
}
function Get-RideUserWallpaperContext {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{$version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';[pscustomobject]@{ComputerName=[Environment]::MachineName;UserSid=$identity.User.Value;UserProfile=[IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\');Build=[string]$version.CurrentBuildNumber;Architecture=$env:PROCESSOR_ARCHITECTURE;Interactive=[Environment]::UserInteractive}}
  finally{$identity.Dispose()}
}
function Assert-RideUserWallpaperContext {
  param($Context,$Expected)
  if(-not $Context.Interactive -or $Context.Architecture -cne 'AMD64' -or [int]$Context.Build -lt 22000){throw 'User wallpaper requires an interactive Windows 11 x64 session.'}
  if($Expected -and ($Context.ComputerName -cne $Expected.ComputerName -or $Context.UserSid -cne $Expected.UserSid -or $Context.UserProfile -cne $Expected.UserProfile -or $Context.Build -cne $Expected.Build)){throw 'The current user or Windows target differs from the captured wallpaper run.'}
}
function Get-RideUserWallpaperSelection {
  $api=New-RideUserWallpaperApi
  try{
    $path=$null;$hr=$api.GetWallpaper($null,[ref]$path)
    if($hr -eq 1){throw 'Windows reports a slideshow or different wallpaper images across displays; this operation supports one static image shared across displays.'}
    if($hr -ne 0){throw ('Windows desktop wallpaper inspection failed with HRESULT 0x{0:X8}.' -f [uint32]$hr)}
    if([string]::IsNullOrWhiteSpace($path)){throw 'Windows reports no static desktop wallpaper image.'}
    $position=[RIDE.UserWallpaperInterop.WallpaperPosition]::Center
    $hr=$api.GetPosition([ref]$position)
    if($hr -ne 0){throw ('Windows wallpaper-position inspection failed with HRESULT 0x{0:X8}.' -f [uint32]$hr)}
    [pscustomobject]@{Path=[IO.Path]::GetFullPath($path);Position=[int]$position}
  }finally{if($api -and [Runtime.InteropServices.Marshal]::IsComObject($api)){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($api)}}
}
function Invoke-RideUserWallpaperSet {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][int]$Position)
  $api=New-RideUserWallpaperApi
  try{
    $hr=$api.SetWallpaper($null,$Path)
    if($hr -ne 0){throw ('Windows wallpaper API failed with HRESULT 0x{0:X8}.' -f [uint32]$hr)}
    $hr=$api.SetPosition([RIDE.UserWallpaperInterop.WallpaperPosition]$Position)
    if($hr -ne 0){throw ('Windows wallpaper-position API failed with HRESULT 0x{0:X8}.' -f [uint32]$hr)}
  }finally{if($api -and [Runtime.InteropServices.Marshal]::IsComObject($api)){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($api)}}
}
function Get-RideUserWallpaperFile {
  param([string]$Path)
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return $null}
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Wallpaper file is a reparse point.'}
  if($item.Length -lt 1 -or $item.Length -gt 16777216){throw 'Wallpaper file exceeds the 16 MiB recovery bound.'}
  [pscustomobject]@{Path=[IO.Path]::GetFullPath($Path);Sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;Bytes=$item.Length}
}
function Save-RideUserWallpaperRecord {
  param([string]$Path,$Record)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 10 -Compress))
  if($bytes.Length -gt 1048576){throw 'User wallpaper state exceeds its bound.'}
  $stream=New-RidePrivateFileStream -Path $Path -Scope User
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Read-RideUserWallpaperRecord {
  param([string]$Path)
  $bytes=Read-RidePrivateFileBytes -Path $Path -MaximumBytes 1048576 -Scope User
  [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
}
function Get-RideUserWallpaperState {
  <#
  .SYNOPSIS
    Inspect the signed-in user's static desktop wallpaper.
  .PARAMETER AssetDirectory
    Existing user-owned directory for RIDE images.
  .PARAMETER StateDirectory
    Existing private user state directory.
  .OUTPUTS
    Current path, position, ownership and selected source hash.
  .NOTES
    Slideshow and per-display wallpaper configurations are unavailable.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$AssetDirectory,[Parameter(Mandatory)][string]$StateDirectory)
  $context=Get-RideUserWallpaperContext;Assert-RideUserWallpaperContext $context $null
  try{$selection=Get-RideUserWallpaperSelection}catch{return [pscustomobject]@{Available=$false;Reason=$_.Exception.Message;PolicyPath=$null;CurrentPath=$null;Position=$null;Owned=$false;SourceSha256=$null;Context=$context}}
  $file=Get-RideUserWallpaperFile $selection.Path;$owned=$false;$hash=$null
  if($file -and [IO.Path]::GetDirectoryName($file.Path) -ieq [IO.Path]::GetFullPath($AssetDirectory).TrimEnd('\')){
    $run=[IO.Path]::GetFileNameWithoutExtension($file.Path);$intentPath=Join-Path $StateDirectory ($run+'.user-wallpaper.intent.json');$donePath=Join-Path $StateDirectory ($run+'.user-wallpaper.applied.json')
    if($run -cmatch '^[a-f0-9]{32}$' -and (Test-Path -LiteralPath $intentPath) -and (Test-Path -LiteralPath $donePath)){
      try{$intent=Read-RideUserWallpaperRecord $intentPath;$done=Read-RideUserWallpaperRecord $donePath;if($intent.RunId -ceq $run -and $intent.Context.UserSid -ceq $context.UserSid -and $done.After.Path -ceq $file.Path -and $done.After.Sha256 -ceq $file.Sha256 -and $done.AfterPosition -eq $selection.Position){$owned=$true;$hash=$intent.SourceSha256}}catch{}
    }
  }
  [pscustomobject]@{Available=$true;PolicyPath=$selection.Path;CurrentPath=$selection.Path;Position=$selection.Position;Owned=$owned;SourceSha256=$hash;Context=$context;Reason=$null}
}
function Set-RideUserWallpaperImage {
  <#
  .SYNOPSIS
    Set the signed-in user's desktop wallpaper image.
  .DESCRIPTION
    Requires one static wallpaper shared across displays. RIDE captures the
    prior image path, bytes and display position before applying the image.
  .PARAMETER Path
    Selected local PNG.
  .PARAMETER ExpectedSha256
    Required hash calculated by the catalog adapter or explicitly pinned.
  .PARAMETER AssetDirectory
    Existing current-user-owned image directory.
  .PARAMETER StateDirectory
    Existing private current-user state directory.
  .PARAMETER ExpectedComputerName
    Target identity captured during planning.
  .PARAMETER ExpectedUserSid
    Signed-in user identity captured during planning.
  .PARAMETER ExpectedBuild
    Windows build captured during planning.
  .PARAMETER RunId
    Outer engine run identity.
  .OUTPUTS
    Applied, AlreadyDesired or Preview result.
  .NOTES
    Compatibility: Windows 11 x64, Windows PowerShell 5.1 or PowerShell 7.
  #>
  [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,[Parameter(Mandatory)][string]$AssetDirectory,[Parameter(Mandatory)][string]$StateDirectory,[Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedUserSid,[Parameter(Mandatory)][string]$ExpectedBuild,[ValidatePattern('^[a-f0-9]{32}$')][string]$RunId)
  $context=Get-RideUserWallpaperContext;Assert-RideUserWallpaperContext $context $null
  if($context.ComputerName -cne $ExpectedComputerName -or $context.UserSid -cne $ExpectedUserSid -or $context.Build -cne $ExpectedBuild){throw 'Selected signed-in user or Windows target differs.'}
  $AssetDirectory=[IO.Path]::GetFullPath($AssetDirectory);$StateDirectory=[IO.Path]::GetFullPath($StateDirectory)
  if(-not (Test-Path -LiteralPath $AssetDirectory -PathType Container) -or -not (Test-Path -LiteralPath $StateDirectory -PathType Container)){throw 'User wallpaper and state directories must already exist.'}
  $source=Get-RidePngSource -Path $Path -ExpectedSha256 $ExpectedSha256 -IncludeContent
  $before=Get-RideUserWallpaperSelection;$prior=Get-RideUserWallpaperFile $before.Path
  if(-not $prior){throw 'The current wallpaper source is missing; exact recovery cannot be captured.'}
  $runId=if($RunId){$RunId}else{[guid]::NewGuid().ToString('N')}
  $asset=Join-Path $AssetDirectory ($runId+'.png');$backup=Join-Path $AssetDirectory ($runId+'.prior.png')
  if((Test-Path -LiteralPath $asset) -or (Test-Path -LiteralPath $backup)){throw 'User wallpaper destination already exists.'}
  if($prior.Sha256 -ceq $source.Sha256 -and [IO.Path]::GetDirectoryName($prior.Path) -ieq $AssetDirectory){return [pscustomobject]@{Scope='User';Status='AlreadyDesired';RunId=$null;AssetPath=$prior.Path}}
  if(-not $PSCmdlet.ShouldProcess($context.UserSid,'Capture current static wallpaper, install selected image and set this user desktop')){return [pscustomobject]@{Scope='User';Status='Preview';RunId=$null}}
  $intentPath=Join-Path $StateDirectory ($runId+'.user-wallpaper.intent.json');$donePath=Join-Path $StateDirectory ($runId+'.user-wallpaper.applied.json')
  $priorBytes=[IO.File]::ReadAllBytes($before.Path)
  if($priorBytes.Length -gt 16777216){throw 'Current wallpaper exceeds the 16 MiB recovery bound.'}
  $intent=[pscustomobject]@{SchemaVersion=1;RunId=$runId;Context=$context;BeforePath=$before.Path;BeforePosition=$before.Position;BeforeSha256=$prior.Sha256;BeforeBytes=$prior.Bytes;BackupPath=$backup;AssetPath=$asset;SourceSha256=$source.Sha256;SourceBytes=$source.Bytes}
  Save-RideUserWallpaperRecord $intentPath $intent
  try{
    [IO.File]::WriteAllBytes($backup,$priorBytes);[IO.File]::WriteAllBytes($asset,$source.Content)
    if((Get-RideUserWallpaperFile $backup).Sha256 -cne $prior.Sha256 -or (Get-RideUserWallpaperFile $asset).Sha256 -cne $source.Sha256){throw 'Captured or selected wallpaper bytes failed readback.'}
    Invoke-RideUserWallpaperSet $asset $before.Position
    $after=Get-RideUserWallpaperSelection;$active=Get-RideUserWallpaperFile $after.Path
    if($after.Path -cne $asset -or $after.Position -ne $before.Position -or $active.Sha256 -cne $source.Sha256){throw 'Windows wallpaper readback differs from the selected image.'}
    $done=[pscustomobject]@{SchemaVersion=1;RunId=$runId;After=$active;AfterPosition=$after.Position}
    Save-RideUserWallpaperRecord $donePath $done
    [pscustomobject]@{Scope='User';Status='Applied';RunId=$runId;AssetPath=$asset}
  }catch{
    $cause=$_.Exception.Message
    try{$now=Get-RideUserWallpaperSelection;$active=Get-RideUserWallpaperFile $asset;$original=Get-RideUserWallpaperFile $before.Path;$saved=Get-RideUserWallpaperFile $backup
      if($now.Path -ceq $asset -and $now.Position -eq $before.Position -and $active -and $active.Sha256 -ceq $source.Sha256 -and $original -and $original.Sha256 -ceq $prior.Sha256 -and $saved -and $saved.Sha256 -ceq $prior.Sha256){Invoke-RideUserWallpaperSet $before.Path $before.Position;if((Get-RideUserWallpaperSelection).Path -cne $before.Path){throw 'Prior wallpaper did not verify during automatic rollback.'};Remove-Item -LiteralPath $asset -ErrorAction Stop;Remove-Item -LiteralPath $backup -ErrorAction Stop}
    }catch{$cause+=" Automatic rollback also requires recovery: $($_.Exception.Message)"}
    throw "User wallpaper apply failed. Run ID: $runId. Automatic rollback was attempted only when the current wallpaper and captured files still match. Preserve private state. Cause: $cause"
  }
}
function Restore-RideUserWallpaperImage {
  <#
  .SYNOPSIS
    Restore the captured current-user desktop wallpaper and position.
  .PARAMETER RunId
    Saved apply run identifier.
  .PARAMETER AssetDirectory
    Existing current-user-owned image directory.
  .PARAMETER StateDirectory
    Existing private current-user state directory.
  .OUTPUTS
    Restored, AlreadyRestored or Preview result.
  .NOTES
    Refuses user, current wallpaper, position and original-source conflicts.
  #>
  [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$AssetDirectory,[Parameter(Mandatory)][string]$StateDirectory)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'Invalid user wallpaper run ID.'}
  $context=Get-RideUserWallpaperContext;Assert-RideUserWallpaperContext $context $null
  $intent=Read-RideUserWallpaperRecord (Join-Path $StateDirectory ($RunId+'.user-wallpaper.intent.json'))
  $done=Read-RideUserWallpaperRecord (Join-Path $StateDirectory ($RunId+'.user-wallpaper.applied.json'))
  if($intent.SchemaVersion -ne 1 -or $done.SchemaVersion -ne 1 -or $intent.RunId -cne $RunId -or $done.RunId -cne $RunId){throw 'Saved user wallpaper recovery identity differs.'}
  Assert-RideUserWallpaperContext $context $intent.Context
  $current=Get-RideUserWallpaperSelection
  if($current.Path -ceq $intent.BeforePath -and $current.Position -eq $intent.BeforePosition -and -not (Test-Path -LiteralPath $intent.AssetPath)){return [pscustomobject]@{Scope='User';Status='AlreadyRestored';RunId=$RunId}}
  $active=Get-RideUserWallpaperFile $intent.AssetPath;$backup=Get-RideUserWallpaperFile $intent.BackupPath
  if($current.Path -cne $done.After.Path -or $current.Position -ne $done.AfterPosition -or -not $active -or $active.Sha256 -cne $done.After.Sha256 -or -not $backup -or $backup.Sha256 -cne $intent.BeforeSha256){throw 'User wallpaper or captured recovery changed; nothing was changed.'}
  if(-not $PSCmdlet.ShouldProcess($context.UserSid,'Restore captured static wallpaper and display position')){return [pscustomobject]@{Scope='User';Status='Preview';RunId=$RunId}}
  $original=Get-RideUserWallpaperFile $intent.BeforePath
  if(-not $original -or $original.Sha256 -cne $intent.BeforeSha256){throw 'Original wallpaper source changed or disappeared; preserve the captured backup and resolve the file conflict before recovery.'}
  Invoke-RideUserWallpaperSet $intent.BeforePath ([int]$intent.BeforePosition)
  $after=Get-RideUserWallpaperSelection
  if($after.Path -cne $intent.BeforePath -or $after.Position -ne $intent.BeforePosition){throw 'Restored wallpaper and display position did not verify; retain both files and recovery records.'}
  Remove-Item -LiteralPath $intent.AssetPath -ErrorAction Stop;Remove-Item -LiteralPath $intent.BackupPath -ErrorAction Stop
  [pscustomobject]@{Scope='User';Status='Restored';RunId=$RunId}
}
Export-ModuleMember -Function Get-RideUserWallpaperState,Set-RideUserWallpaperImage,Restore-RideUserWallpaperImage
