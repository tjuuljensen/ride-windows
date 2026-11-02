<#
.SYNOPSIS
  Exercise machine-font lifecycle in an attested disposable Windows guest.
.DESCRIPTION
  Requires an initially absent selected font batch. Checks native enumeration,
  file/registration state, machine recovery permissions and both saved restores.
  Failures retain evidence and never reset the VM or force font consumers closed.
.NOTES
  Compatibility: Candidate Windows 11 x64; native PowerShell 5.1 and 7.
  Prerequisites: Existing elevation, correlated Hyper-V guest and real licensed fonts.
  Recovery: Retain private run records; incomplete runs need inspection.
  Version: 0.1.0. Changelog: Add current-session native font acceptance.
.LINK
  ../../docs/machine-fonts.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.MachineFonts.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop

function Get-RideFontAcceptanceContext {
  $machine=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $context=& (Get-Module RIDE.MachineFonts) {Get-RideMachineFontContext}
  $context|Add-Member -NotePropertyMembers @{Manufacturer=$machine.Manufacturer;Model=$machine.Model;GuestMarker=$env:RIDE_TEST_GUEST;IntegrationMarker=$env:RIDE_INTEGRATION_VM;RunMarker=$env:RIDE_TEST_RUN_ID}
  $context
}

function Read-RideFontAcceptanceSelection {
  param([string]$ManifestPath)
  $source=& (Get-Module RIDE.MachineFonts) {param($path) Read-RideMachineFontManifest $path} $ManifestPath
  @($source.Entries|Select-Object FileName,RegistryName,FullName,Sha256)
}

function Initialize-RideFontAcceptanceNative {
  if('Ride.FontAcceptanceV1.Enumeration' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace Ride.FontAcceptanceV1 {
 [StructLayout(LayoutKind.Sequential,CharSet=System.Runtime.InteropServices.CharSet.Unicode)] public struct LogFont {
  public int Height,Width,Escapement,Orientation,Weight;
  public byte Italic,Underline,StrikeOut,CharSet,OutPrecision,ClipPrecision,Quality,PitchAndFamily;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string FaceName;
 }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct EnumFont {
  public LogFont Log;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=64)] public string FullName;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string Style;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string Script;
 }
 public static class Enumeration {
  [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate int Callback(IntPtr font,IntPtr metric,uint type,IntPtr data);
  [DllImport("gdi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int EnumFontFamiliesExW(IntPtr dc,ref LogFont font,Callback callback,IntPtr data,uint flags);
  [DllImport("gdi32.dll",ExactSpelling=true)] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
  [DllImport("gdi32.dll",ExactSpelling=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DeleteDC(IntPtr dc);
  public static string[] Read() {
   var names=new SortedSet<string>(StringComparer.Ordinal);var families=new SortedSet<string>(StringComparer.Ordinal);int calls=0;bool overflow=false;
   var dc=CreateCompatibleDC(IntPtr.Zero);if(dc==IntPtr.Zero)throw new InvalidOperationException("Font enumeration DC unavailable.");
   Callback collect=delegate(IntPtr ptr,IntPtr metric,uint type,IntPtr data){
    if(++calls>100000){overflow=true;return 0;}
    if((type&4)!=0){var f=(EnumFont)Marshal.PtrToStructure(ptr,typeof(EnumFont));if(!String.IsNullOrEmpty(f.FullName))names.Add(f.FullName);if(!String.IsNullOrEmpty(f.Log.FaceName))families.Add(f.Log.FaceName);}
    return 1;
   };
   try {
    var query=new LogFont();query.CharSet=1;query.FaceName="";EnumFontFamiliesExW(dc,ref query,collect,IntPtr.Zero,0);
    // A family query obtains its individual styles, including names omitted by
    // the empty-name enumeration. Freeze the family list before callbacks add.
    var selected=new string[families.Count];families.CopyTo(selected);
    foreach(var family in selected){if(overflow)break;query.FaceName=family;EnumFontFamiliesExW(dc,ref query,collect,IntPtr.Zero,0);}
    if(overflow)throw new InvalidOperationException("Font enumeration exceeds its bound.");
    var result=new string[names.Count];names.CopyTo(result);return result;
   }finally{GC.KeepAlive(collect);DeleteDC(dc);}
  }
 }
}
'@ -ErrorAction Stop
}

function Get-RideFontAcceptanceSnapshot {
  param($Context,$Selection)
  Initialize-RideFontAcceptanceNative
  $names=@([Ride.FontAcceptanceV1.Enumeration]::Read())
  $registry=& (Get-Module RIDE.MachineFonts) {Get-RideMachineFontRegistry}
  $files=@(foreach($entry in $Selection){
    & (Get-Module RIDE.MachineFonts) {param($context,$entry,$registry) Get-RideMachineFontSnapshot $context $entry $registry} $Context $entry $registry
  })
  [pscustomobject]@{Registry=$registry;Files=$files;NativeNames=@($Selection|Where-Object {$_.FullName -cin $names}|ForEach-Object FullName|Sort-Object)}
}

function Test-RideFontAcceptanceEqual {
  param($Left,$Right)
  (ConvertTo-Json -InputObject $Left -Depth 12 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 12 -Compress)
}

function Assert-RideFontAcceptanceInstalled {
  param($Snapshot,$Before,$Selection)
  if(@($Snapshot.Files).Count -ne @($Selection).Count -or @($Snapshot.NativeNames).Count -ne @($Selection).Count){throw 'Native font enumeration is incomplete.'}
  for($i=0;$i -lt $Selection.Count;$i++){
    $entry=$Selection[$i];$file=$Snapshot.Files[$i]
    if(-not $file.File.Exists -or $file.File.Sha256 -cne $entry.Sha256 -or $file.Registration.Kind -cne 'String' -or $file.Registration.Value -cne $entry.FileName -or @($file.Aliases).Count -ne 1 -or $entry.FullName -cnotin $Snapshot.NativeNames){throw 'Font installation readback differs.'}
  }
  & (Get-Module RIDE.MachineFonts) {param($before,$after,$names) Assert-RideMachineFontRegistryUnrelated $before $after $names} $Before.Registry $Snapshot.Registry @($Selection.RegistryName)
}

function Assert-RideFontAcceptanceRecords {
  param([string]$StateDirectory,[string]$RunId)
  foreach($part in @('intent','applied')){
    $path=Join-Path $StateDirectory ($RunId+'.fonts.'+$part+'.json')
    $bytes=Read-RidePrivateFileBytes -Path $path -Scope Machine -MaximumBytes 16777216
    $record=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
    if($record.Kind -cne 'MachineFontLifecycle' -or $record.RunId -cne $RunId -or $record.Part -cne $part){throw 'Machine recovery record identity differs.'}
  }
}

function Assert-RideFontAcceptanceResult {
  param($Result,[string]$Status,[bool]$RunRequired=$false)
  if($null -eq $Result -or $Result.SchemaVersion -ne 1 -or $Result.Status -cne $Status -or ($RunRequired -and $Result.RunId -cnotmatch '^[a-f0-9]{32}$')){throw 'Font lifecycle result differs.'}
}

function Save-RideFontAcceptanceReport {
  param([string]$Path,$Report)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Report|ConvertTo-Json -Depth 10).Replace("`r`n","`n")+"`n")
  $stream=New-RidePrivateFileStream -Path $Path -Scope Machine
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

function Invoke-RideFontAcceptance {
  <#
  .SYNOPSIS
    Test install, native enumeration, owned removal and both font restores.
  .PARAMETER RunId
    Correlated request ID matching RIDE_TEST_RUN_ID.
  .PARAMETER ManifestPath
    Reviewed hash-pinned font/license PSD1; real fonts, not name-table fixtures.
  .PARAMETER ExpectedComputerName
    Exact disposable guest name.
  .PARAMETER ExpectedBuild
    Exact guest build.
  .PARAMETER ExpectedEditionId
    Exact guest edition.
  .PARAMETER EvidenceRoot
    Existing local directory; a new RunId child retains private evidence.
  .PARAMETER DisposableVm
    Required disposable-target attestation, in addition to native checks.
  .EXAMPLE
    Invoke-RideFontAcceptance -RunId '<request-id>' -ManifestPath C:\Inputs\fonts.psd1 -ExpectedComputerName '<vm>' -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -EvidenceRoot C:\RIDE\Evidence -DisposableVm -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Preview, NotRun, Passed or Failed result.
  .NOTES
    Passed covers current-session lifecycle only. No reboot or cross-session claim.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidatePattern('(?-i)^[a-f0-9]{32}$')][string]$RunId,
    [Parameter(Mandatory)][string]$ManifestPath,[Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][string]$ExpectedBuild,[Parameter(Mandatory)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][string]$EvidenceRoot,[switch]$DisposableVm)
  $context=Get-RideFontAcceptanceContext
  if(-not $DisposableVm -or $context.GuestMarker -cne '1' -or $context.IntegrationMarker -cne '1' -or $context.RunMarker -cne $RunId -or $context.Manufacturer -cne 'Microsoft Corporation' -or $context.Model -cne 'Virtual Machine'){throw 'Font acceptance requires a correlated disposable Hyper-V guest.'}
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Font acceptance target differs.'}
  & (Get-Module RIDE.MachineFonts) {param($context) Assert-RideMachineFontContext $context $null $false} $context
  & (Get-Module RIDE.MachineFonts) {param($path) Assert-RideMachineFontStateDirectory $path} $EvidenceRoot
  $directory=Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $RunId
  if(Test-Path -LiteralPath $directory){throw 'Acceptance evidence already exists; use a new request ID.'}
  $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='MachineFontAcceptance';RunId=$RunId;RecordedAtUtc=[DateTime]::UtcNow.ToString('o');Status='NotRun';Reason=$null;Stage='Preflight';NativeAcceptancePassed=$false;CrossSessionAcceptancePassed=$false;RestartAcceptancePassed=$false;RecoveryRequired=$false;ComputerName=$context.ComputerName;Build=$context.Build;EditionId=$context.EditionId;SessionId=$context.SessionId;Checks=@();LifecycleRuns=@();StateRunIds=@();EvidenceDirectory=$null;Selection=@()}
  if(-not $context.Administrator -and -not $WhatIfPreference){$report.Reason='ExistingElevationRequired';return $report}
  $selection=@(Read-RideFontAcceptanceSelection $ManifestPath);$report.Selection=$selection
  $before=Get-RideFontAcceptanceSnapshot $context $selection
  if(@($before.Files|Where-Object {$_.File.Exists -or $null -ne $_.Registration -or @($_.Aliases).Count}).Count -or @($before.NativeNames).Count){$report.Reason='SelectedFontsMustBeInitiallyAbsent';return $report}
  if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Run selected machine-font install/repeat/remove/restore and retain private evidence')){$report.Status='Preview';return $report}
  $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
  $report.EvidenceDirectory=$directory;$state=Join-Path $directory 'state';$null=New-Item -ItemType Directory -Path $state -ErrorAction Stop
  Save-RideFontAcceptanceReport (Join-Path $directory 'before.json') $before
  $checks=[Collections.Generic.List[string]]::new();$runs=[Collections.Generic.List[object]]::new()
  $parameters=@{ManifestPath=$ManifestPath;StateDirectory=$state;ExpectedComputerName=$ExpectedComputerName;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;AllowCandidate=$true;Confirm=$false}
  try {
    $report.Stage='Preview';$null=Install-RideMachineFonts @parameters -WhatIf
    if(@(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideFontAcceptanceEqual $before (Get-RideFontAcceptanceSnapshot $context $selection))){throw 'Preview changed state.'}
    $checks.Add('PreviewNoChanges')
    $report.Stage='Install';$installed=Install-RideMachineFonts @parameters
    Assert-RideFontAcceptanceResult $installed Applied $true
    $runs.Add([pscustomobject]@{Action='Install';RunId=$installed.RunId;Restored=$false})
    Assert-RideFontAcceptanceRecords $state $installed.RunId
    $after=Get-RideFontAcceptanceSnapshot $context $selection;Assert-RideFontAcceptanceInstalled $after $before $selection
    Save-RideFontAcceptanceReport (Join-Path $directory 'installed.json') $after
    $checks.Add('InstalledNativeNamesFilesRegistrationAndPrivateState')
    $report.Stage='Repeat';$count=@(Get-ChildItem -LiteralPath $state -File).Count
    Assert-RideFontAcceptanceResult (Install-RideMachineFonts @parameters) AlreadyDesired
    if($count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideFontAcceptanceEqual $after (Get-RideFontAcceptanceSnapshot $context $selection))){throw 'Repeat changed state.'}
    $checks.Add('RepeatNoChanges')
    $report.Stage='Remove';$removed=Remove-RideMachineFonts -OwnerRunId $installed.RunId -StateDirectory $state -AllowCandidate -Confirm:$false
    Assert-RideFontAcceptanceResult $removed Applied $true
    $runs.Add([pscustomobject]@{Action='Remove';RunId=$removed.RunId;Restored=$false})
    Assert-RideFontAcceptanceRecords $state $removed.RunId
    if(-not (Test-RideFontAcceptanceEqual $before (Get-RideFontAcceptanceSnapshot $context $selection))){throw 'Removal did not restore absent files, registration and native enumeration.'}
    $checks.Add('RemovedToInitialState')
    $report.Stage='RestoreRemoval'
    Assert-RideFontAcceptanceResult (Restore-RideMachineFontRun -RunId $removed.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) Restored
    if(-not (Test-RideFontAcceptanceEqual $after (Get-RideFontAcceptanceSnapshot $context $selection))){throw 'Removal recovery differs from captured installed state.'}
    $runs[1].Restored=$true;$checks.Add('InstalledBytesPermissionsMetadataAndNativeNamesRestored')
    $report.Stage='RestoreInitial'
    Assert-RideFontAcceptanceResult (Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) Restored
    if(-not (Test-RideFontAcceptanceEqual $before (Get-RideFontAcceptanceSnapshot $context $selection))){throw 'Initial state was not restored.'}
    $runs[0].Restored=$true;$checks.Add('InitialStateRestored')
    Assert-RideFontAcceptanceResult (Restore-RideMachineFontRun -RunId $installed.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) AlreadyRestored
    if(-not (Test-RideFontAcceptanceEqual $before (Get-RideFontAcceptanceSnapshot $context $selection))){throw 'Repeated restore changed state.'}
    $checks.Add('RepeatedRestoreNoChanges');$report.Stage='Complete';$report.Status='Passed';$report.NativeAcceptancePassed=$true
  }catch{$report.Status='Failed';$report.Reason='AcceptanceStepFailed';$report.RecoveryRequired=$true}
  $report.Checks=$checks.ToArray();$report.LifecycleRuns=$runs.ToArray()
  $report.StateRunIds=@(Get-ChildItem -LiteralPath $state -Filter '*.fonts.intent.json' -File|Select-Object -First 256|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.fonts\.intent\.json$'){$Matches[1]}})
  Save-RideFontAcceptanceReport (Join-Path $directory 'result.json') $report
  $report
}
Export-ModuleMember -Function Invoke-RideFontAcceptance
