<#
.SYNOPSIS
  Exercise first-logon wallpaper lifecycle in two retained disposable-guest phases.
.DESCRIPTION
  Apply verifies preview/apply/repeat and leaves the image active for independent
  visual verification. Restore verifies recovery/repeat and leaves the guest for
  visual recovery verification. Neither phase claims a visible-image pass.
  Capture an initialized control user before Apply. Between phases, verify first
  sign-in, other theme defaults and later user choice using an owned disposable
  account. Export those observations and remove only that owned account/profile
  before Restore; profile inventory drift prevents automatic asset removal.
  Account creation, interactive sign-in and profile deletion are separate steps.
.NOTES
  Native Windows PowerShell 5.1/7; candidate Windows 11 x64 Enterprise/Education.
  Requires existing elevation and correlated Hyper-V guest markers. No UAC,
  sign-out, reboot, checkpoint reset or automatic failed-run cleanup is launched.
  Version: 0.1.1. Changelog: Preserve bounded native failure detail.
.LINK
  ../../docs/image-personalization.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.DefaultWallpaper.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.ImageFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop

function Get-RideDefaultWallpaperAcceptanceContext {
  $context=& (Get-Module RIDE.DefaultWallpaper) {Get-RideDefaultWallpaperContext}
  $context|Add-Member -NotePropertyName RunMarker -NotePropertyValue $env:RIDE_TEST_RUN_ID
  $context
}
function Read-RideDefaultWallpaperAcceptanceSource {
  param([string]$Path)
  $fixture=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '../fixtures/default-wallpaper.acceptance.psd1')
  if($fixture.SchemaVersion -ne 1){throw 'Unknown image acceptance fixture.'}
  $source=Get-RidePngSource -Path $Path -ExpectedSha256 $fixture.Sha256
  if($source.Bytes -ne $fixture.Bytes -or $source.Width -ne $fixture.Width -or $source.Height -ne $fixture.Height){throw 'Selected first-logon wallpaper metadata differs.'}
  $source
}
function Assert-RideDefaultWallpaperAcceptanceRoot {
  param([string]$Path)
  $full=& (Get-Module RIDE.DefaultWallpaper) {param($p) Resolve-RideDefaultWallpaperDirectory $p} $Path
  $acl=Get-Acl -LiteralPath $full
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Acceptance evidence root requires administrator/SYSTEM ownership.'}
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership') -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Acceptance evidence root grants modification to another principal.'}
  }
  $full
}
function New-RideDefaultWallpaperAcceptanceDirectorySecurity {
  param([bool]$PublicRead)
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  $principals=@('S-1-5-32-544','S-1-5-18');if($PublicRead){$principals+=@('S-1-5-32-545')}
  foreach($sid in $principals){
    $rights=if($sid -ceq 'S-1-5-32-545'){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
  }
  $acl
}
function New-RideDefaultWallpaperAcceptanceDirectory {
  param([string]$Path,[bool]$PublicRead)
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $Path
  if(Test-Path -LiteralPath $Path){throw 'Acceptance directory already exists; it will not be adopted.'}
  $acl=New-RideDefaultWallpaperAcceptanceDirectorySecurity $PublicRead
  $directory=[IO.DirectoryInfo]::new($Path)
  if($PSVersionTable.PSEdition -eq 'Desktop'){$directory.Create($acl)}else{[IO.FileSystemAclExtensions]::Create($directory,$acl)}
  $actual=Get-Acl -LiteralPath $Path
  $expectedRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.InheritanceFlags,$_.PropagationFlags,$_.IsInherited}|Sort-Object)
  $actualRules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.InheritanceFlags,$_.PropagationFlags,$_.IsInherited}|Sort-Object)
  if(-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or ($actualRules -join ';') -cne ($expectedRules -join ';')){throw 'New acceptance directory permissions did not verify.'}
}
function Save-RideDefaultWallpaperAcceptanceRecord {
  param([string]$Path,$Record)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 15 -Compress))
  if($bytes.Length -gt 1048576){throw 'Acceptance record exceeds one MiB.'}
  $stream=New-RidePrivateFileStream -Path $Path -Scope Machine
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Read-RideDefaultWallpaperAcceptanceRecord {
  param([string]$Path)
  $bytes=Read-RidePrivateFileBytes -Path $Path -Scope Machine -MaximumBytes 1048576
  [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
}
function Get-RideDefaultWallpaperAcceptanceSnapshot {
  param([string]$AssetPath,[string]$ThemePath)
  $registry=& (Get-Module RIDE.DefaultWallpaper) {Get-RideDefaultWallpaperRegistry}
  $row=@($registry.Rows|Where-Object Name -IEQ 'ThemeFile')
  $policyValue=$null
  if($row.Count){$policyValue=Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name ThemeFile -ErrorAction Stop}
  $file=if($AssetPath){& (Get-Module RIDE.DefaultWallpaper) {param($p) Get-RideDefaultWallpaperAsset $p} $AssetPath}else{$null}
  $theme=if($ThemePath){& (Get-Module RIDE.DefaultWallpaper) {param($p) Get-RideDefaultWallpaperAsset $p} $ThemePath}else{$null}
  $profiles=@(& (Get-Module RIDE.DefaultWallpaper) {Get-RideDefaultWallpaperProfiles})
  [pscustomobject]@{Registry=$registry;PolicyValue=$policyValue;File=$file;Theme=$theme;Profiles=$profiles}
}
function Test-RideDefaultWallpaperAcceptanceEqual {
  param($Left,$Right)
  (ConvertTo-Json -InputObject $Left -Depth 15 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 15 -Compress)
}
function Assert-RideDefaultWallpaperAcceptanceRecords {
  param([string]$StateDirectory,[string]$RunId)
  $intent=& (Get-Module RIDE.DefaultWallpaper) {param($p,$id) Read-RideDefaultWallpaperRun $p $id intent} $StateDirectory $RunId
  $applied=& (Get-Module RIDE.DefaultWallpaper) {param($p,$id) Read-RideDefaultWallpaperRun $p $id applied} $StateDirectory $RunId
  & (Get-Module RIDE.DefaultWallpaper) {param($i,$a) Assert-RideDefaultWallpaperRun $i $a} $intent $applied
}
function Assert-RideDefaultWallpaperAcceptanceResult {
  param($Result,[string[]]$Status,[bool]$RunRequired=$false)
  if($null -eq $Result -or $Result.SchemaVersion -ne 1 -or $Result.Status -cnotin $Status -or $Result.NativeVisualAcceptance -ne $false -or ($RunRequired -and $Result.RunId -cnotmatch '^[a-f0-9]{32}$')){throw 'Default-image lifecycle result differs.'}
}

function Invoke-RideDefaultWallpaperAcceptance {
  <#
  .SYNOPSIS
    Run an apply or restore phase and retain the guest for separate visual checks.
  .PARAMETER Phase
    Apply previews/applies/repeats. Restore previews/restores/repeats the saved run.
  .PARAMETER RunId
    Correlated request ID matching RIDE_TEST_RUN_ID; reuse it for Restore.
  .PARAMETER SourcePath
    Apply-only path to the pinned fedora_sharpened_4k.png input. Omit for Restore.
  .PARAMETER ExpectedComputerName
    Exact disposable guest computer name, checked in both phases.
  .PARAMETER ExpectedBuild
    Exact Windows 11 build, checked in both phases.
  .PARAMETER ExpectedEditionId
    Exact Enterprise/Education candidate edition, checked in both phases.
  .PARAMETER EvidenceRoot
    Existing administrator-controlled local evidence parent. A new RunId child is
    created only by Apply; Restore reads its private records and adds an attempt.
  .PARAMETER DisposableVm
    Required explicit disposable-target attestation; it cannot bypass target checks.
  .EXAMPLE
    Invoke-RideDefaultWallpaperAcceptance -Phase Apply -RunId '<request-id>' -SourcePath C:\Inputs\fedora_sharpened_4k.png -ExpectedComputerName RIDE-Test -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -EvidenceRoot C:\RIDE\Evidence -DisposableVm -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 phased result. NativeLifecycleAcceptancePassed is true only after
    verified machine policy/assets/profile-inventory recovery. NativeFirstLogonAcceptancePassed,
    NativeVisualAcceptancePassed and NativeAcceptancePassed
    remain false until independent visual evidence is evaluated outside this runner.
  .NOTES
    No automatic checkpoint reset or failed-run cleanup. Export private evidence
    and verify visible recovery before resetting the disposable guest.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidateSet('Apply','Restore')][string]$Phase,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,[string]$SourcePath,
    [Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateSet('Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId,
    [Parameter(Mandatory)][string]$EvidenceRoot,[switch]$DisposableVm)
  $Phase=if($Phase -ieq 'Apply'){'Apply'}else{'Restore'}
  $context=Get-RideDefaultWallpaperAcceptanceContext
  if(-not $DisposableVm -or $context.RunMarker -cne $RunId){throw 'Default-image acceptance requires a correlated disposable guest request.'}
  & (Get-Module RIDE.DefaultWallpaper) {param($c,$mutation) Assert-RideDefaultWallpaperContext $c $null $mutation} $context (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Default-image acceptance target differs.'}
  if(($Phase -ceq 'Apply' -and -not $SourcePath) -or ($Phase -ceq 'Restore' -and $SourcePath)){throw 'SourcePath is required only for Apply and must be omitted for Restore.'}
  $EvidenceRoot=Assert-RideDefaultWallpaperAcceptanceRoot $EvidenceRoot
  $directory=Join-Path $EvidenceRoot $RunId;$state=Join-Path $directory 'state';$assets=Join-Path $directory 'images'
  # Validate the eventual owned path before creating any evidence directories.
  $null=& (Get-Module RIDE.DefaultWallpaper) {param($p) New-RideDefaultWallpaperTheme $p} (Join-Path $assets (('0'*32)+'.png'))
  $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='DefaultWallpaperAcceptance';RunId=$RunId;Phase=$Phase;RecordedAtUtc=[datetime]::UtcNow.ToString('o');Status='NotRun';Stage='Preflight';Reason=$null;Error=$null;Context=$context;NativeLifecycleAcceptancePassed=$false;NativeVisualAcceptancePassed=$false;NativeFirstLogonAcceptancePassed=$false;NativeAcceptancePassed=$false;RecoveryRequired=$false;LifecycleRunId=$null;AssetPath=$null;ThemePath=$null;SourceSha256=$null;Checks=@();StateRunIds=@();EvidenceDirectory=$directory}
  $source=$null;$prepared=$null;$before=$null
  if($Phase -ceq 'Apply'){
    if(Test-Path -LiteralPath $directory){throw 'Acceptance request directory already exists; retain it and use a new request ID.'}
    $source=Read-RideDefaultWallpaperAcceptanceSource $SourcePath;$report.SourceSha256=$source.Sha256
    $before=Get-RideDefaultWallpaperAcceptanceSnapshot
  }else{
    $prepared=Read-RideDefaultWallpaperAcceptanceRecord (Join-Path $directory 'apply.json')
    if($prepared.SchemaVersion -ne 1 -or $prepared.Kind -cne 'DefaultWallpaperAcceptance' -or $prepared.RunId -cne $RunId -or $prepared.Phase -cne 'Apply' -or $prepared.Status -cne 'AwaitingVisualVerification' -or $prepared.LifecycleRunId -cnotmatch '^[a-f0-9]{32}$' -or ($prepared.Checks -join ';') -cne 'PreviewNoChanges;AppliedPolicyThemeImageAndPrivateState;RepeatNoChanges' -or $prepared.AssetPath -cne (Join-Path $assets ($prepared.LifecycleRunId+'.png')) -or $prepared.ThemePath -cne (Join-Path $assets ($prepared.LifecycleRunId+'.theme'))){throw 'Completed apply-phase evidence is unavailable or mismatched.'}
    & (Get-Module RIDE.DefaultWallpaper) {param($c,$e) Assert-RideDefaultWallpaperContext $c $e $false} $context $prepared.Context
    $before=Read-RideDefaultWallpaperAcceptanceRecord (Join-Path $directory 'before.json')
    $report.LifecycleRunId=$prepared.LifecycleRunId;$report.AssetPath=$prepared.AssetPath;$report.ThemePath=$prepared.ThemePath;$report.SourceSha256=$prepared.SourceSha256
    Assert-RideDefaultWallpaperAcceptanceRecords $state $prepared.LifecycleRunId
  }
  if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,"Run first-logon wallpaper $Phase phase and retain the guest for visual verification")){$report.Status='Preview';return $report}
  if($Phase -ceq 'Apply'){
    New-RideDefaultWallpaperAcceptanceDirectory $directory $true
    New-RideDefaultWallpaperAcceptanceDirectory $assets $true
    New-RideDefaultWallpaperAcceptanceDirectory $state $false
    Save-RideDefaultWallpaperAcceptanceRecord (Join-Path $directory 'before.json') $before
  }
  $checks=[Collections.Generic.List[string]]::new()
  try{
    if($Phase -ceq 'Apply'){
      $parameters=@{Path=$source.Path;ExpectedSha256=$source.Sha256;AssetDirectory=$assets;StateDirectory=$state;ExpectedComputerName=$ExpectedComputerName;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;AllowCandidate=$true;Confirm=$false}
      $report.Stage='Preview';$preview=Set-RideDefaultWallpaperImage @parameters -WhatIf
      Assert-RideDefaultWallpaperAcceptanceResult $preview @('Preview')
      if(@(Get-ChildItem -LiteralPath $state -File).Count -or @(Get-ChildItem -LiteralPath $assets -Force).Count -or -not (Test-RideDefaultWallpaperAcceptanceEqual $before (Get-RideDefaultWallpaperAcceptanceSnapshot))){throw 'Preview changed state.'}
      $checks.Add('PreviewNoChanges');$report.Stage='Apply';$report.RecoveryRequired=$true
      $result=Set-RideDefaultWallpaperImage @parameters
      Assert-RideDefaultWallpaperAcceptanceResult $result @('Applied') $true
      $report.LifecycleRunId=$result.RunId;$report.AssetPath=$result.AssetPath;$report.ThemePath=$result.ThemePath
      if($result.AssetPath -cne (Join-Path $assets ($result.RunId+'.png')) -or $result.ThemePath -cne (Join-Path $assets ($result.RunId+'.theme'))){throw 'Unexpected run-owned image path.'}
      Assert-RideDefaultWallpaperAcceptanceRecords $state $result.RunId
      $after=Get-RideDefaultWallpaperAcceptanceSnapshot $result.AssetPath $result.ThemePath
      if($after.PolicyValue -cne $result.ThemePath -or $null -eq $after.File -or $after.File.Sha256 -cne $source.Sha256 -or $after.File.Bytes -ne $source.Bytes){throw 'Native image/policy readback differs.'}
      $themeSource=& (Get-Module RIDE.DefaultWallpaper) {param($p) New-RideDefaultWallpaperTheme $p} $result.AssetPath
      if($null -eq $after.Theme -or $after.Theme.Sha256 -cne $themeSource.Sha256 -or $after.Theme.Bytes -ne $themeSource.Bytes -or -not (Test-RideDefaultWallpaperAcceptanceEqual @($before.Profiles) @($after.Profiles))){throw 'Native theme or profile readback differs.'}
      Save-RideDefaultWallpaperAcceptanceRecord (Join-Path $directory 'applied-snapshot.json') $after
      $checks.Add('AppliedPolicyThemeImageAndPrivateState');$report.Stage='Repeat';$count=@(Get-ChildItem -LiteralPath $state -File).Count
      $repeat=Set-RideDefaultWallpaperImage @parameters;Assert-RideDefaultWallpaperAcceptanceResult $repeat @('AlreadyDesired') $true
      if($repeat.RunId -cne $result.RunId -or $count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideDefaultWallpaperAcceptanceEqual $after (Get-RideDefaultWallpaperAcceptanceSnapshot $result.AssetPath $result.ThemePath))){throw 'Repeat changed state or ownership.'}
      $checks.Add('RepeatNoChanges');$report.Status='AwaitingVisualVerification';$report.Stage='RetainedForVisualCheck'
    }else{
      $report.RecoveryRequired=$true;$report.Stage='RestorePreview'
      $current=Get-RideDefaultWallpaperAcceptanceSnapshot $prepared.AssetPath $prepared.ThemePath;$count=@(Get-ChildItem -LiteralPath $state -File).Count
      if(-not (Test-RideDefaultWallpaperAcceptanceEqual @($before.Profiles) @($current.Profiles))){throw 'Profile inventory differs; retain the assets and inspect owned first-logon consumers before recovery.'}
      $preview=Restore-RideDefaultWallpaperRun -RunId $prepared.LifecycleRunId -StateDirectory $state -WhatIf
      Assert-RideDefaultWallpaperAcceptanceResult $preview @('Preview','AlreadyRestored')
      if($count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideDefaultWallpaperAcceptanceEqual $current (Get-RideDefaultWallpaperAcceptanceSnapshot $prepared.AssetPath $prepared.ThemePath))){throw 'Restore preview changed state.'}
      $checks.Add('RestorePreviewNoChanges');$report.Stage='Restore'
      $result=Restore-RideDefaultWallpaperRun -RunId $prepared.LifecycleRunId -StateDirectory $state -AllowCandidate -Confirm:$false
      Assert-RideDefaultWallpaperAcceptanceResult $result @('Restored','AlreadyRestored') $true
      if($result.RunId -cne $prepared.LifecycleRunId -or -not (Test-RideDefaultWallpaperAcceptanceEqual $before (Get-RideDefaultWallpaperAcceptanceSnapshot $prepared.AssetPath $prepared.ThemePath))){throw 'Captured image/policy state did not recover.'}
      $checks.Add('CapturedStateRestored');$report.Stage='RepeatRestore'
      $repeat=Restore-RideDefaultWallpaperRun -RunId $prepared.LifecycleRunId -StateDirectory $state -AllowCandidate -Confirm:$false
      Assert-RideDefaultWallpaperAcceptanceResult $repeat @('AlreadyRestored') $true
      if($repeat.RunId -cne $prepared.LifecycleRunId -or $count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideDefaultWallpaperAcceptanceEqual $before (Get-RideDefaultWallpaperAcceptanceSnapshot $prepared.AssetPath $prepared.ThemePath))){throw 'Repeated restore changed state.'}
      $checks.Add('RepeatedRestoreNoChanges');$report.RecoveryRequired=$false;$report.NativeLifecycleAcceptancePassed=$true;$report.Status='LifecyclePassedVisualPending';$report.Stage='RetainedForVisualRecoveryCheck'
    }
  }catch{$report.Status='Failed';$report.Reason='AcceptanceStepFailed';$report.RecoveryRequired=$true;$message=$_.Exception.Message;$report.Error=$message.Substring(0,[Math]::Min(1000,$message.Length))}
  $report.Checks=$checks.ToArray()
  $report.StateRunIds=@(Get-ChildItem -LiteralPath $state -Filter '*.default-wallpaper.intent.json' -File|Select-Object -First 256|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.default-wallpaper\.intent\.json$'){$Matches[1]}})
  $reportFile=if($Phase -ceq 'Apply'){'apply.json'}else{'restore.'+[guid]::NewGuid().ToString('N')+'.json'}
  Save-RideDefaultWallpaperAcceptanceRecord (Join-Path $directory $reportFile) $report
  $report
}
$script:DefaultWallpaperAcceptanceCompleter={
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{if($fakeBoundParameters.Phase -ine 'Restore' -or -not $fakeBoundParameters.ContainsKey('EvidenceRoot')){return};Get-ChildItem -LiteralPath $fakeBoundParameters.EvidenceRoot -Directory -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^[a-f0-9]{32}$' -and $_.Name.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($_.Name,$_.Name,'ParameterValue','Saved first-logon wallpaper acceptance request')}}}catch{}
}
Register-ArgumentCompleter -CommandName Invoke-RideDefaultWallpaperAcceptance -ParameterName RunId -ScriptBlock $script:DefaultWallpaperAcceptanceCompleter
Export-ModuleMember -Function Invoke-RideDefaultWallpaperAcceptance
