<#
.SYNOPSIS
  Exercise default lock-screen lifecycle in two retained disposable-guest phases.
.DESCRIPTION
  Apply verifies preview/apply/repeat and leaves the image active for independent
  visual verification. Restore verifies recovery/repeat and leaves the guest for
  visual recovery verification. Neither phase claims a visible-image pass.
.NOTES
  Native Windows PowerShell 5.1/7; candidate Windows 11 x64 Enterprise/Education.
  Requires existing elevation and correlated Hyper-V guest markers. No UAC,
  sign-out, reboot, checkpoint reset or automatic failed-run cleanup is launched.
  Version: 0.1.1. Changelog: Retain bounded failure details for native diagnostics.
.LINK
  ../../docs/image-personalization.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.DefaultLockScreen.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.ImageFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop

function Get-RideDefaultLockAcceptanceContext {
  $context=& (Get-Module RIDE.DefaultLockScreen) {Get-RideDefaultLockContext}
  $context|Add-Member -NotePropertyName RunMarker -NotePropertyValue $env:RIDE_TEST_RUN_ID
  $context
}
function Read-RideDefaultLockAcceptanceSource {
  param([string]$Path)
  $fixture=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '../fixtures/default-lock-screen.acceptance.psd1')
  if($fixture.SchemaVersion -ne 1){throw 'Unknown image acceptance fixture.'}
  $source=Get-RidePngSource -Path $Path -ExpectedSha256 $fixture.Sha256
  if($source.Bytes -ne $fixture.Bytes -or $source.Width -ne $fixture.Width -or $source.Height -ne $fixture.Height){throw 'Selected default-image metadata differs.'}
  $source
}
function Assert-RideDefaultLockAcceptanceRoot {
  param([string]$Path)
  $full=& (Get-Module RIDE.DefaultLockScreen) {param($p) Resolve-RideDefaultLockDirectory $p} $Path
  $acl=Get-Acl -LiteralPath $full
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Acceptance evidence root requires administrator/SYSTEM ownership.'}
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership') -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Acceptance evidence root grants modification to another principal.'}
  }
  $full
}
function New-RideDefaultLockAcceptanceDirectorySecurity {
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
function New-RideDefaultLockAcceptanceDirectory {
  param([string]$Path,[bool]$PublicRead)
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $Path
  if(Test-Path -LiteralPath $Path){throw 'Acceptance directory already exists; it will not be adopted.'}
  $acl=New-RideDefaultLockAcceptanceDirectorySecurity $PublicRead
  $directory=[IO.DirectoryInfo]::new($Path)
  if($PSVersionTable.PSEdition -eq 'Desktop'){$directory.Create($acl)}else{[IO.FileSystemAclExtensions]::Create($directory,$acl)}
  $actual=Get-Acl -LiteralPath $Path
  $expectedRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.InheritanceFlags,$_.PropagationFlags,$_.IsInherited}|Sort-Object)
  $actualRules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {'{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value,$_.FileSystemRights,$_.AccessControlType,$_.InheritanceFlags,$_.PropagationFlags,$_.IsInherited}|Sort-Object)
  if(-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or ($actualRules -join ';') -cne ($expectedRules -join ';')){throw 'New acceptance directory permissions did not verify.'}
}
function Save-RideDefaultLockAcceptanceRecord {
  param([string]$Path,$Record)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 15 -Compress))
  if($bytes.Length -gt 1048576){throw 'Acceptance record exceeds one MiB.'}
  $stream=New-RidePrivateFileStream -Path $Path -Scope Machine
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Read-RideDefaultLockAcceptanceRecord {
  param([string]$Path)
  $bytes=Read-RidePrivateFileBytes -Path $Path -Scope Machine -MaximumBytes 1048576
  [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
}
function Get-RideDefaultLockAcceptanceSnapshot {
  param([string]$AssetPath)
  $registry=& (Get-Module RIDE.DefaultLockScreen) {Get-RideDefaultLockRegistry}
  $row=@($registry.Rows|Where-Object Name -IEQ 'LockScreenImage')
  $policyValue=$null
  if($row.Count){$policyValue=Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name LockScreenImage -ErrorAction Stop}
  $file=if($AssetPath){& (Get-Module RIDE.DefaultLockScreen) {param($p) Get-RideDefaultLockAsset $p} $AssetPath}else{$null}
  [pscustomobject]@{Registry=$registry;PolicyValue=$policyValue;File=$file}
}
function Test-RideDefaultLockAcceptanceEqual {
  param($Left,$Right)
  (ConvertTo-Json -InputObject $Left -Depth 15 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 15 -Compress)
}
function Assert-RideDefaultLockAcceptanceRecords {
  param([string]$StateDirectory,[string]$RunId)
  $intent=& (Get-Module RIDE.DefaultLockScreen) {param($p,$id) Read-RideDefaultLockRun $p $id intent} $StateDirectory $RunId
  $applied=& (Get-Module RIDE.DefaultLockScreen) {param($p,$id) Read-RideDefaultLockRun $p $id applied} $StateDirectory $RunId
  & (Get-Module RIDE.DefaultLockScreen) {param($i,$a) Assert-RideDefaultLockRun $i $a} $intent $applied
}
function Assert-RideDefaultLockAcceptanceResult {
  param($Result,[string[]]$Status,[bool]$RunRequired=$false)
  if($null -eq $Result -or $Result.SchemaVersion -ne 1 -or $Result.Status -cnotin $Status -or $Result.NativeVisualAcceptance -ne $false -or ($RunRequired -and $Result.RunId -cnotmatch '^[a-f0-9]{32}$')){throw 'Default-image lifecycle result differs.'}
}

function Invoke-RideDefaultLockAcceptance {
  <#
  .SYNOPSIS
    Run an apply or restore phase and retain the guest for separate visual checks.
  .PARAMETER Phase
    Apply previews/applies/repeats. Restore previews/restores/repeats the saved run.
  .PARAMETER RunId
    Correlated request ID matching RIDE_TEST_RUN_ID; reuse it for Restore.
  .PARAMETER SourcePath
    Apply-only path to the pinned suit_sharpened_4k.png input. Omit for Restore.
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
    Invoke-RideDefaultLockAcceptance -Phase Apply -RunId '<request-id>' -SourcePath C:\Inputs\suit_sharpened_4k.png -ExpectedComputerName RIDE-Test -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -EvidenceRoot C:\RIDE\Evidence -DisposableVm -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 phased result. NativeLifecycleAcceptancePassed is true only after
    verified recovery; NativeVisualAcceptancePassed and NativeAcceptancePassed
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
  $context=Get-RideDefaultLockAcceptanceContext
  if(-not $DisposableVm -or $context.RunMarker -cne $RunId){throw 'Default-image acceptance requires a correlated disposable guest request.'}
  & (Get-Module RIDE.DefaultLockScreen) {param($c,$mutation) Assert-RideDefaultLockContext $c $null $mutation} $context (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Default-image acceptance target differs.'}
  if(($Phase -ceq 'Apply' -and -not $SourcePath) -or ($Phase -ceq 'Restore' -and $SourcePath)){throw 'SourcePath is required only for Apply and must be omitted for Restore.'}
  $EvidenceRoot=Assert-RideDefaultLockAcceptanceRoot $EvidenceRoot
  $directory=Join-Path $EvidenceRoot $RunId;$state=Join-Path $directory 'state';$assets=Join-Path $directory 'images'
  $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='DefaultLockScreenAcceptance';RunId=$RunId;Phase=$Phase;RecordedAtUtc=[datetime]::UtcNow.ToString('o');Status='NotRun';Stage='Preflight';Reason=$null;Error=$null;Context=$context;NativeLifecycleAcceptancePassed=$false;NativeVisualAcceptancePassed=$false;NativeAcceptancePassed=$false;RecoveryRequired=$false;LifecycleRunId=$null;AssetPath=$null;SourceSha256=$null;Checks=@();StateRunIds=@();EvidenceDirectory=$directory}
  $source=$null;$prepared=$null;$before=$null
  if($Phase -ceq 'Apply'){
    if(Test-Path -LiteralPath $directory){throw 'Acceptance request directory already exists; retain it and use a new request ID.'}
    $source=Read-RideDefaultLockAcceptanceSource $SourcePath;$report.SourceSha256=$source.Sha256
    $before=Get-RideDefaultLockAcceptanceSnapshot
  }else{
    $prepared=Read-RideDefaultLockAcceptanceRecord (Join-Path $directory 'apply.json')
    if($prepared.SchemaVersion -ne 1 -or $prepared.Kind -cne 'DefaultLockScreenAcceptance' -or $prepared.RunId -cne $RunId -or $prepared.Phase -cne 'Apply' -or $prepared.Status -cne 'AwaitingVisualVerification' -or $prepared.LifecycleRunId -cnotmatch '^[a-f0-9]{32}$' -or ($prepared.Checks -join ';') -cne 'PreviewNoChanges;AppliedPolicyImageAndPrivateState;RepeatNoChanges' -or $prepared.AssetPath -cne (Join-Path $assets ($prepared.LifecycleRunId+'.png'))){throw 'Completed apply-phase evidence is unavailable or mismatched.'}
    & (Get-Module RIDE.DefaultLockScreen) {param($c,$e) Assert-RideDefaultLockContext $c $e $false} $context $prepared.Context
    $before=Read-RideDefaultLockAcceptanceRecord (Join-Path $directory 'before.json')
    $report.LifecycleRunId=$prepared.LifecycleRunId;$report.AssetPath=$prepared.AssetPath;$report.SourceSha256=$prepared.SourceSha256
    Assert-RideDefaultLockAcceptanceRecords $state $prepared.LifecycleRunId
  }
  if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,"Run default-image $Phase phase and retain the guest for visual verification")){$report.Status='Preview';return $report}
  if($Phase -ceq 'Apply'){
    New-RideDefaultLockAcceptanceDirectory $directory $true
    New-RideDefaultLockAcceptanceDirectory $assets $true
    New-RideDefaultLockAcceptanceDirectory $state $false
    Save-RideDefaultLockAcceptanceRecord (Join-Path $directory 'before.json') $before
  }
  $checks=[Collections.Generic.List[string]]::new()
  try{
    if($Phase -ceq 'Apply'){
      $parameters=@{Path=$source.Path;ExpectedSha256=$source.Sha256;AssetDirectory=$assets;StateDirectory=$state;ExpectedComputerName=$ExpectedComputerName;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;AllowCandidate=$true;Confirm=$false}
      $report.Stage='Preview';$preview=Set-RideDefaultLockScreenImage @parameters -WhatIf
      Assert-RideDefaultLockAcceptanceResult $preview @('Preview')
      if(@(Get-ChildItem -LiteralPath $state -File).Count -or @(Get-ChildItem -LiteralPath $assets -Force).Count -or -not (Test-RideDefaultLockAcceptanceEqual $before (Get-RideDefaultLockAcceptanceSnapshot))){throw 'Preview changed state.'}
      $checks.Add('PreviewNoChanges');$report.Stage='Apply';$report.RecoveryRequired=$true
      $result=Set-RideDefaultLockScreenImage @parameters
      Assert-RideDefaultLockAcceptanceResult $result @('Applied') $true
      $report.LifecycleRunId=$result.RunId;$report.AssetPath=$result.AssetPath
      if($result.AssetPath -cne (Join-Path $assets ($result.RunId+'.png'))){throw 'Unexpected run-owned image path.'}
      Assert-RideDefaultLockAcceptanceRecords $state $result.RunId
      $after=Get-RideDefaultLockAcceptanceSnapshot $result.AssetPath
      if($after.PolicyValue -cne $result.AssetPath -or $null -eq $after.File -or $after.File.Sha256 -cne $source.Sha256 -or $after.File.Bytes -ne $source.Bytes){throw 'Native image/policy readback differs.'}
      Save-RideDefaultLockAcceptanceRecord (Join-Path $directory 'applied-snapshot.json') $after
      $checks.Add('AppliedPolicyImageAndPrivateState');$report.Stage='Repeat';$count=@(Get-ChildItem -LiteralPath $state -File).Count
      $repeat=Set-RideDefaultLockScreenImage @parameters;Assert-RideDefaultLockAcceptanceResult $repeat @('AlreadyDesired') $true
      if($repeat.RunId -cne $result.RunId -or $count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideDefaultLockAcceptanceEqual $after (Get-RideDefaultLockAcceptanceSnapshot $result.AssetPath))){throw 'Repeat changed state or ownership.'}
      $checks.Add('RepeatNoChanges');$report.Status='AwaitingVisualVerification';$report.Stage='RetainedForVisualCheck'
    }else{
      $report.RecoveryRequired=$true;$report.Stage='RestorePreview'
      $current=Get-RideDefaultLockAcceptanceSnapshot $prepared.AssetPath;$count=@(Get-ChildItem -LiteralPath $state -File).Count
      $preview=Restore-RideDefaultLockScreenRun -RunId $prepared.LifecycleRunId -StateDirectory $state -WhatIf
      Assert-RideDefaultLockAcceptanceResult $preview @('Preview','AlreadyRestored')
      if($count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideDefaultLockAcceptanceEqual $current (Get-RideDefaultLockAcceptanceSnapshot $prepared.AssetPath))){throw 'Restore preview changed state.'}
      $checks.Add('RestorePreviewNoChanges');$report.Stage='Restore'
      $result=Restore-RideDefaultLockScreenRun -RunId $prepared.LifecycleRunId -StateDirectory $state -AllowCandidate -Confirm:$false
      Assert-RideDefaultLockAcceptanceResult $result @('Restored','AlreadyRestored') $true
      if($result.RunId -cne $prepared.LifecycleRunId -or -not (Test-RideDefaultLockAcceptanceEqual $before (Get-RideDefaultLockAcceptanceSnapshot $prepared.AssetPath))){throw 'Captured image/policy state did not recover.'}
      $checks.Add('CapturedStateRestored');$report.Stage='RepeatRestore'
      $repeat=Restore-RideDefaultLockScreenRun -RunId $prepared.LifecycleRunId -StateDirectory $state -AllowCandidate -Confirm:$false
      Assert-RideDefaultLockAcceptanceResult $repeat @('AlreadyRestored') $true
      if($repeat.RunId -cne $prepared.LifecycleRunId -or $count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideDefaultLockAcceptanceEqual $before (Get-RideDefaultLockAcceptanceSnapshot $prepared.AssetPath))){throw 'Repeated restore changed state.'}
      $checks.Add('RepeatedRestoreNoChanges');$report.RecoveryRequired=$false;$report.NativeLifecycleAcceptancePassed=$true;$report.Status='LifecyclePassedVisualPending';$report.Stage='RetainedForVisualRecoveryCheck'
    }
  }catch{$report.Status='Failed';$report.Reason='AcceptanceStepFailed';$report.RecoveryRequired=$true;$message=$_.Exception.Message;$report.Error=$message.Substring(0,[Math]::Min(1000,$message.Length))}
  $report.Checks=$checks.ToArray()
  $report.StateRunIds=@(Get-ChildItem -LiteralPath $state -Filter '*.default-lock.intent.json' -File|Select-Object -First 256|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.default-lock\.intent\.json$'){$Matches[1]}})
  $reportFile=if($Phase -ceq 'Apply'){'apply.json'}else{'restore.'+[guid]::NewGuid().ToString('N')+'.json'}
  Save-RideDefaultLockAcceptanceRecord (Join-Path $directory $reportFile) $report
  $report
}
$script:DefaultLockAcceptanceCompleter={
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{if($fakeBoundParameters.Phase -cne 'Restore' -or -not $fakeBoundParameters.ContainsKey('EvidenceRoot')){return};Get-ChildItem -LiteralPath $fakeBoundParameters.EvidenceRoot -Directory -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^[a-f0-9]{32}$' -and $_.Name.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($_.Name,$_.Name,'ParameterValue','Saved default-image acceptance request')}}}catch{}
}
Register-ArgumentCompleter -CommandName Invoke-RideDefaultLockAcceptance -ParameterName RunId -ScriptBlock $script:DefaultLockAcceptanceCompleter
Export-ModuleMember -Function Invoke-RideDefaultLockAcceptance
