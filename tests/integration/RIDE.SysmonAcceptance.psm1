<#
.SYNOPSIS
  Test all three pinned Sysmon XML configurations in a disposable Windows guest.
.DESCRIPTION
  Verifies explicit apply, unchanged repeat and captured baseline restore for
  each selected source. Requires a known XML baseline and existing Sysmon service.
  Stops on failure and retains private evidence; does not reset the checkpoint.
.NOTES
  Compatibility: Native PowerShell 5.1 and 7; candidate Windows 11 x64.
  Prerequisites: Existing elevation and correlated disposable Hyper-V guest.
  Recovery: Inspect retained run IDs; no automatic cleanup of incomplete runs.
  Version: 0.1.1. Changelog: Retain failure location without XML or exception text.
.LINK
  ../../docs/sysmon-configuration.md
#>
$ErrorActionPreference='Stop'
function Get-RideSysmonAcceptanceFailureLocation {
  param([Management.Automation.ErrorRecord]$Record)
  # Exception text can contain configuration data; expose only source location.
  [pscustomobject]@{Script=[IO.Path]::GetFileName($Record.InvocationInfo.ScriptName);Line=$Record.InvocationInfo.ScriptLineNumber;ExceptionType=$Record.Exception.GetType().FullName;Category=[string]$Record.CategoryInfo.Category}
}
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.SysmonConfiguration.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.CatalogData.psm1') -ErrorAction Stop

function Get-RideSysmonAcceptanceEnvironment {
  $machine=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $windows=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{$admin=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}
  [pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$windows.CurrentBuildNumber;EditionId=[string]$windows.EditionID;InstallationType=[string]$windows.InstallationType;NativeProcess=[Environment]::Is64BitProcess;Architecture=$env:PROCESSOR_ARCHITECTURE;Administrator=$admin;Manufacturer=$machine.Manufacturer;Model=$machine.Model;GuestMarker=$env:RIDE_TEST_GUEST;IntegrationMarker=$env:RIDE_INTEGRATION_VM;RunMarker=$env:RIDE_TEST_RUN_ID}
}

function Assert-RideSysmonAcceptanceGuest {
  param($Context,[string]$RunId,[string]$ComputerName,[string]$Build,[string]$EditionId,[bool]$DisposableVm)
  if(-not $DisposableVm -or $Context.GuestMarker -cne '1' -or $Context.IntegrationMarker -cne '1' -or $Context.RunMarker -cne $RunId -or $Context.Manufacturer -cne 'Microsoft Corporation' -or $Context.Model -cne 'Virtual Machine'){throw 'Sysmon acceptance requires a correlated disposable Hyper-V guest.'}
  if($Context.ComputerName -cne $ComputerName -or $Context.Build -cne $Build -or $Context.EditionId -cne $EditionId){throw 'Sysmon acceptance target differs.'}
  & (Get-Module RIDE.SysmonConfiguration) {param($context) Assert-RideSysmonConfigurationContext $context $null $false} $Context
}

function Read-RideSysmonAcceptanceSources {
  param([string]$InputDirectory)
  & (Get-Module RIDE.SysmonConfiguration) {param($path) Assert-RideSysmonStateDirectory $path} $InputDirectory
  $fixture=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '../fixtures/sysmon-configurations.acceptance.psd1')
  $catalog=Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../../catalog/operations.psd1')
  if($fixture.SchemaVersion -ne 1 -or @($fixture.Configurations).Count -ne 3 -or @($fixture.Configurations.ArtifactId|Sort-Object -Unique).Count -ne 3){throw 'The reviewed three-profile fixture is incomplete.'}
  $license=Join-Path $InputDirectory $fixture.License.Path
  $null=& (Get-Module RIDE.PrivateFiles) {param($path) Resolve-RidePrivateFilePath $path} $license
  if((Get-Item -LiteralPath $license).Length -gt 1048576 -or (Get-FileHash -LiteralPath $license).Hash -cne $fixture.License.Sha256){throw 'Retained Sysmon configuration license differs.'}
  $sources=@(foreach($item in $fixture.Configurations){
    $operation=@($catalog.Operations|Where-Object ArtifactId -CEQ $item.ArtifactId)
    if($operation.Count -ne 1 -or $operation[0].ReleaseTag -cne $fixture.ReleaseTag -or $operation[0].TargetSysmonVersion -cne $fixture.TargetSysmonVersion -or $operation[0].AssetName -cne [IO.Path]::GetFileName($item.Path)){throw 'Selected Sysmon fixture and catalog identity differ.'}
    $path=Join-Path $InputDirectory $item.Path
    $source=& (Get-Module RIDE.SysmonConfiguration) {param($path,$sha) Read-RideSysmonSource $path $sha} $path $item.Sha256
    [pscustomobject]@{ArtifactId=$item.ArtifactId;Path=$source.Path;Sha256=$source.Sha256;Bytes=$source.Bytes.Length}
  })
  [pscustomobject]@{ReleaseTag=$fixture.ReleaseTag;TargetSysmonVersion=$fixture.TargetSysmonVersion;LicenseSha256=$fixture.License.Sha256;Configurations=$sources}
}

function Get-RideSysmonAcceptanceSnapshot {
  param([string]$ExecutablePath,[string]$ExecutableSha256,[string]$SysmonVersion)
  $context=& (Get-Module RIDE.SysmonConfiguration) {param($path,$sha,$version) Get-RideSysmonConfigurationContext $path $sha $version} $ExecutablePath $ExecutableSha256 $SysmonVersion
  $configuration=& (Get-Module RIDE.SysmonConfiguration) {Get-RideSysmonConfigurationEvent}
  $lastError=0L
  try{$lastError=[long](Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=255} -MaxEvents 1 -ErrorAction Stop).RecordId}
  catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
  [pscustomobject]@{Context=$context;ConfigurationEvent=$configuration;LastErrorRecordId=$lastError}
}

function Test-RideSysmonAcceptanceEqual {
  param($Left,$Right)
  (ConvertTo-Json -InputObject $Left -Depth 8 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 8 -Compress)
}

function Assert-RideSysmonAcceptanceTransition {
  param($Before,$After,[string]$Sha256,[string]$ConfigurationPath)
  if(-not (Test-RideSysmonAcceptanceEqual $Before.Context $After.Context) -or $After.LastErrorRecordId -ne $Before.LastErrorRecordId){throw 'Sysmon service/target changed or a new error event appeared.'}
  if($After.ConfigurationEvent.RecordId -le $Before.ConfigurationEvent.RecordId -or $After.ConfigurationEvent.Sha256 -cne $Sha256 -or $After.ConfigurationEvent.ConfigurationPath -ine $ConfigurationPath){throw 'Sysmon configuration readback did not match the expected transition.'}
}

function Assert-RideSysmonAcceptanceRecords {
  param([string]$StateDirectory,[string]$RunId,[string]$BeforeSha256,[string]$AfterSha256)
  foreach($part in @('intent.json','applied.json')){
    $null=& (Get-Module RIDE.SysmonConfiguration) {param($directory,$id,$part) Read-RideSysmonRecord $directory $id $part} $StateDirectory $RunId $part
  }
  foreach($part in @('before','after')){
    $bytes=Read-RidePrivateFileBytes -Path (Join-Path $StateDirectory ($RunId+'.sysmon.'+$part+'.xml')) -Scope Machine -MaximumBytes 2097152
    $hash=& (Get-Module RIDE.SysmonConfiguration) {param($bytes) Get-RideSysmonHash $bytes} $bytes
    $expected=if($part -ceq 'before'){$BeforeSha256}else{$AfterSha256}
    if($hash -cne $expected){throw 'Captured Sysmon configuration bytes differ.'}
  }
}

function Save-RideSysmonAcceptanceReport {
  param([string]$Path,$Report)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Report|ConvertTo-Json -Depth 12).Replace("`r`n","`n")+"`n")
  $stream=New-RidePrivateFileStream -Path $Path -Scope Machine
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

function Assert-RideSysmonAcceptanceResult {
  param($Result,[string]$Status,[bool]$NeedsRunId=$false)
  if($null -eq $Result -or $Result.SchemaVersion -ne 1 -or $Result.Status -cne $Status -or ($NeedsRunId -and $Result.RunId -cnotmatch '^[a-f0-9]{32}$')){throw 'Sysmon lifecycle result differs.'}
}

function Invoke-RideSysmonAcceptance {
  <#
  .SYNOPSIS
    Apply, repeat and restore all three pinned Sysmon configurations.
  .PARAMETER RunId
    Correlated 32-hex guest request ID matching RIDE_TEST_RUN_ID.
  .PARAMETER InputDirectory
    Directory containing the acquired release layout and retained license.
  .PARAMETER BaselineConfigurationPath
    Original known XML baseline currently loaded by Sysmon.
  .PARAMETER BaselineConfigurationSha256
    Reviewed baseline digest, matching the latest configuration event.
  .PARAMETER ExecutablePath
    Existing Sysmon64 service executable.
  .PARAMETER ExpectedExecutableSha256
    Exact reviewed executable SHA-256.
  .PARAMETER ExpectedSysmonVersion
    Explicit installed candidate version.
  .PARAMETER ExpectedComputerName
    Exact disposable guest name.
  .PARAMETER ExpectedBuild
    Exact guest build.
  .PARAMETER ExpectedEditionId
    Exact guest edition.
  .PARAMETER EvidenceRoot
    Existing local directory for a new request-specific evidence folder.
  .PARAMETER DisposableVm
    Required attestation, additional to native target and marker checks.
  .EXAMPLE
    Get-Help Invoke-RideSysmonAcceptance -Full
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Preview, NotRun, Passed or Failed result; no XML content.
  .NOTES
    Does not install Sysmon, clear logs/archives or reset the guest checkpoint.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidatePattern('(?-i)^[a-f0-9]{32}$')][string]$RunId,
    [Parameter(Mandatory)][string]$InputDirectory,[Parameter(Mandatory)][string]$BaselineConfigurationPath,
    [Parameter(Mandatory)][string]$BaselineConfigurationSha256,[Parameter(Mandatory)][string]$ExecutablePath,
    [Parameter(Mandatory)][string]$ExpectedExecutableSha256,[Parameter(Mandatory)][string]$ExpectedSysmonVersion,
    [Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedBuild,
    [Parameter(Mandatory)][string]$ExpectedEditionId,[Parameter(Mandatory)][string]$EvidenceRoot,[switch]$DisposableVm)
  $environment=Get-RideSysmonAcceptanceEnvironment
  Assert-RideSysmonAcceptanceGuest $environment $RunId $ExpectedComputerName $ExpectedBuild $ExpectedEditionId ([bool]$DisposableVm)
  & (Get-Module RIDE.SysmonConfiguration) {param($path) Assert-RideSysmonStateDirectory $path} $EvidenceRoot
  $directory=Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $RunId
  if(Test-Path -LiteralPath $directory){throw 'Acceptance evidence already exists; use a new request ID.'}
  $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='SysmonConfigurationAcceptance';RunId=$RunId;RecordedAtUtc=[DateTime]::UtcNow.ToString('o');Status='NotRun';Reason=$null;Stage='Preflight';FailureLocation=$null;NativeAcceptancePassed=$false;RecoveryRequired=$false;ComputerName=$ExpectedComputerName;Build=$ExpectedBuild;EditionId=$ExpectedEditionId;SysmonVersion=$ExpectedSysmonVersion;ExecutableSha256=$ExpectedExecutableSha256;ReleaseTag=$null;BaselineSha256=$BaselineConfigurationSha256;Profiles=@();StateRunIds=@();EvidenceDirectory=$null;RuleDetectionCoverageClaimed=$false;ArchiveCleanupPerformed=$false}
  if(-not $environment.Administrator -and -not $WhatIfPreference){$report.Reason='ExistingElevationRequired';return $report}
  $sources=Read-RideSysmonAcceptanceSources $InputDirectory;$report.ReleaseTag=$sources.ReleaseTag
  if(@($sources.Configurations).Count -ne 3 -or @($sources.Configurations.ArtifactId|Sort-Object -Unique).Count -ne 3){throw 'Acceptance requires all three distinct selected profiles before mutation.'}
  $baseline=& (Get-Module RIDE.SysmonConfiguration) {param($path,$sha) Read-RideSysmonSource $path $sha} $BaselineConfigurationPath $BaselineConfigurationSha256
  if(@($sources.Configurations|Where-Object Sha256 -CEQ $baseline.Sha256).Count){throw 'The baseline must differ from all three selected configurations.'}
  $before=Get-RideSysmonAcceptanceSnapshot $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
  if($before.ConfigurationEvent.Sha256 -cne $baseline.Sha256){$report.Reason='KnownBaselineNotLoaded';return $report}
  if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Apply/repeat/restore all three pinned Sysmon configurations and retain evidence')){$report.Status='Preview';return $report}
  $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
  $state=Join-Path $directory 'state';$null=New-Item -ItemType Directory -Path $state -ErrorAction Stop
  $report.EvidenceDirectory=$directory
  Save-RideSysmonAcceptanceReport (Join-Path $directory 'before.json') $before
  $profiles=[Collections.Generic.List[object]]::new()
  try {
    foreach($source in $sources.Configurations){
      $profile=[pscustomobject]@{ArtifactId=$source.ArtifactId;Sha256=$source.Sha256;RunId=$null;Restored=$false;Checks=@();Before=$null;Applied=$null;Recovered=$null}
      $profiles.Add($profile);$checks=[Collections.Generic.List[string]]::new()
      $current=Get-RideSysmonAcceptanceSnapshot $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
      if($current.ConfigurationEvent.Sha256 -cne $baseline.Sha256 -or -not (Test-RideSysmonAcceptanceEqual $current.Context $before.Context) -or $current.LastErrorRecordId -ne $before.LastErrorRecordId){throw 'Baseline or service health changed between profiles.'}
      $profile.Before=$current.ConfigurationEvent
      $selection=@{ConfigurationPath=$source.Path;ConfigurationSha256=$source.Sha256;PriorConfigurationPath=$baseline.Path;PriorConfigurationSha256=$baseline.Sha256;ExecutablePath=$ExecutablePath;ExpectedExecutableSha256=$ExpectedExecutableSha256;ExpectedSysmonVersion=$ExpectedSysmonVersion;ExpectedComputerName=$ExpectedComputerName;ExpectedBuild=$ExpectedBuild;ExpectedEditionId=$ExpectedEditionId;StateDirectory=$state;AllowCandidate=$true;Confirm=$false}
      $report.Stage=$source.ArtifactId+':Preview';$count=@(Get-ChildItem -LiteralPath $state -File).Count
      $null=Set-RideSysmonConfiguration @selection -WhatIf
      if($count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideSysmonAcceptanceEqual $current (Get-RideSysmonAcceptanceSnapshot $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion))){throw 'Preview changed Sysmon state.'}
      $checks.Add('PreviewNoChanges');$profile.Checks=$checks.ToArray()
      $report.Stage=$source.ArtifactId+':Apply'
      $result=Set-RideSysmonConfiguration @selection;Assert-RideSysmonAcceptanceResult $result Applied $true;$profile.RunId=$result.RunId
      Assert-RideSysmonAcceptanceRecords $state $result.RunId $baseline.Sha256 $source.Sha256
      $applied=Get-RideSysmonAcceptanceSnapshot $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
      Assert-RideSysmonAcceptanceTransition $current $applied $source.Sha256 (Join-Path $state ($result.RunId+'.sysmon.after.xml'))
      $profile.Applied=$applied.ConfigurationEvent;$checks.Add('AppliedSourceEventAndServiceVerified');$profile.Checks=$checks.ToArray()
      $report.Stage=$source.ArtifactId+':Repeat';$count=@(Get-ChildItem -LiteralPath $state -File).Count
      Assert-RideSysmonAcceptanceResult (Set-RideSysmonConfiguration @selection) AlreadyDesired
      if($count -ne @(Get-ChildItem -LiteralPath $state -File).Count -or -not (Test-RideSysmonAcceptanceEqual $applied (Get-RideSysmonAcceptanceSnapshot $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion))){throw 'Repeat changed Sysmon state.'}
      $checks.Add('RepeatNoChanges');$profile.Checks=$checks.ToArray()
      $report.Stage=$source.ArtifactId+':Restore'
      Assert-RideSysmonAcceptanceResult (Restore-RideSysmonConfigurationRun -RunId $result.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) Restored
      $restored=Get-RideSysmonAcceptanceSnapshot $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
      Assert-RideSysmonAcceptanceTransition $applied $restored $baseline.Sha256 (Join-Path $state ($result.RunId+'.sysmon.before.xml'))
      $profile.Recovered=$restored.ConfigurationEvent;$profile.Restored=$true;$checks.Add('BaselineRestoredAndServiceVerified');$profile.Checks=$checks.ToArray()
      $report.Stage=$source.ArtifactId+':RepeatRestore'
      Assert-RideSysmonAcceptanceResult (Restore-RideSysmonConfigurationRun -RunId $result.RunId -StateDirectory $state -AllowCandidate -Confirm:$false) AlreadyRestored
      if(-not (Test-RideSysmonAcceptanceEqual $restored (Get-RideSysmonAcceptanceSnapshot $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion))){throw 'Repeated restore changed Sysmon state.'}
      $checks.Add('RepeatedRestoreNoChanges');$profile.Checks=$checks.ToArray()
    }
    if($profiles.Count -ne 3 -or @($profiles|Where-Object {-not $_.Restored -or $_.Checks.Count -ne 5}).Count){throw 'Three-profile acceptance is incomplete.'}
    $report.Status='Passed';$report.Stage='Complete';$report.NativeAcceptancePassed=$true
  }catch{$report.Status='Failed';$report.Reason='AcceptanceStepFailed';$report.RecoveryRequired=$true;$report.FailureLocation=Get-RideSysmonAcceptanceFailureLocation $_}
  $report.Profiles=$profiles.ToArray()
  $report.StateRunIds=@(Get-ChildItem -LiteralPath $state -Filter '*.sysmon.intent.json' -File|Select-Object -First 256|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.sysmon\.intent\.json$'){$Matches[1]}})
  Save-RideSysmonAcceptanceReport (Join-Path $directory 'result.json') $report
  $report
}
function Get-RideSysmonFixtureFootprint {
  $windows=[Environment]::GetFolderPath('Windows')
  $services=@(Get-CimInstance Win32_Service -Filter "Name='Sysmon' OR Name='Sysmon64'" -ErrorAction Stop)
  $drivers=@(Get-CimInstance Win32_SystemDriver -Filter "Name='SysmonDrv' OR Name='SysmonDriver'" -ErrorAction Stop)
  $paths=@('Sysmon.exe','Sysmon64.exe','SysmonDrv.sys','System32/drivers/SysmonDrv.sys')|ForEach-Object {Join-Path $windows $_}
  $files=@($paths|Where-Object {Test-Path -LiteralPath $_})
  $cursors=@{}
  foreach($eventId in @(16,255)){
    $cursors[$eventId]=0L
    try{$cursors[$eventId]=[long](Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=$eventId} -MaxEvents 1 -ErrorAction Stop).RecordId}
    catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' -and $_.FullyQualifiedErrorId -notlike 'NoMatchingLogsFound*'){throw}}
  }
  [pscustomobject]@{Existing=@($services).Count -gt 0 -or @($drivers).Count -gt 0 -or $files.Count -gt 0;ServiceNames=@($services.Name);DriverNames=@($drivers.Name);Files=$files;ConfigurationRecordId=$cursors[16];LastErrorRecordId=$cursors[255];InstalledExecutablePath=(Join-Path $windows 'Sysmon64.exe')}
}

function Invoke-RideSysmonFixtureInstall {
  param([string]$ExecutablePath,[string]$BaselinePath)
  if($BaselinePath.Contains('"')){throw 'Invalid baseline path.'}
  $process=[Diagnostics.Process]::new()
  try {
    $process.StartInfo=[Diagnostics.ProcessStartInfo]::new($ExecutablePath,('-accepteula -i "'+$BaselinePath+'"'))
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    if(-not $process.Start()){throw 'Fixture installation did not start.'}
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(30000)){$process.Kill();throw 'Fixture installation timed out; retain evidence and inspect the guest.'}
    if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)){throw 'Fixture installer output remained open.'}
    if($process.ExitCode -ne 0 -or $stdout.GetAwaiter().GetResult().Length -gt 1048576 -or $stderr.GetAwaiter().GetResult().Length -gt 1048576){throw 'Fixture installation failed or exceeded its output bound.'}
  }finally{$process.Dispose()}
}

function Initialize-RideSysmonAcceptanceFixture {
  <#
  .SYNOPSIS
    Install an explicitly pinned Sysmon executable with the synthetic XML baseline.
  .DESCRIPTION
    Disposable test setup only. Refuses existing Sysmon services, drivers or known
    files, captures intent, installs the baseline explicitly and verifies the
    service image and configuration event. Leaves the fixture installed for tests.
  .PARAMETER RunId
    Correlated 32-hex request ID matching guest markers.
  .PARAMETER ExecutablePath
    Reviewed local Sysmon64.exe acquired separately from Microsoft.
  .PARAMETER ExpectedExecutableSha256
    Exact acquired executable SHA-256.
  .PARAMETER ExpectedSysmonVersion
    Explicit acquired candidate version.
  .PARAMETER ExpectedComputerName
    Exact disposable guest name.
  .PARAMETER ExpectedBuild
    Exact guest build.
  .PARAMETER ExpectedEditionId
    Exact guest edition.
  .PARAMETER EvidenceRoot
    Existing local fixture evidence root, separate from acceptance evidence.
  .PARAMETER DisposableVm
    Required disposable-target attestation.
  .EXAMPLE
    Get-Help Initialize-RideSysmonAcceptanceFixture -Full
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Preview, NotRun, Prepared or Failed fixture result.
  .NOTES
    Accepts Sysmon's EULA during explicit test installation. This is not package
    acceptance or a configuration-test pass. No uninstall or checkpoint reset.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidatePattern('(?-i)^[a-f0-9]{32}$')][string]$RunId,
    [Parameter(Mandatory)][string]$ExecutablePath,[Parameter(Mandatory)][string]$ExpectedExecutableSha256,
    [Parameter(Mandatory)][string]$ExpectedSysmonVersion,[Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][string]$ExpectedBuild,[Parameter(Mandatory)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][string]$EvidenceRoot,[switch]$DisposableVm)
  $environment=Get-RideSysmonAcceptanceEnvironment
  Assert-RideSysmonAcceptanceGuest $environment $RunId $ExpectedComputerName $ExpectedBuild $ExpectedEditionId ([bool]$DisposableVm)
  & (Get-Module RIDE.SysmonConfiguration) {param($path) Assert-RideSysmonStateDirectory $path} $EvidenceRoot
  $directory=Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $RunId
  if(Test-Path -LiteralPath $directory){throw 'Fixture evidence already exists; use a new request ID.'}
  $result=[pscustomobject][ordered]@{SchemaVersion=1;Kind='SysmonAcceptanceFixture';RunId=$RunId;RecordedAtUtc=[DateTime]::UtcNow.ToString('o');Status='NotRun';Reason=$null;Stage='Preflight';FailureLocation=$null;NativeAcceptancePassed=$false;RecoveryRequired=$false;ComputerName=$ExpectedComputerName;Build=$ExpectedBuild;EditionId=$ExpectedEditionId;SysmonVersion=$ExpectedSysmonVersion;ExecutableSha256=$ExpectedExecutableSha256;InstalledExecutablePath=$null;BaselineConfigurationPath=$null;BaselineConfigurationSha256=$null;EvidenceDirectory=$null;ServiceAndEvent=$null;FixtureRemovalPerformed=$false}
  if(-not $environment.Administrator -and -not $WhatIfPreference){$result.Reason='ExistingElevationRequired';return $result}
  $footprint=Get-RideSysmonFixtureFootprint
  if($footprint.Existing){$result.Reason='ExistingSysmonFootprint';return $result}
  $executable=& (Get-Module RIDE.SysmonConfiguration) {param($path,$sha,$version) Get-RideSysmonExecutableIdentity $path $sha $version} $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
  if([IO.Path]::GetFileName($executable.Path) -ine 'Sysmon64.exe'){throw 'Select the reviewed Sysmon64.exe fixture artifact.'}
  $fixturePath=Join-Path $PSScriptRoot '../fixtures/sysmon-baseline.synthetic.xml'
  $baseline=& (Get-Module RIDE.SysmonConfiguration) {param($path,$sha) Read-RideSysmonSource $path $sha} $fixturePath (Get-FileHash -LiteralPath $fixturePath).Hash
  $result.InstalledExecutablePath=$footprint.InstalledExecutablePath;$result.BaselineConfigurationSha256=$baseline.Sha256
  if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Install the pinned Sysmon test fixture with explicit synthetic XML and EULA acceptance')){$result.Status='Preview';return $result}
  $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
  $result.EvidenceDirectory=$directory;$result.BaselineConfigurationPath=Join-Path $directory 'baseline.xml'
  Save-RideSysmonAcceptanceReport (Join-Path $directory 'intent.json') ([pscustomobject]@{Request=$result;Before=$footprint;Executable=$executable})
  try {
    $result.Stage='Capture'
    & (Get-Module RIDE.SysmonConfiguration) {param($path,$bytes) Save-RideSysmonPrivateBytes $path $bytes} $result.BaselineConfigurationPath $baseline.Bytes
    $result.Stage='Preflight'
    Assert-RideSysmonAcceptanceGuest (Get-RideSysmonAcceptanceEnvironment) $RunId $ExpectedComputerName $ExpectedBuild $ExpectedEditionId ([bool]$DisposableVm)
    if(-not (Test-RideSysmonAcceptanceEqual $footprint (Get-RideSysmonFixtureFootprint))){throw 'Sysmon footprint changed during fixture capture.'}
    $null=& (Get-Module RIDE.SysmonConfiguration) {param($path,$sha,$version) Get-RideSysmonExecutableIdentity $path $sha $version} $ExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
    $result.Stage='Install'
    $stream=[IO.File]::Open($result.BaselineConfigurationPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $exeStream=$null;$sha=[Security.Cryptography.SHA256]::Create()
    try{
      $null=& (Get-Module RIDE.SysmonConfiguration) {param($path,$sha) Read-RideSysmonSource $path $sha} $result.BaselineConfigurationPath $baseline.Sha256
      $exeStream=[IO.File]::Open($executable.Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
      if([BitConverter]::ToString($sha.ComputeHash($exeStream)).Replace('-','') -ine $ExpectedExecutableSha256){throw 'Fixture executable changed before installation.'}
      Invoke-RideSysmonFixtureInstall $executable.Path $result.BaselineConfigurationPath
    }finally{$sha.Dispose();if($exeStream){$exeStream.Dispose()};$stream.Dispose()}
    $result.Stage='Verify'
    $null=& (Get-Module RIDE.SysmonConfiguration) {param($record,$sha,$path) Wait-RideSysmonConfigurationEvent $record $sha $path} $footprint.ConfigurationRecordId $baseline.Sha256 $result.BaselineConfigurationPath
    $snapshot=Get-RideSysmonAcceptanceSnapshot $footprint.InstalledExecutablePath $ExpectedExecutableSha256 $ExpectedSysmonVersion
    & (Get-Module RIDE.SysmonConfiguration) {param($context) Assert-RideSysmonConfigurationContext $context $null $true} $snapshot.Context
    if($snapshot.Context.ComputerName -cne $ExpectedComputerName -or $snapshot.Context.Build -cne $ExpectedBuild -or $snapshot.Context.EditionId -cne $ExpectedEditionId){throw 'Fixture target changed during installation.'}
    if($snapshot.ConfigurationEvent.Sha256 -cne $baseline.Sha256 -or $snapshot.ConfigurationEvent.ConfigurationPath -ine $result.BaselineConfigurationPath -or $snapshot.LastErrorRecordId -ne $footprint.LastErrorRecordId){throw 'Fixture service/event verification failed.'}
    $result.ServiceAndEvent=$snapshot;$result.Status='Prepared';$result.Stage='Complete'
  }catch{$result.Status='Failed';$result.Reason='FixturePreparationFailed';$result.RecoveryRequired=$true;$result.FailureLocation=Get-RideSysmonAcceptanceFailureLocation $_}
  Save-RideSysmonAcceptanceReport (Join-Path $directory 'result.json') $result
  $result
}
Export-ModuleMember -Function Invoke-RideSysmonAcceptance,Initialize-RideSysmonAcceptanceFixture
