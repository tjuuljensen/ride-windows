<#
.SYNOPSIS
  Prepare a disposable Sysmon fixture or test the three pinned configurations.
.DESCRIPTION
  PrepareFixture explicitly installs the pinned executable with synthetic XML
  only when known Sysmon services, drivers and destination files are absent.
  Configurations requires a loaded known baseline and tests all three profiles.
.PARAMETER Mode
  PrepareFixture or Configurations (default); preparation is not an acceptance pass.
.PARAMETER RunId
  Correlated request ID matching disposable guest markers.
.PARAMETER InputDirectory
  Acquired three-profile directory with retained license, for Configurations.
.PARAMETER BaselineConfigurationPath
  Known loaded XML baseline, for Configurations.
.PARAMETER BaselineConfigurationSha256
  Baseline SHA-256, for Configurations.
.PARAMETER ExecutablePath
  Acquired Sysmon64.exe for preparation, or service executable for Configurations.
.PARAMETER ExpectedExecutableSha256
  Reviewed executable digest.
.PARAMETER ExpectedSysmonVersion
  Explicit selected executable version.
.PARAMETER ExpectedComputerName
  Exact guest computer name.
.PARAMETER ExpectedBuild
  Exact guest Windows build.
.PARAMETER ExpectedEditionId
  Exact guest edition.
.PARAMETER EvidenceRoot
  Existing local evidence root; use separate roots for preparation and acceptance.
.PARAMETER DisposableVm
  Required disposable-guest attestation.
.PARAMETER Version
  Print version without importing modules or querying Windows.
.EXAMPLE
  .\tests\integration\Invoke-RideSysmonAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Schema-1 fixture or configuration-acceptance report.
.NOTES
  Compatibility: Native PowerShell 5.1 and 7; candidate Windows 11 x64.
  Prerequisites: Existing elevation, pinned sources and correlated Hyper-V guest.
  Recovery: Private evidence retained; no forced cleanup, UAC or checkpoint reset.
  Version: 0.1.0. Changelog: Add explicit fixture and configuration-test modes.
.LINK
  ../../docs/sysmon-configuration.md
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([ValidateSet('PrepareFixture','Configurations')][string]$Mode='Configurations',
  [string]$RunId,[string]$InputDirectory,[string]$BaselineConfigurationPath,[string]$BaselineConfigurationSha256,
  [string]$ExecutablePath,[string]$ExpectedExecutableSha256,[string]$ExpectedSysmonVersion,
  [string]$ExpectedComputerName,[string]$ExpectedBuild,[string]$ExpectedEditionId,[string]$EvidenceRoot,
  [switch]$DisposableVm,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
$names=@('RunId','ExecutablePath','ExpectedExecutableSha256','ExpectedSysmonVersion','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','EvidenceRoot')
$configurationNames=@('InputDirectory','BaselineConfigurationPath','BaselineConfigurationSha256')
if($Mode -eq 'Configurations'){$names+=$configurationNames}
elseif(@($configurationNames|Where-Object {$PSBoundParameters.ContainsKey($_)}).Count){throw 'Configuration inputs do not apply to PrepareFixture mode.'}
foreach($name in $names){if(-not $PSBoundParameters.ContainsKey($name) -or [string]::IsNullOrWhiteSpace([string]$PSBoundParameters[$name])){throw "Supply the required $name parameter; no interactive input is requested."}}
Import-Module (Join-Path $PSScriptRoot 'RIDE.SysmonAcceptance.psm1') -ErrorAction Stop
$selection=@{};foreach($name in ($names+@('DisposableVm','WhatIf','Confirm'))){if($PSBoundParameters.ContainsKey($name)){$selection[$name]=$PSBoundParameters[$name]}}
if($Mode -eq 'PrepareFixture'){Initialize-RideSysmonAcceptanceFixture @selection}else{Invoke-RideSysmonAcceptance @selection}
