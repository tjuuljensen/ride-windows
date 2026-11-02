<#
.SYNOPSIS
  Run the guarded disposable-guest machine-font lifecycle scenario.
.DESCRIPTION
  Requires correlated guest markers, explicit target and licensed hash-pinned
  inputs. Does not reboot, close consumers or repair incomplete runs automatically.
.PARAMETER RunId
  Correlated 32-hex request ID matching RIDE_TEST_RUN_ID.
.PARAMETER ManifestPath
  Reviewed font/license PSD1 manifest with real, renderable font payloads.
.PARAMETER ExpectedComputerName
  Exact guest name.
.PARAMETER ExpectedBuild
  Exact guest build.
.PARAMETER ExpectedEditionId
  Exact guest edition.
.PARAMETER EvidenceRoot
  Existing local directory for a new request-specific evidence folder.
.PARAMETER DisposableVm
  Required explicit disposable-target attestation.
.PARAMETER Version
  Print version without importing operational modules.
.EXAMPLE
  .\tests\integration\Invoke-RideFontAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Schema-1 current-session font acceptance result.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and 7; candidate Windows 11 x64.
  Prerequisites: Existing elevation and attested Hyper-V guest. No UAC prompt.
  Recovery: Inspect retained lifecycle runs; checkpoint cleanup is separate.
  Version: 0.1.0. Changelog: Add guarded machine-font acceptance entry point.
.LINK
  ../../docs/machine-fonts.md
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([string]$RunId,[string]$ManifestPath,[string]$ExpectedComputerName,[string]$ExpectedBuild,
  [string]$ExpectedEditionId,[string]$EvidenceRoot,[switch]$DisposableVm,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
foreach($name in @('RunId','ManifestPath','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','EvidenceRoot')){if(-not $PSBoundParameters.ContainsKey($name) -or [string]::IsNullOrWhiteSpace([string]$PSBoundParameters[$name])){throw "Supply the required $name parameter; no interactive input is requested."}}
Import-Module (Join-Path $PSScriptRoot 'RIDE.FontAcceptance.psm1') -ErrorAction Stop
$selection=@{};foreach($name in @('RunId','ManifestPath','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','EvidenceRoot','DisposableVm','WhatIf','Confirm')){if($PSBoundParameters.ContainsKey($name)){$selection[$name]=$PSBoundParameters[$name]}}
Invoke-RideFontAcceptance @selection
