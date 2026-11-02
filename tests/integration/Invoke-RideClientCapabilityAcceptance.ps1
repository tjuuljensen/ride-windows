<#
.SYNOPSIS
  Run the guarded OpenSSH Client or RSAT disposable-guest acceptance scenario.
.DESCRIPTION
  Uses catalog install/remove and saved engine recovery with explicit Windows
  Update acquisition. Requires existing elevation and correlated guest markers.
  Failure retains evidence; this entry point never starts a VM or requests UAC.
.PARAMETER Family
  OpenSSHClient or RSAT; the latter selects all observed catalog members.
.PARAMETER RunId
  Request ID matching RIDE_TEST_RUN_ID.
.PARAMETER ExpectedComputerName
  Exact guest computer name.
.PARAMETER ExpectedBuild
  Exact Windows build.
.PARAMETER ExpectedEditionId
  Exact Windows edition.
.PARAMETER ExpectedRevision
  Exact update build revision.
.PARAMETER ServicingSource
  Required explicit WindowsUpdate acquisition route.
.PARAMETER EvidenceRoot
  Existing local directory for new private evidence.
.PARAMETER DisposableVm
  Required disposable-target attestation.
.PARAMETER Version
  Print version without importing operational modules.
.EXAMPLE
  .\tests\integration\Invoke-RideClientCapabilityAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Schema-1 scenario result. Nonzero process exit on a failed actual scenario.
.NOTES
  Compatibility: Native Windows PowerShell 5.1/7; Windows 11 x64 candidate.
  Recovery: Conditional literal state only; preserve engine journals on failure.
  No automatic restart, recovery after failure, SSH connection or domain query.
  A separately reviewed host route must collect evidence before checkpoint reset.
  Version: 0.1.0. Changelog: Add source-prepared capability scenario entry point.
.LINK
  ../../docs/windows-component-inventory.md
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([ValidateSet('OpenSSHClient','RSAT')][string]$Family,[string]$RunId,
  [string]$ExpectedComputerName,[string]$ExpectedBuild,[string]$ExpectedEditionId,
  [int]$ExpectedRevision,[ValidateSet('WindowsUpdate')][string]$ServicingSource,
  [string]$EvidenceRoot,[switch]$DisposableVm,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
foreach($name in @('Family','RunId','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','ExpectedRevision','ServicingSource','EvidenceRoot')){
  if(-not $PSBoundParameters.ContainsKey($name) -or [string]::IsNullOrWhiteSpace([string]$PSBoundParameters[$name])){throw "Supply the required $name parameter; no interactive input is requested."}
}
Import-Module (Join-Path $PSScriptRoot 'RIDE.ClientCapabilityAcceptance.psm1') -ErrorAction Stop
$selection=@{};foreach($name in @('Family','RunId','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','ExpectedRevision','ServicingSource','EvidenceRoot','DisposableVm','WhatIf','Confirm')){if($PSBoundParameters.ContainsKey($name)){$selection[$name]=$PSBoundParameters[$name]}}
$result=Invoke-RideClientCapabilityAcceptance @selection
$result
if($result.Status -notin @('Passed','Preview')){exit 1}
