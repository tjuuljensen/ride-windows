<#
.SYNOPSIS
  Run synthetic WLAN lifecycle acceptance inside the selected disposable guest.
.DESCRIPTION
  Requires correlated disposable guest markers, existing elevation and WLAN.
  Does not connect, start services, elevate or reset a checkpoint. Private state
  remains available on failure. A missing prerequisite is NotRun, not Passed.
.PARAMETER RunId
  Request ID matching RIDE_TEST_RUN_ID; 32 lowercase hexadecimal characters.
.PARAMETER InterfaceId
  Explicit WLAN interface GUID from this guest's read-only inventory.
.PARAMETER ExpectedComputerName
  Exact expected guest name.
.PARAMETER ExpectedBuild
  Exact expected Windows build number.
.PARAMETER ExpectedEditionId
  Exact expected Windows edition identity.
.PARAMETER EvidenceRoot
  Existing local evidence directory; the runner creates a new RunId child.
.PARAMETER DisposableVm
  Required explicit disposable-guest attestation.
.PARAMETER Version
  Print the version without importing modules or querying Windows.
.EXAMPLE
  .\tests\integration\Invoke-RideWirelessAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Schema-1 acceptance result. Actual runs retain private evidence and recovery.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7, Windows 11 x64.
  Prerequisites: Attested Hyper-V guest and WLAN support. No new UAC prompt.
  Recovery: Follow the retained run IDs; incomplete runs require inspection.
  Version: 0.1.0.
  Changelog: 0.1.0: Expose the guarded synthetic WLAN acceptance route.
.LINK
  ../../docs/wireless-profile-inventory.md
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([string]$RunId,[guid]$InterfaceId,[string]$ExpectedComputerName,[string]$ExpectedBuild,
  [string]$ExpectedEditionId,[string]$EvidenceRoot,[switch]$DisposableVm,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
foreach($name in @('RunId','InterfaceId','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','EvidenceRoot')){if(-not $PSBoundParameters.ContainsKey($name) -or [string]::IsNullOrWhiteSpace([string]$PSBoundParameters[$name])){throw "Supply the required $name parameter; no interactive input is requested."}}
Import-Module (Join-Path $PSScriptRoot 'RIDE.WirelessAcceptance.psm1') -ErrorAction Stop
$selection=@{};foreach($name in @('RunId','InterfaceId','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','EvidenceRoot','DisposableVm','WhatIf','Confirm')){if($PSBoundParameters.ContainsKey($name)){$selection[$name]=$PSBoundParameters[$name]}}
Invoke-RideWirelessAcceptance @selection
