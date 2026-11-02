<#
.SYNOPSIS
  Run a retained apply or restore phase for default lock-screen guest acceptance.
.DESCRIPTION
  Requires a correlated disposable Hyper-V guest and existing elevation. Does not
  sign out, reboot or reset the guest. Visual verification remains a separate gate.
.PARAMETER Phase
  Apply leaves the image active; Restore recovers its captured policy/file state.
.PARAMETER RunId
  Request ID matching RIDE_TEST_RUN_ID; reuse the Apply ID for Restore. Restore
  completes saved request directories when EvidenceRoot has already been supplied.
.PARAMETER SourcePath
  Apply-only local path to the selected hash-pinned PNG. Omit for Restore.
.PARAMETER ExpectedComputerName
  Exact guest computer name.
.PARAMETER ExpectedBuild
  Exact guest Windows 11 build.
.PARAMETER ExpectedEditionId
  Exact Enterprise/Education candidate edition.
.PARAMETER EvidenceRoot
  Existing administrator-controlled evidence parent; retains private phase records.
.PARAMETER DisposableVm
  Required explicit disposable-target attestation.
.PARAMETER Version
  Print version without importing modules or inspecting Windows.
.EXAMPLE
  .\tests\integration\Invoke-RideDefaultLockAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Schema-1 phased result, never an overall visual acceptance pass.
.NOTES
  Native Windows PowerShell 5.1/7. Version: 0.1.0.
  Recovery: Retain the guest and private evidence; no automatic checkpoint cleanup.
.LINK
  ../../docs/image-personalization.md
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([ValidateSet('Apply','Restore')][string]$Phase,
  [ArgumentCompleter({
    param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{if($fakeBoundParameters.Phase -cne 'Restore' -or -not $fakeBoundParameters.ContainsKey('EvidenceRoot')){return};Get-ChildItem -LiteralPath $fakeBoundParameters.EvidenceRoot -Directory -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^[a-f0-9]{32}$' -and $_.Name.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($_.Name,$_.Name,'ParameterValue','Saved default-image acceptance request')}}}catch{}
  })][string]$RunId,[string]$SourcePath,
  [string]$ExpectedComputerName,[string]$ExpectedBuild,
  [ValidateSet('Enterprise','EnterpriseN','EnterpriseEval','Education','EducationN')][string]$ExpectedEditionId,
  [string]$EvidenceRoot,[switch]$DisposableVm,[switch]$Version)
if($Version){'0.1.0';return}
$ErrorActionPreference='Stop'
foreach($name in @('Phase','RunId','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','EvidenceRoot')){if(-not $PSBoundParameters.ContainsKey($name) -or [string]::IsNullOrWhiteSpace([string]$PSBoundParameters[$name])){throw "Supply $name explicitly; no interactive input is requested."}}
Import-Module (Join-Path $PSScriptRoot 'RIDE.DefaultLockAcceptance.psm1') -ErrorAction Stop
$selection=@{};foreach($name in @('Phase','RunId','SourcePath','ExpectedComputerName','ExpectedBuild','ExpectedEditionId','EvidenceRoot','DisposableVm','WhatIf','Confirm')){if($PSBoundParameters.ContainsKey($name)){$selection[$name]=$PSBoundParameters[$name]}}
$result=Invoke-RideDefaultLockAcceptance @selection
$result
if($result.Status -in @('Failed','NotRun')){exit 1}
