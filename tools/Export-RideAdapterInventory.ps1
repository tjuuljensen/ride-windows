<#
.SYNOPSIS
  Export read-only network adapter identity observations without overwriting evidence.
.DESCRIPTION
  Requires the expected local Windows machine/build/edition. Collects visible and
  hidden adapter metadata only and creates a new JSON file. WhatIf queries no
  Windows provider and creates no output. No network settings or connections change.
.PARAMETER ExpectedComputerName
  Intended local target name; no remote collection.
.PARAMETER ExpectedBuild
  Exact Windows build independently supplied for the intended target.
.PARAMETER ExpectedEditionId
  Intended Windows EditionID.
.PARAMETER OutputPath
  New JSON path in an existing directory. Existing or racing output files refuse.
.EXAMPLE
  .\tools\Export-RideAdapterInventory.ps1 -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -OutputPath C:\Evidence\adapters.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path; inspect Status before treating adapter rows as captured.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; target acceptance pending.
  Prerequisites: Local NetAdapter provider access; no elevation prompt or network request.
  File/environment inputs: RIDE.AdapterInventory module; explicit new output path.
  Recovery: No network state changes. Preserve failed partial output and choose a new
  filename after resolving the error. Saved observations are not engine restore records.
  Version: 0.1.0.
  Changelog: 0.1.0: Add previewable adapter identity export using exclusive CreateNew.
.LINK
  ../docs/network-adapter-inventory.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
  [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath
)
$ErrorActionPreference='Stop'
$destination=[IO.Path]::GetFullPath($OutputPath)
if(-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($destination))){throw 'Create the output parent directory explicitly.'}
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Adapter output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Collect read-only local adapter identities and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.AdapterInventory.psm1') -Force
  $inventory=Get-RideNetworkAdapterInventory -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory|ConvertTo-Json -Depth 8)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
