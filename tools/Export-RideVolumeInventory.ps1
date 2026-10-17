<#
.SYNOPSIS
  Export read-only volume identity observations without overwriting evidence.
.DESCRIPTION
  Requires the expected local Windows machine/build/edition. Collects local
  volume metadata only and creates a new JSON file. WhatIf queries no
  Windows provider and creates no output. No volume settings or mount points change.
.PARAMETER ExpectedComputerName
  Intended local target name; no remote collection.
.PARAMETER ExpectedBuild
  Exact Windows build independently supplied for the intended target.
.PARAMETER ExpectedEditionId
  Intended Windows EditionID.
.PARAMETER OutputPath
  New JSON path in an existing directory. Existing or racing output files refuse.
.EXAMPLE
  .\tools\Export-RideVolumeInventory.ps1 -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -OutputPath C:\Evidence\volumes.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path; inspect Status before treating volume rows as captured.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; target acceptance pending.
  Prerequisites: Local CIM Win32_Volume provider access; no elevation prompt or network request.
  File/environment inputs: RIDE.VolumeInventory module; explicit new output path.
  Recovery: No volume state changes. Preserve failed partial output and choose a new
  filename after resolving the error. Saved observations are not engine restore records.
  Version: 0.1.0.
  Changelog: 0.1.0: Add previewable volume identity export using exclusive CreateNew.
.LINK
  ../docs/volume-inventory.md
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
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Volume output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Collect read-only local volume identities and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.VolumeInventory.psm1') -Force
  $inventory=Get-RideVolumeInventory -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory|ConvertTo-Json -Depth 8)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
