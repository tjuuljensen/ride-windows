<#
.SYNOPSIS
  Export read-only local-user observations without overwriting evidence.
.DESCRIPTION
  Requires the expected local Windows machine/build/edition and creates new JSON.
  WhatIf queries no Windows provider and creates no output. No account mutation,
  membership query, credential collection or sign-in attempt is performed.
.PARAMETER ExpectedComputerName
  Intended local machine name; no remote collection.
.PARAMETER ExpectedBuild
  Exact Windows build independently supplied for the target.
.PARAMETER ExpectedEditionId
  Intended Windows EditionID.
.PARAMETER OutputPath
  New JSON path in an existing directory. Existing or racing output files refuse.
.EXAMPLE
  .\tools\Export-RideLocalUserInventory.ps1 -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -OutputPath C:\Evidence\local-users.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path; inspect Status before treating user rows as captured.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; acceptance pending.
  Prerequisites: LocalAccounts module and provider access; no elevation prompt.
  File/environment inputs: RIDE.LocalUserInventory; explicit new output path.
  Recovery: No account changes. Preserve partial output on failure and choose a new
  filename after resolving the error. JSON is not an account backup or restore record.
  Version: 0.1.0.
  Changelog: 0.1.0: Add previewable local-user export with exclusive CreateNew.
.LINK
  ../docs/local-user-inventory.md
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
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Local user output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Collect read-only local user SIDs and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.LocalUserInventory.psm1') -Force
  $inventory=Get-RideLocalUserInventory -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory|ConvertTo-Json -Depth 8)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
