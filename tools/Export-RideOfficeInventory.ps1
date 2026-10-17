<#
.SYNOPSIS
  Export read-only, redacted Click-to-Run metadata to a new JSON file.
.DESCRIPTION
  Checks expected execution identity and keeps registry views separate. WhatIf
  makes no registry query and creates no file. No Office/MSI provider or activation.
.PARAMETER ExpectedComputerName
  Independently established target machine name.
.PARAMETER ExpectedBuild
  Expected Windows build number.
.PARAMETER ExpectedEditionId
  Expected Windows EditionID.
.PARAMETER ExpectedUserSid
  Intended interactive account SID.
.PARAMETER ExpectedSessionId
  Expected nonzero session ID.
.PARAMETER OutputPath
  New JSON path in an existing directory; existing/racing output is never replaced.
.EXAMPLE
  .\tools\Export-RideOfficeInventory.ps1 -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath C:\Evidence\office-observation.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path; inspect each source's availability and presence.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; acceptance pending.
  Prerequisites: Registry read and explicit output-parent access; no elevation prompt.
  File/environment inputs: RIDE.OfficeInventory and explicit new output path.
  Recovery: No Office changes. Preserve partial output on write failure; use a new name.
  Output is an observation, not an Office backup, activation report or installer plan.
  Version: 0.1.0.
  Changelog: 0.1.0: Add exclusive JSON export with no-query WhatIf.
.LINK
  ../docs/application-packages.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
  [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
  [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9]+(?:-[0-9]+)+$')][string]$ExpectedUserSid,
  [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath
)
$ErrorActionPreference='Stop'
$destination=[IO.Path]::GetFullPath($OutputPath)
if(-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($destination))){throw 'Create the output parent directory explicitly.'}
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Office output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Collect read-only Click-to-Run metadata and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.OfficeInventory.psm1') -Force
  $inventory=Get-RideOfficeInventory -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -ExpectedUserSid $ExpectedUserSid -ExpectedSessionId $ExpectedSessionId
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory|ConvertTo-Json -Depth 10)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
