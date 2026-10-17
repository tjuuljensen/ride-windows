<#
.SYNOPSIS
  Export read-only user-language observations without overwriting evidence.
.DESCRIPTION
  Requires the expected local Windows machine/build/edition and creates new JSON.
  WhatIf queries no Windows provider and creates no output. No language installation,
  list replacement, regional format or system locale change is performed.
.PARAMETER ExpectedComputerName
  Intended local machine name; no remote collection.
.PARAMETER ExpectedBuild
  Exact Windows build independently supplied for the target.
.PARAMETER ExpectedEditionId
  Intended Windows EditionID.
.PARAMETER ExpectedUserSid
  Intended interactive execution account SID.
.PARAMETER ExpectedSessionId
  Intended nonzero process session ID.
.PARAMETER OutputPath
  New JSON path in an existing directory. Existing or racing output files refuse.
.EXAMPLE
  .\tools\Export-RideUserLanguageInventory.ps1 -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath C:\Evidence\user-languages.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path; inspect Status before treating language rows as captured.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; acceptance pending.
  Prerequisites: International module and provider access; no elevation prompt.
  File/environment inputs: RIDE.UserLanguageInventory; explicit new output path.
  Recovery: No language changes. Preserve partial output on failure and choose a new
  filename after resolving the error. JSON is not a complete regional-settings backup or restore record.
  Version: 0.1.0.
  Changelog: 0.1.0: Add previewable user-language export with exclusive CreateNew.
.LINK
  ../docs/user-language-inventory.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
  [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
  [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid,
  [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath
)
$ErrorActionPreference='Stop'
$destination=[IO.Path]::GetFullPath($OutputPath)
if(-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($destination))){throw 'Create the output parent directory explicitly.'}
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Language output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Collect read-only ordered user languages and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.UserLanguageInventory.psm1') -Force
  $inventory=Get-RideUserLanguageInventory -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -ExpectedUserSid $ExpectedUserSid -ExpectedSessionId $ExpectedSessionId
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory|ConvertTo-Json -Depth 8)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
