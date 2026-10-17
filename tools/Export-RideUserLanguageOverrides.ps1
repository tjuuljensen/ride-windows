<#
.SYNOPSIS
  Export read-only display-language and default-input override observations.
.DESCRIPTION
  Selects explicit current-user providers and refuses identity drift. WhatIf makes
  no provider query and creates no file. No language, keyboard or logon change.
.PARAMETER Kind
  DisplayLanguage and/or DefaultInputMethod; select each provider only once.
.PARAMETER ExpectedComputerName
  Independently supplied target machine name.
.PARAMETER ExpectedBuild
  Exact expected Windows build number.
.PARAMETER ExpectedEditionId
  Expected Windows EditionID.
.PARAMETER ExpectedUserSid
  Intended interactive execution account SID.
.PARAMETER ExpectedSessionId
  Intended nonzero process session ID.
.PARAMETER OutputPath
  New JSON path in an existing directory. Existing/racing output is never replaced.
.EXAMPLE
  .\tools\Export-RideUserLanguageOverrides.ps1 -Kind DisplayLanguage,DefaultInputMethod -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath C:\Evidence\language-overrides.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path; inspect each provider's Status and ObservationState.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; acceptance pending.
  Prerequisites: International module and provider access; no elevation prompt.
  File/environment inputs: RIDE.UserLanguageInventory and explicit new output path.
  Recovery: No language changes. Preserve partial output on failure; use a new name.
  Output is an observation, not a complete regional backup or engine restore record.
  Version: 0.1.0.
  Changelog: 0.1.0: Add explicit provider selection and exclusive JSON export.
.LINK
  ../docs/user-language-inventory.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)][ValidateSet('DisplayLanguage','DefaultInputMethod')][string[]]$Kind,
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
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Language override output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Collect read-only user-language overrides and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.UserLanguageInventory.psm1') -Force
  $inventory=Get-RideUserLanguageOverrideInventory -Kind $Kind -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -ExpectedUserSid $ExpectedUserSid -ExpectedSessionId $ExpectedSessionId
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory|ConvertTo-Json -Depth 8)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
