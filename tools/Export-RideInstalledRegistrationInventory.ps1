<#
.SYNOPSIS
  Export read-only installed-registration observations for adoption review.
.DESCRIPTION
  Captures explicitly selected machine/current-user uninstall roots by registry
  view. WhatIf makes no registry query and creates no file. Does not adopt packages.
.PARAMETER Scope
  Machine and/or current User, selected once each.
.PARAMETER ExpectedComputerName
  Independently supplied intended computer name.
.PARAMETER ExpectedBuild
  Expected Windows build.
.PARAMETER ExpectedEditionId
  Expected Windows EditionID.
.PARAMETER ExpectedUserSid
  Intended interactive execution account SID.
.PARAMETER ExpectedSessionId
  Intended nonzero process session.
.PARAMETER OutputPath
  New JSON path in an existing directory. Existing output is never replaced.
.EXAMPLE
  .\tools\Export-RideInstalledRegistrationInventory.ps1 -Scope Machine,User -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath C:\Evidence\registrations.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path; inspect every Sources.Status before using its rows.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; acceptance pending.
  Prerequisites: Read access to selected roots; no elevation prompt or remote target.
  File/environment inputs: Explicit identity, new output and the inventory module.
  Recovery: No package changes; preserve partial output on failure and use a new name.
  Output can contain user paths and product metadata. It is not an adoption record.
  Version: 0.1.0.
  Changelog: 0.1.0: Add exclusive JSON export and query-free preview.
.LINK
  ../docs/application-packages.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)][ValidateSet('Machine','User')][string[]]$Scope,
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
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Registration output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Observe uninstall registry sources and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.InstalledRegistrationInventory.psm1') -Force
  $inventory=Get-RideInstalledRegistrationInventory -Scope $Scope -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -ExpectedUserSid $ExpectedUserSid -ExpectedSessionId $ExpectedSessionId
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory|ConvertTo-Json -Depth 12)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
