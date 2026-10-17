<#
.SYNOPSIS
  Save a read-only playback-endpoint observation for an explicit user and session.
.DESCRIPTION
  Queries Core Audio render endpoints only after checking the execution identity.
  Creates a new JSON file; refuses overwrite. Does not mute, play sound, change
  volume/default roles, start services or install drivers. WhatIf performs no query.
.PARAMETER ExpectedUserSid
  Intended execution account SID; obtain it in the intended user's session.
.PARAMETER ExpectedSessionId
  Intended nonzero Windows session ID.
.PARAMETER OutputPath
  New JSON file in an existing directory. Existing files are never overwritten.
.EXAMPLE
  .\tools\Export-RideAudioEndpointInventory.ps1 -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath .\audio-observation.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Intended interactive session and available Core Audio; no elevation.
  File/environment inputs: RIDE.AudioEndpointInventory module; explicit output file.
  Recovery: No audio change; retain or delete only this exported observation.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog: 0.1.0: Add non-overwriting, previewable inventory export.
.LINK
  ../docs/audio-service.md#read-only-endpoint-inventory
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid,
  [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$script:ScriptVersion = '0.1.0'
$destination = [IO.Path]::GetFullPath($OutputPath)
if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($destination))) { throw 'Create the inventory parent directory explicitly.' }
if ([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)) { throw 'Inventory output already exists; choose a new file.' }
if ($PSCmdlet.ShouldProcess($destination,'Collect read-only playback inventory and create JSON')) {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.AudioEndpointInventory.psm1') -Force
  $inventory = Get-RideAudioEndpointInventory -ExpectedUserSid $ExpectedUserSid -ExpectedSessionId $ExpectedSessionId
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($inventory | ConvertTo-Json -Depth 10) + "`n")
  $stream = [IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
  $destination
}
