<#
.SYNOPSIS
  Export basic WLAN interface/profile metadata without profile content or keys.
.DESCRIPTION
  Captures the expected user's visible WLAN interfaces and stored profile lists.
  WhatIf queries nothing and creates no output. No scan, connect, import, delete,
  profile XML, key, EAP data, service start or component installation is performed.
.PARAMETER ExpectedComputerName
  Independently supplied local target machine name.
.PARAMETER ExpectedBuild
  Exact expected Windows build number.
.PARAMETER ExpectedEditionId
  Expected Windows EditionID.
.PARAMETER ExpectedUserSid
  Intended interactive execution account SID.
.PARAMETER ExpectedSessionId
  Intended nonzero process session ID.
.PARAMETER OutputPath
  New JSON file in an existing private directory; existing/racing files refuse.
.EXAMPLE
  .\tools\Export-RideWirelessProfileInventory.ps1 -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath C:\Evidence\wireless-profiles.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created evidence path; inspect Status before using rows.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; acceptance pending.
  Prerequisites: Available WLAN service/API and intended interactive session.
  File/environment inputs: RIDE.WirelessInventory and explicit new output path.
  Recovery: No network state changes. Retain partial output on write failure and
  choose a new filename. Names may reveal private networks; keep evidence private.
  Version: 0.1.0.
  Changelog: 0.1.0: Add previewable exclusive JSON export of basic profile metadata.
.LINK
  ../docs/wireless-profile-inventory.md
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
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Wireless output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Collect basic WLAN profile metadata and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.WirelessInventory.psm1') -Force
  $inventory=Get-RideWirelessProfileInventory -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -ExpectedUserSid $ExpectedUserSid -ExpectedSessionId $ExpectedSessionId
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory|ConvertTo-Json -Depth 8)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
