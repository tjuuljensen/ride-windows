<#
.SYNOPSIS
  Export the intended user's default/LAN proxy options to new local evidence.
.DESCRIPTION
  Collects literal WinINet flags and proxy/bypass/PAC strings. WhatIf does not
  query Windows or create output. No PAC retrieval, proxy resolution or setter.
.PARAMETER ExpectedComputerName
  Intended local target name.
.PARAMETER ExpectedUserSid
  Intended interactive execution account SID.
.PARAMETER ExpectedSessionId
  Intended nonzero process session ID.
.PARAMETER ConnectionKind
  Explicit DefaultLan scope; named RAS/VPN settings are not covered.
.PARAMETER OutputPath
  New JSON file in an existing local evidence directory. Existing paths refuse.
.EXAMPLE
  .\tools\Export-RideUserProxyObservation.ps1 -ExpectedComputerName '<target>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -ConnectionKind DefaultLan -OutputPath C:\Evidence\proxy.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; native acceptance pending.
  Prerequisites: Intended interactive user context; no elevation prompt.
  File/environment inputs: RIDE.UserProxyInventory module and new output path.
  Effects: JSON may contain private server names and PAC URLs, including query tokens.
  Recovery: No proxy change. Preserve partial output on write failure; use a new path.
  Version: 0.1.0.
  Changelog: 0.1.0: Add previewable default/LAN observation export with exclusive creation.
.LINK
  ../docs/user-proxy-inventory.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
  [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid,
  [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId,
  [Parameter(Mandatory)][ValidateSet('DefaultLan')][string]$ConnectionKind,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath
)
$ErrorActionPreference='Stop'
$destination=[IO.Path]::GetFullPath($OutputPath)
if(-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($destination))){throw 'Create the output parent directory explicitly.'}
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Proxy output already exists; choose a new file.'}
if($PSCmdlet.ShouldProcess($destination,'Observe default/LAN proxy options for the explicit user/session and create JSON')){
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.UserProxyInventory.psm1') -Force
  $observation=Get-RideUserProxyObservation -ExpectedComputerName $ExpectedComputerName -ExpectedUserSid $ExpectedUserSid -ExpectedSessionId $ExpectedSessionId -ConnectionKind $ConnectionKind
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($observation|ConvertTo-Json -Depth 8)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
