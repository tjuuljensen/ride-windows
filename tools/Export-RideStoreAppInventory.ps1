<#
.SYNOPSIS
  Export an explicit user's read-only Store app inventory for migration review.
.DESCRIPTION
  Requires the intended execution SID, queries this user's Appx registrations,
  and writes review data only. Never uninstalls, registers, provisions or downloads.
.PARAMETER ExpectedUserSid
  Intended user's SID. A mismatch is refused before any Appx query.
.PARAMETER OutputPath
  Literal JSON output path. Its existing parent directory must be available.
.EXAMPLE
  .\tools\Export-RideStoreAppInventory.ps1 -ExpectedUserSid S-1-5-21-1-2-3-1001 -OutputPath .\apps.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Saved inventory path, when written.
.NOTES
  Compatibility: Windows PowerShell 5.1 or PowerShell 7 with available native Appx cmdlets.
  Prerequisites: Run inside the intended user's Windows console; no elevation required.
  File/environment inputs: RIDE.StoreAppReview module and a literal output file.
  Recovery: No Windows mutation; review output can be retained or replaced explicitly.
  Owner: RIDE-Windows maintainers. Version: 0.1.1.
  Changelog: 0.1.1: Retain observed edition/build context for cross-release review.
    0.1.0: Add current-user inventory export with explicit SID correlation.
.LINK
  ../docs/migrations/store-app-removal-review.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([Parameter(Mandatory)][string] $ExpectedUserSid,[Parameter(Mandatory)][string] $OutputPath)
$ErrorActionPreference = 'Stop'
$script:ScriptVersion = '0.1.1'
$destination = [IO.Path]::GetFullPath($OutputPath)
if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) { throw 'Create the inventory output parent directory explicitly.' }
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.StoreAppReview.psm1') -Force
if ($PSCmdlet.ShouldProcess($destination,'Collect current-user read-only Appx inventory and save review JSON')) {
  $inventory = Get-RideStoreAppInventory -ExpectedUserSid $ExpectedUserSid
  $json = $inventory | ConvertTo-Json -Depth 12
  [IO.File]::WriteAllText($destination,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
  $destination
}
