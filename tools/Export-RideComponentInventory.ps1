<#
.SYNOPSIS
  Export separate, read-only Windows component provider observations.
.DESCRIPTION
  Checks an explicit local machine/build/edition before collecting selected providers.
  Uses an existing evidence directory for uniquely named DISM logs and creates a new
  JSON file without overwrite. WhatIf queries no provider and creates no file.
.PARAMETER Kind
  Selected provider namespaces. No component is enabled, disabled or downloaded.
.PARAMETER ExpectedComputerName
  Intended local computer name; no remote target or automatic selection.
.PARAMETER ExpectedBuild
  Exact target build number from the intended image's CurrentVersion registry key.
.PARAMETER ExpectedEditionId
  Intended EditionID from the same key.
.PARAMETER LogDirectory
  Existing local evidence directory for DISM diagnostics and scratch files.
.PARAMETER OutputPath
  New JSON path in an existing directory. Existing or concurrently created files refuse.
.EXAMPLE
  .\tools\Export-RideComponentInventory.ps1 -Kind OptionalFeature,Capability -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -LogDirectory C:\Evidence -OutputPath C:\Evidence\components.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path; inspect each provider's status before using its rows.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Existing elevation for collection, selected native modules, local
  log directory. Native target acceptance remains pending; preview needs no elevation.
  File/environment inputs: RIDE.ComponentInventory module and explicit evidence paths.
  Recovery: No servicing change. Preserve diagnostics; failed write may leave partial
  JSON. Resolve the error and choose a new output name rather than overwrite evidence.
  Version: 0.1.0
  Changelog: 0.1.0: Add previewable, non-overwriting component inventory export.
.LINK
  ../docs/windows-component-inventory.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)][ValidateSet('OptionalFeature','Capability','ServerFeature')][string[]]$Kind,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
  [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LogDirectory,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath
)
$ErrorActionPreference='Stop'
$script:ScriptVersion='0.1.0'
$destination=[IO.Path]::GetFullPath($OutputPath)
if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($destination))) { throw 'Create the output parent directory explicitly.' }
if ([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)) { throw 'Component output already exists; choose a new file.' }
if ($PSCmdlet.ShouldProcess($destination,'Collect read-only component providers, write diagnostic logs and create JSON')) {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.ComponentInventory.psm1') -Force
  $inventory=Get-RideWindowsComponentInventory -Kind $Kind -ExpectedComputerName $ExpectedComputerName -ExpectedBuild $ExpectedBuild -ExpectedEditionId $ExpectedEditionId -LogDirectory $LogDirectory
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($inventory | ConvertTo-Json -Depth 10)+"`n")
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
  $destination
}
