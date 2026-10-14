<#
.SYNOPSIS
  Compare a saved Store app inventory with historical and policy review data.
.DESCRIPTION
  Reads bounded JSON and current catalog candidates. Reports exact family matches,
  mismatches and unfamiliar observed apps; history is optional. No Windows query.
.PARAMETER InventoryPath
  Literal schema-1 JSON inventory exported for the intended user.
.PARAMETER IncludeHistoricalCoverage
  Include archived v2 names for historical comparison; default is current review.
.EXAMPLE
  .\tools\Compare-RideStoreAppInventory.ps1 -InventoryPath .\apps.json | Select-Object Name,MappingStatus,PendingReview
.INPUTS
  None.
.OUTPUTS
  PSCustomObject. Unselected, unapproved per-app review rows.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: Saved inventory; no elevation or operational handler required.
  File/environment inputs: Bounded inventory and catalog/store-app-review.psd1.
  Recovery: Read-only; creates no Windows or output-file state.
  Owner: RIDE-Windows maintainers. Version: 0.2.0.
  Changelog: 0.2.0: Load archived v2 coverage only on explicit request.
    0.1.0: Add exact-identity reconciliation without removal presets.
.LINK
  ../docs/migrations/store-app-removal-review.md
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string] $InventoryPath, [switch] $IncludeHistoricalCoverage)
$ErrorActionPreference = 'Stop'
$script:ScriptVersion = '0.2.0'
if ((Get-Item -LiteralPath $InventoryPath -ErrorAction Stop).Length -gt 10485760) { throw 'Saved app inventory exceeds its data bound.' }
$inventory = Get-Content -LiteralPath $InventoryPath -Raw -ErrorAction Stop | ConvertFrom-Json
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.StoreAppReview.psm1') -Force
Compare-RideStoreAppInventory -Inventory $inventory -IncludeHistoricalCoverage:$IncludeHistoricalCoverage
