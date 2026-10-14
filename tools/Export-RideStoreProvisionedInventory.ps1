<#
.SYNOPSIS
  Export online Windows image provisioning as separate reference inventory.
.DESCRIPTION
  Collects provisioning in an already elevated process and writes inventory plus
  an explicit local DISM log. Never uninstalls, deprovisions, mounts or downloads.
.PARAMETER OutputPath
  Literal JSON file with an existing parent. A sibling .dism.log retains diagnostics.
.EXAMPLE
  .\tools\Export-RideStoreProvisionedInventory.ps1 -OutputPath .\provisioned-apps.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Saved inventory path, when written.
.NOTES
  Compatibility: Windows PowerShell 5.1; PowerShell 7 when DISM cmdlets are available.
  Prerequisites: Already elevated Windows process; otherwise postpone the task.
  File/environment inputs: RIDE.StoreAppReview module, JSON output and sibling log.
  Recovery: Reference files only; no Windows provisioning or app state mutation.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Prepare separate online provisioning evidence collection.
.LINK
  ../docs/store-app-inventory.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([Parameter(Mandatory)][string] $OutputPath)
$ErrorActionPreference='Stop'
$script:ScriptVersion='0.1.0'
$destination=[IO.Path]::GetFullPath($OutputPath)
if(-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)){throw 'Create the provisioning output parent explicitly.'}
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.StoreAppReview.psm1') -Force
if($PSCmdlet.ShouldProcess($destination,'Read online provisioning and save JSON plus local DISM diagnostics')){
  $inventory=Get-RideStoreProvisionedAppInventory -LogPath ($destination+'.dism.log')
  [IO.File]::WriteAllText($destination,($inventory|ConvertTo-Json -Depth 10)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
  $destination
}
