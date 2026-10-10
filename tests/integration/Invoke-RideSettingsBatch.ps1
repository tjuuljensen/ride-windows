<#
.SYNOPSIS
  Verify the forty-setting migration inside a disposable Windows 11 VM.

.DESCRIPTION
  Exercises all explicit states, preview, repeat apply, baseline removal and exact
  registry value/type/existence recovery. Each operation is restored in finally.
  Does not restart Windows, invoke cleanup, or install packages. Registry lifecycle
  checks do not establish that undocumented preferences affect the visible UI.

.PARAMETER Version
  Print the version before operational checks.

.EXAMPLE
  .\Invoke-RideSettingsBatch.ps1 -Version

.INPUTS
  None.

.OUTPUTS
  System.String. Per-setting acceptance and completion messages.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on disposable Windows 11.
  Prerequisites: Elevated guest; RIDE_INTEGRATION_VM=1; staged repository.
  File/environment inputs: Catalog; machine/user saved runs; VM-only environment marker.
  Recovery: Exact restore in finally; restore the clean VM checkpoint after execution.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog: 0.1.0: Verify forty further optional registry operations.

.LINK
  docs/MIGRATION-PLAN.md
#>


[CmdletBinding()]
param([switch] $Version)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if ($env:RIDE_INTEGRATION_VM -ne '1') { throw 'Use this suite only inside a disposable VM with RIDE_INTEGRATION_VM=1.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The disposable guest must be elevated.' }
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $root 'modules/RIDE.Engine.psm1') -Force
if ((Get-RidePlatform) -ne 'Windows 11') { throw 'This migration suite requires Windows 11.' }
$ids = @(
  'windows.content-delivery',
  'windows.oem-preinstalled-app-suggestions',
  'windows.preinstalled-app-suggestions',
  'windows.silent-app-installation',
  'windows.suggested-content-310093',
  'windows.suggested-content-314559',
  'windows.suggested-content-338387',
  'windows.suggested-content-338388',
  'windows.suggested-content-338389',
  'windows.suggested-content-338393',
  'windows.suggested-content-353694',
  'windows.suggested-content-353696',
  'windows.suggested-content-353698',
  'windows.settings-pane-suggestions',
  'windows.post-setup-suggestions',
  'windows.implicit-text-personalization',
  'windows.implicit-ink-personalization',
  'windows.input-personalization-contact-harvesting',
  'windows.diagnostic-data-policy',
  'windows.linguistic-data-collection-policy',
  'windows.feedback-notifications-policy',
  'windows.error-reporting',
  'windows.ncsi-active-probing',
  'windows.msrt-update-offering',
  'windows.update-driver-policy',
  'windows.device-metadata-downloads',
  'windows.update-download-mode',
  'windows.automatic-restart-sign-on',
  'windows.storage-sense',
  'windows.recycle-bin-policy',
  'windows.lock-screen-policy',
  'windows.verbose-logon-status',
  'windows.linked-mapped-drives',
  'windows.attachment-zone-information',
  'windows.desktop-recycle-bin-icon',
  'windows.desktop-this-pc-icon',
  'windows.desktop-user-files-icon',
  'windows.desktop-control-panel-icon',
  'windows.desktop-network-icon',
  'windows.desktop-build-number'
)
foreach ($id in $ids) {
  $operation = Get-RideOperation -Id $id
  $original = Get-RideCurrentState -Operation $operation
  $states = @($operation.States.Keys | Where-Object { $_ -ne 'WindowsDefault' } | Sort-Object)
  $firstState = @($states | Where-Object { -not (Test-RideDesiredState -Operation $operation -State $_) })[0]
  $plan = @(Get-RideSingleOperationPlan -Id $id -Action Set -State $firstState)
  $null = Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false
  if (((Get-RideCurrentState -Operation $operation) | ConvertTo-Json -Compress) -cne ($original | ConvertTo-Json -Compress)) { throw "Preview changed $id." }
  $runId = $null
  $output = @()
  try {
    $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
    $runId = ($output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' } | Select-Object -Last 1) -replace '^Run ID: ', ''
    if (-not $runId) { throw "No saved run for $id." }
    foreach ($state in $states) {
      $statePlan = @(Get-RideSingleOperationPlan -Id $id -Action Set -State $state)
      $null = Invoke-RidePlan -Plan $statePlan -Confirm:$false
      if (-not (Test-RideDesiredState -Operation $operation -State $state)) { throw "Explicit state failed: $id ($state)." }
      $repeat = @(Invoke-RidePlan -Plan $statePlan -Confirm:$false)
      if ('No changes were needed; no state record was created.' -notin $repeat) { throw "Repeat apply changed $id ($state)." }
    }
    $beforePreview = Get-RideCurrentState -Operation $operation
    $null = Restore-RideRun -RunId $runId -WhatIf -Confirm:$false
    if (((Get-RideCurrentState -Operation $operation) | ConvertTo-Json -Compress) -cne ($beforePreview | ConvertTo-Json -Compress)) { throw "Restore preview changed $id." }
    $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $id -Action Unset) -Confirm:$false
    if (-not (Test-RideDesiredState -Operation $operation -State WindowsDefault)) { throw "Baseline failed: $id." }
  }
  catch {
    if (-not $runId -and $_.Exception.Message -match 'Run ID: ([0-9a-f]{32})') { $runId = $Matches[1] }
    throw
  }
  finally {
    if ($runId) { $null = Restore-RideRun -RunId $runId -Confirm:$false }
  }
  $restored = Get-RideCurrentState -Operation $operation
  if ($restored.Exists -ne $original.Exists -or ($original.Exists -and ($restored.Value -ne $original.Value -or $restored.ValueType -ne $original.ValueType))) { throw "Exact restore failed: $id." }
  Write-Output "Forty-setting registry lifecycle passed: $id"
}
Write-Output 'Forty-setting migration suite passed.'
