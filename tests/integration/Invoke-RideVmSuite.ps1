<#
.SYNOPSIS
  Exercise RIDE settings and package lifecycle behavior on a disposable VM.

.DESCRIPTION
  - Requires an explicit VM environment guard and an elevated session.
  - Applies, verifies, and restores changes; package checks may download installers.
  - Supports Windows 11 and Windows Server 2025 only.
  - Writes progress and failure details to the pipeline; changes Windows state
  and installs/removes packages as part of the integration scenarios.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\Invoke-RideVmSuite.ps1 -Version

.EXAMPLE
  Get-Help .\tests\integration\Invoke-RideVmSuite.ps1 -Full

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Scenario progress and completion; errors terminate the suite.

.NOTES
  Compatibility: Windows PowerShell 5.1 or PowerShell 7 on Windows 11 or Windows Server 2025.
  Prerequisites: - Administrator session and RIDE checkout in the VM; outbound access is
  required for package installer downloads.
  - Restore the VM's clean checkpoint after the run.
  File/environment inputs: - RIDE_INTEGRATION_VM must be set to '1' inside the disposable VM.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.3.0
  Changelog:
    - 0.1.0: Initial versioned integration suite.
  - 0.2.0: Add Windows 11 round-trip checks for network, update, and security settings.
  - 0.3.0: Add exact registry subtree round-trip checks for Explorer folder visibility.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

.LINK
  tests/integration/AUTOMATEDLAB.md

#>


[CmdletBinding()]
param([switch] $Version)

$script:ScriptVersion = '0.3.0'
if ($Version) {
  Write-Output $script:ScriptVersion
  return
}

$ErrorActionPreference = 'Stop'
if ($env:RIDE_INTEGRATION_VM -ne '1') { throw "Set RIDE_INTEGRATION_VM=1 only inside a disposable VM before running integration checks." }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the integration suite from an elevated PowerShell session.' }

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $root 'modules/RIDE.Engine.psm1') -Force
$target = Get-RidePlatform
if ($target -notin @('Windows 11', 'Windows Server 2025')) { throw "Unsupported integration VM target: $target" }

if ($target -eq 'Windows 11') {
  $inkingSetting = Get-RideOperation -Id 'windows.inking-typing-data'
  $inkingOriginal = Get-RideCurrentState -Operation $inkingSetting
  $inkingState = if ($inkingOriginal.Exists -and $inkingOriginal.Value -eq 0) { 'Enabled' } else { 'Disabled' }
  $inkingProfile = @{
    SchemaVersion = 1
    Name = 'Inking and typing registry integration'
    Operations = @(@{ Id = $inkingSetting.Id; State = $inkingState })
  }
  $inkingRun = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $inkingProfile) -Confirm:$false | ForEach-Object { $_ })
  $inkingRunIdLine = $inkingRun | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if (-not $inkingRunIdLine) { throw 'Inking and typing integration apply did not return a run ID.' }
  $inkingRunId = $inkingRunIdLine -replace '^Run ID: ', ''
  $inkingCurrent = Get-RideCurrentState -Operation $inkingSetting
  $inkingExpected = $inkingSetting.States[$inkingState]
  if ($null -eq $inkingExpected) {
    if ($inkingCurrent.Exists) { throw 'Enabling inking and typing data did not remove the per-user override.' }
  }
  elseif (-not $inkingCurrent.Exists -or $inkingCurrent.Value -ne $inkingExpected) {
    throw 'Disabling inking and typing data did not set the declared registry value.'
  }
  Restore-RideRun -RunId $inkingRunId -Confirm:$false
  $inkingRestored = Get-RideCurrentState -Operation $inkingSetting
  if ([bool]$inkingRestored.Exists -ne [bool]$inkingOriginal.Exists -or ($inkingOriginal.Exists -and ($inkingRestored.Value -ne $inkingOriginal.Value -or $inkingRestored.ValueType -ne $inkingOriginal.ValueType))) {
    throw 'Inking and typing exact restore did not recover the initial registry value.'
  }

$networkOperation = Get-RideOperation -Id 'windows.current-network-category'
$networkOriginal = Get-RideCurrentState -Operation $networkOperation
if (@($networkOriginal.Profiles).Count -gt 0) {
  $networkCategories = @($networkOriginal.Profiles.NetworkCategory | Select-Object -Unique)
  $networkTestState = if ($networkCategories.Count -eq 1 -and $networkCategories[0] -eq 'Public') { 'Private' } else { 'Public' }
  $networkProfile = @{
    SchemaVersion = 1
    Name = 'Network profile category integration'
    Operations = @(@{ Id = $networkOperation.Id; State = $networkTestState })
  }
  $networkRun = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $networkProfile) -Confirm:$false | ForEach-Object { $_ })
  if (-not (Test-RideDesiredState -Operation $networkOperation -State $networkTestState)) { throw "Network profile apply did not set all eligible profiles to $networkTestState." }
  $networkRunIdLine = $networkRun | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if ($networkRunIdLine) { Restore-RideRun -RunId ($networkRunIdLine -replace '^Run ID: ', '') -Confirm:$false }
  $networkRestored = Get-RideCurrentState -Operation $networkOperation
  $originalProfiles = @($networkOriginal.Profiles | Sort-Object InterfaceIndex, Name | Select-Object InterfaceIndex, Name, NetworkCategory)
  $restoredProfiles = @($networkRestored.Profiles | Sort-Object InterfaceIndex, Name | Select-Object InterfaceIndex, Name, NetworkCategory)
  if ((ConvertTo-Json -InputObject $restoredProfiles -Depth 4 -Compress) -ne (ConvertTo-Json -InputObject $originalProfiles -Depth 4 -Compress)) {
    throw 'Network profile restore did not recover each captured category.'
  }
}
else {
  Write-Warning 'Skipping network profile integration because Windows reports no non-domain connection profiles.'
}

foreach ($settingCase in @(
  @{ Id = 'windows.remote-assistance-policy'; State = 'Disabled' }
  @{ Id = 'windows.bitlocker-encryption-method'; State = 'AesCbc256' }
  @{ Id = 'windows.microsoft-product-updates'; State = 'Enabled' }
)) {
  $operation = Get-RideOperation -Id $settingCase.Id
  $before = Get-RideCurrentState -Operation $operation
  $profile = @{
    SchemaVersion = 1
    Name = "$($operation.Name) integration"
    Operations = @(@{ Id = $operation.Id; State = $settingCase.State })
  }
  $run = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $profile) -Confirm:$false | ForEach-Object { $_ })
  if (-not (Test-RideDesiredState -Operation $operation -State $settingCase.State)) { throw "$($operation.Name) integration apply did not reach '$($settingCase.State)'." }
  $runIdLine = $run | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if ($runIdLine) { Restore-RideRun -RunId ($runIdLine -replace '^Run ID: ', '') -Confirm:$false }
  $after = Get-RideCurrentState -Operation $operation
  if ((ConvertTo-Json -InputObject $after -Depth 4 -Compress) -ne (ConvertTo-Json -InputObject $before -Depth 4 -Compress)) {
    throw "$($operation.Name) integration restore did not recover the original registry state."
  }
}

foreach ($id in @('windows.music-folder-this-pc', 'windows.videos-folder-this-pc', 'windows.3d-objects-folder-this-pc')) {
  $operation = Get-RideOperation -Id $id
  $before = Get-RideCurrentState -Operation $operation
  $originalState = if ($before.PresentCount -eq 0) { 'Hidden' } elseif ($before.PresentCount -eq $before.TotalCount) { 'Visible' } else { 'Mixed' }
  $testState = if ($originalState -eq 'Hidden') { 'Visible' } else { 'Hidden' }
  $profile = @{
    SchemaVersion = 1
    Name = "$($operation.Name) exact registry-tree integration"
    Operations = @(@{ Id = $operation.Id; State = $testState })
  }
  $run = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $profile) -Confirm:$false | ForEach-Object { $_ })
  if (-not (Test-RideDesiredState -Operation $operation -State $testState)) { throw "$($operation.Name) integration apply did not reach '$testState'." }
  $runIdLine = $run | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if (-not $runIdLine) { throw "$($operation.Name) integration apply did not produce saved state for its change." }
  Restore-RideRun -RunId ($runIdLine -replace '^Run ID: ', '') -Confirm:$false
  $after = Get-RideCurrentState -Operation $operation
  $beforeJson = (ConvertTo-Json -InputObject $before.Trees -Depth 40 -Compress) -replace 'D:AI(?=\()', 'D:'
  $afterJson = (ConvertTo-Json -InputObject $after.Trees -Depth 40 -Compress) -replace 'D:AI(?=\()', 'D:'
  if ($afterJson -cne $beforeJson) {
    throw "$($operation.Name) restore did not recover its original registry subtree values and security descriptors. Before: $beforeJson After: $afterJson"
  }
}
}

$setting = Get-RideOperation -Id 'windows.show-known-extensions'
$original = Get-RideCurrentState -Operation $setting
$analystProfile = Get-RideProfile -Path (Join-Path $root 'profiles/analyst-basics.psd1')
$baselineProfile = Get-RideProfile -Path (Join-Path $root 'profiles/baseline.psd1')

try {
  $firstRun = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false | ForEach-Object { $_ })
  $runIdLine = $firstRun | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if (-not $runIdLine) { throw 'First apply did not return a run ID.' }
  $runId = $runIdLine -replace '^Run ID: ', ''

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false
  $status = @(Get-RideStatus -Profile $analystProfile)
  if (@($status | Where-Object { -not $_.InDesiredState }).Count -gt 0) { throw 'Repeated apply did not converge to the requested profile.' }

  Restore-RideRun -RunId $runId -Confirm:$false
  $afterRestore = Get-RideCurrentState -Operation $setting
  if ([bool]$afterRestore.Exists -ne [bool]$original.Exists -or ($original.Exists -and ($afterRestore.Value -ne $original.Value -or $afterRestore.ValueType -ne $original.ValueType))) {
    throw 'Exact setting restore did not recover the initial Explorer value.'
  }

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $baselineProfile) -Confirm:$false
  if (-not (Test-RideDesiredState -Operation $setting -State 'Disabled')) { throw 'Baseline profile did not set the documented Explorer state.' }

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false
  $removePlan = @(Get-RidePlan -Profile $analystProfile -Action Remove)
  $null = Invoke-RidePlan -Plan $removePlan -Confirm:$false
  foreach ($id in @('package.7zip', 'package.notepadpp')) {
    $package = Get-RideOperation -Id $id
    if ((Get-RideCurrentState -Operation $package).Present) { throw "Package removal failed: $id" }
  }

  $sysmon = Get-RideOperation -Id 'package.sysmon64'
  if ((Get-RideCurrentState -Operation $sysmon).Present) { throw 'Sysmon VM integration requires a clean snapshot without a pre-existing standalone Sysmon install.' }
  try {
    $installSysmon = @(Get-RideSingleOperationPlan -Id $sysmon.Id -Action Install)
    $null = Invoke-RidePlan -Plan $installSysmon -Confirm:$false
    if (-not (Get-RideCurrentState -Operation $sysmon).Present) { throw 'Sysmon installation did not register its service.' }
    $null = Invoke-RidePlan -Plan $installSysmon -Confirm:$false
    $removeSysmon = @(Get-RideSingleOperationPlan -Id $sysmon.Id -Action Remove)
    $null = Invoke-RidePlan -Plan $removeSysmon -Confirm:$false
    if ((Get-RideCurrentState -Operation $sysmon).Present) { throw 'Sysmon uninstallation did not remove its service.' }
  }
  finally {
    if ((Get-RideCurrentState -Operation $sysmon).Present) { Uninstall-RidePackage -Operation $sysmon }
  }

  Write-Output "VM integration suite passed on $target. Restore the VM checkpoint before reuse."
}
catch {
  Write-Error ("VM integration suite failed on {0}: {1}" -f $target, $_.Exception.Message)
  throw
}
