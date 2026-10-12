<#
.SYNOPSIS
  Exercise the sixty-setting migration inside a disposable Windows 11 VM.
.DESCRIPTION
  Verifies all named states, preview, repeat apply and exact captured recovery.
  Restores each setting in finally. Does not restart Windows, install packages,
  encrypt drives or change developer-workstation settings. Unavailable power
  settings are reported separately, never counted as passed lifecycle scenarios.
.PARAMETER Selection
  All (default) selects all sixty settings. Recovery12 selects the BCD recovery
  policy and eleven coordinated registry settings awaiting complete evidence.
.PARAMETER Version
  Print the script version before operational checks.
.EXAMPLE
  .\Invoke-RideSettingsBatch60.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  String. Per-setting acceptance and availability messages.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on disposable Windows 11.
  Prerequisites: Elevated guest; RIDE_INTEGRATION_VM=1; staged checkout.
  Recovery: Saved-run restore in finally; controller restores clean checkpoint.
  Owner: RIDE-Windows maintainers. Version: 0.2.0.
  Changelog:
  - 0.2.0: Select the twelve BCD/coordinated recovery acceptance scenarios.
  - 0.1.0: Verify sixty settings, including coordinated value recovery.
#>
[CmdletBinding()]
param([ValidateSet('All', 'Recovery12')][string] $Selection = 'All', [switch] $Version)
$script:ScriptVersion = '0.2.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if ($env:RIDE_INTEGRATION_VM -ne '1') { throw 'Run only inside the disposable VM through its host controller.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The disposable guest must be elevated.' }
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
if ((Get-RidePlatform) -ne 'Windows 11') { throw 'This batch requires Windows 11.' }

function ConvertTo-AcceptanceState($Operation, $Current) {
  if ($Operation.Kind -eq 'RegistryKeySet') {
    # Windows can recalculate DACL auto-inherited flags when reconstructing keys.
    # Retain owner/group/ACE/value comparison, as in the existing namespace suite.
    foreach ($tree in $Current.Trees) {
      if ($tree.Exists) {
        $stack = [Collections.Generic.Stack[object]]::new()
        $stack.Push($tree.Root)
        while ($stack.Count) {
          $node = $stack.Pop()
          if ($node.SecurityDescriptor) { $node.SecurityDescriptor = [regex]::Replace($node.SecurityDescriptor, '(?<=D:)(?:AI|AR)', '') }
          foreach ($child in $node.Children) { $stack.Push($child) }
        }
      }
    }
  }
  $Current | ConvertTo-Json -Depth 100 -Compress
}
$operations = @((Get-RideCatalog).Operations | Where-Object MigrationBatch -eq '2026-10-10-settings60')
if ($operations.Count -ne 60) { throw 'The sixty-setting batch inventory is incomplete.' }
if ($Selection -eq 'Recovery12') {
  $operations = @($operations | Where-Object { $_.Kind -eq 'RegistryValueSet' -or $_.Id -eq 'windows.boot-failure-recovery-policy' })
  if ($operations.Count -ne 12 -or @($operations | Where-Object Kind -eq 'RegistryValueSet').Count -ne 11) { throw 'The twelve-setting recovery inventory is incomplete.' }
}
Write-Output "Sixty-setting selection: $Selection; $($operations.Count) operations."
$passed = 0; $unavailable = 0
foreach ($operation in $operations) {
  $original = Get-RideCurrentState -Operation $operation
  if ($operation.Kind -eq 'PowerSetting' -and -not $original.Available) {
    Write-Output "Sixty-setting unavailable on this device: $($operation.Id)"
    $unavailable++; continue
  }
  $originalText = ConvertTo-AcceptanceState $operation $original
  $states = @($operation.States.Keys | Sort-Object)
  $first = @($states | Where-Object { -not (Test-RideDesiredState -Operation $operation -State $_) })[0]
  $plan = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $first)
  Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
  if ((ConvertTo-AcceptanceState $operation (Get-RideCurrentState -Operation $operation)) -cne $originalText) { throw "Preview changed $($operation.Id)." }
  $runId = $null
  try {
    $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
    $runId = ($output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' } | Select-Object -Last 1) -replace '^Run ID: ', ''
    if (-not $runId) { throw "No saved run for $($operation.Id)." }
    foreach ($state in $states) {
      $statePlan = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $state)
      Invoke-RidePlan -Plan $statePlan -Confirm:$false | Out-Null
      if (-not (Test-RideDesiredState -Operation $operation -State $state)) { throw "State failed: $($operation.Id) / $state" }
      if ('No changes were needed; no state record was created.' -notin @(Invoke-RidePlan -Plan $statePlan -Confirm:$false)) { throw "Repeat changed $($operation.Id)." }
    }
    $beforeRestore = ConvertTo-AcceptanceState $operation (Get-RideCurrentState -Operation $operation)
    Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
    if ((ConvertTo-AcceptanceState $operation (Get-RideCurrentState -Operation $operation)) -cne $beforeRestore) { throw "Restore preview changed $($operation.Id)." }
  }
  catch {
    if (-not $runId -and $_.Exception.Message -match 'Run ID: ([0-9a-f]{32})') { $runId = $Matches[1] }
    throw
  }
  finally { if ($runId) { Restore-RideRun -RunId $runId -Confirm:$false | Out-Null } }
  if ((ConvertTo-AcceptanceState $operation (Get-RideCurrentState -Operation $operation)) -cne $originalText) { throw "Exact restore failed: $($operation.Id)." }
  $passed++
  Write-Output "Sixty-setting lifecycle passed: $($operation.Id)"
}
Write-Output "Sixty-setting suite finished ($Selection): $passed passed; $unavailable unavailable; feature/UI/restart acceptance remains separate."
