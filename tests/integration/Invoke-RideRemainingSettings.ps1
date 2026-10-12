<#
.SYNOPSIS
  Verify either remaining-settings migration batch in a disposable Windows VM.
.DESCRIPTION
  Exercises every available named state, preview, idempotence and saved-run restore.
  Records missing tasks, bindings and scheme variants as unavailable. Uses local
  guest child-process execution. Network changes can interrupt the host transport;
  checkpoint recovery remains the outer boundary if collection cannot complete.
  Restores each captured run in finally; controller recovery resets the VM.
.PARAMETER Batch
  1 selects task/policy settings; 2 selects network, Defender, power and sound settings.
.PARAMETER Version
  Print the version without operational checks.
.EXAMPLE
  .\Invoke-RideRemainingSettings.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  String. Per-operation lifecycle and missing-resource evidence.
.NOTES
  Compatibility: Windows PowerShell 5.1 in disposable Windows 11.
  Prerequisites: Elevated guest; RIDE_INTEGRATION_VM=1; staged checkout.
  Recovery: Exact saved-run restore in finally and host clean checkpoint recovery.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add two focused remaining-settings acceptance selections.
#>
[CmdletBinding()]
param([ValidateSet(1,2)][int]$Batch=1,[switch]$Version)
$script:ScriptVersion='0.1.0'
if($Version){$script:ScriptVersion;return}
$ErrorActionPreference='Stop'
if($env:RIDE_INTEGRATION_VM -ne '1'){throw 'Run only inside the disposable VM through its host controller.'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'The disposable guest must be elevated.'}
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
if((Get-RidePlatform) -ne 'Windows 11'){throw 'These migrations require a disposable Windows 11 guest.'}
$operations=@((Get-RideCatalog).Operations | Where-Object MigrationBatch -eq "2026-10-10-remaining-settings-$Batch")
$expected=if($Batch -eq 1){17}else{19}
if($operations.Count -ne $expected){throw 'Remaining-settings batch inventory is incomplete.'}
# Independent scenarios restore before the next; keep scheme-selection recovery
# last so a platform-specific scheme failure cannot hide unrelated acceptance.
$operations=@($operations | Where-Object Kind -ne PowerScheme)+@($operations | Where-Object Kind -eq PowerScheme)
function ConvertTo-AcceptanceState($Current) { $Current | ConvertTo-Json -Depth 100 -Compress }
function Wait-DesiredState($Operation,$State) {
  $deadline=[DateTime]::UtcNow.AddSeconds(30)
  do { if(Test-RideDesiredState -Operation $Operation -State $State){return};Start-Sleep -Milliseconds 500 } while([DateTime]::UtcNow -lt $deadline)
  throw "Desired state failed: $($Operation.Id) / $State"
}
$passed=0;$unavailable=0;$variants=0;$stateCount=0;$failed=0
foreach($operation in $operations) {
  $original=Get-RideCurrentState -Operation $operation
  if($original.PSObject.Properties.Name -contains 'Available' -and -not $original.Available){Write-Output "Remaining-setting unavailable: $($operation.Id)";$unavailable++;continue}
  $originalText=ConvertTo-AcceptanceState $original
  $states=@($operation.States.Keys | Sort-Object)
  if($operation.Kind -eq 'PowerScheme') {
    foreach($state in $states){if($operation.States[$state] -notin $original.AvailableSchemes){Write-Output "Remaining-setting unavailable state: $($operation.Id) / $state";$variants++}}
    $states=@($states | Where-Object {$operation.States[$_] -in $original.AvailableSchemes})
  }
  $first=@($states | Where-Object {-not (Test-RideDesiredState -Operation $operation -State $_)}) | Select-Object -First 1
  if(-not $first){Write-Output "Remaining-setting has no available alternate state for recovery acceptance: $($operation.Id)";$unavailable++;continue}
  $plan=@(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $first)
  Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
  if((ConvertTo-AcceptanceState (Get-RideCurrentState $operation)) -cne $originalText){throw 'Apply preview changed Windows state.'}
  $runId=$null;$failure=$null
  try {
    $output=@(Invoke-RidePlan -Plan $plan -Confirm:$false)
    $runId=($output | Where-Object {$_ -is [string] -and $_ -match '^Run ID: '} | Select-Object -Last 1) -replace '^Run ID: ',''
    if(-not $runId){throw 'No captured run was returned.'}
    foreach($state in $states) {
      $statePlan=@(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $state)
      Invoke-RidePlan -Plan $statePlan -Confirm:$false | Out-Null
      Wait-DesiredState $operation $state
      if('No changes were needed; no state record was created.' -notin @(Invoke-RidePlan -Plan $statePlan -Confirm:$false)){throw 'Repeat apply changed Windows state.'}
      $stateCount++
    }
    $beforeRestore=ConvertTo-AcceptanceState (Get-RideCurrentState $operation)
    Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
    if((ConvertTo-AcceptanceState (Get-RideCurrentState $operation)) -cne $beforeRestore){throw 'Restore preview changed Windows state.'}
  }
  catch { if(-not $runId -and $_.Exception.Message -match 'Run ID: ([0-9a-f]{32})'){$runId=$Matches[1]};$failure=$_.Exception.Message }
  finally {if($runId){Restore-RideRun -RunId $runId -Confirm:$false | Out-Null}}
  if((ConvertTo-AcceptanceState (Get-RideCurrentState $operation)) -cne $originalText){throw "Exact recovery failed: $($operation.Id)"}
  if($failure){$failed++;Write-Output "Remaining-setting lifecycle failed after recovery: $($operation.Id): $failure";continue}
  $passed++;Write-Output "Remaining-setting lifecycle passed: $($operation.Id)"
}
Write-Output "Remaining-settings batch $Batch finished: $passed passed; $stateCount named states; $unavailable unavailable operations; $variants unavailable variants; $failed failed. Feature/UI/restart acceptance remains separate."
if($failed){throw "$failed remaining-setting lifecycle scenario(s) failed; collected transcript identifies each one."}
