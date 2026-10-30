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
  1 selects task, policy, Explorer, three BitLocker drive-method settings, the
  Click to Do and Storage Sense candidates, and the BitLocker Wizard and Power
  Options current-user desktop shortcut candidates; 2 selects network, Defender,
  power and sound settings.
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
  Owner: RIDE-Windows maintainers. Version: 0.3.4.
  Changelog: 0.3.4: Include the BitLocker Wizard and Power Options shortcut candidates in batch 1 without launching them.
    0.3.3: Include the Storage Sense machine-policy candidate behind a Windows policy-edition guard in batch 1.
    0.3.2: Include the pending current-user Click to Do policy candidate in batch 1 for lifecycle and exact-recovery acceptance.
    0.3.1: Include three pending BitLocker drive-type policies in batch 1 for future-encryption value and exact-restore acceptance.
    0.3.0: Enable only declared Windows 11 candidates in the private guest catalog for their selected lifecycle acceptance; published target support remains unchanged.
    0.2.0: Add the Hash value and Certutil context-menu registry settings to batch 1.
    0.1.0: Add two focused remaining-settings acceptance selections.
#>
[CmdletBinding()]
param([ValidateSet(1,2)][int]$Batch=1,[switch]$Version)
$script:ScriptVersion='0.3.4'
if($Version){$script:ScriptVersion;return}
$ErrorActionPreference='Stop'
if($env:RIDE_INTEGRATION_VM -ne '1'){throw 'Run only inside the disposable VM through its host controller.'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'The disposable guest must be elevated.'}
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
if((Get-RidePlatform) -ne 'Windows 11'){throw 'These migrations require a disposable Windows 11 guest.'}
$catalog=Get-RideCatalog
$operations=@($catalog.Operations | Where-Object MigrationBatch -eq "2026-10-10-remaining-settings-$Batch")
if($Batch -eq 1){
  $bitLockerPolicyIds=@(
    'windows.bitlocker-encryption-method-os'
    'windows.bitlocker-encryption-method-fixed-data'
    'windows.bitlocker-encryption-method-removable-data'
  )
  $bitLockerCandidates=@($catalog.Operations | Where-Object Id -In $bitLockerPolicyIds)
  if($bitLockerCandidates.Count -ne $bitLockerPolicyIds.Count){throw 'Remaining-settings batch 1 is missing a BitLocker drive-method candidate.'}
  $clickToDoCandidate=@($catalog.Operations | Where-Object Id -CEQ 'windows.click-to-do-policy')
  if($clickToDoCandidate.Count -ne 1 -or 'Windows 11' -notin @($clickToDoCandidate[0].CandidateTargets)){throw 'Remaining-settings batch 1 is missing the declared Windows 11 Click to Do candidate.'}
  $storageSenseCandidate=@($catalog.Operations | Where-Object Id -CEQ 'windows.storage-sense-global-policy')
  if($storageSenseCandidate.Count -ne 1 -or 'Windows 11' -notin @($storageSenseCandidate[0].CandidateTargets) -or -not $storageSenseCandidate[0].RequiresAdmin){throw 'Remaining-settings batch 1 is missing the declared elevated Windows 11 Storage Sense policy candidate.'}
  $shortcutCandidateIds=@('windows.bitlocker-wizard-shortcut','windows.power-options-shortcut')
  $shortcutCandidates=@($catalog.Operations | Where-Object Id -In $shortcutCandidateIds)
  if($shortcutCandidates.Count -ne $shortcutCandidateIds.Count -or @($shortcutCandidates | Where-Object {'Windows 11' -notin @($_.CandidateTargets) -or $_.Handler -cne 'DesktopShortcut' -or $_.RequiresAdmin}).Count){throw 'Remaining-settings batch 1 is missing a declared current-user Windows 11 shortcut candidate.'}
  $operations=@($operations)+$bitLockerCandidates+$clickToDoCandidate+$storageSenseCandidate+$shortcutCandidates
}
$expected=if($Batch -eq 1){28}else{19}
if($operations.Count -ne $expected){throw 'Remaining-settings batch inventory is incomplete.'}
$acceptanceTarget=Get-RidePlatform
$candidateIds=@()
foreach($operation in $operations){
  if($acceptanceTarget -in @($operation.SupportedTargets)){continue}
  if(-not $operation.PendingAcceptance -or $acceptanceTarget -notin @($operation.CandidateTargets)){throw "Operation does not declare the guest as an accepted or candidate target: $($operation.Id)"}
  $operation.SupportedTargets=@($acceptanceTarget)
  $operation.PendingAcceptance=$false
  $candidateIds+= $operation.Id
}
if($candidateIds.Count){
  & (Get-Module RIDE.Engine) {param($Catalog) $script:RideLibraryContext=@{Catalog=$Catalog;Libraries=@();ProfileFiles=@()}} $catalog
  Write-Output ("Candidate lifecycle scope enabled only in the private guest catalog for {0}: {1}. Published catalog support is unchanged." -f $acceptanceTarget,($candidateIds -join ', '))
}
# Independent scenarios restore before the next; keep scheme-selection recovery
# last so a platform-specific scheme failure cannot hide unrelated acceptance.
$operations=@($operations | Where-Object Kind -ne PowerScheme)+@($operations | Where-Object Kind -eq PowerScheme)
function ConvertTo-AcceptanceState($Current) { $Current | ConvertTo-Json -Depth 100 -Compress }
function Get-RegistryValueSetDifferences($Before,$After) {
  foreach($prior in @($Before.Values)){
    $current=@($After.Values|Where-Object Key -CEQ $prior.Key)
    if($current.Count -ne 1){[pscustomobject]@{Key=$prior.Key;Difference='MissingOrDuplicate';BeforeExists=$prior.Exists;AfterCount=$current.Count};continue}
    $value=$current[0]
    $sameValue=if($null -eq $prior.Value){$null -eq $value.Value}else{[string]$prior.Value -ceq [string]$value.Value}
    if($prior.Exists -ne $value.Exists -or $prior.KeyExisted -ne $value.KeyExisted -or $prior.ValueType -cne $value.ValueType -or -not $sameValue){
      [pscustomobject]@{Key=$prior.Key;Difference='StateMismatch';BeforeExists=$prior.Exists;AfterExists=$value.Exists;BeforeKeyExisted=$prior.KeyExisted;AfterKeyExisted=$value.KeyExisted;BeforeType=$prior.ValueType;AfterType=$value.ValueType;ValueMatches=$sameValue}
    }
  }
}
function Wait-DesiredState($Operation,$State) {
  $deadline=[DateTime]::UtcNow.AddSeconds(30)
  do { if(Test-RideDesiredState -Operation $Operation -State $State){return};Start-Sleep -Milliseconds 500 } while([DateTime]::UtcNow -lt $deadline)
  throw "Desired state failed: $($Operation.Id) / $State"
}
$passed=0;$unavailable=0;$variants=0;$stateCount=0;$failed=0
foreach($operation in $operations) {
  if($operation.Id -ceq 'windows.storage-sense-global-policy') {
    $editionId=[string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID)
    if($editionId -notmatch '^(Professional|Enterprise|Education|IoTEnterprise)') { throw "Storage Sense policy acceptance requires a Microsoft-listed Windows policy edition; detected EditionID '$editionId'." }
  }
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
  $restored=Get-RideCurrentState $operation
  if((ConvertTo-AcceptanceState $restored) -cne $originalText){
    $differences=if($operation.Kind -eq 'RegistryValueSet'){@(Get-RegistryValueSetDifferences $original $restored|ForEach-Object { '{0}:{1}[exists {2}->{3}, key {4}->{5}, type {6}->{7}, value-match {8}]' -f $_.Key,$_.Difference,$_.BeforeExists,$_.AfterExists,$_.BeforeKeyExisted,$_.AfterKeyExisted,$_.BeforeType,$_.AfterType,$_.ValueMatches }) -join ', '}else{'Handler state differed; detailed values omitted'}
    throw "Exact recovery failed: $($operation.Id). Differences: $differences"
  }
  if($failure){$failed++;Write-Output "Remaining-setting lifecycle failed after recovery: $($operation.Id): $failure";continue}
  $passed++;Write-Output "Remaining-setting lifecycle passed: $($operation.Id)"
}
Write-Output "Remaining-settings batch $Batch finished: $passed passed; $stateCount named states; $unavailable unavailable operations; $variants unavailable variants; $failed failed. Feature/UI/restart acceptance remains separate."
if($failed){throw "$failed remaining-setting lifecycle scenario(s) failed; collected transcript identifies each one."}
