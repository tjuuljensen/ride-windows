<#
.SYNOPSIS
  Verify full observed RSAT selection and dependency-safe outlines using inert data.
.EXAMPLE
  Invoke-Pester ./tests/RsatCapabilityPlanning.Tests.ps1
.NOTES
  Pester 5, Windows PowerShell 5.1/PowerShell 7. Version: 0.1.0.
  No Windows provider, servicing, network, registry or payload is accessed.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.RsatCapabilityPlanning.psm1') -Force
  function New-RsatInventory {
    param([string[]]$Names=@('Rsat.ServerManager.Tools','Rsat.ActiveDirectory.DS-LDS.Tools','Rsat.BitLocker.Recovery.Tools'),[string]$State='NotPresent')
    [pscustomobject]@{
      SchemaVersion=1;Kind='WindowsComponentObservation';ReadyForMutation=$false;RecoverySupported=$false
      WindowsContext=[pscustomobject]@{ComputerName='TEST-VM';Build='26300';EditionId='EnterpriseEval';UpdateBuildRevision=9711;InstallationType='Client';ProductType='WinNT';NativeProcess=$true}
      Providers=@([pscustomobject]@{Kind='Capability';Status='Captured';Coverage='Capabilities reported by the current online image';Rows=@($Names | ForEach-Object {[pscustomobject]@{Name=($_+'~~~~0.0.1.0');StateObserved=$State}})})
    }
  }
}
Describe 'RSAT capability selection and dependency plan' {
  It 'selects all observed reviewed capabilities and puts every prerequisite first' {
    $model=& (Get-Module RIDE.RsatCapabilityPlanning) {Get-RideRsatDependencyModel}
    $inventory=New-RsatInventory -Names @($model.Keys | ForEach-Object {$_.Split('~')[0]})
    $plan=New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate
    $plan.Steps.Count | Should -Be $model.Count
    $plan.OriginalStates.Count | Should -Be $model.Count
    $plan.ReadyForMutation | Should -BeFalse
    $plan.RecoverySupported | Should -BeFalse
    foreach($step in $plan.Steps){foreach($dependency in $step.Dependencies){[array]::IndexOf($plan.InstallOrder,$dependency) | Should -BeLessThan ([array]::IndexOf($plan.InstallOrder,$step.Name))}}
    @($plan.Steps.Parameters | Where-Object {$_.ContainsKey('Source') -or $_.ContainsKey('LimitAccess')}).Count | Should -Be 0
  }
  It 'removes dependents first and restores prerequisites first' {
    $plan=New-RideRsatCapabilityPlan -Inventory (New-RsatInventory -State Installed) -DesiredState Absent -ServicingSource WindowsUpdate
    $plan.Steps.Name | Should -Be @('Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0','Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0','Rsat.ServerManager.Tools~~~~0.0.1.0')
    $plan.RestoreSteps.Name | Should -Be @('Rsat.ServerManager.Tools~~~~0.0.1.0','Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0','Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0')
  }
  It 'preserves pre-existing installed prerequisites in install recovery' {
    $inventory=New-RsatInventory
    $inventory.Providers[0].Rows[0].StateObserved='Installed'
    $plan=New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate
    $plan.Steps.Count | Should -Be 2
    $plan.RestoreSteps.Name | Should -Not -Contain 'Rsat.ServerManager.Tools~~~~0.0.1.0'
    $plan.OriginalStates[2].State | Should -Be 'Installed'
  }
  It 'distinguishes no-change observations from an empty selection' {
    (New-RideRsatCapabilityPlan -Inventory (New-RsatInventory -State Installed) -DesiredState Present -ServicingSource WindowsUpdate).Status | Should -Be 'NoChangeObserved'
    $inventory=New-RsatInventory -Names @('OpenSSH.Client')
    {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate} | Should -Throw '*No RSAT capabilities*'
  }
  It 'does not silently omit an unknown RSAT member or capability version' {
    foreach($name in @('Rsat.Future.Tools~~~~0.0.1.0','Rsat.Dns.Tools~~~~0.0.2.0','RsatUnreviewed~~~~0.0.1.0')){
      $inventory=New-RsatInventory
      $inventory.Providers[0].Rows+= [pscustomobject]@{Name=$name;StateObserved='NotPresent'}
      {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate} | Should -Throw '*Unreviewed observed RSAT*'
    }
  }
  It 'refuses a missing prerequisite or inconsistent installed dependency' {
    $inventory=New-RsatInventory -Names @('Rsat.ActiveDirectory.DS-LDS.Tools')
    {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate} | Should -Throw '*prerequisite*not observed*'
    $inventory=New-RsatInventory
    $inventory.Providers[0].Rows[1].StateObserved='Installed'
    {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Absent -ServicingSource WindowsUpdate} | Should -Throw '*installed-state dependency mismatch*'
  }
  It 'refuses pending states and incomplete provider capture' {
    $inventory=New-RsatInventory -State InstallPending
    {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate} | Should -Throw '*pending or unknown*'
    $inventory.Providers[0].Status='Unavailable';$inventory.Providers[0].Rows=$null
    {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate} | Should -Throw '*complete captured capability provider*'
  }
  It 'does not reinterpret Server roles or unreviewed client editions as client capabilities' {
    $inventory=New-RsatInventory
    $inventory.WindowsContext.ProductType='ServerNT'
    {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate} | Should -Throw '*Windows 11 client*'
    $inventory.WindowsContext.ProductType='WinNT';$inventory.WindowsContext.EditionId='Core'
    {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate} | Should -Throw '*Pro and Enterprise*'
  }
  It 'rejects duplicate identities through the inventory validator' {
    $inventory=New-RsatInventory
    $inventory.Providers[0].Rows+= $inventory.Providers[0].Rows[0]
    {New-RideRsatCapabilityPlan -Inventory $inventory -DesiredState Present -ServicingSource WindowsUpdate} | Should -Throw '*duplicate captured component row*'
  }
  It 'completes the explicit source choice without collecting an inventory' {
    $line='New-RideRsatCapabilityPlan -ServicingSource Win'
    @([Management.Automation.CommandCompletion]::CompleteInput($line,$line.Length,$null).CompletionMatches.CompletionText) | Should -Be @('WindowsUpdate')
  }
}
