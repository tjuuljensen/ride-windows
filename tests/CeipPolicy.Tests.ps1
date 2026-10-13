<#
.SYNOPSIS
  Verify Windows CEIP policy inversion and literal recovery boundaries.
.DESCRIPTION
  Uses metadata and mocked engine/registry calls. No collection, network, live
  privacy preference, App-V activation, package or disposable VM is invoked.
.EXAMPLE
  Invoke-Pester ./tests/CeipPolicy.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-13: Cover opt-out/opt-in/removal and pending scalar policy.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}
Describe 'Windows CEIP policy' {
  It 'retains inverted Windows Group Policy wording and separates removal from explicit opt-in' {
    $op = Get-RideOperation windows.ceip-participation-policy
    $op.States.OptedOut | Should -Be 0
    $op.States.OptedIn | Should -Be 1
    $op.States.WindowsDefault | Should -BeNullOrEmpty
    $op.RegistryPath | Should -Be 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
    $op.ValueName | Should -Be 'CEIPEnable'
    $op.Description | Should -Match 'legacy reverse rather than explicit opt-in'
    $op.Description | Should -Match 'not verified current collection'
    @(Get-RideSingleOperationPlan -Id $op.Id -Action Unset)[0].State | Should -Be 'WindowsDefault'
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
  }
  It 'keeps candidate application blocked before any live inspection or write' {
    InModuleScope RIDE.Engine {
      $op = Get-RideOperation windows.ceip-participation-policy
      $op.PendingAcceptance | Should -BeTrue
      $op.SupportedTargets.Count | Should -Be 0
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideCurrentState { throw 'must not inspect blocked candidate' }
      Mock Set-RideSettingState {}
      $plan = @(Get-RideSingleOperationPlan -Id $op.Id -Action Set -State OptedOut)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Set-RideSettingState -Times 0
    }
  }
  It 'captures actual prior type before a failed write and preserves preview isolation' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'ceip-state') } {
      param($Root)
      $script:CeipRoot = $Root
      $op = (Get-RideOperation windows.ceip-participation-policy).Clone()
      $op.SupportedTargets = @('Windows 11') # Test fixture, not a support declaration.
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { $script:CeipRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:CeipRoot -Force | Out-Null; $script:CeipRoot }
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; ValueType = 'String'; Value = 'custom old CEIP state' } }
      Mock Get-Item { [pscustomobject]@{ KeyExists = $true } } -ParameterFilter { $LiteralPath -eq 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' }
      Mock Set-RideSettingState { throw 'CEIP policy write fixture' }
      $plan = @([pscustomobject]@{ Operation = $op; State = 'OptedOut' })
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      Should -Invoke Set-RideSettingState -Times 0
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*CEIP policy write fixture*'
      $records = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter windows.ceip-participation-policy.json)
      $snapshot = (Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json).Snapshot
      $snapshot.ValueType | Should -Be 'String'
      $snapshot.Value | Should -Be 'custom old CEIP state'
      $snapshot.KeyExisted | Should -BeTrue
    }
  }
  It 'completes both participation states and remains outside recommended profiles' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    $line = "& '$path' set windows.ceip-participation-policy -State opt"
    $matches = [Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches
    @($matches.CompletionText | Sort-Object) | Should -Be @('OptedIn', 'OptedOut')
    (Get-RideProfile).Operations.Id | Should -Not -Contain 'windows.ceip-participation-policy'
  }
}
