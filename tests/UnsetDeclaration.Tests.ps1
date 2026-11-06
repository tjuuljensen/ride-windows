<#
.SYNOPSIS
  Check per-operation unset selection, refusal and local ID completion.
.DESCRIPTION
  Uses catalog data, isolated CLI dispatch and mocked operational boundaries.
  No Windows setting, installer or saved run is changed.
.EXAMPLE
  Invoke-Pester ./tests/UnsetDeclaration.Tests.ps1
.NOTES
  Windows PowerShell 5.1 or PowerShell 7 with Pester 5.
#>
Describe 'Catalog-declared unset' {
  BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repo 'modules/RIDE.Engine.psm1') -Force
    Import-Module (Join-Path $repo 'modules/RIDE.CatalogValidation.psm1')
    $script:cli = Join-Path $repo 'ride.ps1'
    $script:runner = Join-Path $TestDrive 'ride.ps1'
    Copy-Item -LiteralPath $script:cli -Destination $script:runner
  }

  It 'refuses undeclared unset before planning, observation or execution, including preview' {
    Mock Import-Module {} -ParameterFilter { $Name -like '*RIDE.Engine.psm1' }
    Mock Set-RideLibraryContext {}
    Mock Get-RideOperation -ModuleName RIDE.Engine {
      # Tempting state names and null values cannot authorize an undeclared removal.
      @{ Id = $Id; Kind = $Id; Actions = @('Set'); BaselineState = 'WindowsDefault'
         States = @{ WindowsDefault = $null; Absent = 'Absent'; Disabled = 0 } }
    }
    Mock Get-RidePlan -ModuleName RIDE.Engine { throw 'Unexpected planning' }
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { throw 'Unexpected observation' }
    Mock Invoke-RidePlan { throw 'Unexpected execution' }
    foreach ($kind in @('RegistryValue','RegistryValueSet','DefenderExclusion','ShellFolder','DesktopShortcut','ProfileSetting','BootConfiguration')) {
      { & $script:runner unset $kind -Confirm:$false } | Should -Throw '*no declared override-removal state*'
      { & $script:runner unset $kind -WhatIf } | Should -Throw '*no declared override-removal state*'
    }
    { & $script:runner unset RegistryValue -State WindowsDefault } | Should -Throw '*does not accept -State*'
    Should -Invoke Get-RidePlan -ModuleName RIDE.Engine -Exactly 0
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Exactly 0
    Should -Invoke Invoke-RidePlan -Exactly 0
  }

  It 'preserves the catalog removal state even when the user-facing name is Disabled' {
    $plan = @(Get-RideSingleOperationPlan windows.file-operation-details -Action Unset)
    $plan.Count | Should -Be 1
    $plan[0].State | Should -BeExactly 'Disabled'
    ($null -eq $plan[0].Operation.States.Disabled) | Should -BeTrue
    { Get-RideSingleOperationPlan windows.show-known-extensions -Action Unset } | Should -Throw '*no declared override-removal state*'
  }

  It 'selects the declared delete-value state for <Id>' -TestCases @(
    @{ Id = 'windows.boot-failure-recovery-policy'; Expected = 'WindowsDefault' }
    @{ Id = 'windows.f8-boot-menu-policy'; Expected = 'Standard' }
    @{ Id = 'windows.dep-boot-policy'; Expected = 'OptIn' }
  ) {
    param($Id, $Expected)
    $plan = Get-RideSingleOperationPlan $Id -Action Unset
    $plan.State | Should -BeExactly $Expected
    ($null -eq $plan.Operation.States[$Expected]) | Should -BeTrue
  }

  It 'preserves explicit set for an API 1 library without inferring unset from a null state' {
    $manifest = Join-Path (Split-Path -Parent $script:cli) 'examples/library/ride-library.psd1'
    try {
      Set-RideLibraryContext -Library $manifest
      $id = 'example.library.preference-marker'
      $operation = Get-RideOperation $id
      $removeValue = @($operation.States.Keys | Where-Object { $null -eq $operation.States[$_] })[0]
      $removeValue | Should -Not -BeNullOrEmpty
      { Get-RideSingleOperationPlan $id -Action Unset } | Should -Throw '*no declared override-removal state*'
      (Get-RideSingleOperationPlan $id -Action Set -State $removeValue).State | Should -BeExactly $removeValue
    } finally { Set-RideLibraryContext }
  }

  It 'validates the exact removal effect and refuses malformed declarations during planning' {
    $scalar = (Get-RideOperation windows.file-operation-details).Clone()
    $scalar.UnsetState = 'Unknown'
    $writesValue = $scalar.Clone()
    $writesValue.UnsetState = 'Enabled'
    $coordinated = (Get-RideOperation windows.explorer-f1-help).Clone()
    $coordinated.UnsetState = 'Blocked'
    $unsupported = (Get-RideOperation windows.hibernation).Clone()
    $unsupported.UnsetState = 'Reduced'
    foreach ($invalid in @($scalar, $writesValue, $coordinated, $unsupported)) {
      $catalog = @{ SchemaVersion = 1; Operations = @($invalid); Groups = @() }
      @(Get-RideCatalogValidationErrors -Catalog $catalog) -join ' ' | Should -Match 'UnsetState'
      InModuleScope RIDE.Engine -Parameters @{ Operation = $invalid } {
        param($Operation)
        Mock Get-RideOperation { $Operation }
        { Get-RideSingleOperationPlan $Operation.Id -Action Unset } | Should -Throw '*no declared override-removal state*'
      }
    }
  }

  It 'completes only eligible IDs for named and positional unset while retaining set choices' {
    foreach ($prefix in @('unset windows.', '-Command unset -Id windows.')) {
      $line = "& '$script:cli' $prefix"
      $ids = (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText
      $ids | Should -Contain 'windows.file-operation-details'
      $ids | Should -Not -Contain 'windows.show-known-extensions'
    }
    $line = "& '$script:cli' set windows.show-known-ext"
    (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText | Should -Contain 'windows.show-known-extensions'
  }
}
