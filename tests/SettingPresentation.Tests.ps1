<#
.SYNOPSIS
  Verify setting scope, requirements and presentation without changing Windows.
.DESCRIPTION
  Uses catalog fixtures and mocked live-state handlers. Checks that scope does
  not imply enforcement, evidence gaps remain explicit, and presentation reaches
  discovery, group details, profile previews and both status modes.
.EXAMPLE
  Invoke-Pester .\tests\SettingPresentation.Tests.ps1
.INPUTS
  None. Invoked through Pester.
.OUTPUTS
  Pester test results.
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
  No state-changing Windows calls. Live-state inspection is mocked.
#>

BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'modules/RIDE.SettingPresentation.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.Discovery.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.CatalogValidation.psm1') -Force
  $script:Catalog = Get-RideCatalog
}

Describe 'Setting scope and evidence' {
  It 'identifies only live user execution without implying an intended-user check' {
    InModuleScope RIDE.SettingPresentation {
      Mock Get-RideSettingExecutionIdentity { 'FixtureAdmin (S-1-5-21-123); intended user not verified' }
      $user = @{ Kind = 'RegistryValue'; Scope = 'User'; RequiresAdmin = $false }
      $machine = @{ Kind = 'RegistryValue'; Scope = 'Machine'; RequiresAdmin = $true }
      (Get-RideSettingPresentation -Operation $user).ExecutionIdentity | Should -BeNullOrEmpty
      (Get-RideSettingPresentation -Operation $machine -IncludeExecutionIdentity).ExecutionIdentity | Should -BeNullOrEmpty
      $live = Get-RideSettingPresentation -Operation $user -IncludeExecutionIdentity
      $live.ExecutionIdentity | Should -Match 'FixtureAdmin.*intended user not verified'
      $live.AppliesTo | Should -Be 'Current Windows execution user'
      Should -Invoke Get-RideSettingExecutionIdentity -Exactly 1
    }
  }

  It 'does not classify an unknown policy-looking registry path by its hive or name' {
    $operation = @{ Kind = 'RegistryValue'; Scope = 'User'; RequiresAdmin = $false; RegistryPath = 'HKCU:\Software\Policies\Fixture' }
    $row = [pscustomobject]@{ Id = 'fixture.unknown'; CurrentValue = 1; EffectiveDefault = 'Permitted' } |
      Add-RideSettingPresentation -Operation $operation
    $row.Scope | Should -Be 'User'
    $row.RequiresAdmin | Should -BeFalse
    $row.Behavior | Should -Be 'Unverified'
    $row.GuiEffect | Should -Match 'Unverified'
    $row.Requirements | Should -Match 'not yet reviewed'
    $row.EffectivePolicy | Should -Match 'Not inspected'
    $row.EffectiveDefault | Should -Be 'Permitted'
    $row.CurrentValue | Should -Be 1
    $row.ExecutionIdentity | Should -BeNullOrEmpty
  }

  It 'separates current-user enforcement from administrator privileges' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'windows.sound-scheme-change-policy'
    $row = (Get-RideCatalogRows -Catalog $script:Catalog) | Where-Object Id -eq $operation.Id
    $row.Scope | Should -Be 'User'
    $row.RequiresAdmin | Should -BeFalse
    $row.Behavior | Should -Be 'Enforced policy'
    $row.GuiEffect | Should -Match 'Blocked prevents'
    $row.Requirements | Should -Match 'Pro, Enterprise, Education'
  }

  It 'does not turn a machine preference into an enforced policy' {
    $operation = @{ Kind = 'RegistryValue'; Scope = 'Machine'; RequiresAdmin = $true; SettingPresentation = @{ Behavior = 'Preference'; GuiEffect = 'Editable' } }
    $row = [pscustomobject]@{ Id = 'fixture.preference' } | Add-RideSettingPresentation -Operation $operation
    $row.RequiresAdmin | Should -BeTrue
    $row.Behavior | Should -Be 'Preference'
    $row.GuiEffect | Should -Be 'Editable'
  }

  It 'preserves package and mixed-group lifecycle meaning' {
    $package = @{ Kind = 'Package'; Scope = 'User'; RequiresAdmin = $false }
    (Get-RideSettingPresentation -Operation $package).Behavior | Should -BeNullOrEmpty
    $row = [pscustomobject]@{ Scope = ''; RequiresAdmin = $null } | Add-RideSettingPresentation -Operation @{ Members = @('fixture.user', 'fixture.machine') }
    $row.Scope | Should -Be ''
    $row.Behavior | Should -Be 'Varies by member'
    $row.Requirements | Should -Match 'All selected member requirements'
  }

  It 'shows requirements and fixed policy level in literal search results' {
    $row = Find-RideCatalog -Catalog $script:Catalog -Query 'Microsoft Edge startup boost' -Field Name
    $row.Id | Should -Be 'application.edge-startup-boost'
    $row.Scope | Should -Be 'Machine'
    $row.RequiresAdmin | Should -BeTrue
    $row.Requirements | Should -Match '88 or later'
    $row.OtherSupportedChoices | Should -Match 'mandatory path only'
  }

  It 'explains the retained Advanced state without changing its recovery contract' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'windows.defender-cloud-membership'
    $operation.States.Advanced | Should -Be 2
    $operation.States.Disabled | Should -Be 0
    $operation.States.WindowsDefault | Should -BeNullOrEmpty
    $operation.Scope | Should -Be 'Machine'
    $operation.Rollback | Should -Be 'Exact'
    $row = Get-RideSettingPresentation -Operation $operation
    $row.Requirements | Should -Match 'no separate Microsoft 365 or Defender for Endpoint'
    $row.Requirements | Should -Match 'inference; local-account VM acceptance pending'
    $operation.Description | Should -Match 'same effect on Windows 11'
  }
}

Describe 'Setting presentation validation' {
  It 'rejects a scalar registry path in the wrong scope' {
    $operation = ($script:Catalog.Operations | Where-Object Id -eq 'windows.show-known-extensions').Clone()
    $operation.RegistryPath = 'HKLM:\Software\Fixture'
    $errors = @(Get-RideCatalogValidationErrors -Catalog @{ SchemaVersion = 1; Operations = @($operation); Groups = @() })
    $errors | Should -Contain 'Registry path conflicts with declared scope: windows.show-known-extensions'
  }

  It 'rejects a machine setting without elevation' {
    $operation = ($script:Catalog.Operations | Where-Object Id -eq 'application.edge-startup-boost').Clone()
    $operation.RequiresAdmin = $false
    $errors = @(Get-RideCatalogValidationErrors -Catalog @{ SchemaVersion = 1; Operations = @($operation); Groups = @() })
    $errors | Should -Contain 'Machine settings require elevation: application.edge-startup-boost'
  }

  It 'rejects invented behavior and missing authoritative evidence' {
    $operation = ($script:Catalog.Operations | Where-Object Id -eq 'application.edge-startup-boost').Clone()
    $operation.SettingPresentation = $operation.SettingPresentation.Clone()
    $operation.SettingPresentation.Behavior = 'AlwaysSecure'
    $operation.SettingPresentation.ReferenceUris = @('https://example.invalid/guessed-setting')
    $errors = @(Get-RideCatalogValidationErrors -Catalog @{ SchemaVersion = 1; Operations = @($operation); Groups = @() })
    $errors | Should -Contain 'Invalid setting behavior: application.edge-startup-boost'
    $errors | Should -Contain 'Setting presentation requires authoritative HTTPS references: application.edge-startup-boost'
  }

  It 'accepts existing schema-1 metadata without the optional presentation block' {
    $operation = ($script:Catalog.Operations | Where-Object Id -eq 'windows.show-known-extensions').Clone()
    $operation.Remove('SettingPresentation')
    @(Get-RideCatalogValidationErrors -Catalog @{ SchemaVersion = 1; Operations = @($operation); Groups = @() }).Count | Should -Be 0
  }
}

Describe 'Live presentation with mocked state' {
  BeforeEach {
    Mock Get-RideSettingExecutionIdentity -ModuleName RIDE.SettingPresentation { 'FixtureUser (S-1-5-21-123); intended user not verified' }
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { [pscustomobject]@{ Exists = $true; Value = 1; ValueType = 'DWord' } }
    Mock Get-RidePlatform -ModuleName RIDE.Engine { 'Windows 11' }
    Mock Get-RideSettingPresentation -ModuleName RIDE.Engine {
      param($Operation)
      RIDE.SettingPresentation\Get-RideSettingPresentation -Operation $Operation
    }
  }

  It 'includes scope and requirements in default status objects' {
    Mock Test-RideStatusView -ModuleName RIDE.Engine { param($Operation) $Operation.Id -eq 'windows.defender-cloud-membership' }
    $row = Get-RideStatus -View security | Where-Object Id -eq 'windows.defender-cloud-membership'
    $row.Scope | Should -Be 'Machine'
    $row.RequiresAdmin | Should -BeTrue
    $row.Requirements | Should -Match 'paid MAPS membership'
    $row.EffectivePolicy | Should -Match 'Not inspected'
  }

  It 'includes scope and GUI effect in profile status and preview' {
    $profile = @{ SchemaVersion = 1; Name = 'Presentation fixture'; Operations = @(@{ Id = 'windows.sound-scheme-change-policy'; State = 'Blocked' }) }
    $row = Get-RideStatus -Profile $profile
    $row.Scope | Should -Be 'User'
    $row.RequiresAdmin | Should -BeFalse
    $row.Behavior | Should -Be 'Enforced policy'
    $row.DesiredState | Should -Be 'Blocked'
    $text = Show-RidePlan -Plan @(Get-RidePlan -Profile $profile) | Out-String -Width 160
    $text | Should -Match 'Requirements'
    $text | Should -Match 'Pro, Enterprise, Education'
    $text | Should -Match 'GuiEffect'
  }

  It 'includes metadata in single-setting and mixed-group details' {
    Mock Get-RideOperation -ModuleName RIDE.Engine {
      param($Id)
      if ($Id -eq 'fixture.group') { return @{ Id = 'fixture.group'; Name = 'Mixed scope'; Members = @('windows.show-known-extensions', 'application.edge-startup-boost') } }
      (Get-RideCatalog).Operations | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
    }
    $text = Show-RideOperation -Id 'application.edge-startup-boost' | Out-String -Width 160
    $text | Should -Match 'Enforced policy'
    $text | Should -Match 'mandatory path only'
    $groupText = Show-RideOperation -Id 'fixture.group' | Out-String -Width 160
    $groupText | Should -Match 'Preference'
    $groupText | Should -Match 'Enforced policy'
    $groupText | Should -Match 'RequiresAdmin\s+: False'
    $groupText | Should -Match 'RequiresAdmin\s+: True'
  }
}
