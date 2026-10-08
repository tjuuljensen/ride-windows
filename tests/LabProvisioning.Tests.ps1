<#
.SYNOPSIS
  Test provisioning data and controller handoff without changing host resources.
.DESCRIPTION
  Uses data-only helpers and TestDrive; no Hyper-V or AutomatedLab import.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.7.1.
  Owner: RIDE-Windows maintainers. Repository test fixture; no standalone CLI.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.LabProvisioning.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.TestAutomation.psm1') -Force
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogData.psm1') -Force
}

Describe 'Provisioning configuration and per-VM handoff' {
  It 'lets explicit values override a local file while retaining other declared values' {
    $inputPath = Join-Path $TestDrive 'provision.psd1'
    "@{ SchemaVersion = 1; LabName = 'RIDEServerTest'; VMName = 'RIDE-S25-Test'; MemoryGB = 4; GuestRepositoryPath = 'D:\Tests\ride-windows' }" | Set-Content -LiteralPath $inputPath
    $effective = Resolve-RideLabProvisioningConfiguration $inputPath @{ MemoryGB = 12 }
    $effective.MemoryGB | Should -Be 12
    $effective.VMName | Should -Be 'RIDE-S25-Test'
    $effective.GuestRepositoryPath | Should -Be 'D:\Tests\ride-windows'
    $effective.WindowsUpdateMode | Should -Be 'Wait'
  }

  It 'rejects credentials and invalid guest leaf names in local data' {
    $inputPath = Join-Path $TestDrive 'private.psd1'
    "@{ SchemaVersion = 1; Password = 'must-not-store' }" | Set-Content -LiteralPath $inputPath
    { Resolve-RideLabProvisioningConfiguration $inputPath } | Should -Throw '*Unsupported provisioning field*'
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ GuestRepositoryPath = 'C:\Windows' } } | Should -Throw '*end with ride-windows*'
  }

  It 'generates a registration-compatible seed with discovered VM identity and custom path' {
    $effective = Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ LabName = 'RIDEServerTest'; VMName = 'RIDE-S25-Test'; GuestRepositoryPath = 'D:\Tests\ride-windows'; CIRepositoryPath = 'C:\ci\ride-windows' }
    $vmId = [guid]::NewGuid()
    $seed = New-RideLabAutomationSeed $effective $vmId 'C:\source\ride-windows' 'D:\ISOs\server.iso'
    $seed.Name | Should -Be 'RIDEServerTest'
    $seed.VMId | Should -Be $vmId.ToString()
    $seed.GuestRepositoryPath | Should -Be 'D:\Tests\ride-windows'
    $seedPath = Join-Path $TestDrive 'controller.json'
    $seed | ConvertTo-Json | Set-Content -LiteralPath $seedPath
    (Read-RideAutomationConfiguration $seedPath).VMName | Should -Be 'RIDE-S25-Test'
    $seed.ContainsKey('CheckpointId') | Should -BeFalse
  }

  It 'rejects invalid configuration values before provisioning' {
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ MemoryGB = 1 } } | Should -Throw '*MemoryGB*'
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ DisableTpm = 'false' } } | Should -Throw '*Boolean*'
    { Resolve-RideLabProvisioningConfiguration -ExplicitParameters @{ AutomationSeedPath = 'C:\seed.json' } } | Should -Throw '*CIRepositoryPath*'
  }
}

Describe 'Bounded data-only catalog reader' {
  It 'loads the growing catalog on both supported PowerShell editions' {
    $catalog = Import-RideCatalogData (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $catalog.Operations.Count | Should -BeGreaterThan 91
  }
  It 'rejects an executable expression instead of evaluating it' {
    $path = Join-Path $TestDrive 'invalid-catalog.psd1'
    "@{ SchemaVersion = 1; Operations = @(Get-Process); Groups = @() }" | Set-Content -LiteralPath $path
    { Import-RideCatalogData $path } | Should -Throw '*literal hashtables*'
  }
  It 'rejects executable values inside a literal operation' {
    $path = Join-Path $TestDrive 'executable-entry.psd1'
    '@{ SchemaVersion = 1; Operations = @(@{ Id = (Get-Process) }); Groups = @() }' | Set-Content -LiteralPath $path
    { Import-RideCatalogData $path } | Should -Throw
  }
  It 'rejects executable root statements and unexpected catalog fields' {
    $path = Join-Path $TestDrive 'invalid-root.psd1'
    'Get-Process; @{ SchemaVersion = 1; Operations = @(); Groups = @() }' | Set-Content -LiteralPath $path
    { Import-RideCatalogData $path } | Should -Throw '*declarative catalog syntax*'
    '@{ SchemaVersion = 1; Operations = @(); Groups = @(); Extra = 1 }' | Set-Content -LiteralPath $path
    { Import-RideCatalogData $path } | Should -Throw '*Unexpected or duplicate*'
  }
}
