<#
.SYNOPSIS
  Validate package prerequisite graph integrity without executing package handlers.
.DESCRIPTION
  Builds synthetic package catalogs from valid catalog records and verifies that
  acyclic dependency chains pass while self, multi-node and variant cycles fail.
.EXAMPLE
  Invoke-Pester .\tests\CatalogDependencyValidation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  No Windows state, installer, network source or profile is accessed.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogValidation.psm1') -Force
  $script:Catalog = Import-RideCatalogData (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
  $script:Template = $script:Catalog.Operations | Where-Object Id -eq 'package.git-for-windows' | Select-Object -First 1

  function New-TestPackage([string] $Id, [string] $Prerequisite) {
    $operation = $script:Template.Clone()
    $operation.Id = $Id
    $operation.PackageId = $Id
    $operation.Remove('Variants')
    $operation.Remove('DefaultVariant')
    $operation.Remove('PrerequisitePackageId')
    $operation.Remove('PrerequisiteProgramFilesExecutable')
    if ($Prerequisite) { $operation.PrerequisitePackageId = $Prerequisite; $operation.PrerequisiteProgramFilesExecutable = 'bin/tool.exe' }
    $operation
  }
}

Describe 'package prerequisite cycle validation' {
  It 'accepts a safe system DLL prerequisite and rejects paths or malformed lists' {
    $operation=New-TestPackage 'package.system-runtime' 'package.test-runtime'
    $operation.Remove('PrerequisiteProgramFilesExecutable')
    $operation.PrerequisiteSystemFiles=@('vcomp140.dll')
    $catalog=@{SchemaVersion=1;Operations=@($operation,(New-TestPackage 'package.test-runtime' $null));Groups=@()}
    @(Get-RideCatalogValidationErrors -Catalog $catalog|Where-Object {$_ -like '*system DLL prerequisite*'}).Count|Should -Be 0
    $operation.PrerequisiteSystemFiles=@('System32/vcomp140.dll')
    @(Get-RideCatalogValidationErrors -Catalog $catalog|Where-Object {$_ -like '*system DLL prerequisite*'}).Count|Should -BeGreaterThan 0
    $operation.PrerequisiteSystemFiles='vcomp140.dll'
    @(Get-RideCatalogValidationErrors -Catalog $catalog|Where-Object {$_ -like '*PrerequisiteSystemFiles requires*'}).Count|Should -Be 1
    $operation.Remove('PrerequisitePackageId')
    @(Get-RideCatalogValidationErrors -Catalog $catalog|Where-Object {$_ -like '*System DLL prerequisites require PrerequisitePackageId*'}).Count|Should -Be 1
  }

  It 'accepts an acyclic prerequisite chain' {
    $catalog = @{ SchemaVersion = 1; Operations = @(
      (New-TestPackage 'package.cycle-a' 'package.cycle-b'),
      (New-TestPackage 'package.cycle-b' $null),
      (New-TestPackage 'package.cycle-c' 'package.cycle-a')
    ); Groups = @() }
    @(Get-RideCatalogValidationErrors -Catalog $catalog | Where-Object { $_ -like '*Package prerequisite cycle detected*' }).Count | Should -Be 0
  }

  It 'rejects a multi-package prerequisite cycle with a readable path' {
    $catalog = @{ SchemaVersion = 1; Operations = @(
      (New-TestPackage 'package.cycle-a' 'package.cycle-b'),
      (New-TestPackage 'package.cycle-b' 'package.cycle-c'),
      (New-TestPackage 'package.cycle-c' 'package.cycle-a')
    ); Groups = @() }
    $errors = @(Get-RideCatalogValidationErrors -Catalog $catalog)
    $errors | Should -Contain 'Package prerequisite cycle detected: package.cycle-a -> package.cycle-b -> package.cycle-c -> package.cycle-a'
  }

  It 'rejects a self dependency' {
    $catalog = @{ SchemaVersion = 1; Operations = @(New-TestPackage 'package.cycle-self' 'package.cycle-self'); Groups = @() }
    @(Get-RideCatalogValidationErrors -Catalog $catalog) | Should -Contain 'Package prerequisite cycle detected: package.cycle-self -> package.cycle-self'
  }

  It 'detects a cycle that exists only in a declared package variant' {
    $first = New-TestPackage 'package.variant-a' $null
    $first.Variants = @{ 'with-runtime' = @{ PrerequisitePackageId = 'package.variant-b'; PrerequisiteProgramFilesExecutable = 'bin/runtime.exe' } }
    $first.DefaultVariant = 'with-runtime'
    $second = New-TestPackage 'package.variant-b' 'package.variant-a'
    $catalog = @{ SchemaVersion = 1; Operations = @($first, $second); Groups = @() }
    @(Get-RideCatalogValidationErrors -Catalog $catalog) | Should -Contain 'Package prerequisite cycle detected: package.variant-a -> package.variant-b -> package.variant-a'
  }
}
