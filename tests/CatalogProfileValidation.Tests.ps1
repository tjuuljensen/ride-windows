<#
.SYNOPSIS
  Verify strict version-1 profile field and parameter validation.
.DESCRIPTION
  Uses temporary PowerShell data files and the real catalog. No handlers, Windows
  state, registry fixtures, installers or network sources are accessed.
.EXAMPLE
  Invoke-Pester .\tests\CatalogProfileValidation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
#>
BeforeAll {
  $root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogValidation.psm1') -Force
  $script:Catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
  $script:ProfilePath = Join-Path $TestDrive 'validation-profile.psd1'
  $script:ValidProfile = @'
@{
  SchemaVersion = 1
  Name = 'Validation fixture'
  Description = 'Synthetic profile for catalog validation.'
  Operations = @(
    @{ Id = 'package.7zip'; State = 'Present' }
  )
}
'@
  function Get-ProfileFixtureErrors([string] $Text) {
    Set-Content -LiteralPath $script:ProfilePath -Value $Text -Encoding UTF8
    Get-RideCatalogValidationErrors -Catalog $script:Catalog -ProfilePaths @((Get-Item -LiteralPath $script:ProfilePath))
  }
}

Describe 'version-1 profile parameter validation' {
  It 'accepts a profile with the declared root and selection fields' {
    @(Get-ProfileFixtureErrors $ValidProfile | Where-Object { $_ -like '*validation-profile.psd1*' }).Count | Should -Be 0
  }

  It 'rejects an unsupported root parameter' {
    $text = $ValidProfile.Replace("  Name = 'Validation fixture'", "  Name = 'Validation fixture'`r`n  ApplyImmediately = `$true")
    @(Get-ProfileFixtureErrors $text) | Should -Contain "validation-profile.psd1 has unsupported profile field 'ApplyImmediately'."
  }

  It 'requires an integer schema version' {
    $text = $ValidProfile.Replace('SchemaVersion = 1', "SchemaVersion = '1'")
    @(Get-ProfileFixtureErrors $text) | Should -Contain 'validation-profile.psd1 must declare integer SchemaVersion 1.'
  }

  It 'rejects an unsupported operation parameter' {
    $text = $ValidProfile.Replace("State = 'Present'", "State = 'Present'; Script = 'install.exe'")
    @(Get-ProfileFixtureErrors $text) | Should -Contain "validation-profile.psd1 selection has unsupported field 'Script'."
  }

  It 'requires a state for every selection' {
    $text = $ValidProfile.Replace("; State = 'Present'", '')
    @(Get-ProfileFixtureErrors $text) | Should -Contain "validation-profile.psd1 selection 'package.7zip' is missing State."
  }

  It 'requires State to be a nonblank string' {
    $text = $ValidProfile.Replace("State = 'Present'", 'State = 1')
    @(Get-ProfileFixtureErrors $text) | Should -Contain "validation-profile.psd1 selection 'package.7zip' State must be a nonblank string."
  }

  It 'requires Variant to be a nonblank string' {
    $text = $ValidProfile.Replace("State = 'Present'", "State = 'Present'; Variant = 7")
    @(Get-ProfileFixtureErrors $text) | Should -Contain "validation-profile.psd1 selection 'package.7zip' Variant must be a nonblank string."
  }

  It 'rejects operation selections that are not data tables' {
    $text = $ValidProfile.Replace("@{ Id = 'package.7zip'; State = 'Present' }", "'package.7zip'")
    @(Get-ProfileFixtureErrors $text) | Should -Contain 'validation-profile.psd1 contains an operation selection that is not a data table.'
  }
}
