<#
.SYNOPSIS
  Check installer completion policy without executing installers.
.DESCRIPTION
  Verifies opt-in process completion, default tree waiting, exit-code and presence
  checks, and catalog constraints. System/process calls are mocked.
.EXAMPLE
  Invoke-Pester .\tests\InstallerCompletion.Tests.ps1
.NOTES
  Windows PowerShell 5.1 / Pester 5.7.1. Version: 0.1.0.
  Changelog: 0.1.0: Cover the Project Maker completion correction.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-Packages.psm1') -Force}
Describe 'Installer completion policy' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $script:operation=@{Id='package.test';Name='Test';Kind='Package';InstallerType='Exe';InstallerArguments='/S';InstallerWaitMode='Process'}
      Mock Assert-RidePackageExecutionContext {}
      Mock Get-RidePackagePrerequisiteDirectory {$null}
      Mock Resolve-RidePackageSelection {param($Operation);$Operation}
      Mock Save-RidePackageArtifact {[pscustomobject]@{Path='C:\inert\setup.exe'}}
      Mock Get-RideInstalledPackage {[pscustomobject]@{Present=$true}}
      $script:process=[pscustomobject]@{Handle=[intptr]1;ExitCode=0;Waited=$false;Refreshed=$false}
      $script:process|Add-Member ScriptMethod WaitForExit {$this.Waited=$true}
      $script:process|Add-Member ScriptMethod Refresh {$this.Refreshed=$true}
      Mock Start-Process {$script:process}
    }
    It 'opts installation into root-process completion and retains exit status' {
      Install-RidePackage $script:operation $TestDrive
      Should -Invoke Start-Process -Exactly 1 -ParameterFilter {-not $Wait -and $PassThru}
      $script:process.Waited|Should -BeTrue
      $script:process.Refreshed|Should -BeTrue
    }
    It 'preserves the default process-tree wait for other packages' {
      $script:operation.Remove('InstallerWaitMode')
      Install-RidePackage $script:operation $TestDrive
      Should -Invoke Start-Process -Exactly 1 -ParameterFilter {$Wait -and $PassThru}
      $script:process.Waited|Should -BeFalse
    }
    It 'does not apply installation policy to removal operations' {
      Invoke-RidePreservingPackageOperation $script:operation 'uninstall.exe' '/S'
      Should -Invoke Start-Process -Exactly 1 -ParameterFilter {$Wait -and $PassThru}
    }
    It 'rejects unsuccessful installer exit codes' {
      $script:process.ExitCode=7
      {Install-RidePackage $script:operation $TestDrive}|Should -Throw '*exited with code 7*'
    }
    It 'rejects missing exit codes' {
      $script:process.ExitCode=$null
      {Install-RidePackage $script:operation $TestDrive}|Should -Throw '*exit code is unavailable*'
    }
    It 'still requires installed-state detection after successful completion' {
      Mock Get-RideInstalledPackage {[pscustomobject]@{Present=$false}}
      {Install-RidePackage $script:operation $TestDrive}|Should -Throw '*not detected afterward*'
    }
  }
}
Describe 'Installer completion catalog contract' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogData.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
    $script:catalog=Import-RideCatalogData (Join-Path $PSScriptRoot '../catalog/operations.psd1')
  }
  It 'opts only the pinned pending Project Maker candidate into process completion' {
    $selected=@($script:catalog.Operations|Where-Object InstallerWaitMode -eq 'Process')
    $selected.Count|Should -Be 1
    $selected[0].Id|Should -Be 'package.mitec-project-maker'
    $selected[0].PendingAcceptance|Should -BeTrue
    $selected[0].SupportedTargets|Should -Be @()
    @(Get-RideCatalogValidationErrors $script:catalog)|Should -Be @()
  }
  It 'rejects unsupported completion metadata <Mode> for <Type>' -ForEach @(
    @{Mode='Unknown';Type='Exe'},@{Mode='Process';Type='Msi'},@{Mode=$true;Type='Exe'}
  ) {
    $package=($script:catalog.Operations|Where-Object Id -eq 'package.mitec-project-maker').Clone()
    $package.InstallerWaitMode=$Mode;$package.InstallerType=$Type
    $candidate=$script:catalog.Clone();$candidate.Operations=@($package);$candidate.Groups=@()
    @(Get-RideCatalogValidationErrors $candidate) -join ' '|Should -Match 'InstallerWaitMode'
  }
}
