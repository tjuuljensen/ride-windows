<#
.SYNOPSIS
  Validate the Phoenix Protector MSI candidate's declared machine scope.
.DESCRIPTION
  Checks pinned catalog metadata only. Does not download, open, or run the MSI.
.EXAMPLE
  Invoke-Pester .\tests\PhoenixPackage.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester test results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
  Changelog: 2026-10-22: Require the MSI to receive the catalog's machine scope.
  Versioning exception: Pester fixtures have no independent released version.
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-Packages.psm1') -Force
  $script:Phoenix = (Import-RideCatalogData (Join-Path $script:RepositoryRoot 'catalog/operations.psd1')).Operations |
    Where-Object Id -eq 'package.phoenix-protector' | Select-Object -First 1
}

Describe 'Phoenix Protector pinned MSI candidate' {
  It 'requests a machine-wide quiet installation consistent with its scope' {
    $script:Phoenix.Scope | Should -BeExactly 'Machine'
    $script:Phoenix.RequiresAdmin | Should -BeTrue
    $script:Phoenix.InstallerType | Should -BeExactly 'Msi'
    $script:Phoenix.InstallerArguments | Should -Match '(?i)(^|\s)ALLUSERS=1($|\s)'
  }

  It 'retains the exact publisher pin without claiming target acceptance' {
    $script:Phoenix.DownloadUri | Should -BeExactly 'https://ntcore.com/files/Phoenix_Protector.msi'
    $script:Phoenix.PackageVersion | Should -BeExactly '1.7.1'
    $script:Phoenix.ExpectedSha256 | Should -BeExactly '15a7dbbf90ce66fb302a322c6809fafd897808096069dfecededf78e51b16369'
    $script:Phoenix.PendingAcceptance | Should -BeTrue
    $script:Phoenix.MigrationBatch | Should -BeExactly 'ApplicationsBatch1'
    @($script:Phoenix.SupportedTargets).Count | Should -Be 0
    $script:Phoenix.CandidateTargets | Should -Contain 'Windows 11'
  }

  It 'declares and enforces the shared CLR 2.0 prerequisite without installing it' {
    $script:Phoenix.PrerequisiteDotNetFramework35 | Should -BeTrue

    InModuleScope RIDE-Packages -Parameters @{ PackageOperation = $script:Phoenix } {
      param($PackageOperation)
      Mock Test-RideDotNetFramework35Installed { $false }
      Mock Resolve-RidePackageSelection { $Operation }
      Mock Assert-RidePackageExecutionContext {}
      Mock Save-RidePackageArtifact { throw 'Artifact acquisition must not start.' }
      Mock Invoke-RidePackageInstallerProcess { throw 'MSI must not run.' }

      { Install-RidePackage -Operation $PackageOperation -CacheDirectory 'C:\fixture\cache' } |
        Should -Throw '*requires the shared .NET Framework 3.5 feature*'
      Should -Invoke Test-RideDotNetFramework35Installed -Exactly 1
      Should -Invoke Save-RidePackageArtifact -Exactly 0
      Should -Invoke Invoke-RidePackageInstallerProcess -Exactly 0
    }
  }

  It 'passes the catalog machine-wide MSI arguments to msiexec without launching it' {
    InModuleScope RIDE-Packages -Parameters @{ PackageOperation = $script:Phoenix } {
      param($PackageOperation)
      $script:ExpectedMsiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
      Mock Resolve-RidePackageSelection { $Operation }
      Mock Test-RideDotNetFramework35Installed { $true }
      Mock Assert-RidePackageExecutionContext {}
      Mock Save-RidePackageArtifact {
        [pscustomobject]@{ Path = 'C:\fixture\Phoenix_Protector.msi'; Sha256 = ''; Version = $Operation.PackageVersion }
      }
      Mock Invoke-RidePackageInstallerProcess { [pscustomobject]@{ ExitCode = 0 } }
      Mock Get-RideInstalledPackage { [pscustomobject]@{ Present = $true } }

      Install-RidePackage -Operation $PackageOperation -CacheDirectory 'C:\fixture\cache' | Should -Not -BeNullOrEmpty
      Should -Invoke Invoke-RidePackageInstallerProcess -Exactly 1 -ParameterFilter {
        $FilePath -eq $script:ExpectedMsiexec -and
        $ArgumentList -eq '/i "C:\fixture\Phoenix_Protector.msi" /qn /norestart ALLUSERS=1'
      }
    }
  }
}
