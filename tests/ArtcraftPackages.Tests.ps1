<#
.SYNOPSIS
  Validate standalone Artcraft package boundaries without installing apps.
.DESCRIPTION
  Checks publisher source identity, acquisition pins, MSI scope and accepted
  target declarations. Tests use read-only catalog metadata and no network calls.
.EXAMPLE
  Invoke-Pester .\tests\ArtcraftPackages.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester test results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
  Changelog: 2026-10-11: Cover full standalone Artcraft acquisition metadata.
  Versioning exception: Pester fixtures have no independent released version.
#>


BeforeAll {
  $root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE-Packages.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.PackageSelection.psm1') -Force
  $catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
  $packages = @($catalog.Operations | Where-Object Category -eq 'Software / Artcraft')
  $applicationBatchSource = Get-Content (Join-Path $root 'tests/integration/Invoke-RideApplicationBatch.ps1') -Raw
}

Describe 'Artcraft standalone acquisition' {
  It 'covers the twelve apps and the separately selectable launcher' {
    $packages.Count | Should -Be 13
    $group = $catalog.Groups | Where-Object Id -eq 'solution.artcraft-apps'
    $group.Members.Count | Should -Be 12
    $group.Members | Should -Not -Contain 'package.artcraft-launcher'
    @($packages | Where-Object Id -ne 'package.artcraft-launcher' | ForEach-Object Id |
      Where-Object { $_ -notin $group.Members }).Count | Should -Be 0
  }

  It 'binds each pin to its declared publisher repository and MSI filename' {
    foreach ($package in $packages) {
      $repository = if ($package.PackageId -eq 'artcraft-launcher') { 'craft-launcher' } else { $package.PackageId }
      $package.DownloadProvider | Should -Be 'DirectHttps'
      $package.InstallerType | Should -Be 'Msi'
      $package.Architecture | Should -Be 'x64'
      $package.DownloadUri | Should -Be ("https://github.com/storytold/$repository/releases/download/v$($package.PackageVersion)/$($package.AssetName)")
      $package.AssetName | Should -Be ("$($package.PackageId)-$($package.PackageVersion)-windows-x64.msi")
      $package.ExpectedSha256 | Should -Match '^[0-9a-f]{64}$'
      $artifact = Resolve-RidePackageArtifact -Operation $package
      $artifact.ProviderDigest | Should -Be ('sha256:' + $package.ExpectedSha256)
      $artifact.FileName | Should -Be $package.AssetName
    }
  }

  It 'limits declared support to the Artcraft MSI batches that passed Windows 11 acceptance' {
    foreach ($package in $packages) {
      if ($package.MigrationBatch -in @('ApplicationsBatch6','ApplicationsBatch7')) {
        $package.PendingAcceptance | Should -BeFalse
        $package.SupportedTargets | Should -Contain 'Windows 11'
        @($package.CandidateTargets | Where-Object { $_ -in @($package.SupportedTargets) }).Count | Should -Be 0
      } else {
        $package.PendingAcceptance | Should -BeTrue
        @($package.SupportedTargets).Count | Should -Be 0
        $package.CandidateTargets | Should -Contain 'Windows 11'
      }
      $package.CandidateTargets | Should -Not -Contain 'Windows Server 2025'
      $package.Actions | Should -Contain 'Download'
      $package.LicenseUri | Should -Match '^https://github.com/storytold/'
      $package.TermsUri | Should -Match '/docs/brand/LICENSE-brand\.txt$'
    }
  }

  It 'uses the actual publisher MSI installation scope and quiet arguments' {
    foreach ($package in $packages) {
      $package.Name | Should -Match $package.DisplayNamePattern
      ($package.Name + ' Unrelated') | Should -Not -Match $package.DisplayNamePattern
      $package.InstallerArguments | Should -Match '/qn /norestart'
      $package.UninstallerArguments | Should -Be '/qn /norestart'
      $package.SuccessExitCodes | Should -Contain 3010
      if ($package.PackageId -eq 'artcraft-launcher') {
        $package.Scope | Should -Be 'User'
        $package.RequiresAdmin | Should -BeFalse
        $package.MsiUpgradeCode | Should -BeExactly '1AC08DBF-D4CF-4BA4-A81E-CAA5C1004974'
        $package.MsiProductName | Should -BeExactly 'ArtCraft Launcher'
        $package.MsiInstallDirectoryRegistryKey | Should -BeExactly 'HKCU:\Software\Learning Machines LLC\ArtCraft Launcher'
        $package.MsiExecutable | Should -BeExactly 'artcraft-launcher.exe'
      } else {
        $package.Scope | Should -Be 'Machine'
        $package.RequiresAdmin | Should -BeTrue
      }
    }
    ($packages | Where-Object PackageId -eq 'pdfcraft').InstallerArguments | Should -Match 'ALLUSERS=1'
  }

  It 'routes twelve machine apps into ApplicationsBatch6 and the accepted current-user launcher into ApplicationsBatch7' {
    $selected = @($packages | Where-Object MigrationBatch -eq 'ApplicationsBatch6')
    $selected.Count | Should -Be 12
    foreach ($package in $selected) {
      $package.RequiresAdmin | Should -BeTrue
      $package.Scope | Should -Be 'Machine'
      $package.PendingAcceptance | Should -BeFalse
      $package.SupportedTargets | Should -Contain 'Windows 11'
      @($package.CandidateTargets | Where-Object { $_ -in @($package.SupportedTargets) }).Count | Should -Be 0
      $resolved = Resolve-RidePackageSelection -Operation $package
      $resolved.MigrationBatch | Should -Be 'ApplicationsBatch6'
    }
    $launcher = $packages | Where-Object PackageId -eq 'artcraft-launcher'
    $launcher.MigrationBatch | Should -Be 'ApplicationsBatch7'
    $launcher.Scope | Should -Be 'User'
    $launcher.RequiresAdmin | Should -BeFalse
    $launcher.SupportedTargets | Should -Contain 'Windows 11'
    $launcher.PendingAcceptance | Should -BeFalse
    @($launcher.CandidateTargets | Where-Object { $_ -in @($launcher.SupportedTargets) }).Count | Should -Be 0
    (Resolve-RidePackageSelection -Operation $launcher).MigrationBatch | Should -Be 'ApplicationsBatch7'
    @($selected | Where-Object { $_.PendingAcceptance -ne $false }).Count | Should -Be 0
  }

  It 'seeds and verifies Artcraft user profile data across install, vendor uninstall and recovery' {
    $applicationBatchSource | Should -Match 'elseif\(\$Batch -eq 6\)'
    $applicationBatchSource | Should -Match 'elseif\(\$Batch -eq 7\)'
    $applicationBatchSource | Should -Match 'package\.pdfcraft'
    $applicationBatchSource | Should -Match 'ProfilePreservationPath=\$profileRoot'
    $applicationBatchSource | Should -Match 'Installation changed existing profile data'
    $applicationBatchSource | Should -Match 'Removal changed existing profile data'
    $applicationBatchSource | Should -Match 'Recovery changed existing profile data'
  }
}
