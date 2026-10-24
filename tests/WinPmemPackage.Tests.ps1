<#
.SYNOPSIS
  Validate the pinned WinPmem deployment-only package candidate.
.DESCRIPTION
  Checks the source pin, licensing metadata and explicit boundaries. It does not
  download or execute WinPmem, load a driver, or capture memory.
.EXAMPLE
  Invoke-Pester .\tests\WinPmemPackage.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester test results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
  Changelog: 2026-10-24: Add the required WinPmem signed-production candidate.
  Versioning exception: Pester fixtures have no independent released version.
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:WinPmem = (Import-RideCatalogData (Join-Path $script:RepositoryRoot 'catalog/operations.psd1')).Operations |
    Where-Object Id -eq 'package.winpmem' | Select-Object -First 1
}

Describe 'WinPmem signed production deployment candidate' {
  It 'pins the publisher production asset and its published digest' {
    $script:WinPmem.Kind | Should -BeExactly 'Package'
    $script:WinPmem.InstallerType | Should -BeExactly 'Portable'
    $script:WinPmem.PortableFormat | Should -BeExactly 'File'
    $script:WinPmem.DownloadUri | Should -BeExactly 'https://github.com/Velocidex/WinPmem/releases/download/v4.1.dev1/go-winpmem_amd64_1.0-rc2_signed.exe'
    $script:WinPmem.PackageVersion | Should -BeExactly '1.0-rc2'
    $script:WinPmem.ExpectedSha256 | Should -BeExactly '86691bb4af2c17dd9ec4834c04a99ad51e04f780a07d1b05bc382a5d1892e0c4'
    $script:WinPmem.Architecture | Should -BeExactly 'x64'
    $script:WinPmem.RequiredFiles | Should -Contain 'go-winpmem_amd64_1.0-rc2_signed.exe'
  }

  It 'keeps the candidate unsupported until target acceptance is complete' {
    $script:WinPmem.SupportedTargets | Should -BeNullOrEmpty
    $script:WinPmem.CandidateTargets | Should -Contain 'Windows 11'
    $script:WinPmem.PendingAcceptance | Should -BeTrue
    $script:WinPmem.RequiresAdmin | Should -BeTrue
    $script:WinPmem.Scope | Should -BeExactly 'Machine'
  }

  It 'declares Apache licensing and never makes driver loading or capture an installer action' {
    $script:WinPmem.License | Should -Match 'Apache-2.0'
    $script:WinPmem.LicenseUri | Should -BeExactly 'https://github.com/Velocidex/WinPmem/blob/master/LICENSE'
    $script:WinPmem.InstallerArguments | Should -BeExactly ''
    $script:WinPmem.UninstallerArguments | Should -BeExactly ''
    $script:WinPmem.Description | Should -Match 'without launching it'
    $script:WinPmem.Description | Should -Match 'Driver loading and memory capture are explicit operator actions'
  }

  It 'stages and removes only its owned synthetic file without running it' {
    $toolsRoot = Join-Path $TestDrive 'tools'
    $installDirectory = Join-Path $toolsRoot 'winpmem'
    $synthetic = Join-Path $TestDrive 'synthetic-winpmem.exe'
    [IO.File]::WriteAllText($synthetic, 'synthetic inert executable bytes')
    $operation = $script:WinPmem.Clone()
    $operation.SelectedVariant = 'portable'
    $operation.ResolvedToolsDirectory = $toolsRoot
    $operation.InstallDirectory = $installDirectory
    $artifact = [pscustomobject]@{
      Path = $synthetic
      Version = $script:WinPmem.PackageVersion
      Sha256 = (Get-FileHash -LiteralPath $synthetic -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    Install-RidePortablePayload -Operation $operation -Artifact $artifact -Offline
    (Get-RidePortableState $operation).Healthy | Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $installDirectory $script:WinPmem.PortableFileName)) |
      Should -BeExactly 'synthetic inert executable bytes'

    $userFile = Join-Path $installDirectory 'operator-notes.txt'
    [IO.File]::WriteAllText($userFile, 'keep this user-owned file')
    Uninstall-RidePortablePayload -Operation $operation
    Test-Path -LiteralPath (Join-Path $installDirectory $script:WinPmem.PortableFileName) |
      Should -BeFalse
    [IO.File]::ReadAllText($userFile) | Should -BeExactly 'keep this user-owned file'
    Test-Path -LiteralPath $toolsRoot | Should -BeTrue
  }
}
