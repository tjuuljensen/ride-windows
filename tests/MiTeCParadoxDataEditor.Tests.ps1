<#
.SYNOPSIS
  Verify MiTeC Paradox Data Editor package source metadata.
.DESCRIPTION
  Checks the pending catalog candidate against retained, statically extracted
  publisher evidence. It never runs the installer, BDE helpers, or the product.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCParadoxDataEditor.Tests.ps1
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Windows 11 and Windows Server 2025 acceptance remain pending.
#>
BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  $script:Catalog = Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence = Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-installer-extraction-reconciliation-2026-10-21.json') -Raw | ConvertFrom-Json
}

Describe 'MiTeC Paradox Data Editor package candidate' {
  It 'binds the retained publisher installer and keeps native acceptance pending' {
    $operation = $Catalog.Operations | Where-Object Id -eq 'package.mitec-paradox-data-editor'
    $operation | Should -Not -BeNullOrEmpty
    $installerEvidence = $Evidence.ExtractionEvidence.Products | Where-Object Installer -eq 'PDESetup.exe'
    $operation.DownloadUri | Should -BeExactly 'https://www.mitec.cz/wp/files/PDESetup.exe'
    $operation.ExpectedSha256 | Should -BeExactly $installerEvidence.Sha256
    $operation.PackageVersion | Should -BeExactly '3.7.0'
    $operation.Architecture | Should -BeExactly 'x86'
    $operation.InstallerType | Should -BeExactly 'Exe'
    $operation.PendingAcceptance | Should -BeTrue
    $operation.SupportedTargets | Should -Be @()
    $operation.CandidateTargets | Should -Be @('Windows 11', 'Windows Server 2025')
    $operation.License | Should -Match 'does not block download-and-install migration'
    $operation.TermsUri | Should -BeExactly 'https://www.mitec.cz/wp/support/'
  }

  It 'documents the extracted payload without claiming install-time verification' {
    $installerEvidence = $Evidence.ExtractionEvidence.Products | Where-Object Installer -eq 'PDESetup.exe'
    $installerEvidence.Payload | Should -Match 'Paradox Data Editor x86 3\.7\.0\.0'
    $installerEvidence.Payload | Should -Match 'TUTIL32\.DLL 5\.0\.0\.38'
    $Evidence.ExtractionEvidence.ExecutedInstallerOrPayload | Should -BeFalse
    $Evidence.RunBoundaries.InstallerOrPayloadExecuted | Should -BeFalse
    $operation = $Catalog.Operations | Where-Object Id -eq 'package.mitec-paradox-data-editor'
    $operation.ExpectedSha256 | Should -BeExactly $installerEvidence.Sha256
    $operation.PendingAcceptance | Should -BeTrue
  }
}
