<#
.SYNOPSIS
  Verify MiTeC Mail Checker package source metadata.
.DESCRIPTION
  Checks the pending catalog candidate against retained static extraction
  evidence. It never runs the installer, application, or bundled OpenSSL DLLs.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCMailChecker.Tests.ps1
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Windows 11 is exploratory; no target support is declared.
#>
BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  $script:Catalog = Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence = Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-installer-extraction-reconciliation-2026-10-21.json') -Raw | ConvertFrom-Json
  $script:PayloadEvidence = Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-mail-checker-openssl-static-follow-up-2026-10-21.json') -Raw | ConvertFrom-Json
}

Describe 'MiTeC Mail Checker package candidate' {
  It 'binds the retained publisher installer and leaves target acceptance pending' {
    $operation = $Catalog.Operations | Where-Object Id -eq 'package.mitec-mail-checker'
    $operation | Should -Not -BeNullOrEmpty
    $installerEvidence = $Evidence.ExtractionEvidence.Products | Where-Object Installer -eq 'MAILCHECKER_Instal.exe'
    $operation.DownloadUri | Should -BeExactly 'https://www.mitec.cz/Downloads/MAILCHECKER_Instal.exe'
    $operation.ExpectedSha256 | Should -BeExactly $installerEvidence.Sha256
    $operation.PackageVersion | Should -BeExactly '7.2.0'
    $operation.Architecture | Should -BeExactly 'x86'
    $operation.InstallerType | Should -BeExactly 'Exe'
    $operation.PendingAcceptance | Should -BeTrue
    $operation.SupportedTargets | Should -Be @()
    $operation.CandidateTargets | Should -Contain 'Windows 11'
    $operation.License | Should -Match 'does not block direct publisher download-and-install migration'
    $operation.TermsUri | Should -BeExactly 'https://www.mitec.cz/wp/support/'
  }

  It 'retains the TLS dependency warning without asserting the DLLs are loaded' {
    $mailExecutable = $PayloadEvidence.RetainedPayload | Where-Object Path -like '*/MAILCHECKER.EXE'
    $mailExecutable.FileVersion | Should -BeExactly '7.2.0.0'
    $mailExecutable.DirectOpenSslStaticImport | Should -BeFalse
    $openSsl = $PayloadEvidence.RetainedPayload | Where-Object { $_.FileDescription -eq 'OpenSSL Shared Library' }
    @($openSsl | Where-Object FileVersion -eq '1.0.1e').Count | Should -Be 3
    $PayloadEvidence.DllLoaded | Should -BeFalse
    $operation = $Catalog.Operations | Where-Object Id -eq 'package.mitec-mail-checker'
    $operation.AcceptanceNotes | Should -Match 'actual use and exposure remain unverified'
    $operation.PendingAcceptance | Should -BeTrue
  }
}
