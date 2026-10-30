<#
.SYNOPSIS
  Verify the MiTeC Network Meter portable package candidate.
.DESCRIPTION
  Checks catalog metadata against the retained static archive review and exercises
  exact-member staging and recovery with an inert synthetic ZIP. It never launches
  Network Meter, inspects live adapters, generates traffic, downloads the publisher
  archive, or changes Windows state.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCNetworkMeter.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Product behavior and Windows target acceptance remain pending.
#>
BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog = Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence = Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-utility-artifact-review-2026-10-17.json') -Raw | ConvertFrom-Json
  $script:ProductEvidence = $Evidence.Products | Where-Object { $_.Artifact.Product -ceq 'Network Meter' }
  $script:Operation = $Catalog.Operations | Where-Object Id -CEQ 'package.mitec-network-meter'
}

Describe 'MiTeC Network Meter portable package candidate' {
  It 'matches the retained static source review and remains pending target acceptance' {
    $ProductEvidence | Should -Not -BeNullOrEmpty
    $Operation | Should -Not -BeNullOrEmpty
    $Operation.ProductUri | Should -BeExactly $ProductEvidence.ProductUri
    $Operation.DownloadUri | Should -BeExactly $ProductEvidence.Artifact.DownloadUri
    $Operation.PackageVersion | Should -BeExactly '2.5.0'
    $Operation.ExpectedSha256 | Should -BeExactly $ProductEvidence.Artifact.Sha256
    $Operation.RequiredFiles | Should -Be @('NetMet.exe')
    $Operation.PortableMembers | Should -Be @('NetMet.exe')
    $Operation.Architecture | Should -BeExactly 'x86'
    $Operation.CandidateTargets | Should -Be @('Windows 11')
    $Operation.SupportedTargets.Count | Should -Be 0
    $Operation.PendingAcceptance | Should -BeTrue
    $Operation.LicenseReviewStatus | Should -BeNullOrEmpty
    $Operation.TermsUri | Should -BeExactly 'https://www.mitec.cz/wp/support/'
  }

  It 'stages only an inert selected member and restores owned files without losing operator content' {
    $caseRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $caseRoot
    $archivePath = Join-Path $caseRoot 'synthetic-network-meter.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach ($name in @('NetMet.exe', 'ignored.txt')) {
        $writer = [IO.StreamWriter]::new($zip.CreateEntry($name).Open())
        try { $writer.Write('inert fixture ' + $name) } finally { $writer.Dispose() }
      }
    }
    finally { $zip.Dispose() }

    $sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $operation = $Operation.Clone()
    $operation.SelectedVariant = 'portable'
    $operation.ExpectedSha256 = $sha256
    $operation.ResolvedToolsDirectory = $caseRoot
    $operation.InstallDirectory = Join-Path $caseRoot $operation.PackageId
    $artifact = [pscustomobject]@{ Path = $archivePath; Sha256 = $sha256; Version = $operation.PackageVersion }

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state = Get-RidePortableState $operation
    $state.Healthy | Should -BeTrue
    @($state.Files.RelativePath) | Should -Be @('NetMet.exe')
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt') | Should -BeFalse

    $snapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'snapshot')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'), 'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy | Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'operator-note.txt')) | Should -BeExactly 'preserve'
  }
}
