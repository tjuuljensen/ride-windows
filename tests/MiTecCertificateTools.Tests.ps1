<#
.SYNOPSIS
  Verify MiTeC certificate tool package metadata and portable file ownership.
.DESCRIPTION
  Reconciles pinned-source evidence with the catalog and exercises only inert ZIP
  fixtures. It creates no keys or certificates and launches no product.
.EXAMPLE
  Invoke-Pester .\tests\MiTecCertificateTools.Tests.ps1
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Certificate parsing, generation, export, UI, target support and activation remain pending.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-certificate-tools-candidate-preparation-2026-10-22.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-certificate-tools'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC certificate package <PackageId>' -ForEach @(
  @{PackageId='mitec-certificate-generator';Product='MiTeC Certificate Generator';Version='1.0.0';Member='CG.exe';Architecture='x64'},
  @{PackageId='mitec-certificate-information';Product='MiTeC Certificate Information';Version='1.5.0';Member='CertInfo.exe';Architecture='x86'}
) {
  BeforeEach {
    $script:Root=Join-Path $FixtureRoot ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $Root -Force
  }
  AfterEach {
    if(Test-Path -LiteralPath $Root -PathType Container){
      $resolved=[IO.Path]::GetFullPath($Root).TrimEnd('\')
      $parent=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
      if([IO.Path]::GetDirectoryName($resolved) -ine $parent -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$'){
        throw 'Refusing portable fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }
  It 'matches its frozen publisher record and stays unsupported pending synthetic-only acceptance' {
    $row=$Evidence.Products|Where-Object Name -eq $Product
    $operation=$Catalog.Operations|Where-Object Id -eq ('package.'+$PackageId)
    $operation|Should -Not -BeNullOrEmpty
    $operation.ProductUri|Should -BeExactly $row.ProductUri
    $operation.DownloadUri|Should -BeExactly $row.DownloadUri
    $operation.ExpectedSha256|Should -BeExactly $row.Archive.Sha256
    $operation.PackageVersion|Should -BeExactly $Version
    $operation.Architecture|Should -BeExactly $Architecture
    $operation.RequiredFiles|Should -Be @($Member)
    $operation.PortableMembers|Should -Be @($Member)
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.PendingAcceptance|Should -BeTrue
    $operation.License|Should -Match 'private, educational and non-commercial'
    $operation.License|Should -Match 'redistribution remain unresolved'
    $operation.TermsUri|Should -BeExactly $Evidence.TermsUri
  }
  It 'repeats exact-member staging and restores owned files without losing user data' {
    $archivePath=Join-Path $Root 'fixture.zip'
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($name in @($Member,'ignored.txt')) {
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open())
        try{$writer.Write('inert '+$name)}finally{$writer.Dispose()}
      }
    } finally {$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $operation=($Catalog.Operations|Where-Object Id -eq ('package.'+$PackageId)).Clone()
    $operation.SelectedVariant='portable'
    $operation.ExpectedSha256=$sha
    $operation.ResolvedToolsDirectory=$Root
    $operation.InstallDirectory=Join-Path $Root $PackageId
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$sha;Version=$Version}

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    $state.Files.Count|Should -Be 1
    $state.Files[0].RelativePath|Should -BeExactly $Member
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt')|Should -BeFalse

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root 'backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }
}
