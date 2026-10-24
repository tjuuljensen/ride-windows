<#
.SYNOPSIS
  Verify MiTeC SQLite Query's pinned archive metadata and safe portable lifecycle.
.DESCRIPTION
  Uses recorded static source evidence and an inert three-member ZIP fixture. It
  never extracts, loads or executes the retained product binaries or opens a database.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCSqliteQuery.Tests.ps1
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Database behavior, target support, activation and MiTeC license review remain pending.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-sqlite-query-static-dependency-review-2026-10-20.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-sqlite-query'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC SQLite Query portable candidate' {
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
  It 'binds the three-member archive pin and records its unresolved provenance and rights' {
    $operation=$Catalog.Operations|Where-Object Id -eq 'package.mitec-sqlite-query'
    $operation|Should -Not -BeNullOrEmpty
    $operation.DownloadUri|Should -BeExactly $Evidence.PinnedArtifact.DownloadUri
    $operation.ExpectedSha256|Should -BeExactly $Evidence.PinnedArtifact.Sha256
    $operation.PackageVersion|Should -BeExactly '3.2.0'
    $operation.Architecture|Should -BeExactly 'x86'
    $operation.LicenseUri|Should -BeExactly $Evidence.PublisherEvidence.ProductPage.Uri
    $operation.TermsUri|Should -BeExactly $Evidence.PublisherEvidence.TermsPage.Uri
    $operation.RequiredFiles|Should -Be @('SQLiteQuery.exe','sqlite3.dll','sqlite3.exe')
    $operation.PortableMembers|Should -Be @('SQLiteQuery.exe','sqlite3.dll','sqlite3.exe')
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.PendingAcceptance|Should -BeTrue
    $operation.License|Should -Match 'local entitlement and redistribution remain unresolved'
    $operation.License|Should -Match 'SQLite 3.35.5'
    $operation.Description|Should -Match 'never open personal or production databases'
    $operation.AcceptanceNotes|Should -Match 'ProductVersion 3.0.0.0'
  }

  It 'stages all three selected inert members, repeats, and restores owned files without losing user data' {
    $archivePath=Join-Path $Root 'fixture.zip'
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($name in @('SQLiteQuery.exe','sqlite3.dll','sqlite3.exe','ignored.txt')) {
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open())
        try{$writer.Write('inert '+$name)}finally{$writer.Dispose()}
      }
    } finally {$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $operation=($Catalog.Operations|Where-Object Id -eq 'package.mitec-sqlite-query').Clone()
    $operation.SelectedVariant='portable'
    $operation.ExpectedSha256=$sha
    $operation.ResolvedToolsDirectory=$Root
    $operation.InstallDirectory=Join-Path $Root $operation.PackageId
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$sha;Version=$operation.PackageVersion}

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    $state.Files.Count|Should -Be 3
    @($state.Files.RelativePath|Sort-Object)|Should -Be @('sqlite3.dll','sqlite3.exe','SQLiteQuery.exe')
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt')|Should -BeFalse

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root 'backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }
}
