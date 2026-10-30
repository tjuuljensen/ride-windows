<#
.SYNOPSIS
  Verify MiTeC Structured Storage Viewer's pinned package and file-only lifecycle.
.DESCRIPTION
  Checks the catalog against recorded source-pin evidence, then exercises repeat
  staging, snapshot, removal and restore with an inert ZIP and, when available,
  the retained publisher ZIP. It never launches the retained executable or loads
  the optional codec.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCSSView.Tests.ps1
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Structured-storage behavior, activation preservation and Windows acceptance
  require a disposable VM; optional codec/source/sample rights remain separate.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-ssview-candidate-preparation-2026-10-23.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-ssview'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC Structured Storage Viewer portable candidate' {
  BeforeEach {
    $script:Root=Join-Path $FixtureRoot ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $Root -Force
  }
  AfterEach {
    if(Test-Path -LiteralPath $Root -PathType Container){
      $resolved=[IO.Path]::GetFullPath($Root).TrimEnd('\')
      $parent=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
      if([IO.Path]::GetDirectoryName($resolved) -ine $parent -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$'){
        throw 'Refusing SSView fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }

  It 'matches the catalog to recorded source pins and excludes optional members' {
    $operation=$Catalog.Operations|Where-Object Id -eq 'package.mitec-ssview'
    $operation|Should -Not -BeNullOrEmpty
    $operation.PackageVersion|Should -BeExactly '4.1.2'
    $operation.DownloadUri|Should -BeExactly 'https://www.mitec.cz/wp/files/SSView.zip'
    $operation.ExpectedSha256|Should -BeExactly $Evidence.ArchiveSha256
    $operation.Architecture|Should -BeExactly 'x86'
    $operation.RequiredFiles|Should -Be @('SSView.exe')
    $operation.PortableMembers|Should -Be @('SSView.exe')
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.CandidateTargets|Should -Be @('Windows 11')
    $operation.PendingAcceptance|Should -BeTrue
    $Evidence.ArchiveSha256|Should -Match '^[a-f0-9]{64}$'
    $operation.ExpectedSha256|Should -BeExactly $Evidence.ArchiveSha256
    $Evidence.SelectedMembers[0].Path|Should -BeExactly 'SSView.exe'
    $Evidence.SelectedMembers[0].Sha256|Should -Match '^[a-f0-9]{64}$'
    $Evidence.SelectedMembers[0].Length|Should -BeGreaterThan 0
    foreach($optional in @('ZLibCodec.dll','ZLibCodec.dpr','test.ss')){
      $operation.PortableMembers|Should -Not -Contain $optional
    }
  }

  It 'stages only the viewer, repeats safely, and restores owned files without losing user data' {
    $archive=Join-Path $Root 'inert-ssview.zip'
    $zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($name in @('SSView.exe','ZLibCodec.dll','ZLibCodec.dpr','test.ss','ignored.txt')){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open())
        try{$writer.Write('inert '+$name)}finally{$writer.Dispose()}
      }
    } finally {$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $operation=($Catalog.Operations|Where-Object Id -eq 'package.mitec-ssview').Clone()
    $operation.SelectedVariant='portable'
    $operation.ExpectedSha256=$sha
    $operation.ResolvedToolsDirectory=$Root
    $operation.InstallDirectory=Join-Path $Root $operation.PackageId
    $artifact=[pscustomobject]@{Path=$archive;Sha256=$sha;Version=$operation.PackageVersion}

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    $state.Files.Count|Should -Be 1
    $state.Files[0].RelativePath|Should -BeExactly 'SSView.exe'
    foreach($optional in @('ZLibCodec.dll','ZLibCodec.dpr','test.ss','ignored.txt')){
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory $optional)|Should -BeFalse
    }

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root 'backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }

  It 'stages and restores the retained publisher archive without launching the viewer' {
    $archive=Join-Path $RepositoryRoot '.local/collection-inventory-20261017/SSView.zip'
    if(-not (Test-Path -LiteralPath $archive -PathType Leaf)){
      Set-ItResult -Skipped -Because 'The ignored retained publisher archive is unavailable in this checkout.'
      return
    }

    (Get-Item -LiteralPath $archive).Length|Should -Be $Evidence.ArchiveLength
    (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $Evidence.ArchiveSha256
    $zip=[IO.Compression.ZipFile]::OpenRead($archive)
    try {
      $entry=$zip.GetEntry('SSView.exe')
      $entry|Should -Not -BeNullOrEmpty
      $entry.Length|Should -Be $Evidence.SelectedMembers[0].Length
      $stream=$entry.Open()
      try {
        $hash=[Security.Cryptography.SHA256]::Create()
        try { ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()|Should -BeExactly $Evidence.SelectedMembers[0].Sha256 }
        finally { $hash.Dispose() }
      } finally { $stream.Dispose() }
      @($zip.Entries|Where-Object FullName -in @('ZLibCodec.dll','ZLibCodec.dpr','test.ss')).Count|Should -Be 3
    } finally { $zip.Dispose() }

    $operation=($Catalog.Operations|Where-Object Id -eq 'package.mitec-ssview').Clone()
    $operation.SelectedVariant='portable'
    $operation.ResolvedToolsDirectory=$Root
    $operation.InstallDirectory=Join-Path $Root $operation.PackageId
    $artifact=[pscustomobject]@{Path=$archive;Sha256=$Evidence.ArchiveSha256;Version=$operation.PackageVersion}
    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline

    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    $state.Files.Count|Should -Be 1
    $state.Files[0].RelativePath|Should -BeExactly 'SSView.exe'
    foreach($optional in @('ZLibCodec.dll','ZLibCodec.dpr','test.ss')){
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory $optional)|Should -BeFalse
    }
    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root 'real-archive-backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }
}
