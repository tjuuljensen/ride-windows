<#
.SYNOPSIS
  Verify MiTeC Interbase Query variant pins and offline package lifecycle.
.DESCRIPTION
  Checks catalog metadata against recorded source evidence and exercises both
  variants with inert files. It never launches the database utility or connects
  to a database or service.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCInterbaseQuery.Tests.ps1
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Database behavior requires isolated synthetic disposable databases and remains deferred.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-interbase-query-candidate-preparation-2026-10-23-1632.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-interbase-query'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC Interbase Query portable candidate' {
  BeforeEach {
    $script:Root=Join-Path $FixtureRoot ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $Root -Force
  }
  AfterEach {
    if(Test-Path -LiteralPath $Root -PathType Container){
      $resolved=[IO.Path]::GetFullPath($Root).TrimEnd('\')
      $parent=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
      if([IO.Path]::GetDirectoryName($resolved) -ine $parent -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$'){
        throw 'Refusing Interbase Query fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }

  It 'binds the retained archive and matching x86/x64 member variants' {
    $operation=$Catalog.Operations|Where-Object Id -eq 'package.mitec-interbase-query'
    $operation|Should -Not -BeNullOrEmpty
    $operation.PackageVersion|Should -BeExactly '9.5.0'
    $operation.DownloadUri|Should -BeExactly $Evidence.DownloadUri
    $operation.ExpectedSha256|Should -BeExactly $Evidence.ArchiveSha256
    $operation.DefaultVariant|Should -BeExactly 'x64'
    $operation.Architecture|Should -BeExactly 'x64'
    $operation.SupportedTargets|Should -BeNullOrEmpty
    $operation.PendingAcceptance|Should -BeTrue
    $operation.LicenseReviewStatus|Should -BeNullOrEmpty
    foreach($variant in @('x64','x86')){
      $resolved=Resolve-RidePackageSelection -Operation $operation -Variant $variant -MetadataOnly
      $resolved.SelectedVariant|Should -BeExactly $variant
      $resolved.Architecture|Should -BeExactly $Evidence.Variants.$variant.Architecture
      $resolved.RequiredFiles|Should -Be @($Evidence.Variants.$variant.Executable)
      $resolved.PortableMembers|Should -Be $Evidence.Variants.$variant.SelectedMembers
      $resolved.PackageVersion|Should -BeExactly '9.5.0'
    }
    $operation.Description|Should -Match 'does not launch'
    $operation.AcceptanceNotes|Should -Match 'synthetic disposable databases'
  }

  It 'stages only the selected executable and common localization files, then restores owned files exactly' {
    $archive=Join-Path $Root 'inert-interbase-query.zip'
    $zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($name in @('IBQ.exe','IBQ64.exe','Localization.txt','IBQ.en.lng','IBQ.de.lng','IBQ.es.lng','IBQ.fr.lng','IBQ.cs.lng','IBQ.hu.lng','ignored.txt')){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open())
        try{$writer.Write('inert '+$name)}finally{$writer.Dispose()}
      }
    } finally {$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $artifact=[pscustomobject]@{Path=$archive;Sha256=$sha;Version='9.5.0'}
    foreach($variant in @('x64','x86')){
      $base=($Catalog.Operations|Where-Object Id -eq 'package.mitec-interbase-query').Clone()
      $operation=Resolve-RidePackageSelection -Operation $base -Variant $variant -MetadataOnly
      $operation.ExpectedSha256=$sha
      $operation.ResolvedToolsDirectory=Join-Path $Root $variant
      $operation.InstallDirectory=Join-Path $operation.ResolvedToolsDirectory $operation.PackageId
      $null=New-Item -ItemType Directory -Path $operation.ResolvedToolsDirectory -Force

      Install-RidePortablePayload $operation $artifact -Offline
      Install-RidePortablePayload $operation $artifact -Offline
      $state=Get-RidePortableState $operation
      $state.Healthy|Should -BeTrue
      $state.Files.Count|Should -Be 8
      $paths=@($state.Files|ForEach-Object RelativePath|Sort-Object)
      ($paths -join '|')|Should -BeExactly ((@($Evidence.Variants.$variant.SelectedMembers|Sort-Object)) -join '|')
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt')|Should -BeFalse
      $otherExecutable=if($variant -eq 'x64'){'IBQ.exe'}else{'IBQ64.exe'}
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory $otherExecutable)|Should -BeFalse

      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root "backup-$variant")
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy|Should -BeTrue
      [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
    }
  }

  It 'stages the exact retained publisher archive for both variants and restores only managed files' {
    $archivePath=$env:RIDE_MITEC_INTERBASE_QUERY_FIXTURE_ARCHIVE
    if([string]::IsNullOrWhiteSpace($archivePath)){
      Set-ItResult -Skipped -Because 'No explicit retained IBQ.zip archive was supplied.'
      return
    }
    $archivePath=[IO.Path]::GetFullPath($archivePath)
    Test-Path -LiteralPath $archivePath -PathType Leaf|Should -BeTrue
    (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $Evidence.ArchiveSha256
    $zip=[IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
      foreach($variant in @('x64','x86')){
        $record=$Evidence.Variants.$variant
        $entries=@($zip.Entries|Where-Object FullName -CEQ $record.Executable)
        $entries.Count|Should -Be 1
        $entries[0].Length|Should -Be $record.Length
        $stream=$entries[0].Open();$sha=[Security.Cryptography.SHA256]::Create()
        try {$digest=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
        finally {$sha.Dispose();$stream.Dispose()}
        $digest|Should -BeExactly $record.Sha256
        foreach($member in $record.SelectedMembers){@($zip.Entries|Where-Object FullName -CEQ $member).Count|Should -Be 1}
      }
    } finally {$zip.Dispose()}

    foreach($variant in @('x64','x86')){
      $base=($Catalog.Operations|Where-Object Id -eq 'package.mitec-interbase-query').Clone()
      $operation=Resolve-RidePackageSelection -Operation $base -Variant $variant -MetadataOnly
      $operation.ResolvedToolsDirectory=Join-Path $Root "real-$variant"
      $operation.InstallDirectory=Join-Path $operation.ResolvedToolsDirectory $operation.PackageId
      $null=New-Item -ItemType Directory -Path $operation.ResolvedToolsDirectory -Force
      $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$Evidence.ArchiveSha256;Version='9.5.0'}
      Install-RidePortablePayload $operation $artifact -Offline
      Install-RidePortablePayload $operation $artifact -Offline
      $state=Get-RidePortableState $operation
      $state.Healthy|Should -BeTrue
      (@($state.Files.RelativePath|Sort-Object) -join '|')|Should -BeExactly ((@($Evidence.Variants.$variant.SelectedMembers|Sort-Object)) -join '|')
      (Get-FileHash -LiteralPath (Join-Path $operation.InstallDirectory $Evidence.Variants.$variant.Executable) -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $Evidence.Variants.$variant.Sha256

      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root "real-backup-$variant")
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'),'preserve')
      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy|Should -BeTrue
      [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve'
    }
  }
}
