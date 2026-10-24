<#
.SYNOPSIS
  Verify MiTeC UUID Generator source metadata and safe portable file lifecycle.
.DESCRIPTION
  Validates the retained-source pin and uses an inert ZIP fixture through the
  portable ownership handlers. It never launches the product or reads host IDs.
.EXAMPLE
  Invoke-Pester .\tests\MiTecUuidGenerator.Tests.ps1
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Product UI, target support, activation and live-identifier privacy remain pending.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-uuid-generator-static-review-2026-10-20.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-uuid'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC UUID Generator candidate' {
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
  It 'binds the exact retained source and preserves the explicit acceptance and license boundaries' {
    $operation=$Catalog.Operations|Where-Object Id -eq 'package.mitec-uuid-generator'
    $operation|Should -Not -BeNullOrEmpty
    $operation.DownloadUri|Should -BeExactly $Evidence.PinnedArtifact.DownloadUri
    $operation.ExpectedSha256|Should -BeExactly $Evidence.PinnedArtifact.Sha256
    $operation.PackageVersion|Should -BeExactly '1.0.0'
    $operation.RequiredFiles|Should -Be @('UUID.exe')
    $operation.PortableMembers|Should -Be @('UUID.exe')
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.PendingAcceptance|Should -BeTrue
    $operation.License|Should -Match 'private, educational and non-commercial'
    $operation.License|Should -Match 'redistribution remain unresolved'
    $operation.TermsUri|Should -BeExactly $Evidence.PublisherEvidence.TermsPage.Uri
    $operation.Description|Should -Match 'persistent UEFI, SMBIOS, machine and device identifiers'
    $operation.Description|Should -Match 'synthetic values only'
  }

  It 'installs only the selected inert member, repeats, and restores owned files without losing user data' {
    $archivePath=Join-Path $Root 'fixture.zip'
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($name in @('UUID.exe','ignored.txt')) {
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open())
        try{$writer.Write('inert '+$name)}finally{$writer.Dispose()}
      }
    } finally {$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $operation=($Catalog.Operations|Where-Object Id -eq 'package.mitec-uuid-generator').Clone()
    $operation.SelectedVariant='portable'
    $operation.ExpectedSha256=$sha
    $operation.ResolvedToolsDirectory=$Root
    $operation.InstallDirectory=Join-Path $Root $operation.PackageId
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$sha;Version=$operation.PackageVersion}

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    $state.Files.Count|Should -Be 1
    $state.Files[0].RelativePath|Should -BeExactly 'UUID.exe'
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt')|Should -BeFalse

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root 'backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }
}
