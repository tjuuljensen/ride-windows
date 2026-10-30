<#
.SYNOPSIS
  Verify MiTeC Task Manager DeLuxe variant pins and offline package lifecycle.
.DESCRIPTION
  Checks catalog metadata against recorded source evidence and exercises both
  variants with inert files. It never launches the utilities or queries live
  process, service, account, session, network, or reputation data.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCTaskManagerDeluxe.Tests.ps1
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Product behavior requires a disposable guest and synthetic process fixtures.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-task-manager-deluxe-candidate-preparation-2026-10-23-1659.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-task-manager-deluxe'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC Task Manager DeLuxe portable candidate' {
  BeforeEach {
    $script:Root=Join-Path $FixtureRoot ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $Root -Force
  }
  AfterEach {
    if(Test-Path -LiteralPath $Root -PathType Container){
      $resolved=[IO.Path]::GetFullPath($Root).TrimEnd('\')
      $parent=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
      if([IO.Path]::GetDirectoryName($resolved) -ine $parent -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$'){
        throw 'Refusing Task Manager DeLuxe fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }

  It 'binds the retained archive and matching x86/x64 executable pairs' {
    $operation=$Catalog.Operations|Where-Object Id -eq 'package.mitec-task-manager-deluxe'
    $operation|Should -Not -BeNullOrEmpty
    $operation.PackageVersion|Should -BeExactly '5.1.1'
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
      $resolved.RequiredFiles|Should -Be $Evidence.Variants.$variant.SelectedMembers
      $resolved.PortableMembers|Should -Be $Evidence.Variants.$variant.SelectedMembers
      $resolved.PackageVersion|Should -BeExactly '5.1.1'
    }
    $operation.Description|Should -Match 'without launching them'
    $operation.AcceptanceNotes|Should -Match 'do not terminate processes'
    $operation.AcceptanceNotes|Should -Match 'query VirusTotal'
  }

  It 'stages only the requested architecture pair and restores owned files exactly' {
    $archive=Join-Path $Root 'inert-task-manager.zip'
    $zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($name in @('TMX.exe','TMX64.exe','DeskExp.exe','DeskExp64.exe','ignored.txt')){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open())
        try{$writer.Write('inert '+$name)}finally{$writer.Dispose()}
      }
    } finally {$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $artifact=[pscustomobject]@{Path=$archive;Sha256=$sha;Version='5.1.1'}
    foreach($variant in @('x64','x86')){
      $base=($Catalog.Operations|Where-Object Id -eq 'package.mitec-task-manager-deluxe').Clone()
      $operation=Resolve-RidePackageSelection -Operation $base -Variant $variant -MetadataOnly
      $operation.ExpectedSha256=$sha
      $operation.ResolvedToolsDirectory=Join-Path $Root $variant
      $operation.InstallDirectory=Join-Path $operation.ResolvedToolsDirectory $operation.PackageId
      $null=New-Item -ItemType Directory -Path $operation.ResolvedToolsDirectory -Force

      Install-RidePortablePayload $operation $artifact -Offline
      Install-RidePortablePayload $operation $artifact -Offline
      $state=Get-RidePortableState $operation
      $state.Healthy|Should -BeTrue
      $paths=@($state.Files|ForEach-Object RelativePath|Sort-Object)
      ($paths -join '|')|Should -BeExactly ((@($Evidence.Variants.$variant.SelectedMembers|Sort-Object)) -join '|')
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt')|Should -BeFalse
      $otherVariant=if($variant -eq 'x64'){@('TMX.exe','DeskExp.exe')}else{@('TMX64.exe','DeskExp64.exe')}
      foreach($name in $otherVariant){Test-Path -LiteralPath (Join-Path $operation.InstallDirectory $name)|Should -BeFalse}

      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root "backup-$variant")
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'),'preserve')
      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy|Should -BeTrue
      [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve'
    }
  }

  It 'stages the exact retained publisher archive for both variants and restores only managed files' {
    $archivePath=$env:RIDE_MITEC_TMX_FIXTURE_ARCHIVE
    if([string]::IsNullOrWhiteSpace($archivePath)){
      Set-ItResult -Skipped -Because 'No explicit retained TMX.zip archive was supplied.'
      return
    }
    $archivePath=[IO.Path]::GetFullPath($archivePath)
    Test-Path -LiteralPath $archivePath -PathType Leaf|Should -BeTrue
    (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $Evidence.ArchiveSha256
    $zip=[IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
      foreach($variant in @('x64','x86')){
        foreach($member in $Evidence.Variants.$variant.Members){
          $entries=@($zip.Entries|Where-Object FullName -CEQ $member.Path)
          $entries.Count|Should -Be 1
          $entries[0].Length|Should -Be $member.Length
          $stream=$entries[0].Open();$sha=[Security.Cryptography.SHA256]::Create()
          try {$digest=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
          finally {$sha.Dispose();$stream.Dispose()}
          $digest|Should -BeExactly $member.Sha256
        }
      }
    } finally {$zip.Dispose()}

    foreach($variant in @('x64','x86')){
      $base=($Catalog.Operations|Where-Object Id -eq 'package.mitec-task-manager-deluxe').Clone()
      $operation=Resolve-RidePackageSelection -Operation $base -Variant $variant -MetadataOnly
      $operation.ResolvedToolsDirectory=Join-Path $Root "real-$variant"
      $operation.InstallDirectory=Join-Path $operation.ResolvedToolsDirectory $operation.PackageId
      $null=New-Item -ItemType Directory -Path $operation.ResolvedToolsDirectory -Force
      $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$Evidence.ArchiveSha256;Version='5.1.1'}
      Install-RidePortablePayload $operation $artifact -Offline
      Install-RidePortablePayload $operation $artifact -Offline
      $state=Get-RidePortableState $operation
      $state.Healthy|Should -BeTrue
      (@($state.Files.RelativePath|Sort-Object) -join '|')|Should -BeExactly ((@($Evidence.Variants.$variant.SelectedMembers|Sort-Object)) -join '|')
      foreach($member in $Evidence.Variants.$variant.Members){
        (Get-FileHash -LiteralPath (Join-Path $operation.InstallDirectory $member.Path) -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $member.Sha256
      }

      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $Root "real-backup-$variant")
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'),'preserve')
      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy|Should -BeTrue
      [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve'
    }
  }
}
