<#
.SYNOPSIS
  Verify Windows File Analyzer and Icon Explorer candidate package boundaries.
.DESCRIPTION
  Checks retained source pins and exercises only inert synthetic ZIP staging.
  It never opens host artifacts, scans real paths or launches either utility.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCHistoricalFileTools.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Product behavior, report/output cleanup and Windows target acceptance remain deferred.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-file-analyzer-icon-explorer-static-review-2026-10-21.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-historical-file-tools'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC historical portable candidate <Id>' -ForEach @(
  @{Id='package.mitec-windows-file-analyzer';Product='Windows File Analyzer';Version='2.10.0';Members=@('WFA.exe');Uri='https://www.mitec.cz/wfa.html';Download='https://www.mitec.cz/Downloads/WFA.zip'},
  @{Id='package.mitec-icon-explorer';Product='Icon Explorer';Version='5.3.0';Members=@('IconExplorer.exe');Uri='https://www.mitec.cz/iconex.html';Download='https://www.mitec.cz/Downloads/IconExplorer.zip'}
) {
  BeforeEach {
    $script:CaseRoot=Join-Path $FixtureRoot ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot -Force
  }
  AfterEach {
    if(Test-Path -LiteralPath $CaseRoot -PathType Container){
      $resolved=[IO.Path]::GetFullPath($CaseRoot).TrimEnd('\')
      $parent=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
      if([IO.Path]::GetDirectoryName($resolved) -ine $parent -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$'){
        throw 'Refusing historical-tool fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }
  It 'matches the retained version and exact selected member set while leaving support pending' {
    $row=$Evidence.PinnedArtifacts|Where-Object Product -eq $Product
    $operation=$Catalog.Operations|Where-Object Id -eq $Id
    $operation|Should -Not -BeNullOrEmpty
    $operation.ProductUri|Should -BeExactly $Uri
    $operation.DownloadUri|Should -BeExactly $Download
    $operation.ExpectedSha256|Should -BeExactly $row.Sha256
    $operation.PackageVersion|Should -BeExactly $Version
    $operation.RequiredFiles|Should -Be $Members
    $operation.PortableMembers|Should -Be $Members
    $operation.CandidateTargets|Should -Be @('Windows 11')
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.PendingAcceptance|Should -BeTrue
    $operation.LicenseReviewStatus|Should -BeNullOrEmpty
    $operation.TermsUri|Should -BeExactly 'https://www.mitec.cz/wp/support/'
    @($row.Member.Path)|Should -Be $Members
    $row.Member.Sha256|Should -Match '^[a-f0-9]{64}$'
  }
  It 'repeats inert offline staging and restores owned files without losing unowned content' {
    $archivePath=Join-Path $CaseRoot 'fixture.zip'
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($name in @($Members+'ignored.txt')){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open())
        try{$writer.Write('inert fixture '+$name)}finally{$writer.Dispose()}
      }
    } finally {$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $operation=($Catalog.Operations|Where-Object Id -eq $Id).Clone()
    $operation.SelectedVariant='portable'
    $operation.ExpectedSha256=$sha
    $operation.ResolvedToolsDirectory=$CaseRoot
    $operation.InstallDirectory=Join-Path $CaseRoot $operation.PackageId
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$sha;Version=$Version}

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    @($state.Files.RelativePath|Sort-Object)|Should -Be @($Members|Sort-Object)
    @($state.Manifest.Files|Where-Object AuthenticodeStatus -ne 'NotInspectedOffline').Count|Should -Be 0
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt')|Should -BeFalse

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }
}
