<#
.SYNOPSIS
  Verify MiTeC OLE/COM Explorer and sensitive-data viewer package candidates.
.DESCRIPTION
  Checks retained archive/member pins and exercises inert synthetic ZIP lifecycle only.
  No COM activation, registry hive inspection, firmware query or report generation occurs.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCReviewDataTools.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Product behavior, sensitive-data handling and Windows target acceptance remain deferred.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:OleEvidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-olecom-project-maker-static-review-2026-10-21.json') -Raw | ConvertFrom-Json
  $script:SensitiveEvidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-registry-recovery-smbios-static-review-2026-10-21.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-review-data-tools'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC review-data portable candidate <Id>' -ForEach @(
  @{Id='package.mitec-ole-com-explorer';Product='MiTeC OLE/COM Object Explorer';Version='1.4.0.0';Members=@('OLExp.exe');Uri='https://www.mitec.cz/wp/molexp/';Download='https://www.mitec.cz/wp/files/OLExp.zip'},
  @{Id='package.mitec-windows-registry-recovery';Product='MiTeC Windows Registry Recovery';Version='3.1.3';Members=@('WRR.exe','WRR64.exe');Uri='https://www.mitec.cz/wp/mwrr/';Download='https://www.mitec.cz/wp/files/WRR.zip'},
  @{Id='package.mitec-smbios-explorer';Product='MiTeC SMBIOS Explorer';Version='1.8.0';Members=@('SMBE.exe','SMBE64.exe','SMBIOS.exe');Uri='https://www.mitec.cz/wp/smbe/';Download='https://www.mitec.cz/wp/files/SMBE.zip'}
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
        throw 'Refusing review-data tool fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }
  It 'matches the retained source/member pins and leaves support pending' {
    if($Id -ceq 'package.mitec-ole-com-explorer'){
      $source=$OleEvidence.Products|Where-Object Name -eq $Product
      $archiveSha=$source.ArchiveSha256
      $memberRows=@($source.Members)
    }else{
      $source=$SensitiveEvidence.Products|Where-Object ProductUri -eq $Uri
      $archiveSha=$source.ArchiveSha256
      $memberRows=@($source.Members)
    }
    $operation=$Catalog.Operations|Where-Object Id -eq $Id
    $operation|Should -Not -BeNullOrEmpty
    $operation.ProductUri|Should -BeExactly $Uri
    $operation.DownloadUri|Should -BeExactly $Download
    $operation.ExpectedSha256|Should -BeExactly $archiveSha
    $operation.PackageVersion|Should -BeExactly $Version
    $operation.RequiredFiles|Should -Be $Members
    $operation.PortableMembers|Should -Be $Members
    $operation.CandidateTargets|Should -Be @('Windows 11')
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.PendingAcceptance|Should -BeTrue
    $operation.LicenseReviewStatus|Should -BeNullOrEmpty
    $operation.TermsUri|Should -BeExactly 'https://www.mitec.cz/wp/support/'
    @($memberRows.Path)|Should -Be $Members
    @($memberRows|Where-Object {$_.Sha256 -notmatch '^[a-f0-9]{64}$'}).Count|Should -Be 0
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
