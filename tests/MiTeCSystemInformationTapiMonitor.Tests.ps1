<#
.SYNOPSIS
  Verify MiTeC System Information eXtra and TAPI Monitor package candidates.
.DESCRIPTION
  Reconciles retained publisher pins and exercises only synthetic ZIP staging.
  It does not launch either utility, collect host reports, inspect telephone
  lines/calls, or access a TAPI provider.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCSystemInformationTapiMonitor.Tests.ps1
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Report redaction, call control, license entitlement and target acceptance remain pending.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-system-information-tapi-static-review-2026-10-20.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-system-information-tapi'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC portable candidate <Id>' -ForEach @(
  @{Id='package.mitec-system-information';Product='MiTeC System Information eXtra';Version='16.0.0';Members=@('MSIX.exe','GetSys.exe','MSIX64.exe','GetSys64.exe')},
  @{Id='package.mitec-tapi-monitor';Product='MiTeC TAPI Monitor';Version='1.2.0';Members=@('TAPIMon.exe')}
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
        throw 'Refusing portable fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }
  It 'matches the retained source and leaves Windows support pending' {
    $row=$Evidence.Products|Where-Object Name -eq $Product
    $operation=$Catalog.Operations|Where-Object Id -eq $Id
    $operation|Should -Not -BeNullOrEmpty
    $operation.ProductUri|Should -BeExactly $row.ProductUri
    $operation.DownloadUri|Should -BeExactly $row.DownloadUri
    $operation.ExpectedSha256|Should -BeExactly $row.ArchiveSha256
    $operation.PackageVersion|Should -BeExactly $Version
    $operation.RequiredFiles|Should -Be $Members
    $operation.PortableMembers|Should -Be $Members
    $operation.CandidateTargets|Should -Be @('Windows 11')
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.PendingAcceptance|Should -BeTrue
    $operation.LicenseReviewStatus|Should -BeNullOrEmpty
    $operation.LicenseUri|Should -BeExactly $row.ProductUri
    $operation.TermsUri|Should -BeExactly 'https://www.mitec.cz/wp/support/'
    $row.ArchiveSha256|Should -Match '^[a-f0-9]{64}$'
    @($row.Members.Path|Sort-Object)|Should -Be @($Members|Sort-Object)
  }
  It 'repeats inert owned-file staging and restores it without losing unowned content' {
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
