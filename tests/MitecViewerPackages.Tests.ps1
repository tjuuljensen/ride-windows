<#
.SYNOPSIS
  Verify pinned MiTeC viewer variants and preservation of user-owned files.
.DESCRIPTION
  Uses inert ZIP fixtures or retained hash-matched archives selected through
  RIDE_MITEC_FIXTURE_DIRECTORY. All deployment paths are inside TestDrive.
  No acquired viewer is launched, activated or allowed to check for updates.
.EXAMPLE
  Invoke-Pester .\tests\MitecViewerPackages.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture. Real activation and native acceptance stay pending.
#>
BeforeAll {
  $repositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:ViewerCatalog=Import-RideCatalogData (Join-Path $repositoryRoot 'catalog/operations.psd1')
  $script:ViewerEvidenceRoot=Join-Path $repositoryRoot 'docs/archive/evidence'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'MiTeC viewer <Product> / <Variant>' -ForEach @(
  @{Product='mitec-json-viewer';Variant='portable'},
  @{Product='mitec-json-viewer';Variant='portable-x86'},
  @{Product='mitec-xml-viewer';Variant='portable'},
  @{Product='mitec-xml-viewer';Variant='portable-x86'}
) {
  BeforeEach {
    $script:ViewerOperation=($ViewerCatalog.Operations|Where-Object Id -eq ('package.'+$Product)).Clone()
    foreach($field in $ViewerOperation.Variants[$Variant].Keys){$ViewerOperation[$field]=$ViewerOperation.Variants[$Variant][$field]}
    $ViewerOperation.SelectedVariant=$Variant
    $script:ViewerReview=Get-Content (Join-Path $ViewerEvidenceRoot ($Product+'-source-review-2026-10-17.json')) -Raw|ConvertFrom-Json
    $script:ViewerRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $ViewerRoot
    $ViewerOperation.ResolvedToolsDirectory=$ViewerRoot
    $ViewerOperation.InstallDirectory=Join-Path $ViewerRoot $Product
    if($env:RIDE_MITEC_FIXTURE_DIRECTORY){
      $path=Join-Path $env:RIDE_MITEC_FIXTURE_DIRECTORY $ViewerReview.Archive
      $hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
      if($hash -cne $ViewerReview.Sha256 -or $hash -cne $ViewerOperation.ExpectedSha256){throw 'Retained archive differs from reviewed/catalog digest'}
    }else{
      $path=Join-Path $ViewerRoot 'inert.zip'
      $zip=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
      try{foreach($member in $ViewerReview.Members){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($member.Path).Open())
        try{$writer.Write('inert '+$member.Path)}finally{$writer.Dispose()}
      }}finally{$zip.Dispose()}
      $hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
      $ViewerOperation.ExpectedSha256=$hash
    }
    $script:ViewerArtifact=[pscustomobject]@{Path=$path;Sha256=$hash;Version=$ViewerOperation.PackageVersion}
  }
  It 'binds the chosen architecture and licence reference without promoting acceptance' {
    $declared=$ViewerCatalog.Operations|Where-Object Id -eq ('package.'+$Product)
    $declared.ExpectedSha256|Should -BeExactly $ViewerReview.Sha256
    $declared.DownloadUri|Should -BeExactly $ViewerReview.DownloadUri
    $ViewerOperation.PendingAcceptance|Should -BeTrue
    $ViewerOperation.SupportedTargets.Count|Should -Be 0
    $ViewerOperation.LicenseUri|Should -BeExactly 'https://www.mitec.cz/wp/support/'
    $ViewerOperation.ContainsKey('LicenseReviewStatus')|Should -BeFalse
    $ViewerOperation.RequiredFiles.Count|Should -Be 1
    $selected=$ViewerReview.Members|Where-Object Path -eq $ViewerOperation.RequiredFiles[0]
    $selected.PeMachine|Should -BeExactly $(if($Variant -eq 'portable'){'8664'}else{'014c'})
    $selected.FileVersion|Should -BeExactly $ViewerOperation.PackageVersion
  }
  It 'deploys only the selected executable and preserves synthetic licence/configuration through repeat, remove and restore' {
    $null=New-Item -ItemType Directory -Path $ViewerOperation.InstallDirectory
    $licence=Join-Path $ViewerOperation.InstallDirectory 'user-owned.lic'
    $config=Join-Path $ViewerOperation.InstallDirectory 'user-owned.ini'
    [IO.File]::WriteAllText($licence,'inert user-owned fixture; not an activation key')
    [IO.File]::WriteAllText($config,'user preference fixture')
    Install-RidePortablePayload $ViewerOperation $ViewerArtifact -Offline
    Install-RidePortablePayload $ViewerOperation $ViewerArtifact -Offline
    $state=Get-RidePortableState $ViewerOperation
    $state.Healthy|Should -BeTrue;$state.Files.Count|Should -Be 1
    $state.Files[0].RelativePath|Should -BeExactly $ViewerOperation.RequiredFiles[0]
    if($env:RIDE_MITEC_FIXTURE_DIRECTORY){
      $member=$ViewerReview.Members|Where-Object Path -eq $state.Files[0].RelativePath
      $state.Files[0].Sha256|Should -BeExactly $member.Sha256
    }
    $omitted=$ViewerReview.Members|Where-Object Path -ne $ViewerOperation.RequiredFiles[0]
    Test-Path (Join-Path $ViewerOperation.InstallDirectory $omitted.Path)|Should -BeFalse
    $snapshot=Save-RidePortableSnapshot $ViewerOperation (Join-Path $ViewerRoot 'backup')
    Uninstall-RidePortablePayload $ViewerOperation
    Restore-RidePortableSnapshot $ViewerOperation $snapshot
    (Get-RidePortableState $ViewerOperation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText($licence)|Should -BeExactly 'inert user-owned fixture; not an activation key'
    [IO.File]::ReadAllText($config)|Should -BeExactly 'user preference fixture'
  }
  It 'preserves a modified executable and refuses replacement' {
    Install-RidePortablePayload $ViewerOperation $ViewerArtifact -Offline
    $path=Join-Path $ViewerOperation.InstallDirectory $ViewerOperation.RequiredFiles[0]
    [IO.File]::WriteAllText($path,'modified file fixture')
    {Install-RidePortablePayload $ViewerOperation $ViewerArtifact -Offline}|Should -Throw '*modified managed*'
    Uninstall-RidePortablePayload $ViewerOperation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($path)|Should -BeExactly 'modified file fixture'
  }
  It 'refuses an unowned executable without adopting it' {
    $null=New-Item -ItemType Directory -Path $ViewerOperation.InstallDirectory
    $path=Join-Path $ViewerOperation.InstallDirectory $ViewerOperation.RequiredFiles[0]
    [IO.File]::WriteAllText($path,'unowned file fixture')
    {Install-RidePortablePayload $ViewerOperation $ViewerArtifact -Offline}|Should -Throw '*collision*'
    [IO.File]::ReadAllText($path)|Should -BeExactly 'unowned file fixture'
    Test-Path (Join-Path $ViewerOperation.InstallDirectory '.ride-package.json')|Should -BeFalse
  }
}
