<#
.SYNOPSIS
  Verify pinned NTCore candidates, exact member selection and file recovery.
.DESCRIPTION
  Uses inert ZIP fixtures, or retained reviewed archives when the explicit
  RIDE_NTCORE_FIXTURE_DIRECTORY environment variable is set. All product paths
  are in TestDrive. Does not run tools, patch files, scan input, update signatures
  or invoke network/signature providers.
.EXAMPLE
  Invoke-Pester .\tests\NtcorePackages.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture. Native and product compatibility remain pending.
#>
BeforeAll {
  $repositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:NtcoreCatalog=Import-RideCatalogData (Join-Path $repositoryRoot 'catalog/operations.psd1')
  $script:EvidenceRoot=Join-Path $repositoryRoot 'docs/archive/evidence'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'Reviewed NTCore candidate <Product>' -ForEach @(@{Product='ntcore-pe-detective'},@{Product='ntcore-cff-explorer'}) {
  BeforeEach {
    $script:Operation=($NtcoreCatalog.Operations|Where-Object Id -eq ('package.'+$Product)).Clone()
    $script:Review=Get-Content (Join-Path $EvidenceRoot ($Product+'-source-review-2026-10-17.json')) -Raw|ConvertFrom-Json
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    if($env:RIDE_NTCORE_FIXTURE_DIRECTORY){
      $path=Join-Path $env:RIDE_NTCORE_FIXTURE_DIRECTORY $Review.Archive
      $hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
      if($hash -cne $Review.Sha256 -or $hash -cne $Operation.ExpectedSha256){throw 'Retained archive does not match reviewed/catalog digest'}
    }else{
      $path=Join-Path $CaseRoot 'inert.zip'
      $zip=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
      try{foreach($member in @($Review.Members|Where-Object {-not $_.Path.EndsWith('/')})){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($member.Path).Open())
        try{$writer.Write('inert '+$member.Path)}finally{$writer.Dispose()}
      }}finally{$zip.Dispose()}
      $hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
      $Operation.ExpectedSha256=$hash
    }
    $script:Artifact=[pscustomobject]@{Path=$path;Sha256=$hash;Version=$Operation.PackageVersion}
  }
  It 'binds exact source and reviewed content while retaining the native acceptance gate' {
    $declared=$NtcoreCatalog.Operations|Where-Object Id -eq ('package.'+$Product)
    $declared.ExpectedSha256|Should -BeExactly $Review.Sha256
    $declared.DownloadUri|Should -BeExactly $Review.DownloadUri
    $declared.ProductUri|Should -BeExactly $Review.ProductUri
    $declared.PendingAcceptance|Should -BeTrue;$declared.SupportedTargets.Count|Should -Be 0
    $declared.Architecture|Should -Be x86
    @($declared.RequiredFiles|Where-Object {$_ -notin $Review.SelectedFiles}).Count|Should -Be 0
    $declared.RequiredFiles.Count|Should -Be $Review.SelectedFiles.Count
    if($Product -eq 'ntcore-cff-explorer'){$declared.PortableMembers.Count|Should -Be 6;$Review.OmittedFiles.Count|Should -Be 10}
    else{$Review.SelectedFiles.Count|Should -Be 7}
  }
  It 'installs only reviewed members, repeats, removes and exactly restores owned files' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    Install-RidePortablePayload $Operation $Artifact -Offline
    $state=Get-RidePortableState $Operation
    $state.Healthy|Should -BeTrue;$state.Files.Count|Should -Be $Review.SelectedFiles.Count
    @($state.Files|Where-Object {$_.RelativePath -notin $Review.SelectedFiles}).Count|Should -Be 0
    if($env:RIDE_NTCORE_FIXTURE_DIRECTORY){
      foreach($file in $state.Files){$expected=$Review.Members|Where-Object Path -ceq $file.RelativePath;$file.Sha256|Should -BeExactly $expected.Sha256}
    }
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'custom-note.txt'),'preserve me')
    Uninstall-RidePortablePayload $Operation
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'custom-note.txt'))|Should -BeExactly 'preserve me'
  }
  It 'preserves edited signature databases and refuses replacement' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    $relative=@($Review.SelectedFiles|Where-Object {$_ -like '*.xml'})[0]
    $path=Join-Path $Operation.InstallDirectory $relative
    [IO.File]::WriteAllText($path,'custom signatures')
    {Install-RidePortablePayload $Operation $Artifact -Offline}|Should -Throw '*modified managed*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($path)|Should -BeExactly 'custom signatures'
  }
  It 'refuses an unowned executable collision before creating ownership' {
    $path=Join-Path $Operation.InstallDirectory (@($Review.SelectedFiles|Where-Object {$_ -like '*.exe'})[0])
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    [IO.File]::WriteAllText($path,'unowned content')
    {Install-RidePortablePayload $Operation $Artifact -Offline}|Should -Throw '*collision*'
    [IO.File]::ReadAllText($path)|Should -BeExactly 'unowned content'
    Test-Path (Join-Path $Operation.InstallDirectory '.ride-package.json')|Should -BeFalse
  }
}
