<#
.SYNOPSIS
  Validate the pinned Suite snapshot and inert owned-file lifecycle.
.DESCRIPTION
  Builds synthetic ZIP data from reviewed member names. Executes no Sysinternals
  utility, installer, driver, service, EULA interaction or forensic operation.
.EXAMPLE
  Invoke-Pester .\tests\SysinternalsSuitePackage.Tests.ps1
.NOTES
  Compatibility: Pester 5.x on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; individual selection/native acceptance remain pending.
#>
BeforeAll {
  $Repo=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Repo modules/RIDE.CatalogData.psm1) -Force
  Import-Module (Join-Path $Repo modules/RIDE-PortablePackages.psm1) -Force
  $Suite=(Import-RideCatalogData (Join-Path $Repo catalog/operations.psd1)).Operations|Where-Object Id -eq package.sysinternals-suite
  $Evidence=Get-Content -LiteralPath (Join-Path $Repo docs/archive/evidence/sysinternals-suite-source-review-2026-10-17.json) -Raw|ConvertFrom-Json
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
  function New-InertSuiteArchive([string]$Path,[string[]]$Members){
    $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try{foreach($member in $Members){$writer=[IO.StreamWriter]::new($zip.CreateEntry($member).Open());try{$writer.Write('Inert fixture; never execute: '+$member)}finally{$writer.Dispose()}}}finally{$zip.Dispose()}
    [pscustomobject]@{Path=$Path;Version=$Suite.PackageVersion;Sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
  }
}
Describe 'Sysinternals pinned acquisition boundaries' {
  BeforeAll {Import-Module (Join-Path $Repo modules/RIDE-Packages.psm1) -Force}
  BeforeEach {$SelectedSuite=$Suite.Clone();$SelectedSuite.SelectedVariant='portable'}
  It 'resolves the exact snapshot without calling mutable discovery' {
    Mock Invoke-WebRequest -ModuleName RIDE-Packages {throw 'No network discovery'}
    Mock Invoke-RestMethod -ModuleName RIDE-Packages {throw 'No network discovery'}
    $artifact=Resolve-RidePackageArtifact -Operation $SelectedSuite
    $artifact.Version|Should -BeExactly $Suite.PackageVersion
    $artifact.ProviderDigest|Should -BeExactly ('sha256:'+$Suite.ExpectedSha256)
    Should -Invoke Invoke-WebRequest -ModuleName RIDE-Packages -Exactly -Times 0
    Should -Invoke Invoke-RestMethod -ModuleName RIDE-Packages -Exactly -Times 0
  }
  It 'rejects changed upstream bytes without recording success or starting a tool' {
    Mock Invoke-WebRequest -ModuleName RIDE-Packages {[IO.File]::WriteAllText($OutFile,'different inert upstream snapshot')}
    Mock Add-RideArtifactObservation -ModuleName RIDE-Packages {throw 'Must not record a mismatch as success'}
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages {throw 'Must not run a tool'}
    {Save-RidePackageArtifact -Operation $SelectedSuite -DestinationDirectory (Join-Path $TestDrive cache) -ObservationPath (Join-Path $TestDrive observation.json)}|Should -Throw '*digest mismatch*'
    Should -Invoke Add-RideArtifactObservation -ModuleName RIDE-Packages -Exactly -Times 0
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Exactly -Times 0
  }
}
Describe 'Sysinternals reviewed portable snapshot' {
  BeforeEach {
    $CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation=$Suite.Clone();$Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot;$Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    Mock Get-AuthenticodeSignature -ModuleName RIDE-PortablePackages {[pscustomobject]@{Status='NotSigned';SignerCertificate=$null}}
  }
  It 'binds the official observed archive and every reviewed member without support claims' {
    $Suite.ExpectedSha256|Should -BeExactly $Evidence.Acquisition.Sha256
    $Suite.PackageVersion|Should -BeExactly $Evidence.SnapshotId
    $Suite.RequiredFiles.Count|Should -Be 164
    @(Compare-Object $Suite.RequiredFiles $Evidence.Members.Name -CaseSensitive).Count|Should -Be 0
    @($Evidence.Members|Where-Object SignatureStatus -eq Valid).Count|Should -Be 151
    @($Evidence.Members|Where-Object ErrorType).Count|Should -Be 0
    $Suite.RequiredFiles|Should -Contain Eula.txt
    $Suite.DownloadUri|Should -BeExactly 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
    $Suite.PendingAcceptance|Should -BeTrue;$Suite.SupportedTargets.Count|Should -Be 0
    $Suite.InstallerArguments|Should -BeNullOrEmpty;$Suite.UninstallerArguments|Should -BeNullOrEmpty
    $Suite.Architecture|Should -BeExactly neutral
    foreach($path in Get-ChildItem -LiteralPath (Join-Path $Repo profiles) -Filter '*.psd1'){
      [IO.File]::ReadAllText($path.FullName)|Should -Not -Match 'package\.sysinternals-suite'
    }
  }
  It 'refuses an archive missing notices before creating the destination' {
    $artifact=New-InertSuiteArchive (Join-Path $CaseRoot incomplete.zip) @($Suite.RequiredFiles|Where-Object {$_ -cne 'Eula.txt'})
    {Install-RidePortablePayload $Operation $artifact}|Should -Throw '*missing required file*'
    Test-Path -LiteralPath $Operation.InstallDirectory|Should -BeFalse
  }
  It 'rejects changed archive bytes before extraction' {
    $artifact=New-InertSuiteArchive (Join-Path $CaseRoot changed.zip) $Suite.RequiredFiles
    $artifact.Sha256='0'*64
    {Install-RidePortablePayload $Operation $artifact}|Should -Throw '*SHA-256 changed*'
    Test-Path -LiteralPath $Operation.InstallDirectory|Should -BeFalse
  }
  It 'stages repeats removes and restores owned members while preserving operator data' {
    $artifact=New-InertSuiteArchive (Join-Path $CaseRoot suite.zip) $Suite.RequiredFiles
    Install-RidePortablePayload $Operation $artifact
    $settings=Join-Path $Operation.InstallDirectory operator.rdg;[IO.File]::WriteAllText($settings,'operator connections; inert fixture')
    Install-RidePortablePayload $Operation $artifact
    $state=Get-RidePortableState $Operation;$state.Healthy|Should -BeTrue;$state.Manifest.Files.Count|Should -Be 164
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot backup)
    Uninstall-RidePortablePayload $Operation
    [IO.File]::ReadAllText($settings)|Should -BeExactly 'operator connections; inert fixture'
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText($settings)|Should -BeExactly 'operator connections; inert fixture'
  }
  It 'preserves a conflicting or modified executable instead of adopting or replacing it' {
    $artifact=New-InertSuiteArchive (Join-Path $CaseRoot suite.zip) $Suite.RequiredFiles
    $null=New-Item -ItemType Directory -Path $Operation.InstallDirectory
    $path=Join-Path $Operation.InstallDirectory Sysmon64.exe;[IO.File]::WriteAllText($path,'unowned executable fixture')
    {Install-RidePortablePayload $Operation $artifact}|Should -Throw '*collision*'
    [IO.File]::ReadAllText($path)|Should -BeExactly 'unowned executable fixture'
    Remove-Item -LiteralPath $path
    Install-RidePortablePayload $Operation $artifact
    [IO.File]::WriteAllText($path,'modified executable fixture')
    {Install-RidePortablePayload $Operation $artifact}|Should -Throw '*modified*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($path)|Should -BeExactly 'modified executable fixture'
  }
}
