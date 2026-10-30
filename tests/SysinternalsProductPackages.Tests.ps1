<#
.SYNOPSIS
  Check independent Sysinternals product pins and owned-file lifecycle.
.DESCRIPTION
  Uses inert text ZIP members and mocked network/signature calls. No Sysinternals
  program, driver, EULA interaction, startup change or network inspection runs.
.EXAMPLE
  Invoke-Pester .\tests\SysinternalsProductPackages.Tests.ps1
.PARAMETER ProductIds
  Optional test-container data selecting product cases; empty runs every case.
.NOTES
  Compatibility: Pester 5.x, Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: 0.1.0. Native product acceptance remains separate.
#>
param([string[]]$ProductIds=@())
BeforeDiscovery {
  $Products=@(
    @{Id='process-explorer';Version='17.2';Count=4;Signed=3},
    @{Id='autoruns';Version='14.3';Count=7;Signed=6},
    @{Id='tcpview';Version='4.19';Count=8;Signed=6},
    @{Id='procmon';Version='4.12';Count=4;Signed=3},
    @{Id='rammap';Version='1.63';Count=4;Signed=3},
    @{Id='disk2vhd';Version='2.02';Count=5;Signed=3},
    @{Id='sigcheck';Version='2.93';Count=4;Signed=3},
    @{Id='strings';Version='2.54';Count=4;Signed=3},
    @{Id='handle';Version='5.0';Count=4;Signed=3}
  ) | Where-Object {$ProductIds.Count -eq 0 -or $_.Id -in $ProductIds}
}
BeforeAll {
  $Repo=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Repo modules/RIDE.CatalogData.psm1) -Force
  Import-Module (Join-Path $Repo modules/RIDE-PortablePackages.psm1) -Force
  Import-Module (Join-Path $Repo modules/RIDE-Packages.psm1) -Force
  $Catalog=Import-RideCatalogData (Join-Path $Repo catalog/operations.psd1)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
  function New-InertProductArchive([string]$Path,[string[]]$Members,[string]$Version){
    $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try{foreach($member in $Members){$writer=[IO.StreamWriter]::new($zip.CreateEntry($member).Open());try{$writer.Write('Inert fixture; never execute: '+$member)}finally{$writer.Dispose()}}}finally{$zip.Dispose()}
    [pscustomobject]@{Path=$Path;Version=$Version;Sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
  }
}
Describe 'Independent Sysinternals <Id>' -ForEach $Products {
  BeforeAll {
    $Product=$Catalog.Operations|Where-Object Id -eq ('package.sysinternals-'+$Id)
    $Evidence=Get-Content -LiteralPath (Join-Path $Repo ('docs/archive/evidence/sysinternals-'+$Id+'-source-review-2026-10-17.json')) -Raw|ConvertFrom-Json
  }
  BeforeEach {
    $CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation=$Product.Clone();$Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot;$Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    Mock Get-AuthenticodeSignature -ModuleName RIDE-PortablePackages {[pscustomobject]@{Status='NotSigned';SignerCertificate=$null}}
    Mock Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages {throw 'No product launch'}
  }
  It 'binds the complete publisher archive for the accepted Windows 11 lifecycle without executing the product' {
    $Product.ExpectedSha256|Should -BeExactly $Evidence.Acquisition.Sha256
    $Product.PackageVersion|Should -BeExactly $Version
    $Product.RequiredFiles.Count|Should -Be $Count
    @(Compare-Object $Product.RequiredFiles $Evidence.Members.Name -CaseSensitive).Count|Should -Be 0
    @($Evidence.Members|Where-Object SignatureStatus -eq Valid).Count|Should -Be $Signed
    @($Evidence.Members|Where-Object ErrorType).Count|Should -Be 0
    $Product.RequiredFiles|Should -Contain Eula.txt
    $Product.PendingAcceptance|Should -BeFalse;$Product.SupportedTargets|Should -Contain 'Windows 11'
    $Product.InstallerArguments|Should -BeNullOrEmpty;$Product.UninstallerArguments|Should -BeNullOrEmpty
    foreach($path in Get-ChildItem -LiteralPath (Join-Path $Repo profiles) -Filter '*.psd1'){
      [IO.File]::ReadAllText($path.FullName)|Should -Not -Match ([regex]::Escape($Product.Id))
    }
  }
  It 'resolves a pinned version without mutable network discovery' {
    Mock Invoke-WebRequest -ModuleName RIDE-Packages {throw 'No discovery'}
    Mock Invoke-RestMethod -ModuleName RIDE-Packages {throw 'No discovery'}
    $artifact=Resolve-RidePackageArtifact -Operation $Operation
    $artifact.Version|Should -BeExactly $Version
    $artifact.ProviderDigest|Should -BeExactly ('sha256:'+$Product.ExpectedSha256)
    Should -Invoke Invoke-WebRequest -ModuleName RIDE-Packages -Exactly -Times 0
    Should -Invoke Invoke-RestMethod -ModuleName RIDE-Packages -Exactly -Times 0
  }
  It 'refuses changed upstream bytes before recording success or launching' {
    Mock Invoke-WebRequest -ModuleName RIDE-Packages {[IO.File]::WriteAllText($OutFile,'changed inert payload')}
    Mock Add-RideArtifactObservation -ModuleName RIDE-Packages {throw 'Do not record success'}
    {Save-RidePackageArtifact -Operation $Operation -DestinationDirectory (Join-Path $CaseRoot cache) -ObservationPath (Join-Path $CaseRoot observation.json)}|Should -Throw '*digest mismatch*'
    Should -Invoke Add-RideArtifactObservation -ModuleName RIDE-Packages -Exactly -Times 0
    Should -Invoke Invoke-RidePackageInstallerProcess -ModuleName RIDE-Packages -Exactly -Times 0
  }
  It 'requires the complete pinned archive member set before creating the destination' {
    $artifact=New-InertProductArchive (Join-Path $CaseRoot missing.zip) @($Product.RequiredFiles|Where-Object {$_ -cne 'Eula.txt'}) $Version
    {Install-RidePortablePayload $Operation $artifact}|Should -Throw '*missing required file*'
    Test-Path -LiteralPath $Operation.InstallDirectory|Should -BeFalse
  }
  It 'refuses a corrupt archive digest before extraction' {
    $artifact=New-InertProductArchive (Join-Path $CaseRoot changed.zip) $Product.RequiredFiles $Version;$artifact.Sha256='0'*64
    {Install-RidePortablePayload $Operation $artifact}|Should -Throw '*SHA-256 changed*'
    Test-Path -LiteralPath $Operation.InstallDirectory|Should -BeFalse
  }
  It 'repeats removes and restores owned content while retaining user configuration' {
    $artifact=New-InertProductArchive (Join-Path $CaseRoot product.zip) $Product.RequiredFiles $Version
    Install-RidePortablePayload $Operation $artifact
    $custom=Join-Path $Operation.InstallDirectory operator.json;[IO.File]::WriteAllText($custom,'operator choices')
    Install-RidePortablePayload $Operation $artifact
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot backup)
    Uninstall-RidePortablePayload $Operation
    [IO.File]::ReadAllText($custom)|Should -BeExactly 'operator choices'
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText($custom)|Should -BeExactly 'operator choices'
  }
  It 'retains unowned collisions and locally modified product files' {
    $artifact=New-InertProductArchive (Join-Path $CaseRoot product.zip) $Product.RequiredFiles $Version
    $null=New-Item -ItemType Directory -Path $Operation.InstallDirectory
    $path=Join-Path $Operation.InstallDirectory $Product.RequiredFiles[0];[IO.File]::WriteAllText($path,'unowned fixture')
    {Install-RidePortablePayload $Operation $artifact}|Should -Throw '*collision*'
    [IO.File]::ReadAllText($path)|Should -BeExactly 'unowned fixture'
    Remove-Item -LiteralPath $path
    Install-RidePortablePayload $Operation $artifact
    [IO.File]::WriteAllText($path,'modified fixture')
    {Install-RidePortablePayload $Operation $artifact}|Should -Throw '*modified*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($path)|Should -BeExactly 'modified fixture'
  }
  It 'does not remove an independently owned suite folder with matching filenames' {
    $artifact=New-InertProductArchive (Join-Path $CaseRoot product.zip) $Product.RequiredFiles $Version
    Install-RidePortablePayload $Operation $artifact
    $suiteRoot=Join-Path $CaseRoot sysinternals-suite;$null=New-Item -ItemType Directory -Path $suiteRoot
    $sibling=Join-Path $suiteRoot $Product.RequiredFiles[0];[IO.File]::WriteAllText($sibling,'separate Suite fixture')
    Uninstall-RidePortablePayload $Operation
    [IO.File]::ReadAllText($sibling)|Should -BeExactly 'separate Suite fixture'
    Test-Path -LiteralPath (Join-Path $Operation.InstallDirectory $Product.RequiredFiles[0])|Should -BeFalse
  }
}
