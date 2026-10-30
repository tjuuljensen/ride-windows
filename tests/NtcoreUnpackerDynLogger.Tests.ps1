<#
.SYNOPSIS
  Verify NTCore Unpacker and DynLogger package pins and portable file recovery.
.DESCRIPTION
  Checks publisher pins independently of synthetic ZIP file-lifecycle fixtures.
  Set RIDE_NTCORE_FIXTURE_DIRECTORY to run additional retained publisher ZIP
  checks. Destinations are in TestDrive. Never launches a tool or inspects,
  dumps, or instruments a target process, and never loads a driver.
.EXAMPLE
  Invoke-Pester .\tests\NtcoreUnpackerDynLogger.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Retained archives are read-only; all installed files are isolated in TestDrive.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:FixtureRoot=$env:RIDE_NTCORE_FIXTURE_DIRECTORY
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
  function Assert-NtcoreFixtureLifecycle {
    param($Operation, $Artifact, [string]$CaseRoot, [string[]]$Files)
    Install-RidePortablePayload $Operation $Artifact -Offline
    Install-RidePortablePayload $Operation $Artifact -Offline
    $state=Get-RidePortableState $Operation
    $state.Healthy|Should -BeTrue
    @($state.Files.RelativePath)|Should -Be @($Files)
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'operator-note.txt'),'preserve me')
    Uninstall-RidePortablePayload $Operation
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve me'
  }
}

Describe 'NTCore portable candidate <Id> <Variant>' -ForEach @(
  @{Id='package.ntcore-net-generic-unpacker';Variant='portable-x86';Archive='NETUnpack.zip';Hash='e46bd2ecdd1cc72c011406fa07d239f1ad8d8cd5e6c5e9945d186078c3e24278';Files=@('NETUnpack.exe')},
  @{Id='package.ntcore-net-generic-unpacker';Variant='portable-x64';Archive='NETUnpack_x64.zip';Hash='af7f2ca052855d6c1613eb6901897ab9c1ffa4eda17b115e71651fbdcec13852';Files=@('NETUnpack.exe')},
  @{Id='package.ntcore-dynlogger';Variant='portable-x86';Archive='DynLogger_x86.zip';Hash='416e92b91b05ecbcf622476da538785ecfa30910cd42ee1a508361f22a1ccaa5';Files=@('DynLogger.exe','DynLoggerDll.dll','NtHookEngine.dll')},
  @{Id='package.ntcore-dynlogger';Variant='portable-x64';Archive='DynLogger_x64.zip';Hash='a5e17491696d36f5c9b17f0e73ed33cfb9bf0f14fb035bb40c868ab5b6c0be3c';Files=@('DynLogger.exe','DynLoggerDll.dll','NtHookEngine.dll')},
  @{Id='package.ntcore-snsremover';Variant='portable';Archive='SNSRemover.zip';Hash='c6405c5ec5ec8646a02a46bcfdf74e05457addabdc58fe78da84ea28d69ca7cd';Files=@('SNSRemover.exe');ArchiveMembers=@('SNSRemover.exe','PE_Detective.zip')},
  @{Id='package.ntcore-nodel';Variant='portable';Archive='NoDel.zip';Hash='b71b763dd54c5b6d67238d6f118c4ec3bfc531f14663ba59fc72655444ffd386';Files=@('NoDel/Release/NoDel.exe','NoDel/Release/nodel.sys');ArchiveMembers=@('NoDel/','NoDel/Drivers.cpp','NoDel/nodel.cpp','NoDel/nodel.exe.manifest','NoDel/NoDel.rc','NoDel/NoDel.vcproj','NoDel/Release/','NoDel/Release/NoDel.exe','NoDel/Release/nodel.sys','NoDel/resource.h','nodel_drv/','nodel_drv/common.h','nodel_drv/makefile','nodel_drv/nodel.c','nodel_drv/sources','nodel_drv/wr_private.c','nodel_drv/wr_private.h','NoDel.ncb','NoDel.sln')}
) {
  BeforeEach {
    $script:BaseOperation=$Catalog.Operations|Where-Object Id -CEQ $Id
    $script:Operation=Resolve-RidePackageSelection -Operation $BaseOperation -Variant $Variant -MetadataOnly -IgnorePreferences
    $script:Operation=$Operation.Clone()
    $script:DeclaredHash=$Operation.ExpectedSha256
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
  }

  It 'declares the exact publisher pin, architecture and selected member inventory' {
    $BaseOperation.PendingAcceptance|Should -BeTrue
    $BaseOperation.SupportedTargets|Should -BeNullOrEmpty
    $BaseOperation.CandidateTargets|Should -Contain 'Windows 11'
    $Operation.ExpectedSha256|Should -BeExactly $Hash
    $expectedArchitecture=if($Variant -eq 'portable'){'x86'}else{$Variant -replace '^portable-',''}
    $Operation.Architecture|Should -BeExactly $expectedArchitecture
    @($Operation.PortableMembers)|Should -Be @($Files)
    if($Id -eq 'package.ntcore-snsremover'){$Operation.PackageVersion|Should -BeExactly '2005-11-29';$BaseOperation.PortableMembers|Should -Not -Contain 'PE_Detective.zip'}
    if($Id -eq 'package.ntcore-nodel'){$Operation.PackageVersion|Should -BeExactly '2005-05-04';$Operation.RequiredFiles.Count|Should -Be 2}
  }

  It 'stages, repeats, removes and restores synthetic owned files without a publisher cache' {
    $archivePath=Join-Path $CaseRoot 'synthetic.zip'
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($member in @($Files)+@('unselected-fixture.txt')){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($member).Open())
        try{$writer.Write('inert unit-test fixture')}finally{$writer.Dispose()}
      }
    }finally{$zip.Dispose()}
    $fixtureHash=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $Operation.ExpectedSha256=$fixtureHash
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$fixtureHash;Version=$Operation.PackageVersion}
    Assert-NtcoreFixtureLifecycle $Operation $artifact $CaseRoot $Files
    Test-Path -LiteralPath (Join-Path $Operation.InstallDirectory 'unselected-fixture.txt')|Should -BeFalse
  }

  It 'verifies the retained publisher archive and lifecycle when explicitly configured' {
    if([string]::IsNullOrWhiteSpace($FixtureRoot)){
      Set-ItResult -Skipped -Because 'Set RIDE_NTCORE_FIXTURE_DIRECTORY to enable exact publisher archive checks.'
      return
    }
    $archivePath=Join-Path $FixtureRoot $Archive
    $actualHash=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $actualHash|Should -BeExactly $DeclaredHash
    $actualHash|Should -BeExactly $Hash
    $zip=[IO.Compression.ZipFile]::OpenRead($archivePath)
    $expectedMembers=if($ArchiveMembers){$ArchiveMembers}else{$Files}
    try{@($zip.Entries|ForEach-Object FullName)|Should -Be @($expectedMembers)}finally{$zip.Dispose()}
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$actualHash;Version=$Operation.PackageVersion}
    Assert-NtcoreFixtureLifecycle $Operation $artifact $CaseRoot $Files
  }
}
