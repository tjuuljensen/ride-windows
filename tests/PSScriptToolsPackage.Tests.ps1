<#
.SYNOPSIS
  Verify pinned source-script package notice requirements and file ownership.
.DESCRIPTION
  Uses compact inert archives for failure-boundary tests and builds one full
  archive from all 360 reviewed members for lifecycle coverage. Optionally reads
  RIDE_PSSCRIPTTOOLS_FIXTURE_ARCHIVE for the retained, hash-pinned publisher ZIP.
  Product install and backup destinations stay in TestDrive; archive extraction
  uses the process TEMP directory. Uses offline staging to prevent
  certificate-provider network checks. Does not run/import upstream code or
  installers, install dependencies, or inspect editor/session data.
.EXAMPLE
  Invoke-Pester .\tests\PSScriptToolsPackage.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture. Native and interpreter acceptance remain pending.
#>
BeforeAll {
  $root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE-PortablePackages.psm1') -Force
  $script:SourceCatalog=Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
  $script:SourceReview=Get-Content -LiteralPath (Join-Path $root 'docs/archive/evidence/psscripttools-source-review-2026-10-17.json') -Raw | ConvertFrom-Json
  $script:SourceMembers=@($SourceReview.Members | Where-Object {-not $_.Path.EndsWith('/')} | ForEach-Object Path)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
  function New-InertSourceArchive {
    param([string]$Path,[string[]]$Members,[string]$Version)
    $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try{foreach($member in $Members){
      $writer=[IO.StreamWriter]::new($zip.CreateEntry($member).Open())
      try{$writer.Write('Inert fixture, not executable source: '+$member)}finally{$writer.Dispose()}
    }}finally{$zip.Dispose()}
    [pscustomobject]@{Path=$Path;Version=$Version;Sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
  }
}
Describe 'Pinned source package <Id>' -ForEach @(@{Id='package.psscripttools'}) {
  BeforeEach {
    $script:Operation=($SourceCatalog.Operations|Where-Object Id -eq $Id).Clone()
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    $script:FixtureMembers=@(@($Operation.RequiredFiles)+@($SourceMembers[0])|Select-Object -Unique)
    $script:Artifact=New-InertSourceArchive (Join-Path $CaseRoot 'psscripttools-fixture.zip') $FixtureMembers $Operation.PackageVersion
  }
  It 'declares complete pinned source and notices without runtime activation' {
    $Operation.PendingAcceptance | Should -BeTrue
    $Operation.SupportedTargets.Count | Should -Be 0
    $Operation.Architecture | Should -Be neutral
    $Operation.RequiredFiles.Count | Should -Be 10
    @($Operation.RequiredFiles|Where-Object {$_ -like '*/license.txt'}).Count | Should -Be 1
    @($Operation.RequiredFiles|Where-Object {$_ -like '*/PSScriptTools.psm1'}).Count | Should -Be 1
    $Operation.DownloadUri | Should -Match '/archive/[0-9a-f]{40}\.zip$'
    $Operation.ExpectedSha256 | Should -Match '^[0-9a-f]{64}$'
    $Operation.InstallerArguments | Should -BeNullOrEmpty
    $Operation.DependsOn | Should -BeNullOrEmpty
  }
  It 'refuses an incomplete module-only payload when its license and README are missing' {
    $scriptOnly=New-InertSourceArchive (Join-Path $CaseRoot 'incomplete.zip') @($Operation.RequiredFiles|Where-Object {$_ -like '*/PSScriptTools.psm1'}) $Operation.PackageVersion
    {Install-RidePortablePayload $Operation $scriptOnly} | Should -Throw '*missing required file*'
    Test-Path -LiteralPath $Operation.InstallDirectory | Should -BeFalse
  }
  It 'stages, repeats and restores source while preserving unowned analyst output' {
    if($env:RIDE_PSSCRIPTTOOLS_FIXTURE_ARCHIVE){
      $path=[IO.Path]::GetFullPath($env:RIDE_PSSCRIPTTOOLS_FIXTURE_ARCHIVE)
      $hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
      if($hash -cne $SourceReview.Sha256 -or $hash -cne $Operation.ExpectedSha256){throw 'Retained source differs from the reviewed/catalog pin.'}
      $Artifact=[pscustomobject]@{Path=$path;Version=$Operation.PackageVersion;Sha256=$hash}
    }else{
      $Artifact=New-InertSourceArchive (Join-Path $CaseRoot 'psscripttools-full-fixture.zip') $SourceMembers $Operation.PackageVersion
    }
    Install-RidePortablePayload $Operation $Artifact -Offline
    $installed=Get-RidePortableState $Operation
    $installed.Files.Count | Should -Be 360
    @((Compare-Object ($SourceMembers|Sort-Object) ($installed.Files.RelativePath|Sort-Object))).Count | Should -Be 0
    $scriptFiles=@($installed.Manifest.Files|Where-Object {$_.RelativePath -match '\.ps1$'})
    $scriptFiles.Count | Should -BeGreaterThan 0
    @($scriptFiles|Where-Object {$_.AuthenticodeStatus -ne 'NotInspectedOffline'}).Count | Should -Be 0
    $originalHashes=@($installed.Files|Sort-Object RelativePath|ForEach-Object { $_.RelativePath+'='+$_.ActualSha256 })
    $output=Join-Path $Operation.InstallDirectory 'analyst-output.txt'
    [IO.File]::WriteAllText($output,'operator output')
    Install-RidePortablePayload $Operation $Artifact -Offline
    @((Compare-Object $originalHashes @((Get-RidePortableState $Operation).Files|Sort-Object RelativePath|ForEach-Object {$_.RelativePath+'='+$_.ActualSha256}))).Count | Should -Be 0
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup') | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    Uninstall-RidePortablePayload $Operation
    foreach($member in $SourceMembers){Test-Path -LiteralPath (Join-Path $Operation.InstallDirectory $member) | Should -BeFalse}
    [IO.File]::ReadAllText($output) | Should -BeExactly 'operator output'
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy | Should -BeTrue
    @((Compare-Object $originalHashes @((Get-RidePortableState $Operation).Files|Sort-Object RelativePath|ForEach-Object {$_.RelativePath+'='+$_.ActualSha256}))).Count | Should -Be 0
    [IO.File]::ReadAllText($output) | Should -BeExactly 'operator output'
  }
  It 'refuses replacing operator-modified source and preserves it on removal' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    $source=Join-Path $Operation.InstallDirectory @($Operation.RequiredFiles|Where-Object {$_ -like '*/PSScriptTools.psm1'})[0]
    [IO.File]::WriteAllText($source,'operator source edit')
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    {Install-RidePortablePayload $Operation $Artifact -Offline} | Should -Throw '*modified*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($source) | Should -BeExactly 'operator source edit'
    Restore-RidePortableSnapshot $Operation $snapshot
    [IO.File]::ReadAllText($source) | Should -BeExactly 'operator source edit'
    (Get-RidePortableState $Operation).Healthy | Should -BeFalse
  }
  It 'refuses unowned destination collisions before any product write' {
    $path=Join-Path $Operation.InstallDirectory $SourceMembers[0]
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    [IO.File]::WriteAllText($path,'unowned source')
    {Install-RidePortablePayload $Operation $Artifact -Offline} | Should -Throw '*collision*'
    [IO.File]::ReadAllText($path) | Should -BeExactly 'unowned source'
    @(Get-ChildItem -LiteralPath $Operation.InstallDirectory -File -Recurse -Force).Count | Should -Be 1
  }
  It 'refuses changed recovery bytes before removing the installed source' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $snapshot.BackupDirectory $snapshot.Files[0].RelativePath),'changed backup')
    {Restore-RidePortableSnapshot $Operation $snapshot} | Should -Throw '*recovery bytes are unavailable*'
    (Get-RidePortableState $Operation).Healthy | Should -BeTrue
    (Get-RidePortableState $Operation).Files.Count | Should -Be $FixtureMembers.Count
  }
  It 'restores prior absence while preserving unowned content' {
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    Install-RidePortablePayload $Operation $Artifact -Offline
    $output=Join-Path $Operation.InstallDirectory 'custom.txt';[IO.File]::WriteAllText($output,'custom')
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Present | Should -BeFalse
    [IO.File]::ReadAllText($output) | Should -BeExactly custom
  }
}
