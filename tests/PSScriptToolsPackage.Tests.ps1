<#
.SYNOPSIS
  Verify pinned source-script package notice requirements and file ownership.
.DESCRIPTION
  Builds inert archives from the pending PSScriptTools declarations.
  Does not run PowerShell source, upstream code or installers, or inspect editor/session data.
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
    $script:Artifact=New-InertSourceArchive (Join-Path $CaseRoot 'psscripttools.zip') $Operation.RequiredFiles $Operation.PackageVersion
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
    Install-RidePortablePayload $Operation $Artifact
    $output=Join-Path $Operation.InstallDirectory 'analyst-output.txt'
    [IO.File]::WriteAllText($output,'operator output')
    Install-RidePortablePayload $Operation $Artifact
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    Uninstall-RidePortablePayload $Operation
    [IO.File]::ReadAllText($output) | Should -BeExactly 'operator output'
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy | Should -BeTrue
    [IO.File]::ReadAllText($output) | Should -BeExactly 'operator output'
  }
  It 'refuses replacing operator-modified source and preserves it on removal' {
    Install-RidePortablePayload $Operation $Artifact
    $source=Join-Path $Operation.InstallDirectory @($Operation.RequiredFiles|Where-Object {$_ -like '*/PSScriptTools.psm1'})[0]
    [IO.File]::WriteAllText($source,'operator source edit')
    {Install-RidePortablePayload $Operation $Artifact} | Should -Throw '*modified*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($source) | Should -BeExactly 'operator source edit'
  }
}
