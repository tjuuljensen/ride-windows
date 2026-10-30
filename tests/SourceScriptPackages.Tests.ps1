<#
.SYNOPSIS
  Verify pinned source-script package notice requirements and file ownership.
.DESCRIPTION
  Builds inert archives from the pending Hex2text and ChromeSyncParser declarations.
  Optional retained-archive cases run only when their exact paths are supplied by
  RIDE_HEX2TEXT_FIXTURE_ARCHIVE or RIDE_CHROMESYNCPARSER_FIXTURE_ARCHIVE. They
  verify hashes and file lifecycle without running Python/upstream code/installers
  or inspecting browser/evidence data.
.EXAMPLE
  Invoke-Pester .\tests\SourceScriptPackages.Tests.ps1
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
Describe 'Pinned source package <Id>' -ForEach @(@{Id='package.hex2text'},@{Id='package.chromeparser'}) {
  BeforeEach {
    $script:Operation=($SourceCatalog.Operations|Where-Object Id -eq $Id).Clone()
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    $script:Artifact=New-InertSourceArchive (Join-Path $CaseRoot 'source.zip') $Operation.RequiredFiles $Operation.PackageVersion
  }
  It 'declares complete pinned source and notices without runtime activation' {
    $Operation.PendingAcceptance | Should -BeTrue
    $Operation.SupportedTargets.Count | Should -Be 0
    $Operation.Architecture | Should -Be neutral
    $Operation.RequiredFiles.Count | Should -Be 3
    @($Operation.RequiredFiles|Where-Object {$_ -like '*/LICENSE'}).Count | Should -Be 1
    @($Operation.RequiredFiles|Where-Object {$_ -like '*.py'}).Count | Should -Be 1
    $Operation.DownloadUri | Should -Match '/archive/[0-9a-f]{40}\.zip$'
    $Operation.ExpectedSha256 | Should -Match '^[0-9a-f]{64}$'
    $Operation.InstallerArguments | Should -BeNullOrEmpty
    $Operation.DependsOn | Should -BeNullOrEmpty
  }
  It 'refuses the script-only legacy payload when its license and README are missing' {
    $scriptOnly=New-InertSourceArchive (Join-Path $CaseRoot 'incomplete.zip') @($Operation.RequiredFiles|Where-Object {$_ -like '*.py'}) $Operation.PackageVersion
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
    $source=Join-Path $Operation.InstallDirectory @($Operation.RequiredFiles|Where-Object {$_ -like '*.py'})[0]
    [IO.File]::WriteAllText($source,'operator source edit')
    {Install-RidePortablePayload $Operation $Artifact} | Should -Throw '*modified*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($source) | Should -BeExactly 'operator source edit'
  }

  It 'stages the retained pinned archive and restores only its declared source files without executing Python' {
    $environmentVariable = switch ($Id) {
      'package.hex2text' { 'RIDE_HEX2TEXT_FIXTURE_ARCHIVE' }
      'package.chromeparser' { 'RIDE_CHROMESYNCPARSER_FIXTURE_ARCHIVE' }
      default { throw "Unexpected source package: $Id" }
    }
    $archiveValue = [Environment]::GetEnvironmentVariable($environmentVariable)
    if ([string]::IsNullOrWhiteSpace($archiveValue)) {
      Set-ItResult -Skipped -Because "No explicit retained archive was supplied through $environmentVariable."
      return
    }
    $archivePath = [IO.Path]::GetFullPath($archiveValue)
    $archiveFile = Get-Item -LiteralPath $archivePath -Force -ErrorAction Stop
    if ($archiveFile.PSIsContainer -or ($archiveFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Retained archive fixture must be a regular file.'
    }
    $sha = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sha | Should -BeExactly $Operation.ExpectedSha256.ToLowerInvariant()
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
      $archiveMembers = @($zip.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) } | ForEach-Object FullName | Sort-Object)
      $archiveMembers.Count | Should -Be $Operation.RequiredFiles.Count
      [string]::Join("`n", $archiveMembers) | Should -BeExactly ([string]::Join("`n", @($Operation.RequiredFiles | Sort-Object)))
    } finally { $zip.Dispose() }

    $operation = $Operation.Clone()
    $operation.ResolvedToolsDirectory = Join-Path $CaseRoot 'retained-archive'
    $operation.InstallDirectory = Join-Path $operation.ResolvedToolsDirectory $operation.PackageId
    $artifact = [pscustomobject]@{ Path = $archivePath; Sha256 = $sha; Version = $operation.PackageVersion }
    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state = Get-RidePortableState $operation
    $state.Healthy | Should -BeTrue
    @($state.Files.RelativePath | Sort-Object) | Should -Be @($operation.RequiredFiles | Sort-Object)

    $operatorNote = Join-Path $operation.InstallDirectory 'operator-note.txt'
    [IO.File]::WriteAllText($operatorNote, 'preserve operator-owned data')
    $snapshot = Save-RidePortableSnapshot $operation (Join-Path $CaseRoot 'retained-archive-backup')
    Uninstall-RidePortablePayload $operation
    [IO.File]::ReadAllText($operatorNote) | Should -BeExactly 'preserve operator-owned data'
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy | Should -BeTrue
    [IO.File]::ReadAllText($operatorNote) | Should -BeExactly 'preserve operator-owned data'
  }
}
