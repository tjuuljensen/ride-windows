<#
.SYNOPSIS
  Test RegRipper distribution requirements and owned plugin recovery.
.DESCRIPTION
  Builds inert ZIP fixtures from the real pending catalog declaration. No upstream
  binary, script or plugin is executed and no registry hive or evidence data is read.
.EXAMPLE
  Invoke-Pester .\tests\RegRipperPackage.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; native/parser acceptance remains pending.
#>
BeforeAll {
  $root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE-PortablePackages.psm1') -Force
  $script:RegRipperOperation=(Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')).Operations | Where-Object Id -eq package.regripper
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
  function New-RegRipperFixture {
    param([string]$Path,[string[]]$Members)
    $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach($member in $Members){
        $entry=$zip.CreateEntry($member)
        $writer=[IO.StreamWriter]::new($entry.Open())
        try{$writer.Write('Inert required member: '+$member)}finally{$writer.Dispose()}
      }
    } finally{$zip.Dispose()}
    [pscustomobject]@{Path=$Path;Version=$RegRipperOperation.PackageVersion;Sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
  }
}
Describe 'Pinned RegRipper portable candidate' {
  BeforeEach {
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $script:Operation=$RegRipperOperation.Clone()
    $Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    $script:DistributionRoot=($Operation.RequiredFiles[0] -split '/')[0]
    $script:Artifact=New-RegRipperFixture -Path (Join-Path $CaseRoot 'fixture.zip') -Members $Operation.RequiredFiles
  }
  It 'refuses the legacy executable-only payload before creating a product' {
    $incomplete=New-RegRipperFixture -Path (Join-Path $CaseRoot 'incomplete.zip') -Members @($Operation.RequiredFiles[0])
    {Install-RidePortablePayload $Operation $incomplete} | Should -Throw '*missing required file*'
    Test-Path -LiteralPath $Operation.InstallDirectory | Should -BeFalse
  }
  It 'preserves unowned plugins and analyst reports across staging, removal and recovery' {
    Install-RidePortablePayload $Operation $Artifact
    $custom=Join-Path $Operation.InstallDirectory ($DistributionRoot+'/plugins/operator.pl')
    $report=Join-Path $Operation.InstallDirectory 'analyst-report.txt'
    [IO.File]::WriteAllText($custom,'operator plugin')
    [IO.File]::WriteAllText($report,'operator report')
    Install-RidePortablePayload $Operation $Artifact
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    Uninstall-RidePortablePayload $Operation
    [IO.File]::ReadAllText($custom) | Should -Be 'operator plugin'
    [IO.File]::ReadAllText($report) | Should -Be 'operator report'
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy | Should -BeTrue
    [IO.File]::ReadAllText($custom) | Should -Be 'operator plugin'
    [IO.File]::ReadAllText($report) | Should -Be 'operator report'
  }
  It 'refuses upgrade over modified bundled plugins and preserves them on removal' {
    Install-RidePortablePayload $Operation $Artifact
    $plugin=Join-Path $Operation.InstallDirectory ($DistributionRoot+'/plugins/winver.pl')
    [IO.File]::WriteAllText($plugin,'analyst modification')
    {Install-RidePortablePayload $Operation $Artifact} | Should -Throw '*modified*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($plugin) | Should -Be 'analyst modification'
  }
  It 'refuses recovery before writing when a retained runtime backup is missing' {
    Install-RidePortablePayload $Operation $Artifact
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    Uninstall-RidePortablePayload $Operation
    $runtime=@($snapshot.Files | Where-Object RelativePath -Like '*/p2x5124.dll')[0]
    Remove-Item -LiteralPath (Join-Path $snapshot.BackupDirectory $runtime.RelativePath)
    {Restore-RidePortableSnapshot $Operation $snapshot} | Should -Throw '*recovery bytes are unavailable*'
    Test-Path -LiteralPath (Join-Path $Operation.InstallDirectory $Operation.RequiredFiles[0]) | Should -BeFalse
  }
}
