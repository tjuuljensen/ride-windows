<#
.SYNOPSIS
  Verify focused portable acceptance selection and pre-execution boundaries.
.DESCRIPTION
  Uses inert local files; never accesses Hyper-V or runs package handlers.
.EXAMPLE
  Invoke-Pester .\tests\PortableAcceptanceAutomation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.7.1 on Windows PowerShell 5.1 and PowerShell 7.
  Author: RIDE-Windows maintainers. Version: Repository test fixture.
  Changelog: 2026-10-17: Add exact selection and retained archive guard coverage.
#>
Describe 'Focused portable acceptance boundaries' {
  BeforeAll {
    $script:Root=Join-Path $PSScriptRoot 'integration'
    $script:CatalogPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1'
    Import-Module (Join-Path $script:Root 'RIDE.PortableAcceptance.psm1') -Force
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogData.psm1') -Force
  }
  It 'returns version without VM access for <Name>' -ForEach @(
    @{Name='Invoke-RidePortableAcceptance.ps1';Expected='0.6.0'},@{Name='Invoke-RidePortableVmAcceptance.ps1';Expected='0.5.0'},@{Name='Invoke-Ride4GbPatchFunctionalAcceptance.ps1';Expected='0.4.0'},@{Name='Invoke-RideOfflineAcceptance.ps1';Expected='0.1.1'},@{Name='Invoke-RidePSScriptToolsRuntimeAcceptance.ps1';Expected='0.1.3'}
  ) { & (Join-Path $script:Root $Name) -Version | Should -Be $Expected }
  It 'refuses missing host inputs before platform access' {
    { & (Join-Path $script:Root 'Invoke-RidePortableVmAcceptance.ps1') } | Should -Throw '*required*'
  }
  It 'refuses unguarded guest execution' {
    $previous=$env:RIDE_INTEGRATION_VM
    try {
      $env:RIDE_INTEGRATION_VM=$null
      { & (Join-Path $script:Root 'Invoke-RidePortableAcceptance.ps1') -DisposableVm -ExpectedComputerName $env:COMPUTERNAME } | Should -Throw '*no workstation integration*'
      { & (Join-Path $script:Root 'Invoke-RideOfflineAcceptance.ps1') -DisposableVm -ExpectedComputerName $env:COMPUTERNAME } | Should -Throw '*no workstation integration*'
      { & (Join-Path $script:Root 'Invoke-Ride4GbPatchFunctionalAcceptance.ps1') -DisposableVm -ExpectedComputerName $env:COMPUTERNAME -ToolPath 'Z:\blocked.exe' -ExpectedSha256 ('a'*64) -EvidencePath 'C:\RIDE\PortableAcceptance\00000000000000000000000000000000\evidence\4gb-patch-functional' } | Should -Throw '*no workstation integration*'
      { & (Join-Path $script:Root 'Invoke-RidePSScriptToolsRuntimeAcceptance.ps1') -DisposableVm -ExpectedComputerName $env:COMPUTERNAME } | Should -Throw '*no workstation integration*'
    }finally{$env:RIDE_INTEGRATION_VM=$previous}
  }
  It 'builds a synthetic PE32 x86 fixture with the large-address-aware flag clear in memory' {
    $path=Join-Path $script:Root 'Invoke-Ride4GbPatchFunctionalAcceptance.ps1'
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
    @($parseErrors).Count|Should -Be 0
    $names=@('Set-U16','Set-U32','New-SyntheticX86Pe','Get-PeCharacteristics')
    $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names},$true))
    @($definitions.Name|Sort-Object -Unique).Count|Should -Be $names.Count
    . ([scriptblock]::Create(($definitions.Extent.Text -join "`n")))
    $bytes=New-SyntheticX86Pe
    $bytes.Length|Should -Be 1024
    [BitConverter]::ToUInt16($bytes,0x84)|Should -Be 0x14c
    Get-PeCharacteristics $bytes|Should -Be 0x0102
  }
  It 'parses the isolated PSScriptTools runtime probe without executing it' {
    $path=Join-Path $script:Root 'Invoke-RidePSScriptToolsRuntimeAcceptance.ps1'
    $tokens=$null;$parseErrors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
    @($parseErrors).Count|Should -Be 0
    (Get-Content -LiteralPath $path -Raw)|Should -Match '\$env:TEMP'
    (Get-Content -LiteralPath $path -Raw)|Should -Match '\$env:TMP'
    (Get-Content -LiteralPath $path -Raw)|Should -Match 'MissingDependency'
    (Get-Content -LiteralPath $path -Raw)|Should -Match 'CimNamespaceList\.txt'
  }
  It 'cleans only probe-created jobs on every outcome' {
    $path=Join-Path $script:Root 'Invoke-RidePSScriptToolsRuntimeAcceptance.ps1'
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
    $function=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Clear-RuntimeProbeJobs'},$true))
    $function.Count|Should -Be 1
    . ([scriptblock]::Create($function[0].Extent.Text))
    $script:ProbeJobs=@(
      [pscustomobject]@{Id=41;State='Running'},
      [pscustomobject]@{Id=42;State='Running'},
      [pscustomobject]@{Id=43;State='Completed'}
    )
    $script:ProbeStopped=[Collections.Generic.List[int]]::new()
    $script:ProbeRemoved=[Collections.Generic.List[int]]::new()
    Mock Get-Job {$script:ProbeJobs}
    Mock Stop-Job {param($Id)foreach($jobId in $Id){$script:ProbeStopped.Add([int]$jobId)}}
    Mock Remove-Job {param($Id)foreach($jobId in $Id){$script:ProbeRemoved.Add([int]$jobId)}}
    Clear-RuntimeProbeJobs -BaselineJobIds @(41)
    @($script:ProbeStopped.ToArray())|Should -Be @(42)
    @($script:ProbeRemoved.ToArray())|Should -Be @(42,43)
  }
  It 'removes only an empty direct child of the probe TEMP directory' {
    $path=Join-Path $script:Root 'Invoke-RidePSScriptToolsRuntimeAcceptance.ps1'
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
    $function=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-EmptyProbeDirectory'},$true))
    $function.Count|Should -Be 1
    . ([scriptblock]::Create($function[0].Extent.Text))
    $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $root
    $empty=Join-Path $root 'empty-modules';$null=New-Item -ItemType Directory -Path $empty
    $filled=Join-Path $root 'unexpected';$null=New-Item -ItemType Directory -Path $filled
    [IO.File]::WriteAllText((Join-Path $filled 'keep.txt'),'keep')
    $outside=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $outside
    (Remove-EmptyProbeDirectory -Path $empty -ParentPath $root)|Should -BeTrue
    (Test-Path -LiteralPath $empty)|Should -BeFalse
    (Remove-EmptyProbeDirectory -Path $filled -ParentPath $root)|Should -BeFalse
    (Test-Path -LiteralPath (Join-Path $filled 'keep.txt'))|Should -BeTrue
    (Remove-EmptyProbeDirectory -Path $outside -ParentPath $root)|Should -BeFalse
    (Test-Path -LiteralPath $outside)|Should -BeTrue
  }
  It 'selects <Count> reviewed architecture cases for <Batch>' -ForEach @(
    @{Batch='AllReviewed';Count=7},@{Batch='MiTeCViewers';Count=4},@{Batch='NTCore';Count=3},@{Batch='SQLiteQuery';Count=1},@{Batch='MiTeCUtilityFiles';Count=3},@{Batch='SysinternalsSuite';Count=1},@{Batch='SysinternalsProducts';Count=9},@{Batch='ImageMagick';Count=1}
  ) {
    $cases=@(Get-RidePortableAcceptanceCases -Catalog (Import-RideCatalogData $script:CatalogPath) -Batch $Batch)
    $cases.Count|Should -Be $Count
    @($cases|Where-Object Id -notin @('package.mitec-json-viewer','package.mitec-xml-viewer','package.ntcore-pe-detective','package.ntcore-cff-explorer','package.ntcore-4gb-patch','package.mitec-sqlite-query','package.mitec-uuid-generator','package.mitec-certificate-generator','package.mitec-certificate-information','package.sysinternals-suite','package.sysinternals-process-explorer','package.sysinternals-autoruns','package.sysinternals-tcpview','package.sysinternals-procmon','package.sysinternals-rammap','package.sysinternals-disk2vhd','package.sysinternals-sigcheck','package.sysinternals-strings','package.sysinternals-handle','package.imagemagick-portable-q16')).Count|Should -Be 0
    if($Batch -eq 'ImageMagick'){
      @($cases|Where-Object {$_.Operation.SupportedTargets -notcontains 'Windows 11' -or $_.Operation.PendingAcceptance -ne $false}).Count|Should -Be 0
    }else{
      @($cases|Where-Object {$_.Operation.PendingAcceptance -ne $true}).Count|Should -Be 0
    }
  }
  It 'refuses an absent package' {
    $c=Import-RideCatalogData $script:CatalogPath
    $c.Operations=@($c.Operations|Where-Object Id -ne 'package.mitec-json-viewer')
    { Get-RidePortableAcceptanceCases $c }|Should -Throw '*exactly one*'
  }
  It 'selects all 360 reviewed PSScriptTools files without selecting other packages' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch PSScriptTools)
    $cases.Count|Should -Be 1
    $cases[0].Id|Should -Be 'package.psscripttools'
    $cases[0].ExpectedFiles.Count|Should -Be 360
    $cases[0].Operation.PendingAcceptance|Should -BeTrue
  }
  It 'selects only the pending SQLite Query file lifecycle candidate' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch SQLiteQuery)
    $cases.Count|Should -Be 1
    $cases[0].Id|Should -Be 'package.mitec-sqlite-query'
    $cases[0].ExpectedFiles|Should -Be @('SQLiteQuery.exe','sqlite3.dll','sqlite3.exe')
    $cases[0].Operation.PendingAcceptance|Should -BeTrue
    $cases[0].Operation.SupportedTargets.Count|Should -Be 0
  }
  It 'selects only the pinned single-file UUID and certificate candidates without supporting them' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch MiTeCUtilityFiles)
    $cases.Count|Should -Be 3
    ($cases.Id|Sort-Object) | Should -Be @('package.mitec-certificate-generator','package.mitec-certificate-information','package.mitec-uuid-generator')
    @($cases|ForEach-Object { $_.ExpectedFiles[0] }|Sort-Object) | Should -Be @('CertInfo.exe','CG.exe','UUID.exe')
    @($cases|Where-Object {$_.Operation.PendingAcceptance -ne $true -or $_.Operation.SupportedTargets.Count -ne 0}).Count|Should -Be 0
  }
  It 'selects only the accepted pinned Caffeine package for offline execution' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch OfflineCaffeine)
    $cases.Count|Should -Be 1
    $cases[0].Id|Should -Be 'package.caffeine'
    $cases[0].Operation.PendingAcceptance|Should -BeFalse
  }
  It 'selects only the reviewed 164-file Sysinternals Suite snapshot without selecting individual tools' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch SysinternalsSuite)
    $cases.Count|Should -Be 1
    $cases[0].Id|Should -Be 'package.sysinternals-suite'
    $cases[0].ExpectedFiles.Count|Should -Be 164
    $cases[0].Operation.PackageVersion|Should -Be 'snapshot-20261017-e1e75de5'
    $cases[0].Operation.ExpectedSha256|Should -Be 'e1e75de5cdb12116b0a4eca83725dc7c7a1645266196025cbe5ca6c167161aed'
    $cases[0].Operation.SupportedTargets.Count|Should -Be 0
    $cases[0].Operation.PendingAcceptance|Should -BeTrue
  }
  It 'selects only the nine pinned independent Sysinternals products and excludes Defender-blocked collections' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch SysinternalsProducts)
    $cases.Count|Should -Be 9
    ($cases.Id|Sort-Object)|Should -Be @('package.sysinternals-autoruns','package.sysinternals-disk2vhd','package.sysinternals-handle','package.sysinternals-process-explorer','package.sysinternals-procmon','package.sysinternals-rammap','package.sysinternals-sigcheck','package.sysinternals-strings','package.sysinternals-tcpview')
    @($cases|Where-Object {$_.Operation.PendingAcceptance -ne $true -or $_.Operation.SupportedTargets.Count -ne 0 -or $_.Operation.ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$' -or $_.ExpectedFiles -notcontains 'Eula.txt'}).Count|Should -Be 0
    @($cases|Where-Object Id -match '(?i)nirsoft|produkey|wirelesskeyview|bulletspassview').Count|Should -Be 0
  }
  It 'selects the pinned ImageMagick Q16 7z as a whole-archive candidate' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch ImageMagick)
    $cases.Count|Should -Be 1
    $cases[0].Id|Should -Be 'package.imagemagick-portable-q16'
    $cases[0].Operation.PortableFormat|Should -Be 'SevenZip'
    $cases[0].Operation.AssetName|Should -Be 'ImageMagick-7.1.2-34-portable-Q16-x64.7z'
    $cases[0].ExpectedFiles|Should -Be @('magick.exe')
  }
  It 'refuses unsafe metadata for <Field>' -ForEach @(
    @{Field='ExpectedSha256';Value=''},@{Field='InstallerType';Value='Exe'},@{Field='AssetName';Value='../other.zip'},@{Field='DependsOn';Value=@('package.other')}
  ) {
    $c=Import-RideCatalogData $script:CatalogPath
    ($c.Operations|Where-Object Id -eq 'package.ntcore-pe-detective')[$Field]=$Value
    { Get-RidePortableAcceptanceCases $c }|Should -Throw '*Unreviewed*'
  }
  It 'checks archive pins and rejects extra IDs before reading their paths' {
    $c=Import-RideCatalogData $script:CatalogPath
    $cases=@(Get-RidePortableAcceptanceCases $c -Batch NTCore)
    $fixture=Join-Path $TestDrive 'inert.zip'
    [IO.File]::WriteAllText($fixture,'Inert digest fixture, not an executable or ZIP.')
    $hash=(Get-FileHash -LiteralPath $fixture).Hash.ToLowerInvariant()
    foreach($case in $cases){$case.Operation.ExpectedSha256=$hash}
    $manifest=Join-Path $TestDrive 'manifest.json'
    $rows=@($cases|ForEach-Object {@{Id=$_.Id;Path=$fixture}})
    ConvertTo-Json -InputObject $rows|Set-Content -LiteralPath $manifest
    @(Get-RidePortableAcceptancePayloads $cases $manifest).Count|Should -Be 3
    [IO.File]::WriteAllText($fixture,'Changed fixture')
    { Get-RidePortableAcceptancePayloads $cases $manifest }|Should -Throw '*digest mismatch*'
    $rows+=@{Id='package.nirsoft';Path='Z:\must-not-read.exe'}
    ConvertTo-Json -InputObject $rows|Set-Content -LiteralPath $manifest
    { Get-RidePortableAcceptancePayloads $cases $manifest }|Should -Throw '*exactly the selected*'
  }
  It 'accepts only the ImageMagick 7z extension for the exact pinned candidate' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch ImageMagick)
    $fixture=Join-Path $TestDrive 'imagemagick.7z'
    [IO.File]::WriteAllText($fixture,'Inert digest fixture, not an executable or 7z archive.')
    $hash=(Get-FileHash -LiteralPath $fixture).Hash.ToLowerInvariant()
    $cases[0].Operation.ExpectedSha256=$hash
    $manifest=Join-Path $TestDrive 'imagemagick.json'
    @(@{Id=$cases[0].Id;Path=$fixture})|ConvertTo-Json|Set-Content -LiteralPath $manifest
    @(Get-RidePortableAcceptancePayloads -Cases $cases -ManifestPath $manifest).Count|Should -Be 1
    $rows=@(@{Id=$cases[0].Id;Path=($fixture -replace '\.7z$','.zip')})
    $zipFixture=Join-Path $TestDrive 'imagemagick.zip'
    [IO.File]::WriteAllText($zipFixture,'Wrong extension fixture.')
    $rows[0].Path=$zipFixture
    $rows|ConvertTo-Json|Set-Content -LiteralPath $manifest
    {Get-RidePortableAcceptancePayloads -Cases $cases -ManifestPath $manifest}|Should -Throw '*extension*'
  }
}
