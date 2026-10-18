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
    @{Name='Invoke-RidePortableAcceptance.ps1';Expected='0.2.1'},@{Name='Invoke-RidePortableVmAcceptance.ps1';Expected='0.3.0'},@{Name='Invoke-RideOfflineAcceptance.ps1';Expected='0.1.1'}
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
    }finally{$env:RIDE_INTEGRATION_VM=$previous}
  }
  It 'selects <Count> reviewed architecture cases for <Batch>' -ForEach @(
    @{Batch='AllReviewed';Count=6},@{Batch='MiTeCViewers';Count=4},@{Batch='NTCore';Count=2}
  ) {
    $cases=@(Get-RidePortableAcceptanceCases -Catalog (Import-RideCatalogData $script:CatalogPath) -Batch $Batch)
    $cases.Count|Should -Be $Count
    @($cases|Where-Object Id -notin @('package.mitec-json-viewer','package.mitec-xml-viewer','package.ntcore-pe-detective','package.ntcore-cff-explorer')).Count|Should -Be 0
    @($cases|Where-Object {$_.Operation.PendingAcceptance -ne $true}).Count|Should -Be 0
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
  It 'selects only the accepted pinned Caffeine package for offline execution' {
    $cases=@(Get-RidePortableAcceptanceCases (Import-RideCatalogData $script:CatalogPath) -Batch OfflineCaffeine)
    $cases.Count|Should -Be 1
    $cases[0].Id|Should -Be 'package.caffeine'
    $cases[0].Operation.PendingAcceptance|Should -BeFalse
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
    @(Get-RidePortableAcceptancePayloads $cases $manifest).Count|Should -Be 2
    [IO.File]::WriteAllText($fixture,'Changed fixture')
    { Get-RidePortableAcceptancePayloads $cases $manifest }|Should -Throw '*digest mismatch*'
    $rows+=@{Id='package.nirsoft';Path='Z:\must-not-read.exe'}
    ConvertTo-Json -InputObject $rows|Set-Content -LiteralPath $manifest
    { Get-RidePortableAcceptancePayloads $cases $manifest }|Should -Throw '*exactly the selected*'
  }
}
