<#
.SYNOPSIS
  Verify request binding and scope of read-only disposable settings fixture data.
.DESCRIPTION
  Uses temporary metadata files and catalog data only; no VM, registry fixture,
  operational handler, native setting, controller queue or publisher is invoked.
.NOTES
  Compatibility: Pester 5, Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.SettingsFixtureData.psm1') -Force
  $script:catalogPath=Join-Path $PSScriptRoot '../catalog/operations.psd1'
  $script:runId='0123456789abcdef0123456789abcdef'
  function New-FixtureDataFile([string]$Id='windows.wap-push-service',[string]$StateText="'ManualStartup'",[string]$Target='Windows 11',[string]$Allow='$false',[string]$RequestId=$script:runId,[string]$Suite='SettingsBatch60',[string]$Extra='',[int]$Schema=1) {
    $path=Join-Path $TestDrive ([guid]::NewGuid().ToString('N')+'.psd1')
    $data="@{ SchemaVersion=$Schema; RunId='$RequestId'; IntegrationSuite='$Suite'; Target='$Target'; OperationId='$Id'; States=@($StateText); AllowPendingCandidate=$Allow; $Extra }"
    [IO.File]::WriteAllText($path,$data,[Text.UTF8Encoding]::new($false))
    $path
  }
}
Describe 'Request-bound settings fixtures' {
  It 'accepts explicit schema-2 owned scenario <Scenario> without widening public support' -ForEach @(@{Scenario='ActiveRefusal'},@{Scenario='SettingDrift'},@{Scenario='InterruptedCreation'}) {
    $p=New-FixtureDataFile -Id windows.owned-balanced-power-plan -StateText "'Create'" -Allow '$true' -Schema 2 -Extra "Scenario='$Scenario'"
    $d=Read-RideSettingsFixture -Path $p -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath
    $d.Fixture.Scenario | Should -BeExactly $Scenario
    @($d.Operation.SupportedTargets).Count | Should -Be 0
  }
  It 'refuses a scenario in schema 1 or an unknown scenario in schema 2' {
    {Read-RideSettingsFixture -Path (New-FixtureDataFile -Extra "Scenario='Lifecycle'") -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath} | Should -Throw '*uncorrelated*'
    {Read-RideSettingsFixture -Path (New-FixtureDataFile -Schema 2 -Extra "Scenario='IgnoreGuard'") -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath} | Should -Throw '*scenario*'
  }
  It 'refuses owned guards for another handler family and enumerates the same finite choices' {
    {Read-RideSettingsFixture -Path (New-FixtureDataFile -Schema 2 -Extra "Scenario='ActiveRefusal'") -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath} | Should -Throw '*owned power*'
    @(Get-RideSettingsFixtureScenario).Count | Should -Be 4
  }
  It 'resolves a declared single setting without changing published support' {
    $data=Read-RideSettingsFixture -Path (New-FixtureDataFile) -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath
    $data.Operation.Id | Should -BeExactly 'windows.wap-push-service'
    $data.Fixture.States | Should -Be @('ManualStartup')
    $data.Operation.SupportedTargets | Should -Be @('Windows 11')
  }
  It 'refuses another request ID before handler execution' {
    { Read-RideSettingsFixture -Path (New-FixtureDataFile -RequestId ('a'*32)) -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath } | Should -Throw '*uncorrelated*'
  }
  It 'refuses a different selected suite instead of falling back to a broad batch' {
    { Read-RideSettingsFixture -Path (New-FixtureDataFile -Suite SettingsBatch40) -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath } | Should -Throw '*uncorrelated*'
  }
  It 'cannot select package installation' {
    { Read-RideSettingsFixture -Path (New-FixtureDataFile -Id package.7zip -StateText "'Present'") -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath } | Should -Throw '*packages are forbidden*'
  }
  It 'refuses an undeclared state' {
    { Read-RideSettingsFixture -Path (New-FixtureDataFile -StateText "'Invented'") -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath } | Should -Throw '*not declared*'
  }
  It 'refuses duplicate states' {
    { Read-RideSettingsFixture -Path (New-FixtureDataFile -StateText "'ManualStartup','ManualStartup'") -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath } | Should -Throw '*unique*'
  }
  It 'refuses unknown fixture controls' {
    { Read-RideSettingsFixture -Path (New-FixtureDataFile -Extra "IgnoreCheckpoint=`$true") -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath } | Should -Throw '*uncorrelated*'
  }
  It 'requires explicit candidate target approval' {
    { Read-RideSettingsFixture -Path (New-FixtureDataFile -Id windows.ceip-participation-policy -StateText "'OptedOut'") -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath } | Should -Throw '*explicit*'
  }
  It 'allows an applicable candidate only in the explicit fixture contract' {
    $path=New-FixtureDataFile -Id windows.ceip-participation-policy -StateText "'OptedOut'" -Allow '$true'
    $data=Read-RideSettingsFixture -Path $path -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath
    @($data.Operation.SupportedTargets).Count | Should -Be 0
    $data.Fixture.AllowPendingCandidate | Should -BeTrue
  }
  It 'does not invent Server support for a Windows 11-only legacy operation' {
    { Read-RideSettingsFixture -Path (New-FixtureDataFile -Target 'Windows Server 2025' -Allow '$true') -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath } | Should -Throw '*applicable*'
  }
  It 'permits a bounded explicit firewall candidate without enabling unrelated operations' {
    $data=Read-RideSettingsFixture -Path (New-FixtureDataFile -Id windows.firewall-all-profiles -StateText "'On'" -Allow '$true') -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath
    $data.Operation.Kind | Should -Be FirewallProfile
    @($data.Operation.SupportedTargets).Count | Should -Be 0
  }
  It 'accepts a bounded selection from the generated maximum-age range' {
    $data=Read-RideSettingsFixture -Path (New-FixtureDataFile -Id windows.local-password-maximum-age -StateText "'NoExpiry','Days42','Days999'" -Allow '$true') -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath
    @($data.Fixture.States).Count | Should -Be 3
    $data.Operation.Kind | Should -Be LocalPasswordMaximumAge
  }
  It 'permits only the declared owned-copy creation state through an explicit candidate' {
    $data=Read-RideSettingsFixture -Path (New-FixtureDataFile -Id windows.owned-balanced-power-plan -StateText "'Create'" -Allow '$true') -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath $catalogPath
    $data.Operation.Kind | Should -Be OwnedPowerPlan
    @($data.Operation.SupportedTargets).Count | Should -Be 0
  }
}
