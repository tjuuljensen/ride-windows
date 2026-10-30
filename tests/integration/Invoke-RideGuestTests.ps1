<#
.SYNOPSIS
  Run RIDE tests in a dedicated Windows PowerShell process inside a disposable VM.

.DESCRIPTION
  Internal guest entry point for Invoke-RideVmTest.ps1. Requires its VM-only
  environment marker, validates the staged checkout, runs Pester 5.7.1, and
  optionally runs the state-changing integration suite. Exports correlated
  transcript, phase progress, Pester results, summary and saved state when
  ResultsPath is supplied.
  A request-bound settings-validation.fixture.psd1 can explicitly select one
  setting instead of a named settings batch; Full/application suites refuse it.

.PARAMETER GuestPath
  Staged repository directory inside the disposable guest.

.PARAMETER Integration
  Run the integration suite after successful Pester tests; defaults to false.

.PARAMETER IntegrationSuite
  ApplicationsBatch1 and ApplicationsBatch2 select installed/portable application migration tests.
  ApplicationsBatch1Machine and ApplicationsBatch1User split machine and limited-user packages.
  ApplicationsBatch4 selects the Slack and Discord current-user EXE lifecycle tests.
  ApplicationsBatch6 selects the twelve Artcraft machine-scope MSI applications.
  ApplicationsBatch7 selects the current-user ArtCraft Launcher MSI without launching it.
  ApplicationsBatch8 selects four side-by-side Microsoft OpenJDK packages on Server 2025.
  ApplicationsBatch9 tests MiTeC InfoBar 4.6.2 install/remove/recovery on Windows 11 without launching the application.
  ApplicationsBatch10 tests MiTeC Project Maker 1.9.0 install/remove/recovery on Windows 11 without launching the application.
  ApplicationsBatch11 tests HashCheck 2.6.3 install/remove/recovery on Windows 11 without launching HashCheck.
  ApplicationsBatch12 tests the pinned NTCore Explorer Suite installer lifecycle on Windows 11 without launching suite utilities.
  SettingsRemainingBatch1 and SettingsRemainingBatch2 select the two focused migration suites.
  Full (default) runs all integration scenarios. SettingsBatch40 runs only the
  forty-setting registry migration suite, without package downloads. SettingsBatch60 runs the sixty-setting suite.
  SettingsBatch60Recovery selects only its BCD policy and eleven coordinated settings.

.PARAMETER ResultsPath
  Optional guest directory for evidence; the host runner collects this directory.

.PARAMETER ResultRunId
  Correlated request ID, required when ResultsPath is supplied.

.PARAMETER GuestGitHubAuthentication
  Anonymous (default) or explicit PAT; PAT requires the focused GitHubAuthentication suite.

.PARAMETER ExpectedCredentialSid
  Nonsecret guest execution SID captured during explicit credential delivery.

.PARAMETER GitHubTestScenario
  Acquire (default), FailAfterDelivery or WaitForTimeout; focused-suite recovery scenarios.

.PARAMETER Version
  Print the version before operational checks.

.EXAMPLE
  .\Invoke-RideGuestTests.ps1 -Version

.INPUTS
  None.

.OUTPUTS
  System.String. Test output; evidence files are written when requested.

.NOTES
  Compatibility: Windows PowerShell 5.1 on disposable Windows 11/Server 2025 guests.
  Prerequisites: Elevated guest; Pester 5.7.1; the VM host runner.
  File/environment inputs: Staged checkout; RIDE_TEST_GUEST must be 1.
  Recovery: The host controller restores the clean disposable-VM checkpoint.
  Author: RIDE-Windows maintainers.
  Version: 1.9.0
  Changelog:
    1.9.0: Dispatch the exact-package NTCore Explorer Suite ApplicationsBatch12 lifecycle acceptance.
    1.8.0: Dispatch focused HashCheck ApplicationsBatch11 lifecycle acceptance.
    1.7.0: Dispatch MiTeC Project Maker ApplicationsBatch10 lifecycle acceptance.
    1.6.0: Dispatch MiTeC InfoBar ApplicationsBatch9 lifecycle acceptance.
    1.5.0: Persist phase start/completion markers so timeout evidence identifies the stalled guest stage.
    1.4.0: Dispatch separate ApplicationsBatch1 machine- and limited-user acceptance suites.
  1.3.0: Select focused catalog, lifecycle, registry value-set recovery, presentation and controller regressions for remaining-settings acceptance batches.
    1.2.0: Run package dependency planning regressions alongside each application acceptance batch.
    1.1.0: Add Server 2025 ApplicationsBatch8 and its pinned OpenJDK package checks.
    1.0.0: Select the ArtCraft Launcher ApplicationsBatch7 acceptance tests and runner.
    0.9.0: Add focused current-user Slack and Discord application lifecycle acceptance.
    0.8.6: Select isolated Store desktop Plan regression with no app mutations.
    0.8.5: Select focused Store desktop resource-probe regression.
    0.8.4: Select Store app preflight regression without mutation or package suites.
    0.8.3: Select combined provisioning/user reference collection regression.
    0.8.2: Select read-only Store inventory regression independently from setting lifecycle.
    0.8.1: Select focused firewall, local maximum-age and owned-copy fixture regression.
    0.8.0: Add explicit GitHub PAT selection and credential-safe acceptance boundaries.
    0.7.0: Support explicit request-bound single-setting fixtures in a fresh process.
    0.6.0: Dispatch either focused application migration suite.
  - 0.5.0: Select either remaining-settings migration acceptance batch.
  - 0.4.0: Select the twelve outstanding BCD/coordinated recovery scenarios.
  - 0.3.0: Select SettingsBatch60 without package integration.
  - 0.2.0: Add explicit settings-only integration selection.
    0.1.0: Isolate Pester from the remoting thread's call-depth limit.

.LINK
  tests/integration/Invoke-RideVmTest.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string] $GuestPath,
  [switch] $Integration,
  [ValidateSet('Full', 'SettingsBatch40', 'SettingsBatch60', 'SettingsBatch60Recovery', 'SettingsRemainingBatch1', 'SettingsRemainingBatch2', 'ApplicationsBatch1', 'ApplicationsBatch1Machine', 'ApplicationsBatch1User', 'ApplicationsBatch2', 'ApplicationsBatch3', 'ApplicationsBatch3AllUsers', 'ApplicationsBatch4', 'ApplicationsBatch5', 'ApplicationsBatch6', 'ApplicationsBatch7', 'ApplicationsBatch8', 'ApplicationsBatch9', 'ApplicationsBatch10', 'ApplicationsBatch11', 'ApplicationsBatch12', 'GitHubAuthentication')][string] $IntegrationSuite = 'Full',
  [string] $ResultsPath,
  [ValidateSet('Anonymous','PAT')][string] $GuestGitHubAuthentication = 'Anonymous',
  [ValidateSet('Acquire','FailAfterDelivery','WaitForTimeout')][string] $GitHubTestScenario = 'Acquire',
  [string] $ExpectedCredentialSid,
  [ValidatePattern('^[0-9a-f]{32}$')][string] $ResultRunId,
  [switch] $Version
)
$script:ScriptVersion = '1.9.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if ($env:RIDE_TEST_GUEST -ne '1') { throw 'Use the disposable-VM host runner; this entry point must not run on a developer workstation.' }
if (-not $Integration -and $IntegrationSuite -ne 'Full') { throw 'Specify -Integration when selecting an integration suite.' }
if (-not $GuestPath -or -not (Test-Path -LiteralPath (Join-Path $GuestPath 'tools/validate.ps1') -PathType Leaf)) { throw 'GuestPath must identify the staged RIDE checkout.' }
if ($ResultsPath -and -not $ResultRunId) { throw 'ResultRunId is required for evidence collection.' }
if ($GuestGitHubAuthentication -eq 'PAT') {
  if (-not $Integration -or $IntegrationSuite -ne 'GitHubAuthentication' -or -not $ResultsPath -or $ExpectedCredentialSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw 'Guest authentication requires the correlated focused suite and the credential delivery identity.' }
}
$fixturePath = Join-Path $GuestPath 'tests/integration/settings-validation.fixture.psd1'
$fixture = $null
if (Test-Path -LiteralPath $fixturePath -PathType Leaf) {
  if (-not $Integration -or $IntegrationSuite -notin @('SettingsBatch40', 'SettingsBatch60', 'SettingsBatch60Recovery', 'SettingsRemainingBatch1', 'SettingsRemainingBatch2')) { throw 'A settings fixture requires an explicit settings-only integration suite.' }
  Import-Module (Join-Path $GuestPath 'modules/RIDE.SettingsFixtureData.psm1') -Force
  $fixtureData = Read-RideSettingsFixture -Path $fixturePath -RunId $ResultRunId -IntegrationSuite $IntegrationSuite -CatalogPath (Join-Path $GuestPath 'catalog/operations.psd1')
  $fixture = $fixtureData.Fixture
  if (-not $ResultsPath) { throw 'Settings fixtures require retained evidence.' }
}
if (-not $PSCmdlet.ShouldProcess($GuestPath, 'Run validation, Pester and selected disposable-VM integration tests')) { return }

Set-Location -LiteralPath $GuestPath
$summary = [ordered]@{ SchemaVersion = 1; RunId = $ResultRunId; Status = 'Failed'; ValidationPassed = $false; IntegrationPassed = $false; Pester = $null; Error = $null; StateCollectionError = $null; Guest = $null }
$summary.GuestGitHubAuthentication = $GuestGitHubAuthentication
$summary.GitHubTestScenario = $GitHubTestScenario
$summary.CredentialCleanupVerified = $null
$transcribing = $false
$progressPath = if ($ResultsPath) { Join-Path $ResultsPath 'progress.jsonl' } else { $null }
function Write-RideGuestProgress {
  param([Parameter(Mandatory)][string] $Phase, [Parameter(Mandatory)][ValidateSet('Started', 'Completed', 'Failed')][string] $State, [string] $Message)
  if (-not $script:ProgressPath) { return }
  $record = [ordered]@{
    TimestampUtc = [datetime]::UtcNow.ToString('o')
    Phase = $Phase
    State = $State
    Message = $Message
  }
  try {
    Add-Content -LiteralPath $script:ProgressPath -Value ($record | ConvertTo-Json -Compress) -Encoding UTF8
  }
  catch {
    Write-Warning ("Unable to persist guest progress for '{0}': {1}" -f $Phase, $_.Exception.Message)
  }
}
$script:ProgressPath = $progressPath
$activePhase = 'Guest initialization'
try {
  if ($ResultsPath) {
    New-Item -ItemType Directory -Path $ResultsPath -Force | Out-Null
    Start-Transcript -LiteralPath (Join-Path $ResultsPath 'transcript.log') -Force | Out-Null
    $transcribing = $true
    Write-RideGuestProgress -Phase $activePhase -State Started
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Guest session is not elevated.' }
    $summary.Guest = @{ OS = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber); Account = $identity.Name; SID = $identity.User.Value; PowerShell = $PSVersionTable.PSVersion.ToString() }
    Write-RideGuestProgress -Phase $activePhase -State Completed
  }
  $activePhase = 'Pester import'
  Write-RideGuestProgress -Phase $activePhase -State Started
  Import-Module Pester -RequiredVersion '5.7.1' -ErrorAction Stop
  Write-RideGuestProgress -Phase $activePhase -State Completed
  $env:RIDE_TEST_EVIDENCE_PATH = $ResultsPath
  $env:RIDE_TEST_RUN_ID = $ResultRunId
  $activePhase = 'Catalog export'
  Write-RideGuestProgress -Phase $activePhase -State Started
  & .\tools\Export-RideCatalog.ps1
  Write-RideGuestProgress -Phase $activePhase -State Completed
  $activePhase = 'Repository validation'
  Write-RideGuestProgress -Phase $activePhase -State Started
  & .\tools\validate.ps1
  Write-RideGuestProgress -Phase $activePhase -State Completed
  $summary.ValidationPassed = $true
  $testPaths = if ($fixture) {
    $names = @('Catalog.Tests.ps1','SettingsFixtureData.Tests.ps1','CliShouldProcess.Tests.ps1')
    if($fixture.Scenario -in @('StoreAppPreflight','StoreDesktopProbe','StoreDesktopPlan')){$names += @('StoreAppReview.Tests.ps1','StoreApps.Tests.ps1','SettingPresentation.Tests.ps1')}elseif($fixture.Scenario -in @('StoreInventory','StoreReferenceInventory')){$names += 'StoreAppReview.Tests.ps1'}else{
    switch ($fixtureData.Operation.Kind) {
      WindowsService { $names += @('ServiceSettings.Tests.ps1','AudioService.Tests.ps1') }
      FirewallProfile { $names += 'FirewallProfiles.Tests.ps1' }
      LocalPasswordMaximumAge { $names += 'LocalPasswordAge.Tests.ps1' }
      OwnedPowerPlan { $names += 'OwnedPowerPlans.Tests.ps1' }
      default { $names += @('RegistryFailures.Tests.ps1','KeyboardSettings.Tests.ps1','ServerPolicies.Tests.ps1','UpdateNotificationPolicy.Tests.ps1','MediaPolicies.Tests.ps1','CeipPolicy.Tests.ps1') }
    }
    }
    @($names | ForEach-Object { Join-Path $GuestPath ('tests/'+$_) })
  } elseif ($IntegrationSuite -eq 'GitHubAuthentication') {
    @('.\tests\GitHubAuthentication.Tests.ps1', '.\tests\GitHubReleaseDiscovery.Tests.ps1', '.\tests\GitHubVmAuthentication.Tests.ps1', '.\tests\PackageEvidence.Tests.ps1', '.\tests\CliShouldProcess.Tests.ps1', '.\tests\TestAutomation.Tests.ps1')
  } elseif ($IntegrationSuite -in @('SettingsRemainingBatch1', 'SettingsRemainingBatch2')) {
    @('.\tests\Catalog.Tests.ps1', '.\tests\CliShouldProcess.Tests.ps1', '.\tests\HashValueContextMenu.Tests.ps1', '.\tests\RemainingSettings.Tests.ps1', '.\tests\SettingPresentation.Tests.ps1', '.\tests\TestAutomation.Tests.ps1')
  } elseif ($IntegrationSuite -like 'ApplicationsBatch*') {
    $selectedTests=@('.\tests\ApplicationPackages.Tests.ps1', '.\tests\ChatPackagePins.Tests.ps1', '.\tests\Catalog.Tests.ps1', '.\tests\PackageDependencyPlanning.Tests.ps1', '.\tests\PackageEvidence.Tests.ps1', '.\tests\TestAutomation.Tests.ps1')
    if($IntegrationSuite -in @('ApplicationsBatch6','ApplicationsBatch7')){$selectedTests+= '.\tests\ArtcraftPackages.Tests.ps1'}
    $selectedTests
  } else { @('.\tests') }
  $summary['PesterSelection'] = if ($fixture) { 'Focused fixture contract, catalog, preview and selected handler regression' } elseif ($IntegrationSuite -in @('SettingsRemainingBatch1', 'SettingsRemainingBatch2')) { 'Remaining settings catalog, lifecycle, registry value-set recovery, presentation and controller regression' } elseif ($IntegrationSuite -like 'ApplicationsBatch*') { 'Application lifecycle, catalog, acquisition and controller regression' } else { 'Full repository regression' }
  $activePhase = 'Pester'
  Write-RideGuestProgress -Phase $activePhase -State Started -Message $summary.PesterSelection
  if ($ResultsPath) {
    $pesterConfiguration = New-PesterConfiguration
    $pesterConfiguration.Run.Path = $testPaths
    $pesterConfiguration.Run.PassThru = $true
    if ($fixture) {
      $pesterConfiguration.Filter.ExcludeTag = @('WindowsIntegration')
      $pesterConfiguration.TestRegistry.Enabled = $false
    }
    $pesterConfiguration.TestResult.Enabled = $true
    $pesterConfiguration.TestResult.OutputPath = Join-Path $ResultsPath 'pester.xml'
    $pesterConfiguration.TestResult.OutputFormat = 'NUnitXml'
    $pesterResult = Invoke-Pester -Configuration $pesterConfiguration
  }
  else { $pesterResult = Invoke-Pester -Path $testPaths -PassThru }
  $summary.Pester = @{ Total = $pesterResult.TotalCount; Passed = $pesterResult.PassedCount; Failed = $pesterResult.FailedCount; Result = [string]$pesterResult.Result; Version = '5.7.1' }
  if ($pesterResult.FailedCount -gt 0 -or ($ResultsPath -and ($pesterResult.Result -ne 'Passed' -or $pesterResult.TotalCount -lt 1))) { throw "Pester did not pass: $($pesterResult.FailedCount) failing test(s)." }
  Write-Output ("Pester passed: {0} test(s)." -f $pesterResult.PassedCount)
  Write-RideGuestProgress -Phase $activePhase -State Completed -Message ("{0} tests passed." -f $pesterResult.PassedCount)
  if ($Integration) {
    $activePhase = 'Windows integration'
    Write-RideGuestProgress -Phase $activePhase -State Started -Message $IntegrationSuite
    $env:RIDE_INTEGRATION_VM = '1'
    if ($fixture) {
      $fixtureEvidence = Join-Path $ResultsPath 'settings-fixture.json'
      # Pester may compile mock native types. Real integration needs fresh types
      # and a fresh module catalog context, not those retained in the test process.
      & (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $GuestPath 'tests/integration/Invoke-RideSettingsFixture.ps1') -FixturePath $fixturePath -EvidencePath $fixtureEvidence
      if ($LASTEXITCODE -ne 0) { throw "Settings fixture failed with exit code $LASTEXITCODE; inspect settings-fixture.json." }
      $summary['IntegrationFixture'] = Get-Content -LiteralPath $fixtureEvidence -Raw | ConvertFrom-Json
    }
    elseif ($IntegrationSuite -eq 'GitHubAuthentication') {
      & .\tests\integration\Invoke-RideGitHubAuthentication.ps1 -RunId $ResultRunId -ResultsPath $ResultsPath -Authentication $GuestGitHubAuthentication -Scenario $GitHubTestScenario
    }
    elseif ($IntegrationSuite -eq 'SettingsBatch40') { & .\tests\integration\Invoke-RideSettingsBatch.ps1 }
    elseif ($IntegrationSuite -eq 'SettingsBatch60') { & .\tests\integration\Invoke-RideSettingsBatch60.ps1 }
    elseif ($IntegrationSuite -eq 'SettingsBatch60Recovery') { & .\tests\integration\Invoke-RideSettingsBatch60.ps1 -Selection Recovery12 }
    elseif ($IntegrationSuite -eq 'SettingsRemainingBatch1') { & .\tests\integration\Invoke-RideRemainingSettings.ps1 -Batch 1 }
    elseif ($IntegrationSuite -eq 'SettingsRemainingBatch2') { & .\tests\integration\Invoke-RideRemainingSettings.ps1 -Batch 2 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch1') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 1 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch1Machine') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 1 -PackageScope Machine }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch1User') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 1 -PackageScope User }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch2') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 2 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch3') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 3 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch3AllUsers') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 3 -Variant all-users }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch4') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 4 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch5') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 5 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch6') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 6 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch7') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 7 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch8') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 8 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch9') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 9 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch10') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 10 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch11') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 11 }
    elseif ($IntegrationSuite -eq 'ApplicationsBatch12') { & .\tests\integration\Invoke-RideApplicationBatch.ps1 -Batch 12 -PackageId package.ntcore-explorer-suite }
    else { & .\tests\integration\Invoke-RideVmSuite.ps1 }
    $summary['IntegrationSuite'] = $IntegrationSuite
    $summary.IntegrationPassed = $true
    Write-RideGuestProgress -Phase $activePhase -State Completed -Message $IntegrationSuite
  }
  else { Write-Output 'VM integration suite skipped by -UnitOnly.' }
  $summary.Status = 'Passed'
}
catch {
  $summary.Error = $_.Exception.Message
  Write-RideGuestProgress -Phase $activePhase -State Failed -Message $_.Exception.Message
  throw
}
finally {
  if ($GuestGitHubAuthentication -eq 'PAT') {
    try {
      Import-Module (Join-Path $GuestPath 'modules/RIDE.GitHubAuthentication.psm1') -ErrorAction Stop
      Remove-RideGitHubCredential -Name ('run:' + $ResultRunId) -Confirm:$false
      $summary.CredentialCleanupVerified = Test-RideGitHubGuestCredentialAbsent $ResultRunId
      if ($summary.CredentialCleanupVerified -ne $true) { throw 'Credential cleanup was not verified.' }
    } catch { $summary.Status = 'Failed'; $summary.Error = 'Guest GitHub credential cleanup could not be verified.' }
  }
  if ($ResultsPath) {
    try {
      $observations = Join-Path $GuestPath 'catalog\artifact-observations.json'
      if (Test-Path -LiteralPath $observations) { Copy-Item -LiteralPath $observations -Destination (Join-Path $ResultsPath 'artifact-observations.json') -Force }
      foreach ($scope in @('Machine', 'User')) {
        $base = if ($scope -eq 'Machine') { [Environment]::GetFolderPath('CommonApplicationData') } else { [Environment]::GetFolderPath('LocalApplicationData') }
        $statePath = Join-Path $base 'RIDE\State'
        if (Test-Path -LiteralPath $statePath) {
          $destination = Join-Path $ResultsPath "state\$scope"
          New-Item -ItemType Directory -Path $destination -Force | Out-Null
          Get-ChildItem -LiteralPath $statePath -Force | Where-Object Name -NotIn @('Cache', 'Artifacts') | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force }
        }
      }
    }
    catch { $summary.Status = 'Failed'; $summary.StateCollectionError = $_.Exception.Message }
    if ($transcribing) { Stop-Transcript | Out-Null }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $ResultsPath 'summary.json') -Encoding UTF8
  }
}
