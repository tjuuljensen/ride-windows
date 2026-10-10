<#
.SYNOPSIS
  Run RIDE tests in a dedicated Windows PowerShell process inside a disposable VM.

.DESCRIPTION
  Internal guest entry point for Invoke-RideVmTest.ps1. Requires its VM-only
  environment marker, validates the staged checkout, runs Pester 5.7.1, and
  optionally runs the state-changing integration suite. Exports correlated
  transcript, Pester results, summary and saved state when ResultsPath is supplied.

.PARAMETER GuestPath
  Staged repository directory inside the disposable guest.

.PARAMETER Integration
  Run the integration suite after successful Pester tests; defaults to false.

.PARAMETER IntegrationSuite
  Full (default) runs all integration scenarios. SettingsBatch40 runs only the
  forty-setting registry migration suite, without package downloads.

.PARAMETER ResultsPath
  Optional guest directory for evidence; the host runner collects this directory.

.PARAMETER ResultRunId
  Correlated request ID, required when ResultsPath is supplied.

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
  Version: 0.2.0
  Changelog: 0.2.0: Add explicit settings-only integration selection.
    0.1.0: Isolate Pester from the remoting thread's call-depth limit.

.LINK
  tests/integration/Invoke-RideVmTest.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string] $GuestPath,
  [switch] $Integration,
  [ValidateSet('Full', 'SettingsBatch40')][string] $IntegrationSuite = 'Full',
  [string] $ResultsPath,
  [ValidatePattern('^[0-9a-f]{32}$')][string] $ResultRunId,
  [switch] $Version
)
$script:ScriptVersion = '0.2.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if ($env:RIDE_TEST_GUEST -ne '1') { throw 'Use the disposable-VM host runner; this entry point must not run on a developer workstation.' }
if (-not $Integration -and $IntegrationSuite -ne 'Full') { throw 'Specify -Integration when selecting an integration suite.' }
if (-not $GuestPath -or -not (Test-Path -LiteralPath (Join-Path $GuestPath 'tools/validate.ps1') -PathType Leaf)) { throw 'GuestPath must identify the staged RIDE checkout.' }
if ($ResultsPath -and -not $ResultRunId) { throw 'ResultRunId is required for evidence collection.' }
if (-not $PSCmdlet.ShouldProcess($GuestPath, 'Run validation, Pester and selected disposable-VM integration tests')) { return }

Set-Location -LiteralPath $GuestPath
$summary = [ordered]@{ SchemaVersion = 1; RunId = $ResultRunId; Status = 'Failed'; ValidationPassed = $false; IntegrationPassed = $false; Pester = $null; Error = $null; StateCollectionError = $null; Guest = $null }
$transcribing = $false
try {
  if ($ResultsPath) {
    New-Item -ItemType Directory -Path $ResultsPath -Force | Out-Null
    Start-Transcript -LiteralPath (Join-Path $ResultsPath 'transcript.log') -Force | Out-Null
    $transcribing = $true
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Guest session is not elevated.' }
    $summary.Guest = @{ OS = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber); Account = $identity.Name; SID = $identity.User.Value; PowerShell = $PSVersionTable.PSVersion.ToString() }
  }
  Import-Module Pester -RequiredVersion '5.7.1' -ErrorAction Stop
  $env:RIDE_TEST_EVIDENCE_PATH = $ResultsPath
  $env:RIDE_TEST_RUN_ID = $ResultRunId
  & .\tools\Export-RideCatalog.ps1
  & .\tools\validate.ps1
  $summary.ValidationPassed = $true
  if ($ResultsPath) {
    $pesterConfiguration = New-PesterConfiguration
    $pesterConfiguration.Run.Path = '.\tests'
    $pesterConfiguration.Run.PassThru = $true
    $pesterConfiguration.TestResult.Enabled = $true
    $pesterConfiguration.TestResult.OutputPath = Join-Path $ResultsPath 'pester.xml'
    $pesterConfiguration.TestResult.OutputFormat = 'NUnitXml'
    $pesterResult = Invoke-Pester -Configuration $pesterConfiguration
  }
  else { $pesterResult = Invoke-Pester -Path .\tests -PassThru }
  $summary.Pester = @{ Total = $pesterResult.TotalCount; Passed = $pesterResult.PassedCount; Failed = $pesterResult.FailedCount; Result = [string]$pesterResult.Result; Version = '5.7.1' }
  if ($pesterResult.FailedCount -gt 0 -or ($ResultsPath -and ($pesterResult.Result -ne 'Passed' -or $pesterResult.TotalCount -lt 1))) { throw "Pester did not pass: $($pesterResult.FailedCount) failing test(s)." }
  Write-Output ("Pester passed: {0} test(s)." -f $pesterResult.PassedCount)
  if ($Integration) {
    $env:RIDE_INTEGRATION_VM = '1'
    if ($IntegrationSuite -eq 'SettingsBatch40') { & .\tests\integration\Invoke-RideSettingsBatch.ps1 }
    else { & .\tests\integration\Invoke-RideVmSuite.ps1 }
    $summary['IntegrationSuite'] = $IntegrationSuite
    $summary.IntegrationPassed = $true
  }
  else { Write-Output 'VM integration suite skipped by -UnitOnly.' }
  $summary.Status = 'Passed'
}
catch { $summary.Error = $_.Exception.Message; throw }
finally {
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
