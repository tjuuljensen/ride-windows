<#
.SYNOPSIS
  Stage this checkout in a disposable Windows VM and run RIDE validation,
  Pester, and optionally the real-Windows integration suite.

.DESCRIPTION
  - Supports AutomatedLab and PowerShell Direct transports.
  - Skips AutomatedLab definition validation when importing an existing lab;
  the VM must already have been provisioned successfully.
  - Waits up to five minutes for AutomatedLab guest remoting after VM startup.
  - Uses ShouldProcess before staging files or running guest commands.
  - Removes its temporary host staging directory after the run.
  - Optional ResultDirectory exports guest transcript, Pester XML, summary and
  saved RIDE state before the task controller restores the checkpoint.
  - Copies the working tree to the guest and runs validation and Pester.
  - Runs guest tests in a fresh Windows PowerShell process to isolate the mock
  call stack from the remoting thread.
  - Unless UnitOnly is set, changes guest Windows state and installs/removes
  packages; restore the guest's clean checkpoint after the run.

.PARAMETER Transport
  AutomatedLab or PowerShellDirect; required for operational invocation. PowerShellDirect prompts
  for guest administrator credentials.

.PARAMETER LabName
  Existing AutomatedLab definition; required for the AutomatedLab transport.

.PARAMETER VMName
  Existing disposable Hyper-V guest; defaults to RIDE-Win11-Test.

.PARAMETER RepositoryPath
  Source checkout including uncommitted files; defaults to this script's repository root.

.PARAMETER GuestRepositoryPath
  Guest checkout directory below a drive root; defaults to C:\RIDE\ride-windows. Match the source
  directory name for AutomatedLab copying.

.PARAMETER UnitOnly
  Run catalog generation, static validation, and Pester in the guest without the state-changing
  integration suite.

.PARAMETER IntegrationSuite
  ApplicationsBatch1 and ApplicationsBatch2 select installed/portable application migration tests;
  ApplicationsBatch3 selects both Docker Desktop installation variants.
  ApplicationsBatch3AllUsers selects only the elevated Docker Desktop variant.
  ApplicationsBatch4 selects the Slack and Discord current-user EXE candidates.
  ApplicationsBatch5 selects the Microsoft Visual C++ v14 runtime lifecycle candidate on Windows 11.
  ApplicationsBatch6 selects the twelve Artcraft machine-scope MSI applications on Windows 11.
  ApplicationsBatch7 selects only the current-user ArtCraft Launcher MSI on Windows 11; it does not launch the app.
  ApplicationsBatch8 selects four side-by-side Microsoft OpenJDK MSIs on Windows Server 2025.
  SettingsRemainingBatch1 and SettingsRemainingBatch2 select the two focused migration suites.
  Full (default) runs all integration scenarios. SettingsBatch40 runs the forty-setting
  registry migration suite without package downloads; SettingsBatch60 selects the sixty-setting suite; cannot be combined with UnitOnly.
  SettingsBatch60Recovery selects only its BCD policy and eleven coordinated settings.

.PARAMETER ResultDirectory
  Optional host directory for correlated transcript, Pester XML, summary, and saved-state exports.

.PARAMETER RunId
  32 lowercase hexadecimal characters for result correlation; defaults to a newly generated GUID in
  N format.

.PARAMETER GuestGitHubAuthentication
  Anonymous (default) or explicit PAT; PAT requires the focused GitHubAuthentication suite.

.PARAMETER AuthenticationConfigurationPath
  Protected installed controller configuration supplying the dedicated VmTest reference.

.PARAMETER AuthenticationDeadlineUtc
  Absolute request deadline; bounds the transient guest credential lifetime.

.PARAMETER AuthenticationCredentialRevision
  Nonsecret credential revision pinned by the controller for delivery and evidence scanning.

.PARAMETER GitHubTestScenario
  Acquire (default), FailAfterDelivery or WaitForTimeout; focused-suite recovery scenarios.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\Invoke-RideVmTest.ps1 -Version

.EXAMPLE
  .\tests\integration\Invoke-RideVmTest.ps1 -Transport AutomatedLab -LabName RIDEWin11Pilot -VMName RIDE-W11-Pilot -WhatIf

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.Object. Guest validation/test output and host progress messages; optional evidence files.

.NOTES
  Compatibility: Windows PowerShell 5.1 or PowerShell 7 on Windows with Hyper-V management
  support; the guest must be Windows 11 or Windows Server 2025.
  Prerequisites: - Host access to the selected VM transport; Pester 5.7.1 in the guest.
  - AutomatedLab commands for AutomatedLab transport, or a configured
  PowerShell Direct-capable Hyper-V VM.
  File/environment inputs: - Transport, optional lab/VM names and checkout/guest paths, and
  UnitOnly and IntegrationSuite.
  - Optional ResultDirectory and RunId correlate guest exports with a host request.
  - PowerShell Direct prompts for a guest administrator credential.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.14.0
  Changelog:
    0.14.0: Forward Server 2025 Microsoft OpenJDK side-by-side acceptance.
    0.13.0: Forward the dedicated ArtCraft Launcher ApplicationsBatch7 suite.
    0.12.0: Forward the focused Slack and Discord package acceptance suite.
    0.11.0: Add explicit GitHub PAT selection and credential-safe acceptance boundaries.
    0.10.0: Accept application migration suites through the VM runner.
  - 0.9.0: Forward remaining-settings acceptance batches without package downloads.
  - 0.8.0: Select the twelve outstanding BCD/coordinated recovery scenarios.
  - 0.7.0: Select SettingsBatch60 without package integration.
  - 0.6.0: Add explicit selection of the settings-only integration suite.
  - 0.5.0: Run guest validation and tests outside the remoting thread.
  - 0.4.0: Export acquisition observations with correlated guest evidence.
    - 0.3.0: Wait for guest WinRM before staging files and running commands.
  - 0.2.0: Add opt-in correlated result export for the task controller.
  - 0.1.0: Initial versioned VM test runner.

.LINK
  tests/integration/automatedlab-tasks.md

.LINK
  tests/integration/automatedlab.md

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [ValidateSet('AutomatedLab', 'PowerShellDirect')]
  [string] $Transport,

  [string] $LabName,
  [string] $VMName = 'RIDE-Win11-Test',
  [string] $RepositoryPath,
  [string] $GuestRepositoryPath = 'C:\RIDE\ride-windows',
  [switch] $UnitOnly,
  [ValidateSet('Full', 'SettingsBatch40', 'SettingsBatch60', 'SettingsBatch60Recovery', 'SettingsRemainingBatch1', 'SettingsRemainingBatch2', 'ApplicationsBatch1', 'ApplicationsBatch2', 'ApplicationsBatch3', 'ApplicationsBatch3AllUsers', 'ApplicationsBatch4', 'ApplicationsBatch5', 'ApplicationsBatch6', 'ApplicationsBatch7', 'ApplicationsBatch8', 'GitHubAuthentication')][string] $IntegrationSuite = 'Full',
  [string] $ResultDirectory,
  [ValidateSet('Anonymous','PAT')][string] $GuestGitHubAuthentication = 'Anonymous',
  [ValidateSet('Acquire','FailAfterDelivery','WaitForTimeout')][string] $GitHubTestScenario = 'Acquire',
  [string] $AuthenticationConfigurationPath,
  [datetime] $AuthenticationDeadlineUtc,
  [ValidatePattern('^[0-9a-f]{32}$')][string] $AuthenticationCredentialRevision,
  [ValidatePattern('^[0-9a-f]{32}$')]
  [string] $RunId = ([guid]::NewGuid().ToString('N')),

  [switch] $Version
)

$script:ScriptVersion = '0.13.0'
if ($Version) {
  Write-Output $script:ScriptVersion
  return
}

if (-not $Transport) {
  throw "Specify -Transport as 'AutomatedLab' or 'PowerShellDirect'."
}

$ErrorActionPreference = 'Stop'
if ($UnitOnly -and $IntegrationSuite -ne 'Full') { throw 'IntegrationSuite cannot be selected with UnitOnly.' }
if ($GuestGitHubAuthentication -eq 'PAT' -and ($UnitOnly -or $IntegrationSuite -ne 'GitHubAuthentication' -or -not $ResultDirectory -or -not $AuthenticationConfigurationPath)) { throw 'PAT requires the focused GitHubAuthentication suite, retained results and protected configuration.' }
if ($GuestGitHubAuthentication -eq 'PAT') {
  $configurationFullPath = [IO.Path]::GetFullPath($AuthenticationConfigurationPath)
  $configurationRoot = Split-Path -Parent $configurationFullPath
  $controllerName = Split-Path -Leaf $configurationRoot
  $protectedRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('RIDE\TestAutomation\' + $controllerName)
  if ($controllerName -notmatch '^RIDE[A-Za-z0-9-]{1,55}$' -or (Split-Path -Leaf $configurationFullPath) -ne 'configuration.json' -or $configurationRoot -ne $protectedRoot -or [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') -ne (Join-Path $protectedRoot 'bin')) { throw 'PAT guest delivery must run from the registered protected controller installation.' }
}

if ($Transport -eq 'AutomatedLab' -and -not $LabName) {
  throw "-LabName is required when -Transport is 'AutomatedLab'."
}

if (-not $RepositoryPath) {
  $RepositoryPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$resolvedRepositoryPath = (Resolve-Path -LiteralPath $RepositoryPath).Path
foreach ($requiredPath in @('tools/validate.ps1', 'tools/Export-RideCatalog.ps1', 'tests/Catalog.Tests.ps1')) {
  if (-not (Test-Path -LiteralPath (Join-Path $resolvedRepositoryPath $requiredPath) -PathType Leaf)) {
    throw "'$resolvedRepositoryPath' is not a RIDE-Windows checkout; missing '$requiredPath'."
  }
}

if ([string]::IsNullOrWhiteSpace($GuestRepositoryPath) -or $GuestRepositoryPath -match '^[A-Za-z]:\\?$') {
  throw '-GuestRepositoryPath must identify a guest directory below a drive root.'
}

$runIntegration = -not $UnitOnly
$action = if ($runIntegration) { 'copy the checkout and run validation, Pester, and VM integration tests' } else { 'copy the checkout and run validation and Pester' }
if (-not $PSCmdlet.ShouldProcess("$VMName via $Transport", $action)) { return }

$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ride-vm-test-' + [guid]::NewGuid().ToString('N'))
$stagedRepository = Join-Path $stageRoot 'ride-windows'
$session = $null
$resultSession = $null
$authenticationContext = $null
$leaseSession = $null
$lease = $null
$guestResultsPath = if ($ResultDirectory) { "C:\RIDE\TestResults\$RunId" } else { '' }
if ($ResultDirectory) { New-Item -ItemType Directory -Path $ResultDirectory -Force | Out-Null }

try {
  if ($GuestGitHubAuthentication -eq 'PAT') {
    Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -ErrorAction Stop
    Import-Module (Join-Path $PSScriptRoot 'RIDE.GitHubVmAuthentication.psm1') -ErrorAction Stop
    $authConfiguration = Read-RideAutomationConfiguration $AuthenticationConfigurationPath
    if ($authConfiguration.VMName -ne $VMName -or $authConfiguration.GuestRepositoryPath -ne $GuestRepositoryPath -or $AuthenticationDeadlineUtc.ToUniversalTime() -le [datetime]::UtcNow) { throw 'Authentication target or request deadline does not match.' }
    if ((Get-VM -Name $VMName -ErrorAction Stop).Id -ne [guid]$authConfiguration.VMId) { throw 'Authentication VM identity differs from its configured pin.' }
    $authenticationContext = Get-RideVmGitHubContext $authConfiguration
    if ($authenticationContext.Revision -ne $AuthenticationCredentialRevision) { throw 'Credential changed after request preflight; submit a new request.' }
  }
  New-Item -ItemType Directory -Path $stagedRepository -Force | Out-Null
  Get-ChildItem -LiteralPath $resolvedRepositoryPath -Force |
    Where-Object { $_.Name -notin @('.git', '.local', 'testResults.xml') } |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $stagedRepository -Recurse -Force }

  $remoteTest = {
    param(
      [string] $GuestPath,
      [bool] $RunIntegration,
      [string] $ResultsPath,
      [string] $ResultRunId,
      [string] $SelectedSuite,
      [string] $AuthenticationMode,
      [string] $ExpectedCredentialSid,
      [string] $AuthenticationScenario
    )

    $ErrorActionPreference = 'Stop'
    $guestRunner = Join-Path $GuestPath 'tests\integration\Invoke-RideGuestTests.ps1'
    if (-not (Test-Path -LiteralPath $guestRunner -PathType Leaf)) { throw 'The staged checkout is missing the guest test runner.' }
    # Keep Pester's mock call stack on a fresh powershell.exe main thread.
    $previousGuestMarker = $env:RIDE_TEST_GUEST
    try {
      $env:RIDE_TEST_GUEST = '1'
      $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $guestRunner, '-GuestPath', $GuestPath)
      if ($ResultsPath) { $arguments += @('-ResultsPath', $ResultsPath, '-ResultRunId', $ResultRunId) }
      # File arguments do not reliably accept Boolean strings on Windows PowerShell 5.1.
      if ($RunIntegration) { $arguments += @('-Integration', '-IntegrationSuite', $SelectedSuite) }
      if ($SelectedSuite -eq 'GitHubAuthentication') { $arguments += @('-GuestGitHubAuthentication', $AuthenticationMode, '-GitHubTestScenario', $AuthenticationScenario) }
      if ($AuthenticationMode -eq 'PAT') { $arguments += @('-ExpectedCredentialSid', $ExpectedCredentialSid) }
      & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') @arguments
      if ($LASTEXITCODE -ne 0) { throw "Guest test process failed with exit code $LASTEXITCODE." }
    }
    finally { $env:RIDE_TEST_GUEST = $previousGuestMarker }
  }

  if ($Transport -eq 'AutomatedLab') {
    if (-not (Get-Command Import-Lab -ErrorAction SilentlyContinue) -or -not (Get-Command Copy-LabFileItem -ErrorAction SilentlyContinue)) {
      throw 'AutomatedLab commands are unavailable. Install/import AutomatedLab or select -Transport PowerShellDirect.'
    }

    Import-Lab -Name $LabName -NoValidation
    Write-Output "Waiting up to five minutes for the AutomatedLab session to '$VMName'."
    $readinessSession = $null
    try {
      $readinessSession = New-LabPSSession -ComputerName $VMName -Retries 30 -Interval 10 -ErrorAction Stop
    }
    catch {
      throw "Could not establish guest WinRM for '$VMName' after waiting up to five minutes. Confirm that Windows has completed startup and the guest WinRM listener and firewall rule are enabled. $($_.Exception.Message)"
    }
    finally {
      if ($readinessSession) { Remove-PSSession -Session $readinessSession -ErrorAction SilentlyContinue }
    }
    if ($ResultDirectory) {
      # Session creation is bounded by the outer task controller timeout.
      $resultSession = New-LabPSSession -ComputerName $VMName -Retries 20 -Interval 5
      Invoke-Command -Session $resultSession -ScriptBlock {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Guest session is not elevated.' }
      } -ErrorAction Stop
    }
    Invoke-LabCommand -ComputerName $VMName -ScriptBlock {
      param([string] $Path)
      New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    } -ArgumentList $GuestRepositoryPath | Out-Null

    Copy-LabFileItem -Path $stagedRepository -ComputerName $VMName -DestinationFolderPath (Split-Path -Parent $GuestRepositoryPath) -Recurse
    if ($GuestGitHubAuthentication -eq 'PAT') {
      $leaseSession = $resultSession
      $lease = New-RideVmGitHubLease $leaseSession $GuestRepositoryPath $RunId $authenticationContext $AuthenticationDeadlineUtc
      $lease | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ResultDirectory 'guest-authentication.json') -Encoding UTF8
      Invoke-Command -Session $leaseSession -ScriptBlock $remoteTest -ArgumentList @($GuestRepositoryPath, [bool]$runIntegration, $guestResultsPath, $RunId, $IntegrationSuite, $GuestGitHubAuthentication, $lease.WindowsSid, $GitHubTestScenario) -ErrorAction Stop
    } else {
      Invoke-LabCommand -ComputerName $VMName -ScriptBlock $remoteTest -ArgumentList @($GuestRepositoryPath, [bool]$runIntegration, $guestResultsPath, $RunId, $IntegrationSuite, $GuestGitHubAuthentication, '', $GitHubTestScenario) -PassThru
    }
  }
  else {
    $credential = Get-Credential -Message "Enter the local administrator account for guest VM '$VMName'."
    $session = New-PSSession -VMName $VMName -Credential $credential
    Invoke-Command -Session $session -ScriptBlock {
      param([string] $Path)
      New-Item -ItemType Directory -Path $Path -Force | Out-Null
    } -ArgumentList $GuestRepositoryPath | Out-Null

    Copy-Item -Path (Join-Path $stagedRepository '*') -Destination $GuestRepositoryPath -ToSession $session -Recurse -Force
    if ($GuestGitHubAuthentication -eq 'PAT') {
      $leaseSession = $session
      $lease = New-RideVmGitHubLease $leaseSession $GuestRepositoryPath $RunId $authenticationContext $AuthenticationDeadlineUtc
      $lease | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ResultDirectory 'guest-authentication.json') -Encoding UTF8
    }
    Invoke-Command -Session $session -ScriptBlock $remoteTest -ArgumentList @($GuestRepositoryPath, [bool]$runIntegration, $guestResultsPath, $RunId, $IntegrationSuite, $GuestGitHubAuthentication, $(if ($lease) { $lease.WindowsSid } else { '' }), $GitHubTestScenario)
  }

  Write-Output "RIDE VM test completed on '$VMName'. Restore the VM's clean checkpoint before its next integration run."
}
finally {
  try {
    if ($leaseSession) { $null = Remove-RideVmGitHubLease $leaseSession $GuestRepositoryPath $RunId }
    if ($ResultDirectory) {
      $exportSession = if ($resultSession) { $resultSession } else { $session }
      if (-not $exportSession) { throw 'No guest session available to export results.' }
      Copy-Item -LiteralPath $guestResultsPath -Destination (Join-Path $ResultDirectory 'guest') -FromSession $exportSession -Recurse -Force -ErrorAction Stop
      $guestResult = Get-Content -LiteralPath (Join-Path $ResultDirectory 'guest\summary.json') -Raw | ConvertFrom-Json
      if ($guestResult.RunId -ne $RunId -or $guestResult.Status -ne 'Passed') { throw 'Guest results are mismatched or unsuccessful. Inspect exported summary.json.' }
    }
  }
  finally {
    if ($authenticationContext) { $authenticationContext.Token.Dispose() }
    if ($resultSession) { Remove-PSSession -Session $resultSession -ErrorAction SilentlyContinue }
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $stageRoot) {
      $resolvedStage = (Resolve-Path -LiteralPath $stageRoot).Path
      $expectedStage = [IO.Path]::GetFullPath($stageRoot)
      if ($resolvedStage -ne $expectedStage -or (Split-Path -Leaf $resolvedStage) -notmatch '^ride-vm-test-[0-9a-f]{32}$') { throw 'Refusing to delete an unexpected staging directory.' }
      Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
  }
}
