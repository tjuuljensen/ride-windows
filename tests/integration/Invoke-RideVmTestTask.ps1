<#
.SYNOPSIS
  Request a RIDE VM test through the previously registered elevated task.

.DESCRIPTION
  - Runs unelevated as the configured signed-in account; correlates unique results.
  - Serializes through the worker queue and retries task launch across exit races.
  Writes a request, starts the configured task and returns its result object.
  Throws for failed, blocked, incomplete or timed-out runs.

.PARAMETER ConfigurationPath
  Installed administrative configuration.json for the registered task; required for operational use.

.PARAMETER Source
  Local (default) or CI selects the corresponding approved source checkout; no caller-supplied
  arbitrary source path.

.PARAMETER UnitOnly
  Request guest generation/validation/Pester without the integration suite; VM checkpoint reset
  still occurs.

.PARAMETER TimeoutMinutes
  Request budget including queue/staging, range 1-180; defaults to 90. Client allows five extra
  minutes for evidence and cleanup.

.PARAMETER IntegrationSuite
  NTCore, NTCoreAdditional, MiTeCMailHistoryViewers, MiTeCAnalysisTools, MiTeCSystemAndTelephony, PSScriptTools, OfflineCaffeine, SQLiteQuery, MiTeCUtilityFiles,
  SysinternalsSuite, SysinternalsProducts, ImageMagick, RawCopy and WinPmem use fixed retained payloads and PowerShell Direct
  through the protected FocusedPortableV1 controller, with no per-run UAC prompt. NTCore
  executes 4GB Patch only on a generated synthetic x86 PE inside the disposable guest.
  ImageMagick runs version reporting and a synthetic 1x1 PNG encode/identify check.
  RawCopy runs only on one generated 4096-byte NTFS fixture with all optional output modes disabled.
  WinPmem performs only exact package file install/remove/recovery; no executable or driver runs.
  ApplicationsBatch1 selects the complete installed/portable application migration suite. Use ApplicationsBatch1Machine and ApplicationsBatch1User to run its machine and limited-user packages separately;
  ApplicationsBatch2 selects the remaining installed/portable application migration tests;
  ApplicationsBatch3 selects both Docker Desktop installation variants.
  ApplicationsBatch3AllUsers selects only the elevated Docker Desktop variant.
  ApplicationsBatch4 selects the Slack and Discord current-user EXE candidates.
  ApplicationsBatch5 selects the Microsoft Visual C++ v14 runtime lifecycle candidate on Windows 11.
  ApplicationsBatch6 selects the twelve Artcraft machine-scope MSI applications on Windows 11.
  ApplicationsBatch7 selects only the current-user ArtCraft Launcher MSI on Windows 11; it does not launch the app.
  ApplicationsBatch8 selects four side-by-side Microsoft OpenJDK MSIs on Windows Server 2025.
  ApplicationsBatch9 selects MiTeC InfoBar 4.6.2 install/remove/recovery on Windows 11 without launching the application.
  ApplicationsBatch10 selects MiTeC Project Maker 1.9.0 install/remove/recovery on Windows 11 without launching the application.
  ApplicationsBatch11 selects only HashCheck 2.6.3 install/remove/recovery on Windows 11; it does not launch HashCheck.
  Requires ApplicationsBatch11InteractiveV1 and one signed-in guest administrator desktop.
  ApplicationsBatch12 selects only the pinned NTCore Explorer Suite installer lifecycle on Windows 11; suite utilities are not launched.
  MiTeCAnalysisTools selects only the pinned EXE Explorer 3.7.5 and HexEdit 7.1.0 archive lifecycle; it does not launch either tool or exercise analysis features.
  MiTeCSystemAndTelephony selects only the pinned System Information eXtra and TAPI Monitor archive lifecycle; it does not create system reports, inspect providers, place calls or launch either utility.
  SettingsRemainingBatch1 and SettingsRemainingBatch2 select the two focused migration suites.
  Full (default), SettingsBatch40, SettingsBatch60, or SettingsBatch60Recovery.
  The recovery suite selects twelve BCD/coordinated settings without packages.
  Cannot be combined with UnitOnly. Requires the installed controller to support suite selection.

.PARAMETER ReceiptPath
  Optional caller-owned JSON output identifying the request and its result directory.

.PARAMETER GuestGitHubAuthentication
  Anonymous (default) or explicit PAT; PAT requires the focused GitHubAuthentication suite.

.PARAMETER GitHubTestScenario
  Acquire (default), FailAfterDelivery or WaitForTimeout; focused-suite recovery scenarios.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\Invoke-RideVmTestTask.ps1 -Version

.EXAMPLE
  Get-Help .\tests\integration\Invoke-RideVmTestTask.ps1 -Full

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.Management.Automation.PSCustomObject. Correlated result on success; failures, missing
  results, and timeouts throw.

.NOTES
  Compatibility: Windows PowerShell 5.1 or PowerShell 7 on Windows.
  Prerequisites: Registered task; same signed-in account as registration; existing disposable VM.
  File/environment inputs: Installed configuration; Source selects one of its two approved checkout
  paths.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 1.14.1
  Changelog:
    1.14.1: Document the signed-in guest requirement for HashCheck acceptance.
    1.14.0: Accept the focused NTCore Explorer Suite ApplicationsBatch12 request.
    1.13.0: Add the focused WinPmem file-lifecycle package batch.
    1.12.0: Add fixed, capability-gated HashCheck ApplicationsBatch11 acceptance.
    1.11.0: Add the fixed MiTeCSystemAndTelephony portable acceptance request.
    1.10.0: Add the fixed MiTeCAnalysisTools portable acceptance request.
    1.9.0: Accept the focused MiTeC Project Maker ApplicationsBatch10 request.
    1.8.0: Accept the focused MiTeC InfoBar ApplicationsBatch9 request.
    1.7.0: Add the RawCopy synthetic-only package acceptance batch.
    1.6.0: Require the registered ApplicationsBatch1SplitV1 capability before queuing split suites.
    1.5.0: Expose separate ApplicationsBatch1 machine- and limited-user acceptance suites.
    1.4.0: Accept the MiTeC mail/history viewer fixed portable lifecycle suite.
    1.3.0: Accept the NTCoreAdditional fixed portable lifecycle suite.
    1.2.0: Accept the Server 2025 OpenJDK ApplicationsBatch8 request.
    1.1.0: Accept the dedicated ArtCraft Launcher ApplicationsBatch7 request.
    1.0.0: Add isolated ImageMagick Q16 synthetic feature acceptance.
    0.9.0: Add the isolated MiTeC utility file-lifecycle batch.
    0.8.0: Add the file-lifecycle-only SQLiteQuery batch.
    0.7.0: Add the focused Slack and Discord package acceptance selection.
    0.6.0: Submit fixed preregistered portable batches with a capability guard.
    0.5.0: Add explicit GitHub PAT selection and credential-safe acceptance boundaries.
    0.4.0: Accept application migration suites in correlated task requests.
  - 0.3.0: Submit either remaining-settings migration batch.
    - 0.2.0: Forward validated integration-suite selection through the protected controller.
    - 0.1.0: Initial on-demand/CI task client.

.LINK
  tests/integration/automatedlab-tasks.md

.LINK
  tests/integration/automatedlab.md

#>


[CmdletBinding()]
param(
  [string] $ConfigurationPath,
  [ValidateSet('Local', 'CI')][string] $Source = 'Local',
  [switch] $UnitOnly,
  [ValidateSet('Full', 'SettingsBatch40', 'SettingsBatch60', 'SettingsBatch60Recovery', 'SettingsRemainingBatch1', 'SettingsRemainingBatch2', 'ApplicationsBatch1', 'ApplicationsBatch1Machine', 'ApplicationsBatch1User', 'ApplicationsBatch2', 'ApplicationsBatch3', 'ApplicationsBatch3AllUsers', 'ApplicationsBatch4', 'ApplicationsBatch5', 'ApplicationsBatch6', 'ApplicationsBatch7', 'ApplicationsBatch8', 'ApplicationsBatch9', 'ApplicationsBatch10', 'ApplicationsBatch11', 'ApplicationsBatch12', 'GitHubAuthentication', 'NTCore', 'NTCoreAdditional', 'MiTeCMailHistoryViewers', 'MiTeCAnalysisTools', 'MiTeCSystemAndTelephony', 'PSScriptTools', 'OfflineCaffeine', 'SQLiteQuery', 'MiTeCUtilityFiles', 'SysinternalsSuite', 'SysinternalsProducts', 'ImageMagick', 'RawCopy', 'WinPmem')][string] $IntegrationSuite = 'Full',
  [ValidateRange(1, 180)][int] $TimeoutMinutes = 90,
  [string] $ReceiptPath,
  [ValidateSet('Anonymous','PAT')][string] $GuestGitHubAuthentication = 'Anonymous',
  [ValidateSet('Acquire','FailAfterDelivery','WaitForTimeout')][string] $GitHubTestScenario = 'Acquire',
  [switch] $Version
)
$script:ScriptVersion = '1.14.1'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if ($UnitOnly -and $IntegrationSuite -ne 'Full') { throw 'IntegrationSuite cannot be selected with UnitOnly.' }
if ($GitHubTestScenario -ne 'Acquire' -and $IntegrationSuite -ne 'GitHubAuthentication') { throw 'GitHub recovery scenarios require the focused suite.' }
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
if (-not $ConfigurationPath) { throw '-ConfigurationPath is required.' }
$config = Read-RideAutomationConfiguration $ConfigurationPath
Assert-RideAutomationSuiteCapability -Configuration $config -Suite $IntegrationSuite
if ($IntegrationSuite -in @('NTCore','NTCoreAdditional','MiTeCMailHistoryViewers','MiTeCAnalysisTools','MiTeCSystemAndTelephony','PSScriptTools','OfflineCaffeine','SQLiteQuery','MiTeCUtilityFiles','SysinternalsSuite','SysinternalsProducts','ImageMagick','RawCopy','WinPmem')) {
  if ($Source -ne 'Local') { throw 'Focused portable acceptance requires the registered Local source.' }
  if ('FocusedPortableV1' -notin @($config.Capabilities)) { throw 'One elevated controller refresh is required for FocusedPortableV1; no request was queued and no elevation prompt was opened.' }
}
if ($GuestGitHubAuthentication -eq 'PAT') {
  if ($UnitOnly -or $IntegrationSuite -ne 'GitHubAuthentication') { throw 'PAT is initially supported only by the GitHubAuthentication suite.' }
  if ($config.SchemaVersion -ne 2 -or 'GitHubPatGuestV1' -notin @($config.Capabilities) -or -not $config.GuestGitHubCredentialReference) { throw 'Refresh and configure the protected controller before submitting PAT requests.' }
}
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $config.HostAccountSid) { throw 'Submit requests as the same account used to register the task.' }
$root = Get-RideAutomationRoot $config.Name
if (Test-Path -LiteralPath (Join-Path $root 'runtime\blocked.json')) { throw 'VM cleanup is blocked. Follow automatedlab-tasks.md before requesting more runs.' }
$request = [ordered]@{ RunId = [guid]::NewGuid().ToString('N'); Source = $Source; UnitOnly = [bool]$UnitOnly; IntegrationSuite = $IntegrationSuite; TimeoutMinutes = $TimeoutMinutes; SubmittedAtUtc = [datetime]::UtcNow.ToString('o') }
if ($IntegrationSuite -eq 'GitHubAuthentication') { $request.SchemaVersion = 2; $request.GuestGitHubAuthentication = $GuestGitHubAuthentication; $request.GitHubTestScenario = $GitHubTestScenario }
$pendingPath = Join-Path $root "queue\pending\$($request.RunId).json"
$runningPath = Join-Path $root "queue\running\$($request.RunId).json"
$resultPath = Join-Path $root "results\$($request.RunId)\result.json"
Write-RideAutomationJson -Path $pendingPath -Value $request
if ($ReceiptPath) { Write-RideAutomationJson -Path $ReceiptPath -Value @{ RunId = $request.RunId; ResultDirectory = (Split-Path -Parent $resultPath); GuestGitHubAuthentication = $GuestGitHubAuthentication } }
Write-Host "RIDE request $($request.RunId): $Source; results at $(Split-Path -Parent $resultPath)"
# Give the worker five additional minutes to collect evidence and restore the VM.
$deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes + 5)
while ([datetime]::UtcNow -lt $deadline) {
  if (Test-Path -LiteralPath $resultPath) {
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ($result.RunId -ne $request.RunId) { throw 'Result correlation failed.' }
    if ($IntegrationSuite -eq 'GitHubAuthentication' -and $result.GuestGitHubAuthentication -ne $GuestGitHubAuthentication) { throw 'Controller authentication evidence is missing or mismatched.' }
    if (-not $UnitOnly -and $IntegrationSuite -ne 'Full' -and ($result.PSObject.Properties.Name -notcontains 'IntegrationSuite' -or $result.IntegrationSuite -ne $IntegrationSuite)) { throw 'Installed controller did not return evidence for the requested integration suite. Refresh its protected files using Register-RideVmTestTask.ps1.' }
    if ($result.Status -ne 'Passed') { throw "RIDE run $($request.RunId) $($result.Status): $($result.Error) $($result.CleanupError). Results: $(Split-Path -Parent $resultPath)" }
    $result
    return
  }
  if (Test-Path -LiteralPath $pendingPath) { Start-ScheduledTask -TaskPath '\RIDE\' -TaskName $config.Name -ErrorAction Stop }
  elseif (-not (Test-Path -LiteralPath $runningPath)) { throw 'Request disappeared without a correlated result.' }
  Start-Sleep -Seconds 2
}
throw "No terminal result for $($request.RunId). The VM may still be cleaning up; do not run it manually. Inspect task state and the recovery runbook. Results: $(Split-Path -Parent $resultPath)"
