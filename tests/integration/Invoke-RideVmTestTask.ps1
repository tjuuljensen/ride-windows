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

.PARAMETER ReceiptPath
  Optional caller-owned JSON output identifying the request and its result directory.

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
  Version: 0.1.0
  Changelog:
    - 0.1.0: Initial on-demand/CI task client.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

.LINK
  tests/integration/AUTOMATEDLAB.md

#>


[CmdletBinding()]
param(
  [string] $ConfigurationPath,
  [ValidateSet('Local', 'CI')][string] $Source = 'Local',
  [switch] $UnitOnly,
  [ValidateRange(1, 180)][int] $TimeoutMinutes = 90,
  [string] $ReceiptPath,
  [switch] $Version
)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
if (-not $ConfigurationPath) { throw '-ConfigurationPath is required.' }
$config = Read-RideAutomationConfiguration $ConfigurationPath
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $config.HostAccountSid) { throw 'Submit requests as the same account used to register the task.' }
$root = Get-RideAutomationRoot $config.Name
if (Test-Path -LiteralPath (Join-Path $root 'runtime\blocked.json')) { throw 'VM cleanup is blocked. Follow AUTOMATEDLAB-TASKS.md before requesting more runs.' }
$request = [ordered]@{ RunId = [guid]::NewGuid().ToString('N'); Source = $Source; UnitOnly = [bool]$UnitOnly; TimeoutMinutes = $TimeoutMinutes; SubmittedAtUtc = [datetime]::UtcNow.ToString('o') }
$pendingPath = Join-Path $root "queue\pending\$($request.RunId).json"
$runningPath = Join-Path $root "queue\running\$($request.RunId).json"
$resultPath = Join-Path $root "results\$($request.RunId)\result.json"
Write-RideAutomationJson -Path $pendingPath -Value $request
if ($ReceiptPath) { Write-RideAutomationJson -Path $ReceiptPath -Value @{ RunId = $request.RunId; ResultDirectory = (Split-Path -Parent $resultPath) } }
Write-Host "RIDE request $($request.RunId): $Source; results at $(Split-Path -Parent $resultPath)"
# Give the worker five additional minutes to collect evidence and restore the VM.
$deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes + 5)
while ([datetime]::UtcNow -lt $deadline) {
  if (Test-Path -LiteralPath $resultPath) {
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ($result.RunId -ne $request.RunId) { throw 'Result correlation failed.' }
    if ($result.Status -ne 'Passed') { throw "RIDE run $($request.RunId) $($result.Status): $($result.Error) $($result.CleanupError). Results: $(Split-Path -Parent $resultPath)" }
    $result
    return
  }
  if (Test-Path -LiteralPath $pendingPath) { Start-ScheduledTask -TaskPath '\RIDE\' -TaskName $config.Name -ErrorAction Stop }
  elseif (-not (Test-Path -LiteralPath $runningPath)) { throw 'Request disappeared without a correlated result.' }
  Start-Sleep -Seconds 2
}
throw "No terminal result for $($request.RunId). The VM may still be cleaning up; do not run it manually. Inspect task state and the recovery runbook. Results: $(Split-Path -Parent $resultPath)"
