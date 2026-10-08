<#
.SYNOPSIS
  Drain the RIDE request queue inside the registered elevated task.

.DESCRIPTION
  - Claims requests atomically and holds a process-scoped file lock.
  - Blocks execution after interrupted requests or failed VM cleanup.
  Invokes the fixed controller; restores only the explicitly configured VM.

.PARAMETER ConfigurationPath
  Installed controller configuration.json selected by the registered elevated task.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\Invoke-RideVmTestTaskWorker.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None. Writes queue transitions, block markers, and correlated result files.

.NOTES
  Compatibility: 64-bit Windows PowerShell 5.1 on a prepared Windows Hyper-V host.
  Prerequisites: Registered task; do not invoke this script directly for routine testing.
  File/environment inputs: Administrative configuration and account-owned request queue.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    - 0.1.0: Initial serialized task worker.
  Internal entry point: use the registered task, not direct invocation, for operational execution.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

.LINK
  tests/integration/AUTOMATEDLAB.md

#>


[CmdletBinding()]
param([string] $ConfigurationPath, [switch] $Version)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
$config = Read-RideAutomationConfiguration $ConfigurationPath
$root = Get-RideAutomationRoot $config.Name
Assert-RideAutomationDirectory $root
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $config.HostAccountSid) { throw 'Worker identity differs from the configured account.' }
$lock = Enter-RideAutomationWorker $root
if (-not $lock) { return }
try {
  $interrupted = @(Get-ChildItem -LiteralPath (Join-Path $root 'queue\running') -Filter '*.json' -File)
  if ($interrupted.Count) { Write-RideAutomationJson -Path (Join-Path $root 'runtime\blocked.json') -Value @{ Error = 'A previous worker stopped with an active request. Inspect child processes and restore the VM before recovery.'; Requests = @($interrupted.Name) } }
  while ($true) {
    $claim = Get-RideAutomationClaim $root
    if (-not $claim) { break }
    $null = Invoke-RideAutomationRequest -Configuration $config -Request $claim.Request -Root $root
    Move-Item -LiteralPath $claim.Path -Destination (Join-Path $root "queue\finished\$($claim.Name)")
  }
}
finally { if ($lock) { $lock.Dispose() } }
