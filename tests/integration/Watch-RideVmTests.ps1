<#
.SYNOPSIS
  Run the complete disposable-VM suite after relevant local edits settle.

.DESCRIPTION
  - Uses a bounded polling scan, excluding generated outputs and Git internals.
  - Coalesces edits during a run into one subsequent run; failures are reported.
  Requests the elevated test task. Ctrl+C stops watching, not an active VM run.

.PARAMETER ConfigurationPath
  Installed controller configuration.json; LocalRepositoryPath is the watched checkout.

.PARAMETER DebounceSeconds
  Quiet interval before submission, range 1-600; defaults to 30. Polls every two seconds; Ctrl+C
  stops watching, not an active VM run.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\Watch-RideVmTests.ps1 -Version

.EXAMPLE
  Get-Help .\tests\integration\Watch-RideVmTests.ps1 -Full

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None. Host status/warnings; submits full test requests after watched edits settle.

.NOTES
  Compatibility: Windows PowerShell 5.1 or PowerShell 7 on Windows.
  Prerequisites: Registered task and the same signed-in account; watcher starts explicitly.
  File/environment inputs: Installed configuration; watches only its approved local checkout.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    - 0.1.0: Initial debounced local test watcher.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

.LINK
  tests/integration/AUTOMATEDLAB.md

#>


[CmdletBinding()]
param([string] $ConfigurationPath, [ValidateRange(1, 600)][int] $DebounceSeconds = 30, [switch] $Version)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
$config = Read-RideAutomationConfiguration $ConfigurationPath
$source = (Resolve-Path -LiteralPath $config.LocalRepositoryPath).Path.TrimEnd('\')
function Get-WatchSignature {
  $rows = [Collections.Generic.List[string]]::new()
  $queue = [Collections.Generic.Queue[string]]::new()
  $queue.Enqueue($source)
  while ($queue.Count) {
    foreach ($item in Get-ChildItem -LiteralPath $queue.Dequeue() -Force) {
      $relative = $item.FullName.Substring($source.Length + 1)
      if (-not (Test-RideAutomationWatchPath $relative)) { continue }
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
      if ($item.PSIsContainer) { $queue.Enqueue($item.FullName) }
      else { $rows.Add("$relative|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)") }
    }
  }
  ($rows | Sort-Object) -join "`n"
}
$observed = Get-WatchSignature
$tested = $observed
$changedAt = [datetime]::UtcNow
Write-Host "Watching '$source'. Full VM runs after $DebounceSeconds quiet seconds; Ctrl+C stops the watcher."
while ($true) {
  Start-Sleep -Seconds 2
  $current = Get-WatchSignature
  if ($current -ne $observed) { $observed = $current; $changedAt = [datetime]::UtcNow }
  if ($observed -ne $tested -and ([datetime]::UtcNow - $changedAt).TotalSeconds -ge $DebounceSeconds) {
    $tested = $observed
    try { & (Join-Path $PSScriptRoot 'Invoke-RideVmTestTask.ps1') -ConfigurationPath $ConfigurationPath -Source Local | Out-Host }
    catch { Write-Warning $_.Exception.Message }
    # Keep the pre-run signature: edits during execution will be detected next scan.
  }
}
