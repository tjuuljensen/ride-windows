<#
.SYNOPSIS
  Collect partial guest evidence after an unsuccessful task-controlled VM run.

.DESCRIPTION
  - Reads saved RIDE state and guest logs; never invokes RIDE handlers or tests.
  - The worker bounds this collector to 60 seconds before checkpoint recovery.
  Copies evidence into the guest result directory and back to the host.

.PARAMETER ConfigurationPath
  Installed pinned controller configuration.json.

.PARAMETER RunId
  32 lowercase hexadecimal request ID used to select C:\RIDE\TestResults\<RunId> in the guest.

.PARAMETER ResultDirectory
  Host request-result directory receiving the guest evidence subdirectory.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\Export-RideVmTestEvidence.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None. Copies guest evidence and saved state to the correlated host result directory.

.NOTES
  Compatibility: 64-bit Windows PowerShell 5.1 with AutomatedLab 5.61.0.
  Prerequisites: Guest is still reachable; unavailable evidence is reported without preventing
  reset.
  File/environment inputs: Fixed installed configuration and a correlated test request ID.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.2.0
  Changelog:
  - 0.2.0: Collect observations from the configured guest repository after failure.
    - 0.1.0: Initial bounded failure-evidence collection.
  Internal bounded collector. It writes evidence directories but does not invoke RIDE handlers or
  integration scenarios.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

.LINK
  tests/integration/AUTOMATEDLAB.md

#>


[CmdletBinding()]
param([string] $ConfigurationPath, [ValidatePattern('^[0-9a-f]{32}$')][string] $RunId, [string] $ResultDirectory, [switch] $Version)
$script:ScriptVersion = '0.2.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
$config = Read-RideAutomationConfiguration $ConfigurationPath
$null = Assert-RideAutomationHost $config
$null = Import-RideAutomationLab $config
$session = $null
try {
  $session = New-LabPSSession -ComputerName $config.VMName -Retries 1 -Interval 1
  $guestPath = "C:\RIDE\TestResults\$RunId"
  Invoke-Command -Session $session -ArgumentList @($guestPath, $config.GuestRepositoryPath) -ScriptBlock {
    param($Path, $RepositoryPath)
    $ErrorActionPreference = 'Stop'
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $observations = Join-Path $RepositoryPath 'catalog\artifact-observations.json'
    if (Test-Path -LiteralPath $observations) { Copy-Item -LiteralPath $observations -Destination (Join-Path $Path 'artifact-observations.json') -Force }
    foreach ($scope in @('Machine', 'User')) {
      $base = if ($scope -eq 'Machine') { [Environment]::GetFolderPath('CommonApplicationData') } else { [Environment]::GetFolderPath('LocalApplicationData') }
      $source = Join-Path $base 'RIDE\State'
      if (Test-Path -LiteralPath $source) {
        $destination = Join-Path $Path "state\$scope"
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Get-ChildItem -LiteralPath $source -Force | Where-Object Name -NotIn @('Cache', 'Artifacts') | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force }
      }
    }
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Path 'partial-guest.json') -Encoding UTF8
  } -ErrorAction Stop
  $destination = Join-Path $ResultDirectory 'guest'
  New-Item -ItemType Directory -Path $destination -Force | Out-Null
  Copy-Item -Path "$guestPath\*" -Destination $destination -FromSession $session -Recurse -Force -ErrorAction Stop
}
finally { if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } }
