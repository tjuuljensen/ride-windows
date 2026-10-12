<#
.SYNOPSIS
  Provide a matching idle PowerShell process for disposable-VM measurements.

.DESCRIPTION
  Sleeps indefinitely without creating COM objects, sending input, or changing
  console configuration. Use the same host and launch options as caffeine.

.EXAMPLE
  powershell.exe -NoLogo -NoProfile -File .\tests\integration\Invoke-RideIdleHost.ps1
  Run only in the measurement guest; press Ctrl+C to exit.

.INPUTS
  None.

.OUTPUTS
  None.

.NOTES
  Compatibility: PowerShell 5.1 and 7 on Windows. Guest measurements pending.
  Author: RIDE-Windows maintainers. Version: 0.1.0
  CLI exception: Benchmark workload, not a standalone management CLI.
  Recovery: Ctrl+C; no intentional persistent configuration.
  Changelog: 0.1.0: Add idle-host measurement control.
#>
$script:ScriptVersion = '0.1.0'
$ErrorActionPreference = 'Stop'
while ($true) { Start-Sleep -Seconds 60 }
