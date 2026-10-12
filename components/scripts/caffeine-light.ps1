<#
.SYNOPSIS
  Discourage idle screen locking with a minimal, parameterless input loop.

.DESCRIPTION
  Sends a Scroll Lock key pair immediately and every 60 seconds thereafter, indefinitely until
  Ctrl+C. Uses one WScript.Shell object, with only start/stop messages. No console customization,
  stopwatch, periodic reports, configuration files, installation or power-plan changes are used.
  The script is standalone and does not load RIDE or the full caffeine script.
  Keystrokes reach the active application. Paired presses normally return Scroll Lock to its prior
  state, but delivery is not atomic. This does not unlock a session or override enforced locks.
  A timeout shorter than 60 seconds or a lock mechanism that ignores this input can still lock.

.EXAMPLE
  .\components\scripts\caffeine-light.ps1
  Start the fallback loop. Press Ctrl+C to stop.

.EXAMPLE
  Get-Help .\components\scripts\caffeine-light.ps1 -Full
  Read documentation without starting the loop.

.INPUTS
  None. Command-line arguments are rejected.

.OUTPUTS
  None. Start/stop messages use the host.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; real idle-lock prevention
  requires disposable-VM verification. Requires an interactive session and WScript.Shell COM.
  Recovery: Ctrl+C stops the loop; finally releases the owned COM object. Forced termination
  bypasses cleanup, and interrupted or concurrent input can leave Scroll Lock changed.
  Host impact: PowerShell and Windows may create execution artifacts; this is not artifact-free.
  CLI exception: Intentionally no parameters, CmdletBinding or help/version/preview switches.
  Use Get-Help for documentation; the version is recorded here and in ScriptVersion.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Add a standalone parameterless fallback with a fixed 60-second interval.
#>

$script:ScriptVersion = '0.1.0'
$ErrorActionPreference = 'Stop'
if ($args.Count -gt 0) { throw 'Caffeine Light takes no arguments. Use Get-Help to read its documentation.' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  throw 'Caffeine Light requires an interactive Windows session.'
}

$keySender = $null
try {
  $keySender = New-Object -ComObject 'WScript.Shell' -ErrorAction Stop
  Write-Host 'Caffeine Light running: Scroll Lock pairs every 60 seconds. Press Ctrl+C to stop.'
  while ($true) {
    $keySender.SendKeys('{SCROLLLOCK}{SCROLLLOCK}')
    Start-Sleep -Seconds 60
  }
}
finally {
  if ($null -ne $keySender) {
    if ([Runtime.InteropServices.Marshal]::IsComObject($keySender)) {
      try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($keySender) }
      catch { Write-Warning 'Unable to release the Caffeine Light COM object cleanly.' }
    }
    Write-Host 'Caffeine Light stopped.'
  }
}
