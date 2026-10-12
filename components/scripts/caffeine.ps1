<#
.SYNOPSIS
  Send periodic Scroll Lock key pairs to discourage idle screen locking.

.DESCRIPTION
  Runs indefinitely unless StopAfterSeconds is supplied or Ctrl+C is pressed. Sends paired Scroll
  Lock presses to the active window, with the first pair sent immediately. This simulates activity;
  it does not change lock policy, unlock a session, or guarantee that every lock mechanism accepts
  the input. Applications can react to the keys. Choose an interval shorter than the idle timeout.
  Uses one WScript.Shell COM object and a monotonic stopwatch. Reports elapsed time independently
  of the key interval. By default, clears the screen and applies magenta console colors and a
  distinctive title. Restores captured colors and title on exit. Console and buffer dimensions
  are left to the user. No configuration or log files are written by the script. Help, Version
  and WhatIf return before operational work.

.PARAMETER IntervalSeconds
  Seconds between key pairs; defaults to 120. The former sleep parameter is removed.

.PARAMETER StopAfterSeconds
  Maximum running time in seconds; defaults to 0 for indefinite execution. The duration starts
  after initialization. No new pair is sent after the deadline is observed.

.PARAMETER ReportIntervalSeconds
  Seconds between elapsed-time reports; defaults to 3600. Use 0 to disable periodic reports.
  Startup and stop messages remain visible.

.PARAMETER NoConsoleCustomization
  Skip screen clearing and leave console colors and title unchanged. Avoids all RawUI
  access; status messages still print.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\components\scripts\caffeine.ps1
  Run indefinitely in a magenta monitoring window with hourly elapsed-time reports.

.EXAMPLE
  .\components\scripts\caffeine.ps1 -IntervalSeconds 30 -ReportIntervalSeconds 60 -StopAfterSeconds 1800
  Send a pair every 30 seconds, report every minute, and stop after 30 minutes.

.EXAMPLE
  .\components\scripts\caffeine.ps1 -NoConsoleCustomization -ReportIntervalSeconds 0
  Run indefinitely without changing console properties or printing periodic reports.

.EXAMPLE
  .\components\scripts\caffeine.ps1 -WhatIf
  Preview without creating COM objects, changing the console, or sending keys.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None during normal execution; status messages use the host. Help and Version return help/string.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; actual idle-lock prevention
  requires disposable-VM verification. Not intended for a background service or noninteractive job.
  Prerequisites: Interactive Windows session and WScript.Shell COM support. Console customization
  is best effort; unsupported properties produce a warning and input processing continues.
  File/environment inputs: Current console and desktop key state; no files or credentials are used.
  Recovery: Ctrl+C or the duration limit stops processing. Finally releases the owned COM object
  and attempts to restore console colors and title. Cleared console history cannot be restored.
  Forced process termination bypasses cleanup.
  Input limitation: A pair uses one SendKeys call to reduce the interruption window, but delivery
  is not atomic and Scroll Lock state cannot be guaranteed after interruption or concurrent input.
  Host impact: PowerShell, Windows and security software may create execution artifacts independently
  of the script. No package installation, power-plan changes or persisted settings are performed.
  Author: RIDE-Windows maintainers.
  Version: 0.2.2
  Changelog:
    0.2.2: Remove host-dependent console resizing while retaining screen clearing, colors and title.
    0.2.1: Restore screen clearing and compact console sizing with ordered size restoration.
    0.2.0: Rename interval, add duration/report/console options, preview, cleanup and launcher forwarding.
    0.1.0: Establish versioned help and move the sleep declaration into the parameter block.

.LINK
  https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/8c6yea83(v=vs.84)
#>


[CmdletBinding(SupportsShouldProcess)]
param(
  [ValidateRange(1, 2147483647)][int] $IntervalSeconds = 120,
  [ValidateRange(0, 2147483647)][int] $StopAfterSeconds = 0,
  [ValidateRange(0, 2147483647)][int] $ReportIntervalSeconds = 3600,
  [switch] $NoConsoleCustomization,
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.2.2'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  throw 'Caffeine requires an interactive Windows session.'
}
if (-not $PSCmdlet.ShouldProcess('Current interactive Windows session',
    "Send Scroll Lock pairs every $IntervalSeconds seconds to discourage idle screen locking")) {
  return
}

function Invoke-CaffeineInputLoop {
  param(
    [object] $KeySender,
    [object] $Clock,
    [int] $IntervalSeconds,
    [int] $StopAfterSeconds,
    [int] $ReportIntervalSeconds
  )

  $nextInputSeconds = 0.0
  $nextReportSeconds = [double]::PositiveInfinity
  if ($ReportIntervalSeconds -gt 0) { $nextReportSeconds = [double]$ReportIntervalSeconds }

  while ($true) {
    $elapsedSeconds = $Clock.Elapsed.TotalSeconds
    if ($StopAfterSeconds -gt 0 -and $elapsedSeconds -ge $StopAfterSeconds) { break }

    if ($elapsedSeconds -ge $nextInputSeconds) {
      # Send both presses together; there is no cancellable sleep between them.
      $KeySender.SendKeys('{SCROLLLOCK}{SCROLLLOCK}')
      $nextInputSeconds = $Clock.Elapsed.TotalSeconds + $IntervalSeconds
    }

    $elapsedSeconds = $Clock.Elapsed.TotalSeconds
    if ($StopAfterSeconds -gt 0 -and $elapsedSeconds -ge $StopAfterSeconds) { break }
    if ($elapsedSeconds -ge $nextReportSeconds) {
      Write-Host ('Elapsed time: {0}. Screen-lock blocker is running.' -f
        $Clock.Elapsed.ToString('dd\.hh\:mm\:ss'))
      # Do not send/report a burst to catch up after a delayed wake-up.
      $nextReportSeconds = $Clock.Elapsed.TotalSeconds + $ReportIntervalSeconds
    }

    $nextWakeSeconds = [Math]::Min($nextInputSeconds, $nextReportSeconds)
    if ($StopAfterSeconds -gt 0) { $nextWakeSeconds = [Math]::Min($nextWakeSeconds, $StopAfterSeconds) }
    $remainingSeconds = $nextWakeSeconds - $Clock.Elapsed.TotalSeconds
    if ($remainingSeconds -gt 0) {
      # Bound milliseconds to Start-Sleep's integer range; Ctrl+C interrupts the wait.
      $waitMilliseconds = [int][Math]::Min(2147483647.0, [Math]::Ceiling($remainingSeconds * 1000))
      Start-Sleep -Milliseconds $waitMilliseconds
    }
  }
}
$keySender = $null
$clock = $null
$consoleUi = $null
$consoleState = [ordered]@{}
try {
  # Initialize before announcing the loop or modifying console appearance.
  $keySender = New-Object -ComObject 'WScript.Shell' -ErrorAction Stop

  if (-not $NoConsoleCustomization) {
    try {
      $consoleUi = $Host.UI.RawUI
      foreach ($property in @('BackgroundColor', 'ForegroundColor', 'WindowTitle')) {
        $consoleState[$property] = $consoleUi.$property
      }
      $consoleUi.BackgroundColor = 'Magenta'
      $consoleUi.ForegroundColor = 'White'
      $consoleUi.WindowTitle = 'Caffeine - idle screen-lock blocker'
      Clear-Host
    }
    catch {
      Write-Warning 'Console customization is unavailable or incomplete. Continuing; use -NoConsoleCustomization to skip it.'
    }
  }

  Write-Host "Caffeine input loop starting. Interval: $IntervalSeconds seconds. Press Ctrl+C to stop."
  Write-Host ('Start time: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'))
  if ($StopAfterSeconds -gt 0) { Write-Host "Automatic stop after $StopAfterSeconds seconds." }
  else { Write-Host 'Running indefinitely.' }
  $clock = [System.Diagnostics.Stopwatch]::StartNew()
  $loopParameters = @{
    KeySender = $keySender
    Clock = $clock
    IntervalSeconds = $IntervalSeconds
    StopAfterSeconds = $StopAfterSeconds
    ReportIntervalSeconds = $ReportIntervalSeconds
  }
  Invoke-CaffeineInputLoop @loopParameters
}
finally {
  if ($null -ne $clock) { $clock.Stop() }
  if ($null -ne $keySender -and [Runtime.InteropServices.Marshal]::IsComObject($keySender)) {
    try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($keySender) }
    catch { Write-Warning 'Unable to release the Caffeine COM object cleanly.' }
  }
  foreach ($property in $consoleState.Keys) {
    try { $consoleUi.$property = $consoleState[$property] }
    catch { Write-Warning "Unable to restore console property '$property'." }
  }
  if ($null -ne $clock) {
    Write-Host ('Caffeine stopped. Elapsed time: {0}.' -f $clock.Elapsed.ToString('dd\.hh\:mm\:ss'))
  }
}
