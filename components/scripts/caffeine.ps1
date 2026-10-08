<#
.SYNOPSIS
  Keep an interactive Windows session awake by sending Scroll Lock key pairs.

.DESCRIPTION
  Configures console colors and size, creates WScript.Shell, then loops sending paired Scroll Lock
  keys with a configurable sleep interval. Prints elapsed time periodically when a stopwatch is
  available. Ctrl+C stops the loop. Help and Version return before console or COM changes.

.PARAMETER sleep
  Seconds between key pairs; defaults to 120, range 1-2147483647.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\components\scripts\caffeine.ps1 -Help

.EXAMPLE
  .\components\scripts\caffeine.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Initial status; ongoing status uses the host. Changes console appearance/key state.

.NOTES
  Compatibility: Interactive Windows console with WScript.Shell COM support; not validated as a
  background service or noninteractive job.
  Prerequisites: Interactive console with writable RawUI window/buffer properties and WScript.Shell.
  File/environment inputs: Current console and desktop key state; no files or credentials are used.
  Recovery: Ctrl+C stops execution; reopen the console to restore its default appearance.
  Error-handling exception: Existing operational error policy is retained; globally enabling Stop
  requires a separate tested change.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.
  2026-10-08: Move the previously misplaced sleep declaration into the script parameter block; leave
  the keep-awake loop unchanged.

#>


[CmdletBinding()]
param(
  [ValidateRange(1, 2147483647)][int] $sleep = 120,
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

Clear-Host
Write-Output "Keep-alive with Scroll Lock..."

$Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Magenta')
$Host.UI.RawUI.ForegroundColor = 'White'
$Host.PrivateData.ErrorForegroundColor = 'Red'
$Host.PrivateData.ErrorBackgroundColor = $bckgrnd
$Host.PrivateData.WarningForegroundColor = 'Magenta'
$Host.PrivateData.WarningBackgroundColor = $bckgrnd
$Host.PrivateData.DebugForegroundColor = 'Yellow'
$Host.PrivateData.DebugBackgroundColor = $bckgrnd
$Host.PrivateData.VerboseForegroundColor = 'Green'
$Host.PrivateData.VerboseBackgroundColor = $bckgrnd
$Host.PrivateData.ProgressForegroundColor = 'Cyan'
$Host.PrivateData.ProgressBackgroundColor = $bckgrnd

$Shell = $Host.UI.RawUI
$size = $Shell.WindowSize
$size.width=50
$size.height=24
$Shell.WindowSize = $size
$size = $Shell.BufferSize
$size.width=50
$size.height=3000
$Shell.BufferSize = $size
$WShell = New-Object -com "Wscript.Shell"

$host.ui.RawUI.WindowTitle = "Caffeine (nosleep)"

#
# -- NoSleep --
# Keep your computer awake by programmatically pressing the ScrollLock key every X seconds
#

# The interval is declared in the script parameter block above.
$announcementInterval = 30 # At the default 120-second interval, 30 loops means once per hour.

Clear-Host

$WShell = New-Object -com "Wscript.Shell"

$stopwatch
# Some environments don't support invocation of this method.
try {
    $stopwatch = [system.diagnostics.stopwatch]::StartNew()
} catch {
   Write-Host "Couldn't start the stopwatch."
}

Write-Host "Running caffeine... (nosleep)"
Write-Host "Start time:" $(Get-Date -Format "dddd MM/dd HH:mm (K)")

$index = 0
while ( $true )
{
    $WShell.sendkeys("{SCROLLLOCK}")

    Start-Sleep -Milliseconds 200

    $WShell.sendkeys("{SCROLLLOCK}")

    Start-Sleep -Seconds $sleep

    # Announce runtime on an interval
    if ( $stopwatch.IsRunning -and (++$index % $announcementInterval) -eq 0 )
    {
        Write-Host "Elapsed time: " $stopwatch.Elapsed.ToString('dd\.hh\:mm\:ss')
    }
}
