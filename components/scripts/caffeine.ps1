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

param($sleep = 120) # seconds
$announcementInterval = 30 # loops - 30 (120*30) means announce once every hour

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