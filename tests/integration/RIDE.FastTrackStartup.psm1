<#
.SYNOPSIS
  Observe bounded startup of an exact executable in an attested disposable guest.
.DESCRIPTION
  No arguments, account configuration or product actions are supplied. Reports
  process exit, visible error title and correlated Application error events.
  Noninteractive observation is not interactive UI or feature acceptance.
.NOTES
  Windows PowerShell 5.1 / PowerShell 7 on Windows. Version: 0.2.0.
  Changelog: Select System Information's primary applications separately from GetSys helpers.
  Requires RIDE_INTEGRATION_VM=1 from the existing identity-checked guest runner.
  Closes only the process it started; checkpoint recovery remains host-owned.
#>
function Get-RideFastTrackStartupSelection {
  <#
  .SYNOPSIS
    Select installed MiTeC application entry points without executing files.
  .PARAMETER PackageId
    Exact MiTeC package ID from the fixed acceptance scenario.
  .PARAMETER Files
    Verified owned-file manifest containing relative paths and SHA-256 digests.
  .OUTPUTS
    Executables selected for startup and helpers whose execution remains deferred.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$PackageId,[Parameter(Mandatory)][object[]]$Files)
  $executables=@($Files|Where-Object {$_.RelativePath -match '(?i)\.exe$'})
  $deferred=@();$reason=$null
  if($PackageId -ceq 'package.mitec-system-information'){
    $expected=@('MSIX.exe','MSIX64.exe','GetSys.exe','GetSys64.exe')
    if($executables.Count -ne 4 -or @($executables.RelativePath|Sort-Object -Unique).Count -ne 4 -or @($executables|Where-Object {$_.RelativePath -cnotin $expected}).Count){throw 'System Information startup requires the exact four reviewed executable members.'}
    $deferred=@($executables|Where-Object {$_.RelativePath -cin @('GetSys.exe','GetSys64.exe')})
    $executables=@(foreach($name in @('MSIX64.exe','MSIX.exe')){$executables|Where-Object RelativePath -CEQ $name})
    $reason='GetSys helper execution and report behavior are outside primary-application startup acceptance; deferred to v3.1.'
  }
  if(-not $executables.Count){throw 'No selected executable exists for the fast-track startup check.'}
  [pscustomobject]@{Executables=$executables;DeferredExecutables=$deferred;DeferredReason=$reason}
}

function Invoke-RideFastTrackStartup {
  <#
  .SYNOPSIS
    Start a hash-verified executable and collect a bounded startup observation.
  .PARAMETER ExecutablePath
    Exact installed executable selected by the acceptance scenario.
  .PARAMETER ExpectedSha256
    Reviewed installed executable digest, not the installer digest.
  .PARAMETER ObservationSeconds
    Bounded startup observation, between 5 and 30 seconds.
  .OUTPUTS
    Startup evidence. Throws on observed errors; never proves product features.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ExecutablePath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [ValidateRange(5,30)][int]$ObservationSeconds=8)
  $ErrorActionPreference='Stop'
  if($env:RIDE_INTEGRATION_VM -cne '1'){throw 'Startup acceptance requires an attested disposable guest.'}
  $file=Get-Item -LiteralPath $ExecutablePath -ErrorAction Stop
  if($file.PSIsContainer -or $file.Extension -ine '.exe' -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'An exact ordinary executable file is required.'}
  if((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ine $ExpectedSha256){throw 'Startup executable digest differs.'}
  $started=Get-Date
  $process=$null
  $record=[ordered]@{Status='Failed';Executable=$file.FullName;Sha256=$ExpectedSha256;StartedAtUtc=$started.ToUniversalTime().ToString('o');ObservationSeconds=$ObservationSeconds;ExitCode=$null;WindowTitle=$null;ProcessId=$null;SessionId=$null;Closure=$null;ErrorEvents=@();Boundary='Bounded process startup; no feature or interactive UI acceptance'}
  try {
    $process=Start-Process -FilePath $file.FullName -WorkingDirectory $file.DirectoryName -PassThru
    $record.ProcessId=$process.Id;$record.SessionId=$process.SessionId
    $deadline=[datetime]::UtcNow.AddSeconds($ObservationSeconds)
    do {
      $process.Refresh()
      if($process.HasExited){$record.ExitCode=$process.ExitCode;if($process.ExitCode -ne 0){throw "Startup exited with code $($process.ExitCode)."};break}
      $record.WindowTitle=$process.MainWindowTitle
      if($process.MainWindowTitle -match '(?i)\b(error|exception|application failed)\b'){throw 'Startup exposed an error window title.'}
      if($process.MainWindowHandle -ne [intptr]::Zero -and -not $process.Responding){throw 'Startup window was not responding.'}
      Start-Sleep -Milliseconds 250
    } while([datetime]::UtcNow -lt $deadline)
    # NoMatchingEventsFound is an expected empty observation; other provider
    # failures must not be silently converted into a clean startup result.
    $eventErrors=@()
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$started;Id=@(1000,1001,1026,33)} -ErrorAction SilentlyContinue -ErrorVariable eventErrors)
    if(@($eventErrors|Where-Object FullyQualifiedErrorId -NotLike 'NoMatchingEventsFound*').Count){throw 'Application error-event observation failed.'}
    $record.ErrorEvents=@($events|Where-Object {$_.Message -match [regex]::Escape($file.Name)}|Select-Object Id,ProviderName,TimeCreated,Message)
    if($record.ErrorEvents.Count){throw 'Application error events reference the startup executable.'}
    $record.Status='NoErrorObserved'
  } catch {
    $record.Error=$_.Exception.Message
    $_.Exception.Data['RideStartupEvidence']=$record
    throw
  } finally {
    if($process){
      $process.Refresh()
      if($process.HasExited){$record.Closure='Exited'}else{
        $closed=$process.CloseMainWindow()
        if($closed -and $process.WaitForExit(5000)){$record.Closure='ClosedWindow'}else{
          $process.Kill()
          if(-not $process.WaitForExit(5000)){throw 'Started process did not stop; retain guest for recovery.'}
          $record.Closure='StoppedOwnedProcess'
        }
      }
      $process.Dispose()
    }
  }
  [pscustomobject]$record
}
Export-ModuleMember -Function Invoke-RideFastTrackStartup,Get-RideFastTrackStartupSelection
