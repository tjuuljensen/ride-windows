<#
.SYNOPSIS
Run focused HashCheck acceptance in the intended disposable guest desktop session.
.DESCRIPTION
Import is read-only. Explicit coordinator calls register one temporary elevated
interactive task; worker calls run the existing RIDE guest suite. Retains context,
task cleanup and suite evidence under the correlated results directory.
.NOTES
Windows PowerShell 5.1 on disposable Windows 11 guests. Version 0.1.1.
Version 0.1.1 runs the suite in a fresh PowerShell process to keep Pester outside module scope.
Requires a signed-in administrator desktop, ScheduledTasks and Pester 5.7.1.
Recover through the host controller's pinned clean checkpoint after collection.
#>

function Get-RideInteractiveGuestContext {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  [pscustomobject]@{ Computer = $env:COMPUTERNAME; SID = $identity.User.Value; User = $identity.Name
    SessionId = (Get-Process -Id $PID).SessionId; UserInteractive = [Environment]::UserInteractive
    Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
}

function Get-RideInteractiveGuestDesktop {
  param([string]$SID)
  $sessions = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | ForEach-Object {
    $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction Stop
    if ($owner.ReturnValue -eq 0 -and $owner.Sid -eq $SID -and $_.SessionId -gt 0) { [int]$_.SessionId }
  } | Sort-Object -Unique)
  if ($sessions.Count -ne 1) { throw 'HashCheck acceptance requires exactly one signed-in desktop for the guest administrator. Prepare the guest baseline/session; no installer was started.' }
  $sessions[0]
}

function Assert-RideInteractiveGuestPaths {
  param([string]$GuestPath, [string]$ResultsPath, [string]$RunId)
  if ($RunId -notmatch '^[a-f0-9]{32}$') { throw 'Invalid interactive run ID.' }
  foreach ($path in @($GuestPath, $ResultsPath)) {
    if ($path -match '["`\r\n]' -or -not [IO.Path]::IsPathRooted($path)) { throw 'Interactive guest paths must be absolute and contain no quotes, backticks or newlines.' }
  }
  if ([IO.Path]::GetFullPath($ResultsPath).TrimEnd('\') -ine ('C:\RIDE\TestResults\' + $RunId)) { throw 'Interactive results must use the correlated guest results directory.' }
  if (-not (Test-Path -LiteralPath (Join-Path $GuestPath 'tests/integration/Invoke-RideGuestTests.ps1') -PathType Leaf)) { throw 'Staged guest suite is missing.' }
}

function Invoke-RideInteractiveGuestSuite {
  param([string]$GuestPath, [string]$ResultsPath, [string]$RunId)
  # Running Pester inside this module hides imported commands from completion and mocks.
  # The child inherits this task's desktop, user, elevation and VM marker.
  $runner = Join-Path $GuestPath 'tests/integration/Invoke-RideGuestTests.ps1'
  $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
    '-File', $runner, '-GuestPath', $GuestPath, '-ResultsPath', $ResultsPath, '-ResultRunId', $RunId,
    '-Integration', '-IntegrationSuite', 'ApplicationsBatch11')
  & (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') @arguments
  if ($LASTEXITCODE -ne 0) { throw "Interactive guest suite process exited $LASTEXITCODE; inspect interactive-output.log and summary.json." }
}

function Invoke-RideInteractiveGuestWorker {
  <#
  .SYNOPSIS
  Run the correlated HashCheck suite after verifying the scheduled-task identity.
  .DESCRIPTION
  Requires the coordinator request file and exact machine, user and desktop
  session. Refuses duplicate execution and preserves previous result files.
  .PARAMETER GuestPath
  Staged checkout containing the guest suite.
  .PARAMETER ResultsPath
  Correlated C:\RIDE\TestResults directory.
  .PARAMETER RunId
  Lowercase 32-character request ID.
  .PARAMETER ExpectedComputerName
  Guest computer name captured by the remote coordinator.
  .PARAMETER ExpectedUserSid
  Intended guest administrator SID.
  .PARAMETER ExpectedSessionId
  Exact nonzero desktop session selected by the coordinator.
  .OUTPUTS
  Suite output and retained worker/summary evidence.
  .NOTES
  Windows PowerShell 5.1, disposable Windows 11 guest, version 0.1.1.
  #>
  [CmdletBinding()]
  param([string]$GuestPath, [string]$ResultsPath, [string]$RunId,
    [string]$ExpectedComputerName, [string]$ExpectedUserSid, [int]$ExpectedSessionId)
  $ErrorActionPreference = 'Stop'
  Assert-RideInteractiveGuestPaths $GuestPath $ResultsPath $RunId
  $context = Get-RideInteractiveGuestContext
  if ($context.Computer -ine $ExpectedComputerName -or $context.SID -ne $ExpectedUserSid -or
      $ExpectedSessionId -le 0 -or $context.SessionId -ne $ExpectedSessionId -or
      -not $context.UserInteractive -or -not $context.Elevated) { throw 'Interactive worker identity, session or elevation differs; no suite was started.' }
  $request = Get-Content -LiteralPath (Join-Path $ResultsPath 'interactive-request.json') -Raw | ConvertFrom-Json
  if ($request.RunId -cne $RunId -or $request.GuestPath -ine $GuestPath -or $request.ExpectedComputerName -ine $ExpectedComputerName -or
      $request.ExpectedUserSid -ne $ExpectedUserSid -or $request.ExpectedSessionId -ne $ExpectedSessionId) { throw 'Interactive worker request correlation differs.' }
  $claim = [IO.File]::Open((Join-Path $ResultsPath 'interactive-worker.claim'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  $claim.Dispose()
  $record = [ordered]@{ RunId = $RunId; Context = $context; StartedAtUtc = [datetime]::UtcNow.ToString('o'); Status = 'Failed'; Error = $null }
  $previousMarker = $env:RIDE_TEST_GUEST
  try {
    $env:RIDE_TEST_GUEST = '1'
    Invoke-RideInteractiveGuestSuite $GuestPath $ResultsPath $RunId *> (Join-Path $ResultsPath 'interactive-output.log')
    $summary = Get-Content -LiteralPath (Join-Path $ResultsPath 'summary.json') -Raw | ConvertFrom-Json
    if ($summary.RunId -cne $RunId -or $summary.Status -ne 'Passed' -or -not $summary.ValidationPassed -or -not $summary.IntegrationPassed -or
        $summary.IntegrationSuite -ne 'ApplicationsBatch11' -or $summary.Error -or $summary.StateCollectionError) { throw 'Interactive guest suite failed; inspect summary.json.' }
    $record.Status = 'Passed'
  } catch { $record.Error = $_.Exception.Message; throw }
  finally {
    $env:RIDE_TEST_GUEST = $previousMarker
    $record['FinishedAtUtc'] = [datetime]::UtcNow.ToString('o')
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ResultsPath 'interactive-worker.json') -Encoding UTF8
  }
}

function Invoke-RideInteractiveGuestTests {
  <#
  .SYNOPSIS
  Coordinate a single temporary interactive task for HashCheck acceptance.
  .DESCRIPTION
  Requires the VM-only environment marker, elevation and one desktop belonging
  to the remote administrator. Captures identity, claims the request once, waits
  for completion and removes its own task. Never falls back to Session 0.
  .PARAMETER GuestPath
  Staged checkout; no source downloads are performed by this coordinator.
  .PARAMETER ResultsPath
  Correlated C:\RIDE\TestResults directory collected by the host controller.
  .PARAMETER RunId
  Lowercase 32-character request ID.
  .PARAMETER ExpectedComputerName
  Expected disposable guest name.
  .PARAMETER TimeoutMinutes
  Task execution limit, 1-120 minutes; default 30.
  .EXAMPLE
  Invoke-RideInteractiveGuestTests -GuestPath C:\RIDE\ride-windows -ResultsPath C:\RIDE\TestResults\0123456789abcdef0123456789abcdef -RunId 0123456789abcdef0123456789abcdef -ExpectedComputerName RIDE-Win11-Test
  .OUTPUTS
  Completion object; task and worker evidence remain in ResultsPath.
  .NOTES
  Windows PowerShell 5.1, disposable Windows 11 guest, version 0.1.1.
  Requires a signed-in guest administrator. No credentials are stored in tasks.
  #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$GuestPath, [string]$ResultsPath, [string]$RunId, [string]$ExpectedComputerName,
    [ValidateRange(1,120)][int]$TimeoutMinutes = 30)
  $ErrorActionPreference = 'Stop'
  if ($env:RIDE_TEST_GUEST -ne '1') { throw 'Use the disposable-VM host runner.' }
  Assert-RideInteractiveGuestPaths $GuestPath $ResultsPath $RunId
  $context = Get-RideInteractiveGuestContext
  if ($context.Computer -ine $ExpectedComputerName -or -not $context.Elevated) { throw 'Expected elevated disposable guest coordinator.' }
  $sessionId = Get-RideInteractiveGuestDesktop $context.SID
  if (-not $PSCmdlet.ShouldProcess($ExpectedComputerName, 'Run HashCheck lifecycle in the intended administrator desktop session')) { return }
  New-Item -ItemType Directory -Path $ResultsPath -Force | Out-Null
  $claim = [IO.File]::Open((Join-Path $ResultsPath 'interactive-dispatch.claim'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  $claim.Dispose()
  $request = [ordered]@{ RunId = $RunId; GuestPath = $GuestPath; ExpectedComputerName = $ExpectedComputerName; ExpectedUserSid = $context.SID; ExpectedSessionId = $sessionId }
  $request | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ResultsPath 'interactive-request.json') -Encoding UTF8
  $taskName = 'RIDE-InteractiveGuest-' + $RunId
  if (Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $taskName) { throw 'Interactive task already exists; inspect before recovery.' }
  $launcher = Join-Path $GuestPath 'tests/integration/Invoke-RideInteractiveGuestTests.ps1'
  if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw 'Staged interactive launcher is missing.' }
  $arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $launcher +
    '" -Worker -GuestPath "' + $GuestPath + '" -ResultsPath "' + $ResultsPath + '" -RunId ' + $RunId +
    ' -ExpectedComputerName "' + $context.Computer + '" -ExpectedUserSid ' + $context.SID + ' -ExpectedSessionId ' + $sessionId
  $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') -Argument $arguments -WorkingDirectory $GuestPath
  $principal = New-ScheduledTaskPrincipal -UserId $context.SID -LogonType Interactive -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $TimeoutMinutes) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
  $registered = $false
  $record = [ordered]@{ RunId = $RunId; TaskName = $taskName; ExpectedUserSid = $context.SID; ExpectedSessionId = $sessionId; LastTaskResult = $null; TaskRemoved = $false; Error = $null; CleanupError = $null }
  try {
    $null = Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Principal $principal -Settings $settings
    $registered = $true
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
    if ($task.Principal.LogonType -ne 'Interactive' -or $task.Principal.RunLevel -ne 'Highest') { throw 'Registered task context differs.' }
    Export-ScheduledTask -TaskName $taskName -TaskPath '\' | Set-Content -LiteralPath (Join-Path $ResultsPath 'interactive-task.xml') -Encoding UTF8
    $started = Get-Date
    Start-ScheduledTask -TaskName $taskName -TaskPath '\'
    $deadline = $started.AddMinutes($TimeoutMinutes + 1)
    do {
      Start-Sleep -Seconds 2
      $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
      $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\'
      $finished = $info.LastRunTime -ge $started.AddSeconds(-2) -and $task.State -notin @('Running','Queued')
    } while (-not $finished -and (Get-Date) -lt $deadline)
    $record.LastTaskResult = $info.LastTaskResult
    if (-not $finished) { throw 'Interactive guest task exceeded its deadline.' }
    if ($info.LastTaskResult -ne 0) { throw "Interactive guest task exited $($info.LastTaskResult); inspect worker evidence." }
    $worker = Get-Content -LiteralPath (Join-Path $ResultsPath 'interactive-worker.json') -Raw | ConvertFrom-Json
    if ($worker.RunId -cne $RunId -or $worker.Status -ne 'Passed') { throw 'Interactive worker did not report correlated success.' }
  } catch { $record.Error = $_.Exception.Message; throw }
  finally {
    if ($registered) {
      try {
        $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
        if ($task.State -in @('Running','Queued')) {
          Stop-ScheduledTask -TaskName $taskName -TaskPath '\'
          Start-Sleep -Seconds 2
          $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
        }
        if ($task.State -in @('Running','Queued')) { throw 'Temporary guest task did not stop.' }
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
        $record.TaskRemoved = -not [bool](Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $taskName)
        if (-not $record.TaskRemoved) { throw 'Temporary guest task remains registered.' }
      } catch { $record.CleanupError = $_.Exception.Message }
    }
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ResultsPath 'interactive-task.json') -Encoding UTF8
  }
  if ($record.CleanupError) { throw "Interactive task cleanup failed: $($record.CleanupError)" }
  [pscustomobject]@{ RunId = $RunId; Interactive = $true; TaskRemoved = $record.TaskRemoved; Status = 'Passed' }
}

Export-ModuleMember -Function Invoke-RideInteractiveGuestTests, Invoke-RideInteractiveGuestWorker
