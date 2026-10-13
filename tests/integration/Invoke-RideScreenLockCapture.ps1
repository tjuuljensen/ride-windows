<#
.SYNOPSIS
  Sample a pinned workload in a disposable Windows guest interactive session.

.DESCRIPTION
  Validates VM identity, interactive desktop and input hashes before launching
  one manifest case. Samples baseline, startup, steady, exit-wait and post-exit
  memory, cumulative process I/O and WTS session lock flags. Buffers rows in
  memory until final export. CSV numeric values use invariant culture. Session
  flags still require independent review.
  Does not send input itself, change lock policies, stop workloads, install
  runtimes, or start tracing. Stop the workload normally in its guest window.
  Requires separate Process Monitor traces and behavioral observations.

.PARAMETER ManifestPath
  Path to manifest.json from New-RideScreenLockInputs.ps1 in the guest.
.PARAMETER CaseId
  Case ID from that manifest; completion reads the supplied manifest quietly.
.PARAMETER ConditionsPath
  Completed conditions JSON from screen-lock-conditions.example.json.
.PARAMETER OutputDirectory
  New results directory on the guest evidence volume. Existing paths are rejected.
.PARAMETER ExpectedComputerName
  Exact disposable guest computer name. Never supply the developer host name.
.PARAMETER DisposableVm
  Attest that this guest is disposable and its clean measurement checkpoint was restored.
.PARAMETER RunNumber
  Repetition number, defaults to 1; use at least 3 clean repetitions per case.
.PARAMETER BaselineSeconds
  Instrumentation-only prelaunch time, defaults to 60.
.PARAMETER StartupSeconds
  Startup phase after launch, defaults to 120.
.PARAMETER RunSeconds
  Total workload observation after launch, defaults to 4200 (includes hourly report).
.PARAMETER ExitWaitSeconds
  Time to allow manual normal exit after RunSeconds, defaults to 120.
.PARAMETER PostExitSeconds
  Observation after root exit or exit timeout, defaults to 300.
.PARAMETER SampleMilliseconds
  Requested sampling interval, defaults to 1000. Actual gaps are recorded.
.PARAMETER Version
  Print tooling version before accessing the machine or manifest.
.EXAMPLE
  .\tests\integration\Invoke-RideScreenLockCapture.ps1 -ManifestPath C:\RIDE\inputs\manifest.json -CaseId ps51-light -ConditionsPath C:\RIDE\conditions.json -ExpectedComputerName RIDE-Win11-Test -DisposableVm -OutputDirectory E:\evidence\ps51-light-1
.INPUTS
  None.
.OUTPUTS
  String. Results directory containing metadata.json, samples.csv and processes.json.
.NOTES
  Compatibility: Parser/help verified on Windows PowerShell 5.1 and PowerShell 7.
  Guest measurement behavior is pending; use only in disposable Windows VMs.
  Prerequisites: Signed-in interactive guest session, CIM, pinned inputs, conditions JSON.
  Recovery: Stop the workload normally and restore the measurement checkpoint.
  A timed-out or interrupted sampler does not terminate its workload.
  Author: RIDE-Windows maintainers. Version: 0.1.2
  Changelog: 0.1.2: Export numeric CSV values in invariant culture.
  0.1.1: Record documented WTS session lock flags alongside samples.
  0.1.0: Add guarded interactive guest footprint capture.
.LINK
  ../../docs/screen-lock-impact.md
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string] $ManifestPath,
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      if (-not $fakeBoundParameters.ManifestPath) { return }
      $data = Get-Content -LiteralPath $fakeBoundParameters.ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
      $data.Cases.Id | Sort-Object -Unique | Where-Object { $_.StartsWith($wordToComplete, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
        [Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
      }
    } catch { }
  })][string] $CaseId, [string] $ConditionsPath,
  [string] $OutputDirectory, [string] $ExpectedComputerName, [switch] $DisposableVm,
  [ValidateRange(1, 100)][int] $RunNumber = 1,
  [ValidateRange(1, 3600)][int] $BaselineSeconds = 60,
  [ValidateRange(1, 3600)][int] $StartupSeconds = 120,
  [ValidateRange(1, 86400)][int] $RunSeconds = 4200,
  [ValidateRange(1, 3600)][int] $ExitWaitSeconds = 120,
  [ValidateRange(1, 3600)][int] $PostExitSeconds = 300,
  [ValidateRange(250, 10000)][int] $SampleMilliseconds = 1000,
  [switch] $Version
)
$script:ScriptVersion = '0.1.2'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $ManifestPath -or -not $CaseId -or -not $ConditionsPath -or -not $OutputDirectory) {
  throw 'ManifestPath, CaseId, ConditionsPath and OutputDirectory are required.'
}
if ($RunSeconds -le $StartupSeconds) { throw 'RunSeconds must exceed StartupSeconds.' }
if (-not $DisposableVm -or -not $ExpectedComputerName -or $env:COMPUTERNAME -ine $ExpectedComputerName) {
  throw 'Disposable guest attestation and matching ExpectedComputerName are required. No workload was launched.'
}
if (-not [Environment]::UserInteractive -or (Get-Process -Id $PID).SessionId -eq 0) {
  throw 'Use a signed-in guest desktop, not WinRM, a service or a noninteractive job.'
}
$machine = Get-CimInstance Win32_ComputerSystem
if ($machine.Model -notmatch 'Virtual Machine|VMware|VirtualBox|KVM|QEMU') {
  throw 'A recognized virtual-machine model is required.'
}
$inputRoot = Split-Path ([IO.Path]::GetFullPath($ManifestPath)) -Parent
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($manifest.SchemaVersion -ne 1) { throw 'Unsupported input manifest schema.' }
$selected = @($manifest.Cases | Where-Object { $_.Id -ceq $CaseId })
if ($selected.Count -ne 1) { throw 'CaseId must match exactly one manifest case.' }
$case = $selected[0]
$conditions = Get-Content -LiteralPath $ConditionsPath -Raw | ConvertFrom-Json
foreach ($field in @('VmId', 'CheckpointId', 'OsTarget', 'OsBuild', 'SessionTransport', 'ConsoleHost', 'RuntimeVersions', 'AccountElevation', 'LockMechanism', 'IdleLockSeconds', 'ControlLockObservedSeconds', 'Instrumentation', 'CleanCheckpointRestoredAtUtc')) {
  if ($null -eq $conditions.$field -or [string]$conditions.$field -match '^REPLACE' -or [string]::IsNullOrWhiteSpace([string]$conditions.$field)) {
    throw "Complete conditions field: $field"
  }
}
if ([int]$conditions.IdleLockSeconds -le 0 -or [double]$conditions.ControlLockObservedSeconds -le 0) {
  throw 'Record an independently observed no-tool idle-lock control before launching a workload.'
}
$os = Get-CimInstance Win32_OperatingSystem
if ($os.Caption -notmatch 'Windows 11|Windows Server 2025' -or $os.Caption -notmatch [regex]::Escape([string]$conditions.OsTarget)) {
  throw 'Use Windows 11 first, or Windows Server 2025 with Desktop Experience; verify conditions.OsTarget.'
}
$currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$observedBuild = "$($os.BuildNumber).$($currentVersion.UBR)"
if ($conditions.OsBuild -ne $observedBuild) { throw "OS build mismatch: actual $observedBuild." }
if ($os.Caption -match 'Server' -and $currentVersion.InstallationType -ne 'Server') {
  throw 'Windows Server Desktop Experience is required.'
}
foreach ($pin in $manifest.Pins) {
  $path = [IO.Path]::GetFullPath((Join-Path $inputRoot $pin.Path))
  if (-not $path.StartsWith($inputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Pin path escapes input directory.' }
  if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $pin.Sha256) { throw "Input hash mismatch: $($pin.Path)" }
}
$executable = $null
if ($case.Executable) {
  if ($case.Executable -in @('powershell.exe', 'pwsh.exe')) {
    $executable = (Get-Command -Name $case.Executable -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
  }
  else {
    $executable = [IO.Path]::GetFullPath((Join-Path $inputRoot $case.Executable))
    if (-not $executable.StartsWith($inputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        -not @($manifest.Pins | Where-Object { $_.Path -eq $case.Executable }).Count) { throw 'Executable must be a pinned input.' }
  }
}
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputPath) { throw 'Use a new results directory.' }
$arguments = ([string]$case.Arguments).Replace('{Inputs}', $inputRoot)
if (-not $PSCmdlet.ShouldProcess("$ExpectedComputerName / $CaseId", "Launch $executable $arguments and capture guest process samples to $outputPath")) { return }

# Read-only desktop probe; no synthetic input and no policy writes.
if (-not ('RideScreenLockProbe' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RideScreenLockProbe {
  [StructLayout(LayoutKind.Sequential)] public struct LastInput { public uint cbSize; public uint dwTime; }
  [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LastInput value);
  [DllImport("user32.dll", SetLastError=true)] static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
  [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr handle);
  [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool WTSQuerySessionInformation(IntPtr server, int session, int info, out IntPtr buffer, out int bytes);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr buffer);
  public static int SessionLockFlag(int session) {
    IntPtr buffer; int bytes;
    if (!WTSQuerySessionInformation(IntPtr.Zero, session, 25, out buffer, out bytes)) return -1;
    try {
      // WTSINFOEX level 1: aligned union at byte 8, then ID/state/flags.
      // These offsets are for the supported Windows native ABI, not packed data.
      if (bytes < 20 || Marshal.ReadInt32(buffer, 0) != 1 || Marshal.ReadInt32(buffer, 8) != session) return -1;
      return Marshal.ReadInt32(buffer, 16);
    } finally { WTSFreeMemory(buffer); }
  }
  public static double IdleMilliseconds() {
    LastInput value = new LastInput(); value.cbSize = (uint)Marshal.SizeOf(value);
    if (!GetLastInputInfo(ref value)) return -1;
    return unchecked((uint)Environment.TickCount - value.dwTime);
  }
  public static bool InputDesktopAccessible() {
    IntPtr handle = OpenInputDesktop(0, false, 1);
    if (handle == IntPtr.Zero) return false;
    CloseDesktop(handle); return true;
  }
}
'@
}
if (-not [RideScreenLockProbe]::InputDesktopAccessible()) { throw 'Unlock the guest desktop before capture.' }
[void](New-Item -ItemType Directory -Path $outputPath)
$rows = [Collections.Generic.List[object]]::new()
$processes = @{}
$family = @{}
$root = $null
$launchTime = $null
$exitTime = $null
$postStart = $null
$failure = $null
$clock = [Diagnostics.Stopwatch]::StartNew()
$sessionId = (Get-Process -Id $PID).SessionId
$metadata = [ordered]@{
  SchemaVersion = 1; ToolingVersion = $script:ScriptVersion; CaseId = $CaseId; RunNumber = $RunNumber
  Status = 'Capturing'; StartedAtUtc = [datetime]::UtcNow.ToString('o'); Conditions = $conditions
  OS = @{ Caption = $os.Caption; Build = $observedBuild; Version = $os.Version; InstallationType = $currentVersion.InstallationType }
  Sampler = @{ Pid = $PID; SessionId = $sessionId; PSVersion = $PSVersionTable.PSVersion.ToString(); Is64Bit = [Environment]::Is64BitProcess; Culture = [Globalization.CultureInfo]::CurrentCulture.Name }
  CsvNumericCulture = 'InvariantCulture'
  Manifest = $manifest; Command = @{ Executable = $executable; Arguments = $arguments; WorkingDirectory = $inputRoot }
  Timing = @{ BaselineSeconds = $BaselineSeconds; StartupSeconds = $StartupSeconds; RunSeconds = $RunSeconds; ExitWaitSeconds = $ExitWaitSeconds; PostExitSeconds = $PostExitSeconds; SampleMilliseconds = $SampleMilliseconds }
  InstrumentationLimits = 'Sampled tree misses short-lived children. ConsoleCandidate is unassigned; trace association is required. Process I/O includes non-file writes. Desktop accessibility/idle time do not prove lock prevention. Buffered sampler memory is instrumentation overhead.'
}
if ($executable) {
  $metadata.Command.Sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
  $metadata.Command.FileVersion = (Get-Item -LiteralPath $executable).VersionInfo.FileVersion
}
$lastSample = 0.0
$prompted = $false
try {
  while ($true) {
    $sampleStart = $clock.Elapsed.TotalSeconds
    if ($null -eq $launchTime -and $sampleStart -ge $BaselineSeconds) {
      if ($executable) {
        $start = @{ FilePath = $executable; WorkingDirectory = $inputRoot; PassThru = $true }
        if (-not [string]::IsNullOrWhiteSpace($arguments)) { $start.ArgumentList = $arguments }
        $root = Start-Process @start
        $metadata.RootPid = $root.Id
      }
      $launchTime = $clock.Elapsed.TotalSeconds
      $metadata.LaunchOffsetSeconds = $launchTime
    }
    if ($null -ne $root -and $null -eq $exitTime -and $root.HasExited) {
      $exitTime = $clock.Elapsed.TotalSeconds
      $postStart = $exitTime
      $metadata.ExitCode = $root.ExitCode
      $metadata.RootExitOffsetSeconds = $exitTime
    }
    if ($null -ne $launchTime -and $sampleStart - $launchTime -ge $RunSeconds -and -not $prompted) {
      Write-Host 'Observation complete. Stop the workload normally in its guest window now (Ctrl+C for scripts; Exit for GUI tools).'
      $prompted = $true
      if (-not $root) { $postStart = $sampleStart }
    }
    if ($null -eq $postStart -and $null -ne $launchTime -and $sampleStart - $launchTime -ge ($RunSeconds + $ExitWaitSeconds)) {
      $metadata.Status = 'ExitTimedOut'; $postStart = $sampleStart
      Write-Warning 'Workload is still running. Post-timeout observation is not post-exit evidence. No process was terminated.'
    }
    if ($null -ne $postStart -and $sampleStart - $postStart -ge $PostExitSeconds) { break }
    $phase = if ($null -eq $launchTime) { 'Baseline' } elseif ($null -ne $postStart) {
      if ($metadata.Status -eq 'ExitTimedOut') { 'PostTimeout' } else { 'PostExit' }
    } elseif ($sampleStart - $launchTime -lt $StartupSeconds) { 'Startup' } elseif ($sampleStart - $launchTime -lt $RunSeconds) { 'Steady' } else { 'ExitWait' }
    $snapshot = @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,CreationDate,Name,SessionId,WorkingSetSize,PrivatePageCount,PeakWorkingSetSize,PageFileUsage,PeakPageFileUsage,WriteTransferCount,WriteOperationCount,ExecutablePath)
    $live = @{}
    foreach ($process in $snapshot) {
      if ($null -eq $process.CreationDate) { continue }
      $key = '{0}:{1}' -f $process.ProcessId, $process.CreationDate.ToUniversalTime().Ticks
      $live[[int]$process.ProcessId] = @{ Key = $key; Process = $process }
      if (-not $processes.ContainsKey($key)) {
        $processes[$key] = @{ Key = $key; Pid = $process.ProcessId; ParentPid = $process.ParentProcessId; Name = $process.Name; SessionId = $process.SessionId; CreatedAtUtc = $process.CreationDate.ToUniversalTime().ToString('o'); Path = $process.ExecutablePath; FirstObservedSeconds = $sampleStart }
      }
      $processes[$key].LastObservedSeconds = $sampleStart
    }
    if ($root -and $live.ContainsKey($root.Id) -and $null -eq $exitTime) { $family[$live[$root.Id].Key] = $true }
    # Iterate to include grandchildren regardless of CIM enumeration order.
    do {
      $added = $false
      foreach ($entry in $live.Values) {
        $parent = $live[[int]$entry.Process.ParentProcessId]
        if ($parent -and $family.ContainsKey($parent.Key) -and -not $family.ContainsKey($entry.Key) -and $entry.Process.CreationDate -ge $parent.Process.CreationDate) {
          $family[$entry.Key] = $true; $added = $true
        }
      }
    } while ($added)
    $idle = [RideScreenLockProbe]::IdleMilliseconds()
    $desktopAccessible = [RideScreenLockProbe]::InputDesktopAccessible()
    $sessionLockFlag = [RideScreenLockProbe]::SessionLockFlag($sessionId)
    foreach ($entry in $live.Values) {
      $process = $entry.Process
      $role = if ($process.ProcessId -eq $PID) { 'Sampler' } elseif ($family.ContainsKey($entry.Key)) { 'Workload' } elseif ($process.SessionId -eq $sessionId -and $process.Name -match '^(conhost|OpenConsole|WindowsTerminal)\.exe$') { 'ConsoleCandidate' } else { $null }
      if (-not $role) { continue }
      # Use an API with documented byte units, rather than assuming CIM
      # PrivatePageCount units from its name. Preserve the raw value separately.
      $privateBytes = $null
      $memoryError = $null
      $nativeProcess = $null
      try {
        $nativeProcess = [Diagnostics.Process]::GetProcessById([int]$process.ProcessId)
        $nativeProcess.Refresh()
        if ([Math]::Abs(($nativeProcess.StartTime.ToUniversalTime() - $process.CreationDate.ToUniversalTime()).TotalMilliseconds) -ge 1) {
          throw 'Process identity changed between discovery and memory sampling.'
        }
        $privateBytes = $nativeProcess.PrivateMemorySize64
      }
      catch { $memoryError = $_.Exception.Message }
      finally { if ($nativeProcess) { $nativeProcess.Dispose() } }
      $rows.Add([pscustomobject]@{
        Sample = $sampleStart; GapSeconds = $sampleStart - $lastSample; Utc = [datetime]::UtcNow.ToString('o'); Phase = $phase
        ProcessKey = $entry.Key; Pid = $process.ProcessId; Role = $role; Name = $process.Name
        WorkingSetBytes = $process.WorkingSetSize; PrivateBytes = $privateBytes
        PrivatePageCountRaw = $process.PrivatePageCount; MemoryReadError = $memoryError
        LifetimePeakWorkingSetBytes = [uint64]$process.PeakWorkingSetSize * 1024
        PageFileUsageBytes = [uint64]$process.PageFileUsage * 1024; LifetimePeakPageFileUsageBytes = [uint64]$process.PeakPageFileUsage * 1024
        CumulativeIoWriteBytes = $process.WriteTransferCount; CumulativeIoWriteOperations = $process.WriteOperationCount
        SessionIdleMilliseconds = $idle; InputDesktopAccessible = $desktopAccessible
        SessionLockFlag = $sessionLockFlag
      })
    }
    $lastSample = $sampleStart
    $remaining = $SampleMilliseconds - ($clock.Elapsed.TotalSeconds - $sampleStart) * 1000
    if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int]$remaining) }
  }
  if ($metadata.Status -eq 'Capturing') {
    $metadata.Status = if ($root -and $exitTime - $launchTime -lt $RunSeconds) { 'EarlyExit' } else { 'Captured' }
  }
}
catch {
  $failure = $_; $metadata.Status = 'Failed'; $metadata.Error = $_.Exception.Message
}
finally {
  $clock.Stop()
  if ($metadata.Status -eq 'Capturing') { $metadata.Status = 'Interrupted' }
  $metadata.EndedAtUtc = [datetime]::UtcNow.ToString('o')
  $metadata.TotalSeconds = $clock.Elapsed.TotalSeconds
  $metadata.BehaviorVerified = $false
  $metadata.WorkloadStillRunning = [bool]($root -and -not $root.HasExited)
  $metadata.FamilyKeys = @($family.Keys)
  $rows.ToArray() | ForEach-Object {
    $exportRow = [ordered]@{}
    foreach ($property in $_.PSObject.Properties) {
      $value = $property.Value
      if ($value -is [double] -or $value -is [single]) {
        $value = $value.ToString('R', [Globalization.CultureInfo]::InvariantCulture)
      }
      elseif ($value -is [decimal]) { $value = $value.ToString([Globalization.CultureInfo]::InvariantCulture) }
      $exportRow[$property.Name] = $value
    }
    [pscustomobject]$exportRow
  } | Export-Csv -LiteralPath (Join-Path $outputPath 'samples.csv') -NoTypeInformation -Encoding UTF8
  @($processes.Values) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputPath 'processes.json') -Encoding UTF8
  $metadata | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $outputPath 'metadata.json') -Encoding UTF8
}
if ($failure) { throw $failure }
$outputPath
