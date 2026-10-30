<#
.SYNOPSIS
  Verify the persistent current-user bin PATH setting in a disposable Windows 11 VM.
.DESCRIPTION
  Exercises preview, apply, repeat, exact saved-run restore, registry-value kind,
  and preservation of an owned sentinel file in the existing user-bin directory.
  It does not broadcast environment changes or claim that existing processes see
  the updated PATH. The outer checkpoint runner restores the guest after testing.
.PARAMETER Stage
  Prepare reports the interactive-session requirement; Run coordinates an interactive
  limited task when called over PowerShell Direct; InteractiveWorker performs the lifecycle.
.PARAMETER ExpectedComputerName
  Exact disposable guest identity supplied by the host runner.
.PARAMETER EvidencePath
  Run evidence directory under C:\RIDE\ProfileAcceptance.
.PARAMETER DisposableVm
  Required disposable-guest attestation.
.PARAMETER ExpectedUserSid
  Exact guest user SID bound by the PowerShell Direct coordinator for its interactive worker.
.PARAMETER Version
  Print the version before accessing the guest.
.EXAMPLE
  .\Invoke-RidePersistentUserPathAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  Preparation status or lifecycle evidence.
.NOTES
  Compatibility: Windows PowerShell 5.1 in a disposable Windows 11 guest.
  Prerequisites: Existing checkpoint-backed guest and permission to write the current user's HKCU Environment/Path.
  Recovery: Restore the captured RIDE run; remove only the runner-owned sentinel and empty bin fixture.
  Author: RIDE-Windows maintainers. Version: 0.2.0.
  Changelog: 0.2.0: Run lifecycle in the signed-in user session using a limited scheduled task.
    0.1.0: Add guarded Q08 persistent user PATH lifecycle acceptance.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [ValidateSet('Prepare','Run','InteractiveWorker')][string] $Stage = 'Run',
  [string] $ExpectedComputerName,
  [string] $EvidencePath,
  [string] $ExpectedUserSid,
  [switch] $DisposableVm,
  [switch] $Version
)

$script:ScriptVersion = '0.2.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or -not $ExpectedComputerName -or
    $env:COMPUTERNAME -ine $ExpectedComputerName -or
    (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine') {
  throw 'Use the attested disposable guest runner; no workstation integration is permitted.'
}
$evidence = [IO.Path]::GetFullPath($EvidencePath)
if (-not $evidence.StartsWith('C:\RIDE\ProfileAcceptance\',[StringComparison]::OrdinalIgnoreCase)) {
  throw 'Evidence must belong to this guest run.'
}
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.UserPathPreparation.psm1') -Force
if ((Get-RidePlatform) -ne 'Windows 11') { throw 'This Q08 acceptance case is limited to Windows 11.' }

$catalog = Get-RideCatalog
$operation = @($catalog.Operations | Where-Object Id -CEQ 'windows.user-bin-persistent-path')
if ($operation.Count -ne 1) { throw 'Expected one Q08 persistent user PATH operation.' }
$operation = $operation[0]
if ('Windows 11' -notin @($operation.CandidateTargets)) { throw 'Windows 11 must be a declared candidate.' }
if ($Stage -eq 'Prepare') {
  [pscustomobject]@{ RebootRequired = $false; Target = 'Windows 11'; OperationId = $operation.Id; InteractiveUserRequired = $true }
  return
}
if ($Stage -eq 'Run' -and -not [Environment]::UserInteractive) {
  if (-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Run Q08 acceptance in the signed-in guest user session and recover the pinned checkpoint')) { return }
  $coordinatorIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { $coordinatorSid = $coordinatorIdentity.User.Value; $coordinatorName = $coordinatorIdentity.Name }
  finally { $coordinatorIdentity.Dispose() }
  $loggedOnUser = (Get-CimInstance Win32_ComputerSystem).UserName
  if ([string]::IsNullOrWhiteSpace($loggedOnUser) -or $loggedOnUser -ine $coordinatorName) {
    throw 'Q08 requires the PowerShell Direct credential to match the currently signed-in guest user.'
  }
  $taskName = 'RIDE-Q08-' + [guid]::NewGuid().ToString('N')
  $null = New-Item -ItemType Directory -Path $evidence -Force
  $workerLog = Join-Path $evidence ($taskName + '.log')
  $resultPath = Join-Path $evidence 'persistent-user-path.json'
  $quote = { param([string]$Value) "'" + $Value.Replace("'", "''") + "'" }
  $command = '$env:RIDE_INTEGRATION_VM=''1''; & ' + (& $quote $PSCommandPath) + ' -Stage InteractiveWorker -ExpectedComputerName ' + (& $quote $ExpectedComputerName) + ' -EvidencePath ' + (& $quote $evidence) + ' -ExpectedUserSid ' + (& $quote $coordinatorSid) + ' -DisposableVm -Confirm:$false *> ' + (& $quote $workerLog)
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
  $action = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe') -Argument ('-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
  $principal = New-ScheduledTaskPrincipal -UserId $coordinatorName -LogonType Interactive -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  try {
    $task = Register-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -Action $action -Principal $principal -Settings $settings -ErrorAction Stop
    Start-ScheduledTask -InputObject $task
    $deadline = [datetime]::UtcNow.AddMinutes(10)
    while (-not (Test-Path -LiteralPath $resultPath) -and [datetime]::UtcNow -lt $deadline) {
      $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\RIDE\' -ErrorAction Stop
      $state = (Get-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -ErrorAction Stop).State
      if ($info.LastRunTime.Year -gt 2000 -and $state -notin @('Running','Queued') -and $info.LastTaskResult -ne 267009) { throw "Interactive Q08 worker exited without evidence (0x$('{0:X}' -f $info.LastTaskResult)); see $workerLog." }
      Start-Sleep -Seconds 1
    }
    if (-not (Test-Path -LiteralPath $resultPath)) { throw "Interactive Q08 worker timed out; inspect $workerLog before checkpoint recovery." }
    $workerResult = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ($workerResult.Status -ne 'Passed') { throw ('Interactive Q08 worker failed: ' + $workerResult.Error + '; ' + (@($workerResult.CleanupErrors) -join '; ')) }
    return $workerResult
  } finally {
    if (Get-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -ErrorAction SilentlyContinue) {
      Stop-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -ErrorAction SilentlyContinue
      Unregister-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -Confirm:$false -ErrorAction SilentlyContinue
    }
  }
}
if ($Stage -eq 'InteractiveWorker') {
  $workerIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { $workerSid = $workerIdentity.User.Value }
  finally { $workerIdentity.Dispose() }
  if (-not [Environment]::UserInteractive -or (Get-Process -Id $PID).SessionId -eq 0 -or $workerSid -cne $ExpectedUserSid) {
    throw 'Q08 worker must run interactively in the exact user session authorized by its coordinator.'
  }
} elseif (-not [Environment]::UserInteractive) {
  throw 'Q08 direct execution requires an interactive native user session.'
}
if (-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Verify Q08 persistent user PATH lifecycle and recovery')) { return }

$operation.SupportedTargets = @('Windows 11')
$operation.PendingAcceptance = $false
& (Get-Module RIDE.Engine) {
  param($Catalog)
  $script:RideLibraryContext = @{ Catalog = $Catalog; Libraries = @(); ProfileFiles = @() }
} $catalog
$operation = Get-RideOperation -Id 'windows.user-bin-persistent-path'
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$profileBin = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'bin'
$binCreatedByRunner = $false
$sentinel = Join-Path $profileBin ('ride-q08-' + [guid]::NewGuid().ToString('N') + '.tmp')
$sentinelContent = 'RIDE Q08 acceptance fixture; owned by this run.'
$runIds = [Collections.Generic.List[string]]::new()
$rows = [Collections.Generic.List[object]]::new()
$original = $null
$failure = $null

function Assert-Q08([bool] $Condition,[string] $Message) {
  if (-not $Condition) { throw $Message }
}
function Get-Q08PathValue($CurrentState) {
  if (-not $CurrentState.Available -or -not $CurrentState.Observation) { throw "The intended user's persistent PATH is unavailable." }
  $CurrentState.Observation.Path
}
function Test-Q08PathEqual($Left,$Right) {
  return ($Left.KeyExists -eq $Right.KeyExists -and $Left.Exists -eq $Right.Exists -and
    $Left.Kind -ceq $Right.Kind -and $Left.Value -ceq $Right.Value)
}
function Invoke-Q08Enabled {
  $plan = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Enabled)
  try { $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false) }
  catch {
    if ($_.Exception.Message -match 'Run ID: ([0-9a-f]{32})') { $runIds.Add($Matches[1]) }
    throw
  }
  $run = @($output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' })
  if ($run.Count -ne 1) { throw 'Expected one recoverable saved run for Q08.' }
  $id = $run[0] -replace '^Run ID: ',''
  $runIds.Add($id)
  return $id
}

try {
  if (-not (Test-Path -LiteralPath $profileBin -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $profileBin
    $binCreatedByRunner = $true
  }
  [IO.File]::WriteAllText($sentinel,$sentinelContent)
  $original = Get-RideCurrentState -Operation $operation
  Assert-Q08 ($original.Available -and $original.Observation.Context.UserSid -ceq $owner) 'PATH observation did not resolve to the current intended user.'
  $originalPath = Get-Q08PathValue $original
  Assert-Q08 ($original.Observation.Context.UserProfile -ieq (Split-Path -Parent $profileBin)) 'PATH observation does not match the current profile directory.'
  $patch = New-RideUserBinPathPatch -Observation $original.Observation
  Assert-Q08 $patch.ChangeRequired 'The user PATH already contains an equivalent bin entry; this run cannot verify adding an owned entry.'
  $plan = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Enabled)
  $null = Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false
  Assert-Q08 (Test-Q08PathEqual (Get-Q08PathValue (Get-RideCurrentState -Operation $operation)) $originalPath) 'Preview changed the persistent user PATH.'
  $originalProcessPath = $env:Path
  $installRun = Invoke-Q08Enabled
  Assert-Q08 ('No changes were needed; no state record was created.' -in @(Invoke-RidePlan -Plan $plan -Confirm:$false)) 'Repeat apply was not a no-op.'
  $enabled = Get-RideCurrentState -Operation $operation
  $enabledPath = Get-Q08PathValue $enabled
  Assert-Q08 (Test-RideDesiredState -Operation $operation -State Enabled) 'The engine does not report the requested persistent user PATH state.'
  Assert-Q08 (Test-Q08PathEqual $enabledPath $patch.DesiredValue) 'Enabled state differs from the prepared literal user PATH value.'
  Assert-Q08 (-not (New-RideUserBinPathPatch -Observation $enabled.Observation).ChangeRequired) 'Enabled state does not contain exactly one equivalent bin entry.'
  Assert-Q08 ($enabledPath.Kind -ceq $originalPath.Kind) 'Apply changed the registry value kind.'
  Assert-Q08 ($env:Path -ceq $originalProcessPath) 'Apply changed the current process PATH.'
  Assert-Q08 ([IO.File]::ReadAllText($sentinel) -ceq $sentinelContent) 'Apply changed the runner-owned bin sentinel.'
  Restore-RideRun -RunId $installRun -Confirm:$false | Out-Null
  $null = $runIds.Remove($installRun)
  $restoredPath = Get-Q08PathValue (Get-RideCurrentState -Operation $operation)
  Assert-Q08 (Test-Q08PathEqual $restoredPath $originalPath) 'Saved-run recovery did not restore the exact prior registry PATH state.'
  Assert-Q08 ([IO.File]::ReadAllText($sentinel) -ceq $sentinelContent) 'Recovery changed the runner-owned bin sentinel.'
  Assert-Q08 ($env:Path -ceq $originalProcessPath) 'Recovery changed the current process PATH.'
  $rows.Add([pscustomobject]@{
    Operation = $operation.Id
    OwnerVerified = $true
    RegistryKindPreserved = $true
    PreviewNoWrite = $true
    RepeatApplyNoOp = $true
    ExactSavedRunRestore = $true
    BinDirectoryCreatedByRunner = $binCreatedByRunner
    SentinelPreserved = $true
    ProcessPathChanged = $false
    EnvironmentBroadcastPerformed = $false
    EffectivePathVerified = $false
    Status = 'Passed'
  })
} catch {
  $failure = $_.Exception.Message
  throw
} finally {
  $restoreErrors = [Collections.Generic.List[string]]::new()
  for ($i = $runIds.Count - 1; $i -ge 0; $i--) {
    try { Restore-RideRun -RunId $runIds[$i] -Confirm:$false | Out-Null }
    catch { $restoreErrors.Add($_.Exception.Message) }
  }
  if ([IO.File]::Exists($sentinel)) {
    try {
      if ([IO.File]::ReadAllText($sentinel) -ceq $sentinelContent) { Remove-Item -LiteralPath $sentinel }
      else { $restoreErrors.Add('Runner sentinel content changed; it was preserved for inspection.') }
    } catch { $restoreErrors.Add($_.Exception.Message) }
  }
  if ($binCreatedByRunner -and (Test-Path -LiteralPath $profileBin -PathType Container)) {
    try {
      if (@(Get-ChildItem -LiteralPath $profileBin -Force).Count -eq 0) { Remove-Item -LiteralPath $profileBin }
      else { $restoreErrors.Add('Runner-created bin directory is not empty; it was preserved for inspection.') }
    } catch { $restoreErrors.Add($_.Exception.Message) }
  }
  if ($null -ne $original) {
    try {
      $finalPath = Get-Q08PathValue (Get-RideCurrentState -Operation $operation)
      if (-not (Test-Q08PathEqual $finalPath $originalPath)) { $restoreErrors.Add('Final PATH differs from its captured state.') }
    } catch { $restoreErrors.Add($_.Exception.Message) }
  }
  $result = [pscustomobject]@{
    SchemaVersion = 1
    Scenario = 'Q08PersistentUserPath'
    Target = 'Windows 11'
    OwnerVerified = [bool]($null -ne $original)
    Status = if ($failure -or $restoreErrors.Count) { 'Failed' } else { 'Passed' }
    Error = $failure
    CleanupErrors = @($restoreErrors)
    EnvironmentBroadcastPerformed = $false
    EffectivePathVerified = $false
    Operations = @($rows)
  }
  $null = New-Item -ItemType Directory -Path $evidence -Force
  $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $evidence 'persistent-user-path.json') -Encoding UTF8
}

$result
if ($result.Status -ne 'Passed') { throw ('Q08 acceptance failed; inspect persistent-user-path.json: ' + ($result.CleanupErrors -join '; ')) }
