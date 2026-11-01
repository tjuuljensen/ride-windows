<#
.SYNOPSIS
  Exercise a request-bound hibernation candidate in a disposable Hyper-V guest.
.DESCRIPTION
  Called only by Invoke-RideSettingsFixture after private catalog preparation.
  Tests three starting configurations against six choices, previews, repeat
  application, saved recovery and an interruption after a native size reset.
  Never requests sleep, shutdown or reboot. Evidence covers configuration only.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Elevated Windows 11 Hyper-V guest, correlated fixture markers,
  private engine and a host-managed clean checkpoint. Not a workstation runner.
  Recovery: Saved runs unwind in reverse order; the host checkpoint is required
  independently. Failed recovery keeps evidence and the private candidate copy.
  Version: 0.1.0.
  Changelog: 0.1.0: Add native hibernation configuration acceptance matrix.
.LINK
  ../../docs/hibernation.md
#>
$script:ModuleVersion = '0.1.0'
$ErrorActionPreference = 'Stop'

function Assert-RideHibernationAcceptanceGuest {
  param($Operation, [string] $PrivateRoot, [string] $RunId)
  if ($env:RIDE_TEST_GUEST -ne '1' -or $env:RIDE_INTEGRATION_VM -ne '1' -or
      $RunId -notmatch '^[0-9a-f]{32}$' -or $RunId -cne $env:RIDE_TEST_RUN_ID) {
    throw 'Hibernation acceptance requires correlated disposable guest markers.'
  }
  $expected = [IO.Path]::GetFullPath((Join-Path $env:TEMP ('RIDE-settings-fixture-' + $RunId)))
  $engine = Get-Module RIDE.Engine
  if ([IO.Path]::GetFullPath($PrivateRoot) -ine $expected -or -not $engine -or
      $engine.Path -ine (Join-Path $expected 'modules/RIDE.Engine.psm1')) {
    throw 'Hibernation acceptance requires the retained private candidate engine.'
  }
  if ($Operation.Id -cne 'windows.hibernation' -or $Operation.Kind -cne 'Hibernation' -or
      $Operation.Rollback -cne 'Conditional' -or -not $Operation.PendingAcceptance -or
      (@($Operation.SupportedTargets) -join ',') -cne 'Windows 11' -or
      (Get-RidePlatform) -ne 'Windows 11' -or -not (& $engine { Test-RideAdministrator })) {
    throw 'Hibernation acceptance requires the elevated Windows 11 candidate context.'
  }
  $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  if ($computer.Manufacturer -ne 'Microsoft Corporation' -or $computer.Model -ne 'Virtual Machine') {
    throw 'Hibernation acceptance refuses a non-Hyper-V guest.'
  }
}

function ConvertTo-HibernationAcceptanceConfiguration {
  param($Current)
  # File bytes and S4 availability are observations, not restorable configuration.
  # Off deliberately excludes dormant size values, matching Conditional recovery.
  $o = $Current.Observation
  [ordered]@{ Mode = $o.Mode; SizePercent = $(if ($o.Mode -eq 'Off') { $null } else { $o.SizePercent }) } | ConvertTo-Json -Compress
}

function Invoke-HibernationReadOnlyPowercfg {
  param([ValidateSet('/a', '/getactivescheme')][string] $Argument)
  $previous = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = @(& (Join-Path $env:SystemRoot 'System32/powercfg.exe') $Argument 2>&1)
    $code = $LASTEXITCODE
  } finally { $ErrorActionPreference = $previous }
  $text = $output -join [Environment]::NewLine
  if ($code -ne 0 -or $text.Length -gt 65536) { throw 'Read-only powercfg observation failed or exceeded its bound.' }
  $text
}

function Get-HibernationAcceptancePreferences {
  $values = @(
    @{ Path = 'SYSTEM\CurrentControlSet\Control\Session Manager\Power'; Name = 'HiberbootEnabled' },
    @{ Path = 'SYSTEM\CurrentControlSet\Control\Session Manager\Power'; Name = 'HibernateEnabled' },
    @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings'; Name = 'ShowHibernateOption' },
    @{ Path = 'SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'HiberbootEnabled' }
  )
  $records = foreach ($value in $values) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($value.Path, $false)
    try {
      $exists = $null -ne $key -and $value.Name -in $key.GetValueNames()
      [ordered]@{ Path = $value.Path; Name = $value.Name; KeyExists = ($null -ne $key); Exists = $exists
        Kind = $(if ($exists) { $key.GetValueKind($value.Name).ToString() } else { $null })
        Value = $(if ($exists) { $key.GetValue($value.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }) }
    } finally { if ($key) { $key.Dispose() } }
  }
  [ordered]@{ Registry = @($records); ActiveScheme = Invoke-HibernationReadOnlyPowercfg '/getactivescheme' } | ConvertTo-Json -Depth 8 -Compress
}

function Get-HibernationAcceptancePlatform {
  $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  if ($env:SystemDrive -notmatch '^[A-Za-z]:$') { throw 'Unrecognized system drive.' }
  $drive = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) -ErrorAction Stop
  if (-not $drive -or $computer.TotalPhysicalMemory -le 0) { throw 'Cannot establish RAM and system-drive capacity.' }
  [ordered]@{ WindowsVersion = $os.Version; Build = $os.BuildNumber; Caption = $os.Caption
    PowerShell = $PSVersionTable.PSVersion.ToString(); PhysicalMemoryBytes = [long]$computer.TotalPhysicalMemory
    SystemDrive = $env:SystemDrive; FreeBytes = [long]$drive.FreeSpace }
}

function Get-HibernationAcceptanceStateRoot { & (Get-Module RIDE.Engine) { Get-RideStateRoot -Scope Machine } }

function Get-HibernationAcceptanceRuns {
  $root = Get-HibernationAcceptanceStateRoot
  if (-not (Test-Path -LiteralPath $root)) { return }
  Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop | Where-Object Name -Match '^[0-9a-f]{32}$' | Sort-Object Name | ForEach-Object Name
}

function Assert-HibernationAcceptanceSnapshot {
  param([string] $RunId, $Before)
  $path = Join-Path (Get-HibernationAcceptanceStateRoot) ($RunId + '/windows.hibernation.json')
  $record = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
  if ($record.OperationId -cne 'windows.hibernation' -or $record.Snapshot.SnapshotVersion -ne 1 -or
      $record.Snapshot.OperationId -cne 'windows.hibernation' -or
      (ConvertTo-HibernationAcceptanceConfiguration @{ Observation = $record.Snapshot.Prior }) -cne
      (ConvertTo-HibernationAcceptanceConfiguration $Before)) { throw 'Saved hibernation predecessor does not match the actual pre-change configuration.' }
}

function Start-HibernationAcceptanceTrace {
  param([string] $PrivateRoot)
  $engine = Get-Module RIDE.Engine
  $handler = & $engine { (Get-Command Set-RideHibernationState -ErrorAction Stop).Module }
  if (-not $handler -or $handler.Path -ine (Join-Path $PrivateRoot 'modules/RIDE-Hibernation.psm1')) {
    throw 'Cannot bind native tracing to the private hibernation handler.'
  }
  & $handler {
    if (Get-Variable HibernationFixtureOriginal -Scope Script -ErrorAction SilentlyContinue) { throw 'A hibernation interceptor is already installed.' }
    $script:HibernationFixtureOriginal = (Get-Command Invoke-RideHibernationCommand -CommandType Function).ScriptBlock
    $script:HibernationFixtureCalls = [Collections.Generic.List[object]]::new()
    $script:HibernationFixtureInterrupt = $false
    function script:Invoke-RideHibernationCommand {
      param([string[]] $Arguments)
      if ($script:HibernationFixtureCalls.Count -ge 1000) { throw 'Native hibernation acceptance command bound exceeded.' }
      $event = [ordered]@{ Arguments = @($Arguments); NativeCompleted = $false; InjectedInterruption = $false; Error = $null }
      $script:HibernationFixtureCalls.Add($event)
      try {
        & $script:HibernationFixtureOriginal -Arguments $Arguments
        $event.NativeCompleted = $true
      } catch { $event.Error = $_.Exception.Message; throw }
      if ($script:HibernationFixtureInterrupt -and ($Arguments -join ' ') -ceq '/hibernate /size 0') {
        $script:HibernationFixtureInterrupt = $false
        $event.InjectedInterruption = $true
        throw 'RIDE hibernation fixture interruption after successful native size reset.'
      }
    }
  }
  $handler
}

function Get-HibernationAcceptanceTrace { param($Handler) & $Handler { $script:HibernationFixtureCalls.ToArray() } }
function Set-HibernationAcceptanceInterruption { param($Handler, [bool] $Enabled) & $Handler { param($Value) $script:HibernationFixtureInterrupt = $Value } $Enabled }
function Stop-HibernationAcceptanceTrace {
  param($Handler)
  & $Handler {
    Set-Item Function:script:Invoke-RideHibernationCommand -Value $script:HibernationFixtureOriginal
    Remove-Variable HibernationFixtureOriginal,HibernationFixtureCalls,HibernationFixtureInterrupt -Scope Script
  }
}

function Invoke-RideHibernationAcceptance {
  <#
  .SYNOPSIS
    Run the fixed 18-case configuration matrix and controlled failure recovery.
  .PARAMETER Operation
    Single private Windows 11 hibernation candidate.
  .PARAMETER PrivateRoot
    Request-owned temporary source copy prepared by Invoke-RideSettingsFixture.
  .PARAMETER Report
    Shared ordered evidence dictionary, including the correlated RunId.
  .PARAMETER EvidencePath
    Explicit output path supplied by the guest runner.
  .OUTPUTS
    None. Updates Report and persists progress; failures throw after recovery.
  .NOTES
    This proves only configuration lifecycle. PowerTransitionPassed and
    PromotionReady remain false, including when all configuration cases pass.
  #>
  [CmdletBinding()]
  param([hashtable] $Operation, [string] $PrivateRoot,
    [System.Collections.IDictionary] $Report, [string] $EvidencePath)
  Assert-RideHibernationAcceptanceGuest $Operation $PrivateRoot $Report.RunId
  $Report['AcceptanceScope'] = 'HibernationFileConfigurationOnly'
  $Report['RecoveryMode'] = 'ConditionalConfiguration'
  $Report['PowerTransitionPassed'] = $false
  $Report['PromotionReady'] = $false
  $Report['Cases'] = @()
  $Report['ControlledFailure'] = $null
  $Report['PendingEvidence'] = @('Actual hibernate/resume, hybrid sleep and Fast Startup', 'Native access denial and disk exhaustion; no destructive resource fault is induced', 'Target defaults, managed precedence and other Windows builds', 'Server support is not declared')
  $Report['SourceHashes'] = @('modules/RIDE-Hibernation.psm1','modules/RIDE.Engine.psm1' | ForEach-Object {
    [ordered]@{ Path = $_; SHA256 = (Get-FileHash -LiteralPath (Join-Path $PrivateRoot $_) -Algorithm SHA256).Hash }
  })
  $pending = [Collections.Generic.List[object]]::new()
  $handler = $null; $original = $null; $preferences = $null; $failure = $null
  function Save-Evidence { $Report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8 }
  function Read-State { Get-RideCurrentState -Operation $Operation }
  function Assert-Preferences {
    if ((Get-HibernationAcceptancePreferences) -cne $preferences) { throw 'Independent Fast Startup/menu/mirror/policy preferences or the active scheme changed.' }
  }
  function Apply-State([string] $State) {
    $before = Read-State
    $id = $null; $applyError = $null
    try {
      $output = @(Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $Operation.Id -Action Set -State $State) -Confirm:$false)
      foreach ($line in $output) { if ($line -is [string] -and $line -match '^Run ID: ([0-9a-f]{32})$') { $id = $Matches[1] } }
    } catch {
      $applyError = $_
      if ($_.Exception.Message -match 'Run ID: ([0-9a-f]{32})') { $id = $Matches[1] }
    }
    if ($id) {
      $pending.Add([pscustomobject]@{ RunId = $id; Before = $before })
      $Report.SavedRunIds += $id
      Save-Evidence
      Assert-HibernationAcceptanceSnapshot $id $before
    }
    if ($applyError) { throw $applyError }
    if (-not $id -and (ConvertTo-HibernationAcceptanceConfiguration (Read-State)) -cne (ConvertTo-HibernationAcceptanceConfiguration $before)) {
      throw 'A hibernation change returned no saved recovery run.'
    }
    $id
  }
  function Assert-Preview([string] $State, [string] $RestoreId) {
    $before = ConvertTo-HibernationAcceptanceConfiguration (Read-State)
    $calls = @(Get-HibernationAcceptanceTrace $handler).Count
    $runs = @(Get-HibernationAcceptanceRuns) -join ','
    if ($RestoreId) { $null = Restore-RideRun -RunId $RestoreId -WhatIf -Confirm:$false }
    else { $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $Operation.Id -Action Set -State $State) -WhatIf -Confirm:$false }
    if ($before -cne (ConvertTo-HibernationAcceptanceConfiguration (Read-State)) -or
        $calls -ne @(Get-HibernationAcceptanceTrace $handler).Count -or $runs -cne (@(Get-HibernationAcceptanceRuns) -join ',')) {
      throw 'Hibernation preview changed configuration, invoked a native command or created a run.'
    }
    Assert-Preferences
  }
  function Restore-Last {
    $entry = $pending[$pending.Count - 1]
    Assert-Preview -RestoreId $entry.RunId
    $null = Restore-RideRun -RunId $entry.RunId -Confirm:$false
    if ((ConvertTo-HibernationAcceptanceConfiguration (Read-State)) -cne (ConvertTo-HibernationAcceptanceConfiguration $entry.Before)) {
      throw 'Saved hibernation recovery did not restore its captured active configuration.'
    }
    $calls = @(Get-HibernationAcceptanceTrace $handler).Count
    $null = Restore-RideRun -RunId $entry.RunId -Confirm:$false
    if ($calls -ne @(Get-HibernationAcceptanceTrace $handler).Count -or
        (ConvertTo-HibernationAcceptanceConfiguration (Read-State)) -cne (ConvertTo-HibernationAcceptanceConfiguration $entry.Before)) {
      throw 'Repeated saved recovery changed the configuration or invoked a native command.'
    }
    Assert-Preferences
    $pending.RemoveAt($pending.Count - 1)
  }
  try {
    $Report['Platform'] = Get-HibernationAcceptancePlatform
    $Report['PowercfgAvailableBefore'] = Invoke-HibernationReadOnlyPowercfg '/a'
    $original = Read-State; $Report.Original = $original
    if (-not $original.Available) { throw 'Initial hibernation configuration is unavailable for captured recovery; no writes attempted.' }
    $preferences = Get-HibernationAcceptancePreferences
    $Report['IndependentPreferencesBefore'] = $preferences
    # A conservative space check, not a promise that Windows will accept allocation.
    if ($Report.Platform.FreeBytes + [long]$original.Observation.FileBytes -lt $Report.Platform.PhysicalMemoryBytes + 64MB) {
      throw 'Insufficient system-drive space for the Size100 matrix plus safety margin; no writes attempted.'
    }
    $handler = Start-HibernationAcceptanceTrace $PrivateRoot
    Save-Evidence
    foreach ($start in @('Off','Reduced','Size75')) {
      $seedId = Apply-State $start
      if (-not (Test-RideDesiredState -Operation $Operation -State $start)) { throw 'Matrix starting-state preparation failed.' }
      foreach ($state in @('Off','Full','Reduced','Size50','Size75','Size100')) {
        Assert-Preview -State $state
        $before = Read-State
        $case = [ordered]@{ Start = $start; State = $state; Before = $before; SavedRunId = $null; Applied = $null; Restored = $null; PowercfgAvailable = $null; PreviewPassed = $true; RepeatPassed = $false; RecoveryPassed = $false }
        $Report.Cases += $case
        $case.SavedRunId = Apply-State $state
        $case.Applied = Read-State
        $case.PowercfgAvailable = Invoke-HibernationReadOnlyPowercfg '/a'
        if (-not (Test-RideDesiredState -Operation $Operation -State $state)) { throw 'Matrix desired-state check failed.' }
        $calls = @(Get-HibernationAcceptanceTrace $handler).Count
        $runs = @(Get-HibernationAcceptanceRuns) -join ','
        $repeatId = Apply-State $state
        if ($repeatId -or $calls -ne @(Get-HibernationAcceptanceTrace $handler).Count -or $runs -cne (@(Get-HibernationAcceptanceRuns) -join ',')) { throw 'Repeat application was not a native/state-store no-op.' }
        $case.RepeatPassed = $true
        Assert-Preferences
        if ($case.SavedRunId) { Restore-Last }
        if ((ConvertTo-HibernationAcceptanceConfiguration (Read-State)) -cne (ConvertTo-HibernationAcceptanceConfiguration $before)) { throw 'Matrix case recovery failed.' }
        $case.RecoveryPassed = $true
        $case.Restored = Read-State
        Save-Evidence
      }
      if ($seedId) { Restore-Last }
    }
    $seedId = Apply-State 'Size75'
    $beforeFault = Read-State
    $beforeCount = $pending.Count
    $fault = [ordered]@{ Method = 'Interrupt after successful native /hibernate /size 0 while changing Size75 to Reduced'; Triggered = $false; SavedRunId = $null; Intermediate = $null; RecoveryPassed = $false }
    $Report.ControlledFailure = $fault
    Set-HibernationAcceptanceInterruption $handler $true
    try {
      $null = Apply-State 'Reduced'
      throw 'Controlled hibernation interruption did not trigger.'
    } catch {
      if ($_.Exception.Message -notlike '*RIDE hibernation fixture interruption after successful native size reset*' -or $pending.Count -ne $beforeCount + 1) { throw }
      $fault.Triggered = $true
      $fault.SavedRunId = $pending[$pending.Count - 1].RunId
      $fault.Intermediate = Read-State
      if ($fault.Intermediate.Observation.Mode -ne 'Full' -or
          (ConvertTo-HibernationAcceptanceConfiguration $fault.Intermediate) -ceq (ConvertTo-HibernationAcceptanceConfiguration $beforeFault)) { throw 'Controlled interruption did not leave an observed partial size change.' }
    } finally { Set-HibernationAcceptanceInterruption $handler $false }
    Restore-Last
    $fault.RecoveryPassed = $true
    if ($seedId) { Restore-Last }
    $Report.LifecyclePassed = $true
  } catch { $failure = $_; $Report.Error = $_.Exception.Message }
  finally {
    if ($handler) {
      try {
        Set-HibernationAcceptanceInterruption $handler $false
        while ($pending.Count) { Restore-Last }
      } catch { $Report.RecoveryError = $_.Exception.Message }
      try { $Report['NativeCommands'] = @(Get-HibernationAcceptanceTrace $handler) }
      catch { $Report.RecoveryError = $_.Exception.Message }
      finally {
        try { Stop-HibernationAcceptanceTrace $handler }
        catch { $Report.RecoveryError = $_.Exception.Message }
      }
    }
    try {
      if ($original) {
        $Report.Restored = Read-State
        $Report.RecoveryPassed = -not $Report.RecoveryError -and (ConvertTo-HibernationAcceptanceConfiguration $Report.Restored) -ceq (ConvertTo-HibernationAcceptanceConfiguration $original)
        if ($preferences) { Assert-Preferences }
        $Report['PowercfgAvailableAfter'] = Invoke-HibernationReadOnlyPowercfg '/a'
      }
    } catch { $Report.RecoveryError = $_.Exception.Message; $Report.RecoveryPassed = $false }
    $Report.ExactRecovery = $false
    $Report['UnrecoveredRunIds'] = @($pending | ForEach-Object RunId)
    Save-Evidence
  }
  if ($failure) { throw $failure }
  if ($Report.RecoveryError -or -not $Report.RecoveryPassed) { throw 'Hibernation configuration recovery failed; retain evidence and restore the host checkpoint.' }
}

Export-ModuleMember -Function Invoke-RideHibernationAcceptance
