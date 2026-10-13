<#
.SYNOPSIS
  Inspect and restore Windows service startup and runtime state.

.DESCRIPTION
  Defines service handlers using Get-Service and Win32_Service. Writes transition
  Automatic/Manual/Disabled startup, SCM delayed auto-start and optional stable runtime states. Import defines
  commands only. Opted-in dependency refusal preflights and compares bounded related
  service state; it never starts/stops or restores those related services.

.EXAMPLE
  Import-Module .\modules\RIDE-Services.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Service/CIM cmdlets and elevation for configuration changes.
  File/environment inputs: Catalog ServiceName and state maps; versioned startup/runtime/delay snapshots.
  Recovery: State-changing handlers are engine-internal: use ride.ps1 preview and captured-run
  restoration. Direct calls bypass ShouldProcess and snapshot capture.
  Author: RIDE-Windows maintainers.
  Version: 0.4.0
  Changelog:
  - 0.4.0: Preflight/refuse implicit dependency transitions for opted-in service operations.
  - 0.3.1: Capture service-key existence explicitly and retain older raw-only recovery records.
  - 0.3.0: Add explicit SCM delayed-start and startup-only choices with typed compatible recovery.
  - 0.2.0: Preserve delayed-start values for declared service operations.
    0.1.0: Establish documented module ownership, version, and exported-command help during this
    walkthrough.
  Supported targets are declared per operation in catalog/operations.psd1. This walkthrough
  validates syntax/help, not Windows state transitions.

.LINK
  docs/models/script-repository-model.md

.LINK
  docs/OPERATIONS.md

#>


$script:ModuleVersion = '0.4.0'
Import-Module (Join-Path $PSScriptRoot 'RIDE-Settings.psm1') -ErrorAction Stop

function Assert-RideServiceIdentity {
  param([hashtable] $Operation)
  if ([string]$Operation.ServiceName -notmatch '^[A-Za-z0-9_.-]+$') {
    throw 'Service identity must be an exact service name without wildcard or query characters.'
  }
}

function Assert-RideServiceDelaySnapshot {
  param($Snapshot)
  if ($Snapshot -and ($Snapshot.Exists -isnot [bool] -or
      $Snapshot.KeyExisted -isnot [bool] -or
      ($Snapshot.Exists -and $Snapshot.ValueType -notin @('DWord', 'QWord', 'String', 'ExpandString', 'Binary', 'MultiString', 'None')))) {
    throw 'Invalid typed service delay snapshot.'
  }
}

function Initialize-RideServiceNativeApi {
  # Lazy compilation: importing handlers and catalog completion never query the SCM.
  if ('Ride.ServiceDelayApi' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Ride {
  public static class ServiceDelayApi {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryServiceConfig2W(IntPtr service, uint level, out int info, uint size, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ChangeServiceConfig2W(IntPtr service, uint level, ref int info);
    public static bool Access(string name, bool change, bool delayed) {
      IntPtr manager = OpenSCManagerW(null, null, 1); // SC_MANAGER_CONNECT
      if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
      try {
        IntPtr service = OpenServiceW(manager, name, change ? 2u : 1u);
        if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
          int info = delayed ? 1 : 0;
          uint needed;
          bool ok = change ? ChangeServiceConfig2W(service, 3, ref info)
                           : QueryServiceConfig2W(service, 3, out info, 4, out needed);
          if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
          return info != 0;
        } finally { CloseServiceHandle(service); }
      } finally { CloseServiceHandle(manager); }
    }
  }
}
'@ -ErrorAction Stop
}

function Get-RideServiceDelayedAutoStart {
  param([hashtable] $Operation)
  Assert-RideServiceIdentity $Operation
  Initialize-RideServiceNativeApi
  [Ride.ServiceDelayApi]::Access($Operation.ServiceName, $false, $false)
}

function Set-RideServiceDelayedAutoStart {
  param([hashtable] $Operation, [bool] $Delayed)
  Assert-RideServiceIdentity $Operation
  Initialize-RideServiceNativeApi
  [Ride.ServiceDelayApi]::Access($Operation.ServiceName, $true, $Delayed) | Out-Null
}

function Get-RideWindowsServiceState {
  <#
  .SYNOPSIS
    Read a Windows service startup type and runtime status.

  .DESCRIPTION
    Combines service-manager status and Win32_Service start mode; rejects unsupported startup modes.
    No changes occur.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideWindowsServiceState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. StartupType, Status and, where declared,
    SnapshotVersion 2, exact registry delay state and SCM-reported EffectiveDelayedAutoStart.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  Assert-RideServiceIdentity $Operation
  $service = Get-Service -Name $Operation.ServiceName -ErrorAction Stop
  $cimService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($Operation.ServiceName)'" -ErrorAction Stop
  if (-not $cimService) { throw "Windows service '$($Operation.ServiceName)' was not found." }

  $result = [pscustomobject]@{
    StartupType = switch ($cimService.StartMode) {
      'Auto' { 'Automatic' }
      'Manual' { 'Manual' }
      'Disabled' { 'Disabled' }
      default { throw "Unsupported startup mode '$($cimService.StartMode)' for '$($Operation.ServiceName)'." }
    }
    Status = [string]$service.Status
  }
  if ($Operation.PreserveDelayedAutoStart) {
    $delayedOperation = @{ RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $Operation.ServiceName; ValueName = 'DelayedAutoStart'; ValueType = 'DWord' }
    $keyExisted = Test-Path -LiteralPath $delayedOperation.RegistryPath -PathType Container -ErrorAction Stop
    if (-not $keyExisted) { throw "Service registry key is unavailable for '$($Operation.ServiceName)'." }
    $rawDelay = Get-RideSettingState -Operation $delayedOperation
    $rawDelay | Add-Member -NotePropertyName KeyExisted -NotePropertyValue ([bool]$keyExisted) -Force
    $result | Add-Member -NotePropertyName DelayedAutoStart -NotePropertyValue $rawDelay
    $result | Add-Member -NotePropertyName EffectiveDelayedAutoStart -NotePropertyValue (Get-RideServiceDelayedAutoStart $Operation)
    $result | Add-Member -NotePropertyName SnapshotVersion -NotePropertyValue 2
    $result | Add-Member -NotePropertyName ServiceName -NotePropertyValue $Operation.ServiceName
  }
  if ($Operation.RefuseDependencyChanges) {
    $result | Add-Member -NotePropertyName Dependencies -NotePropertyValue (Get-RideServiceDependencyState $Operation $service)
  }
  $result
}

function Get-RideServiceDependencyState {
  param([hashtable] $Operation, $Controller)
  if ($Controller.PSObject.Properties.Name -notcontains 'ServicesDependedOn' -or
      $Controller.PSObject.Properties.Name -notcontains 'DependentServices') { throw 'Service dependency inspection is unavailable.' }
  $rows = @(foreach ($direction in @('ServicesDependedOn', 'DependentServices')) {
    $services = @($Controller.$direction)
    if ($services.Count -gt 32) { throw 'Service dependency inspection exceeds 32 entries per direction.' }
    if (@($services.ServiceName | Sort-Object -Unique).Count -ne $services.Count) { throw 'Service dependency identities are missing or duplicated.' }
    foreach ($related in $services) {
      if ($related.ServiceName -notmatch '^[A-Za-z0-9_.-]+$' -or [string]$related.Status -notin @('Running', 'Stopped', 'Paused')) { throw 'Service dependency identity/status is unknown or transitional.' }
      [pscustomobject]@{ Direction = $direction; ServiceName = [string]$related.ServiceName; Status = [string]$related.Status }
    }
  })
  $group = Get-RideSettingState @{ RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $Operation.ServiceName; ValueName = 'DependOnGroup'; ValueType = 'MultiString' }
  if ($group.Exists -and $group.ValueType -ne 'MultiString') { throw 'Service load-order group dependency data has an unsupported type.' }
  $groups = @($group.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($groups.Count -gt 32) { throw 'Service load-order group dependency inspection exceeds 32 entries.' }
  [pscustomobject]@{ Entries = $rows; LoadOrderGroups = $groups }
}

function Assert-RideServiceDependencyTransition {
  param($Current, [string] $DesiredStatus)
  if (-not $Current.Dependencies) { throw 'Service dependency preflight was not captured.' }
  if (@($Current.Dependencies.LoadOrderGroups).Count) { throw 'Service load-order group dependencies require separate review; refusing transition.' }
  if ($DesiredStatus -eq $Current.Status) { return }
  if ($DesiredStatus -in @('Running', 'Paused') -and
      @($Current.Dependencies.Entries | Where-Object { $_.Direction -eq 'ServicesDependedOn' -and $_.Status -ne 'Running' }).Count) {
    throw 'Required services are not already running; refusing implicit dependency start before changing configuration.'
  }
  if ($DesiredStatus -eq 'Stopped' -and
      @($Current.Dependencies.Entries | Where-Object { $_.Direction -eq 'DependentServices' -and $_.Status -ne 'Stopped' }).Count) {
    throw 'Dependent services are active; refusing forced or undeclared dependent-service changes before changing configuration.'
  }
}

function ConvertTo-RideServiceDependencyText {
  param($Dependencies)
  (@($Dependencies.Entries | Sort-Object Direction, ServiceName | ForEach-Object { $_.Direction + ':' + $_.ServiceName + ':' + $_.Status }) -join ';') + '|groups:' + (@($Dependencies.LoadOrderGroups | Sort-Object) -join ';')
}

function Set-RideWindowsServiceState {
  <#
  .SYNOPSIS
    Apply the catalog service startup and runtime state.

  .DESCRIPTION
    Resolves a declared state, rejects unstable transition states, and changes startup/status as
    needed. Startup-only states preserve runtime. Explicit delay uses the SCM before runtime
    actions; compatibility presets preserve captured literal and SCM delay. Failures identify
    the incomplete stage; use the saved run for recovery. Use the engine to preview/capture.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER State
    Declared desired state for the selected catalog operation.

  .EXAMPLE
    Get-Help Set-RideWindowsServiceState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $State
  )

  if (-not $Operation.States.ContainsKey($State)) { throw "State '$State' is not supported by '$($Operation.Id)'." }
  $desired = $Operation.States[$State]
  $parameters = @{ Operation = $Operation; StartupType = $desired.StartupType }
  if ($desired.ContainsKey('Status')) { $parameters.Status = $desired.Status }
  if ($desired.ContainsKey('DelayedAutoStart')) { $parameters.Delayed = $desired.DelayedAutoStart }
  Set-RideWindowsServiceConfiguration @parameters
}

function Restore-RideWindowsServiceState {
  <#
  .SYNOPSIS
    Restore captured service startup and runtime state.

  .DESCRIPTION
    Restores version-2 startup/runtime plus SCM and literal typed delay state. Unversioned
    snapshots retain their older literal-delay recovery path without inventing prior SCM state.
    Unknown versions/identities fail before writes. Use Restore-RideRun for engine safeguards.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER Snapshot
    Captured pre-change state for this operation, read from the matching saved run.

  .EXAMPLE
    Get-Help Restore-RideWindowsServiceState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)] $Snapshot
  )

  if ($null -ne $Snapshot.SnapshotVersion -and ($Snapshot.SnapshotVersion -ne 2 -or
      $Snapshot.ServiceName -ne $Operation.ServiceName -or
      $Snapshot.EffectiveDelayedAutoStart -isnot [bool] -or -not $Snapshot.DelayedAutoStart)) {
    throw 'Invalid or unsupported Windows service snapshot version, identity or delay state.'
  }
  $literalDelay = $Snapshot.DelayedAutoStart
  if ($null -eq $Snapshot.SnapshotVersion -and $literalDelay -and $null -eq $literalDelay.KeyExisted) {
    # Older service records captured the named value only. Keep the service key;
    # never infer key absence or delete a service key from that incomplete record.
    $literalDelay = [pscustomobject]@{
      Exists = $literalDelay.Exists; Value = $literalDelay.Value
      ValueType = $literalDelay.ValueType; KeyExisted = $true
    }
  }
  Assert-RideServiceDelaySnapshot $literalDelay
  $parameters = @{ Operation = $Operation; StartupType = $Snapshot.StartupType; Status = $Snapshot.Status }
  if ($Operation.PreserveDelayedAutoStart -and $literalDelay) { $parameters.DelayedSnapshot = $literalDelay }
  if ($Snapshot.SnapshotVersion -eq 2) { $parameters.Delayed = $Snapshot.EffectiveDelayedAutoStart }
  # Disabled services can still be running/paused after a startup-only change.
  # Recover that valid combination without trying to start a disabled service.
  if ($Snapshot.StartupType -eq 'Disabled' -and $Snapshot.Status -in @('Running', 'Paused')) {
    $current = Get-RideWindowsServiceState $Operation
    if ($current.Status -ne $Snapshot.Status) {
      Set-RideWindowsServiceConfiguration -Operation $Operation -StartupType Manual -Status $Snapshot.Status
    }
  }
  Set-RideWindowsServiceConfiguration @parameters
}

function Set-RideWindowsServiceConfiguration {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][ValidateSet('Automatic', 'Manual', 'Disabled')][string] $StartupType,
    [ValidateSet('Running', 'Stopped', 'Paused')][string] $Status,
    [bool] $Delayed,
    $DelayedSnapshot
  )

  Assert-RideServiceIdentity $Operation
  if ($PSBoundParameters.ContainsKey('Delayed') -and -not $Operation.PreserveDelayedAutoStart) {
    throw 'Explicit service delay requires declared delayed-start capture.'
  }
  Assert-RideServiceDelaySnapshot $DelayedSnapshot
  $service = Get-RideWindowsServiceState $Operation
  if ($service.Status -notin @('Running', 'Stopped', 'Paused')) {
    throw "Cannot change '$($Operation.ServiceName)' while its status is '$($service.Status)'. Retry after the service reaches a stable state."
  }
  $desiredStatus = if ($Status) { $Status } else { [string]$service.Status }
  if ($Operation.RefuseDependencyChanges) { Assert-RideServiceDependencyTransition $service $desiredStatus }
  $delayedOperation = @{ RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $Operation.ServiceName; ValueName = 'DelayedAutoStart'; ValueType = 'DWord' }
  $preservedDelay = $null
  $effectiveDelay = $null
  $literal = $null
  $targetDelay = $null
  if ($Operation.PreserveDelayedAutoStart) {
    $effectiveDelay = $service.EffectiveDelayedAutoStart
    if (-not $PSBoundParameters.ContainsKey('Delayed') -and -not $DelayedSnapshot) {
      $preservedDelay = $service.DelayedAutoStart
    }
  }
  $stage = 'startup'
  try {
    if ([string]$service.StartupType -ne $StartupType) {
      Set-Service -Name $Operation.ServiceName -StartupType $StartupType -ErrorAction Stop
    }
    $stage = 'delayed-start configuration'
    if ($Operation.PreserveDelayedAutoStart) {
      $targetDelay = if ($PSBoundParameters.ContainsKey('Delayed')) { $Delayed } else { $effectiveDelay }
      if ((Get-RideServiceDelayedAutoStart $Operation) -ne $targetDelay) {
        Set-RideServiceDelayedAutoStart -Operation $Operation -Delayed $targetDelay
      }
      $literal = if ($DelayedSnapshot) { $DelayedSnapshot } else { $preservedDelay }
      if ($literal) {
        $liveLiteral = Get-RideSettingState -Operation $delayedOperation
        if (($liveLiteral | ConvertTo-Json -Compress) -ne ($literal | ConvertTo-Json -Compress)) {
          Restore-RideSettingState -Operation $delayedOperation -Snapshot $literal
        }
      }
      if (($PSBoundParameters.ContainsKey('Delayed') -or $preservedDelay) -and
          (Get-RideServiceDelayedAutoStart $Operation) -ne $targetDelay) {
        throw 'SCM delayed-start readback does not match the requested/captured flag.'
      }
    }
    $stage = 'runtime'
    $runtimeStatus = $service.Status
    if ($Operation.RefuseDependencyChanges) {
      $runtimeBefore = Get-RideWindowsServiceState $Operation
      Assert-RideServiceDependencyTransition $runtimeBefore $desiredStatus
      if ((ConvertTo-RideServiceDependencyText $runtimeBefore.Dependencies) -cne (ConvertTo-RideServiceDependencyText $service.Dependencies)) {
        throw 'Service dependency state changed after configuration; refusing runtime transition.'
      }
      $runtimeStatus = $runtimeBefore.Status
    }
    if ($Status -eq 'Running' -and $runtimeStatus -ne 'Running') {
      if ($runtimeStatus -eq 'Paused') {
        Resume-Service -Name $Operation.ServiceName -ErrorAction Stop
      }
      else {
        Start-Service -Name $Operation.ServiceName -ErrorAction Stop
      }
    }
    elseif ($Status -eq 'Stopped' -and $runtimeStatus -ne 'Stopped') {
      Stop-Service -Name $Operation.ServiceName -ErrorAction Stop
    }
    elseif ($Status -eq 'Paused' -and $runtimeStatus -ne 'Paused') {
      if ($runtimeStatus -eq 'Stopped') {
        Start-Service -Name $Operation.ServiceName -ErrorAction Stop
      }
      Suspend-Service -Name $Operation.ServiceName -ErrorAction Stop
    }
    $stage = 'verification'
    $after = Get-RideWindowsServiceState $Operation
    if ($Operation.RefuseDependencyChanges -and (ConvertTo-RideServiceDependencyText $after.Dependencies) -cne (ConvertTo-RideServiceDependencyText $service.Dependencies)) {
      throw 'Service dependency state changed during the operation; only the primary service was owned. Review dependencies separately.'
    }
    if ($Operation.PreserveDelayedAutoStart -and ($PSBoundParameters.ContainsKey('Delayed') -or $preservedDelay) -and
        $after.EffectiveDelayedAutoStart -ne $targetDelay) {
      throw 'SCM delayed-start readback changed during the runtime stage.'
    }
    if ($after.StartupType -ne $StartupType -or $after.Status -ne $desiredStatus) {
      throw 'Service startup/runtime readback does not match; a trigger, dependency or concurrent change may be involved.'
    }
    if ($literal) {
      if ($after.DelayedAutoStart.Exists -ne $literal.Exists -or
          ($literal.Exists -and ($after.DelayedAutoStart.ValueType -ne $literal.ValueType -or
           (ConvertTo-Json -InputObject $after.DelayedAutoStart.Value -Compress) -ne (ConvertTo-Json -InputObject $literal.Value -Compress)))) {
        throw 'Literal delayed-start readback does not match the captured value/type/absence.'
      }
    }
  }
  catch { throw "Service '$($Operation.ServiceName)' failed during $stage; partial changes may remain. Restore the saved run. $($_.Exception.Message)" }
}

Export-ModuleMember -Function Get-RideWindowsServiceState, Set-RideWindowsServiceState, Restore-RideWindowsServiceState
