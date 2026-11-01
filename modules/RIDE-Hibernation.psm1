<#
.SYNOPSIS
  Inspect and configure the hibernation file as one coupled machine setting.
.DESCRIPTION
  Uses a read-only Windows power-capability query and HiberFileSizePercent for
  observation. Writes use powercfg only. Import does not query or change Windows.
  The engine saves state before writes; each exported writer also supports preview.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows. Windows 11
  is a candidate only; native lifecycle and power-transition acceptance is pending.
  Prerequisites: Administrator for writes, powercfg and a recoverable observation.
  Recovery: Conditional configuration recovery, not hiberfil.sys content/byte-size
  or dormant registry recovery. Off restores absence of the file. See the guide.
  Version: 0.1.1.
  Changelog: 0.1.1: Read file length without the Windows PowerShell 5.1 Get-Item
    lookup that can misreport the active hibernation file as missing.
    0.1.0: Add coordinated Off, Full, Reduced and explicit full-file sizes.
.LINK
  ../docs/hibernation.md
#>

$script:ModuleVersion = '0.1.1'
$ErrorActionPreference = 'Stop'

function Initialize-RideHibernationApi {
  if ('Ride.HibernationApi' -as [type]) { return }
  # Windows SDK winnt.h SYSTEM_POWER_CAPABILITIES (Windows 10+): BOOLEAN is
  # one byte; the complete structure is 76 bytes on both x86 and x64.
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Ride {
  [StructLayout(LayoutKind.Explicit, Size=76)]
  public struct HibernationCapabilities {
    [FieldOffset(6)] public byte SystemS4;
    [FieldOffset(8)] public byte HiberFilePresent;
    [FieldOffset(22)] public byte HiberFileType;
  }
  public static class HibernationApi {
    [DllImport("powrprof.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool GetPwrCapabilities(out HibernationCapabilities value);
    public static HibernationCapabilities Read() {
      HibernationCapabilities value;
      if (!GetPwrCapabilities(out value)) throw new Win32Exception(Marshal.GetLastWin32Error());
      return value;
    }
  }
}
'@
}

function Get-RideHibernationFileLength {
  param([string] $Path)
  # Get-Item -Force on Windows PowerShell 5.1 can report an existing active
  # hiberfil.sys as missing. FileInfo reads metadata without opening its contents.
  # Invoke the getter explicitly: PowerShell property access can suppress getter
  # exceptions. A missing/unreadable file must throw, not become zero or Off.
  ([IO.FileInfo]::new($Path)).get_Length()
}

function Get-RideHibernationObservation {
  Initialize-RideHibernationApi
  $capabilities = [Ride.HibernationApi]::Read()
  $mode = if ($capabilities.HiberFilePresent -eq 0) { 'Off' }
    elseif ($capabilities.HiberFileType -eq 1) { 'Reduced' }
    elseif ($capabilities.HiberFileType -eq 2) { 'Full' }
    else { 'Unknown' }
  $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Power', $false)
  if ($null -eq $key) { throw 'Cannot inspect the hibernation power configuration.' }
  try {
    $percent = $null
    if ('HiberFileSizePercent' -in $key.GetValueNames()) {
      if ($key.GetValueKind('HiberFileSizePercent') -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
        throw 'HiberFileSizePercent has an unsupported registry type.'
      }
      $percent = $key.GetValue('HiberFileSizePercent')
    }
  }
  finally { $key.Dispose() }
  $bytes = if ($mode -eq 'Off') { 0L } else {
    Get-RideHibernationFileLength -Path (Join-Path $env:SystemDrive 'hiberfil.sys')
  }
  [pscustomobject]@{ Mode = $mode; SizePercent = $percent; FileBytes = $bytes
    HibernateAvailable = ($capabilities.SystemS4 -ne 0) }
}

function Assert-RideHibernationOperation {
  param([hashtable] $Operation)
  if ($Operation.Kind -ne 'Hibernation' -or $Operation.Handler -ne 'Hibernation' -or
      $Operation.Scope -ne 'Machine' -or $Operation.RequiresAdmin -ne $true) {
    throw 'Invalid machine hibernation operation.'
  }
}

function Test-RideHibernationRecoverable {
  param($Observation)
  if ($null -eq $Observation -or $Observation.Mode -notin @('Off', 'Reduced', 'Full')) { return $false }
  $percent = $Observation.SizePercent
  if ($null -ne $percent -and ($percent -isnot [int] -and $percent -isnot [long])) { return $false }
  if ($Observation.Mode -eq 'Off') { return ($null -eq $percent -or ($percent -ge 0 -and $percent -le 100)) }
  if ($null -eq $percent) { return $false }
  if ($Observation.Mode -eq 'Reduced') { return ($percent -in @(0, 20)) }
  return ($percent -in @(0, 40) -or ($percent -ge 50 -and $percent -le 100))
}

function Test-RideHibernationObservationEqual {
  param($Left, $Right)
  # Off has no active file sizing. Byte length can change independently of the
  # requested percentage and is diagnostic only, never a recovery identity.
  return ($Left.Mode -eq $Right.Mode -and ($Left.Mode -eq 'Off' -or
    (($null -eq $Left.SizePercent) -eq ($null -eq $Right.SizePercent) -and $Left.SizePercent -eq $Right.SizePercent)))
}

function Get-RideHibernationState {
  <#
  .SYNOPSIS
    Read file mode, configured RAM percentage, byte length and S4 availability.
  .PARAMETER Operation
    Machine-scoped Hibernation catalog operation.
  .OUTPUTS
    Observation and recoverability; Available=false refuses unsafe state changes.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable] $Operation)
  Assert-RideHibernationOperation $Operation
  $observation = Get-RideHibernationObservation
  $recoverable = Test-RideHibernationRecoverable $observation
  [pscustomobject]@{ Available = $recoverable; Observation = $observation
    Reason = $(if (-not $recoverable) { 'Unrecognized or incomplete file configuration; recovery is not established.' } else { '' }) }
}

function Test-RideHibernationMatch {
  <#
  .SYNOPSIS
    Compare a declared state against an already captured observation, without I/O.
  .PARAMETER Operation
    Hibernation catalog operation and state vocabulary.
  .PARAMETER State
    Off, Full, Reduced, or Size50 through Size100 from the catalog.
  .PARAMETER CurrentState
    State returned by Get-RideHibernationState.
  .OUTPUTS
    Boolean. Full accepts an existing full file without changing its sizing.
  #>
  [CmdletBinding()]
  param([hashtable] $Operation, [string] $State, $CurrentState)
  if (-not $CurrentState.Available -or -not $Operation.States.ContainsKey($State)) { return $false }
  $desired = [string]$Operation.States[$State]
  if ($desired -in @('Off', 'Full', 'Reduced')) { return ($CurrentState.Observation.Mode -eq $desired) }
  if ($desired -match '^Full:([0-9]+)$') {
    return ($CurrentState.Observation.Mode -eq 'Full' -and $CurrentState.Observation.SizePercent -eq [int]$Matches[1])
  }
  return $false
}

function Invoke-RideHibernationCommand {
  param([string[]] $Arguments)
  $previous = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = @(& (Join-Path $env:SystemRoot 'System32/powercfg.exe') @Arguments 2>&1)
    $code = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $previous }
  if ($code -ne 0) { throw "powercfg $($Arguments -join ' ') failed ($code): $($output -join ' ')" }
}

function Invoke-RideHibernationConfiguration {
  param([string] $Mode, $Percent = $null)
  if ($Mode -eq 'Off') { Invoke-RideHibernationCommand @('/hibernate', 'off'); return }
  Invoke-RideHibernationCommand @('/hibernate', 'on')
  if ($Mode -eq 'Reduced') {
    # Required when switching a custom-size full file to reduced.
    Invoke-RideHibernationCommand @('/hibernate', '/size', '0')
    Invoke-RideHibernationCommand @('/hibernate', '/type', 'reduced')
  }
  else {
    Invoke-RideHibernationCommand @('/hibernate', '/type', 'full')
    if ($null -ne $Percent) {
      Invoke-RideHibernationCommand @('/hibernate', '/size', ([int]$Percent).ToString([Globalization.CultureInfo]::InvariantCulture))
    }
  }
}

function Set-RideHibernationState {
  <#
  .SYNOPSIS
    Set one coordinated hibernation-file choice after engine snapshot capture.
  .PARAMETER Operation
    Hibernation catalog operation.
  .PARAMETER State
    Declared state. Size choices enable a full file and use percent of RAM.
  .PARAMETER ExpectedState
    Required pre-change observation captured by the engine; drift refuses writes.
  .OUTPUTS
    None. Native failures or failed postconditions throw for saved-run recovery.
  .NOTES
    Administrator required. This handler does not suspend, shut down or reboot.
  #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([hashtable] $Operation, [string] $State, [Parameter(Mandatory = $true)] $ExpectedState)
  Assert-RideHibernationOperation $Operation
  if (-not $Operation.States.ContainsKey($State)) { throw 'Unsupported hibernation state.' }
  $desired = [string]$Operation.States[$State]
  $mode = $desired; $percent = $null
  if ($desired -match '^Full:([0-9]+)$' -and [int]$Matches[1] -ge 50 -and [int]$Matches[1] -le 100) {
    $mode = 'Full'; $percent = [int]$Matches[1]
  }
  elseif ($desired -notin @('Off', 'Full', 'Reduced')) { throw 'Unsupported hibernation size; expected 50..100 percent.' }
  $current = Get-RideHibernationState $Operation
  if (-not $current.Available -or -not $ExpectedState.Available -or
      -not (Test-RideHibernationObservationEqual $current.Observation $ExpectedState.Observation)) {
    throw 'Hibernation configuration is unavailable or drifted since capture.'
  }
  if (Test-RideHibernationMatch $Operation $State $current) { return }
  if (-not $PSCmdlet.ShouldProcess('Machine hibernation file', "Set $State (may allocate, resize or remove hiberfil.sys)")) { return }
  Invoke-RideHibernationConfiguration $mode $percent
  if (-not (Test-RideHibernationMatch $Operation $State (Get-RideHibernationState $Operation))) {
    throw 'Hibernation postcondition failed; restore the saved run to recover the captured configuration.'
  }
}

function Restore-RideHibernationState {
  <#
  .SYNOPSIS
    Recover captured active file mode and sizing, subject to Windows acceptance.
  .PARAMETER Operation
    Original Hibernation catalog operation.
  .PARAMETER Snapshot
    Version 1 snapshot bound to the original operation, with Prior observation.
  .PARAMETER ValidateOnly
    Check the saved contract without native observation or changes.
  .OUTPUTS
    None. Failed recovery postconditions throw and leave saved state available.
  .NOTES
    Conditional recovery: Off recovers file absence; no dormant registry values,
    hibernated session, physical allocation or file contents are restored.
  #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([hashtable] $Operation, $Snapshot, [switch] $ValidateOnly)
  Assert-RideHibernationOperation $Operation
  if ($Snapshot.SnapshotVersion -ne 1 -or $Snapshot.OperationId -cne $Operation.Id -or
      -not (Test-RideHibernationRecoverable $Snapshot.Prior)) { throw 'Invalid hibernation snapshot identity, version or prior configuration.' }
  if ($ValidateOnly) { return }
  $current = Get-RideHibernationState $Operation
  if (Test-RideHibernationObservationEqual $current.Observation $Snapshot.Prior) { return }
  if (-not $PSCmdlet.ShouldProcess('Machine hibernation file', 'Restore captured file configuration')) { return }
  $percent = $Snapshot.Prior.SizePercent
  # The documented 40% full default is recovered through Windows sizing, not
  # assumed to be a valid custom size on every build. Verify the literal result.
  if ($Snapshot.Prior.Mode -eq 'Full' -and $percent -eq 40) { $percent = 0 }
  Invoke-RideHibernationConfiguration $Snapshot.Prior.Mode $percent
  $after = Get-RideHibernationState $Operation
  if (-not (Test-RideHibernationObservationEqual $after.Observation $Snapshot.Prior)) {
    throw 'Hibernation recovery postcondition failed; retain the saved run and use the VM checkpoint if required.'
  }
}

Export-ModuleMember -Function Get-RideHibernationState, Test-RideHibernationMatch, Set-RideHibernationState, Restore-RideHibernationState
