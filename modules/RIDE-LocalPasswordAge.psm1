<#
.SYNOPSIS
  Inspect and recover the local SAM maximum password age with a focused setter.
.DESCRIPTION
  Reads local NetUserModals levels 0/2 and uses only level 1002 for writes. No
  password, per-account flag, minimum age, history, length or lockout is changed.
  Refuses domain controllers, authority/context drift and unsafe minimum-age
  combinations. Native definitions load lazily; import performs no inspection.
.EXAMPLE
  Import-Module ./modules/RIDE-LocalPasswordAge.psm1
  Get-Help Get-RideLocalPasswordAgeState -Full
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Local SAM, readable computer role, administrator for writes.
  Recovery: Engine ShouldProcess and saved snapshot version 1; raw seconds and
  SAM SID identify the prior field. Recovery does not restore changed passwords.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add pending maximum-age lifecycle without full policy replay.
.LINK
  ../docs/local-password-policy.md
.LINK
  https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset
#>

$script:ModuleVersion = '0.1.0'
$ErrorActionPreference = 'Stop'

function Initialize-RideLocalPasswordAgeApi {
  if ('Ride.LocalPasswordAgeApi' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace Ride {
  [StructLayout(LayoutKind.Sequential)] public struct UserModals0 {
    public uint MinLength, MaxAgeSeconds, MinAgeSeconds, ForceLogoffSeconds, HistoryLength;
  }
  [StructLayout(LayoutKind.Sequential)] public struct UserModals2 {
    public IntPtr DomainName, DomainSid;
  }
  [StructLayout(LayoutKind.Sequential)] public struct UserModals1002 {
    public uint MaxAgeSeconds;
  }
  public sealed class LocalPasswordAgeRecord {
    public uint MinLength, MaxAgeSeconds, MinAgeSeconds, ForceLogoffSeconds, HistoryLength;
    public string SamDomainSid;
  }
  public static class LocalPasswordAgeApi {
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode)]
    private static extern uint NetUserModalsGet(string server, uint level, out IntPtr buffer);
    [DllImport("netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr buffer);
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode)]
    private static extern uint NetUserModalsSet(string server, uint level, ref UserModals1002 data, out uint parameterError);
    private static void Check(uint status) {
      if (status != 0) throw new Win32Exception((int)status);
    }
    public static LocalPasswordAgeRecord Read() {
      IntPtr p0=IntPtr.Zero, p2=IntPtr.Zero;
      try {
        Check(NetUserModalsGet(null, 0, out p0));
        Check(NetUserModalsGet(null, 2, out p2));
        if (p0==IntPtr.Zero || p2==IntPtr.Zero) throw new InvalidOperationException("Local SAM policy buffer is unavailable.");
        UserModals0 v0=(UserModals0)Marshal.PtrToStructure(p0, typeof(UserModals0));
        UserModals2 v2=(UserModals2)Marshal.PtrToStructure(p2, typeof(UserModals2));
        if (v2.DomainSid==IntPtr.Zero) throw new InvalidOperationException("Local SAM identity is unavailable.");
        return new LocalPasswordAgeRecord {
          MinLength=v0.MinLength, MaxAgeSeconds=v0.MaxAgeSeconds, MinAgeSeconds=v0.MinAgeSeconds,
          ForceLogoffSeconds=v0.ForceLogoffSeconds, HistoryLength=v0.HistoryLength,
          SamDomainSid=new SecurityIdentifier(v2.DomainSid).Value
        };
      } finally {
        if (p2!=IntPtr.Zero) NetApiBufferFree(p2);
        if (p0!=IntPtr.Zero) NetApiBufferFree(p0);
      }
    }
    public static void SetMaximumAge(uint seconds) {
      UserModals1002 value=new UserModals1002 { MaxAgeSeconds=seconds };
      uint parameterError;
      uint status=NetUserModalsSet(null, 1002, ref value, out parameterError);
      if (status!=0) throw new Win32Exception((int)status, "Local maximum-age write failed; parameter index " + parameterError + ".");
    }
  }
}
'@ -ErrorAction Stop
}

function Get-RideLocalPasswordAgeNative {
  Initialize-RideLocalPasswordAgeApi
  [Ride.LocalPasswordAgeApi]::Read()
}

function Set-RideLocalPasswordAgeNative {
  param([uint32] $Seconds)
  Initialize-RideLocalPasswordAgeApi
  [Ride.LocalPasswordAgeApi]::SetMaximumAge($Seconds)
}

function Assert-RideLocalPasswordAgeOperation {
  param([hashtable] $Operation)
  if ($Operation.Kind -ne 'LocalPasswordMaximumAge' -or $Operation.Scope -ne 'Machine' -or
      $Operation.Handler -ne 'LocalPasswordMaximumAge') { throw 'Invalid local maximum password-age operation.' }
}

function Assert-RideLocalPasswordAgeComputer {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
  if ($os.ProductType -eq 2 -or $computer.DomainRole -in @(4,5)) { throw 'Domain-controller password-policy inspection/mutation is not supported by this local SAM handler.' }
  if (-not (($os.ProductType -eq 1 -and $computer.DomainRole -in @(0,1)) -or
            ($os.ProductType -eq 3 -and $computer.DomainRole -in @(2,3)))) { throw 'Local SAM computer role is unknown or inconsistent.' }
}

function Assert-RideLocalPasswordAgeRecord {
  param($Record)
  if ([string]$Record.SamDomainSid -notmatch '^S-1-5-21-\d+-\d+-\d+$') { throw 'Local SAM identity is invalid.' }
  foreach ($field in @('MaxAgeSeconds','MinAgeSeconds','MinLength','ForceLogoffSeconds','HistoryLength')) {
    $value = $Record.$field
    if ($value -isnot [byte] -and $value -isnot [int] -and $value -isnot [uint32] -and $value -isnot [long]) { throw 'Local SAM policy fields must be unsigned integer values.' }
    if ([long]$value -lt 0 -or [long]$value -gt [uint32]::MaxValue) { throw 'Local SAM policy field exceeds DWORD bounds.' }
  }
  if ([long]$Record.MaxAgeSeconds -ne [uint32]::MaxValue -and
      ([long]$Record.MaxAgeSeconds -lt 86400 -or [long]$Record.MaxAgeSeconds -lt [long]$Record.MinAgeSeconds)) {
    throw 'Captured maximum password age cannot be safely recovered through the documented API.'
  }
}

function ConvertTo-RideLocalPasswordAgeSeconds {
  param([hashtable] $Operation, [string] $State)
  if (-not $Operation.States.ContainsKey($State)) { throw 'Unknown maximum password-age state.' }
  $days = $Operation.States[$State]
  if ($days -isnot [int] -or $days -lt 0 -or $days -gt 999) { throw 'Maximum password age must be Never expires or 1-999 explicit days.' }
  if ($days -eq 0) { return [uint32]::MaxValue }
  [uint32]($days * 86400)
}

function Test-RideLocalPasswordAgeContext {
  param($Left, $Right, [switch] $IncludeMaximum)
  foreach ($field in @('SamDomainSid','MinAgeSeconds','MinLength','ForceLogoffSeconds','HistoryLength')) {
    if ($Left.$field -cne $Right.$field) { return $false }
  }
  if ($IncludeMaximum -and $Left.MaxAgeSeconds -ne $Right.MaxAgeSeconds) { return $false }
  $true
}

function Get-RideLocalPasswordAgeState {
  <#
  .SYNOPSIS
    Read the local SAM applied maximum-age field and nonsecret recovery context.
  .PARAMETER Operation
    Machine-scoped maximum-age catalog entry. No server/domain parameter exists.
  .OUTPUTS
    Applied raw seconds, day interpretation, SAM SID and other read-only modal fields.
    This does not inspect local GPO definitions, policy provenance or user passwords.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation)
  Assert-RideLocalPasswordAgeOperation $Operation
  Assert-RideLocalPasswordAgeComputer
  $raw = Get-RideLocalPasswordAgeNative
  Assert-RideLocalPasswordAgeRecord $raw
  $policy = [pscustomobject]@{
    SamDomainSid = [string]$raw.SamDomainSid; MaxAgeSeconds = [long]$raw.MaxAgeSeconds
    MinAgeSeconds = [long]$raw.MinAgeSeconds; MinLength = [long]$raw.MinLength
    ForceLogoffSeconds = [long]$raw.ForceLogoffSeconds; HistoryLength = [long]$raw.HistoryLength
  }
  $forever = $policy.MaxAgeSeconds -eq [uint32]::MaxValue
  $days = if ($forever) { 0 } elseif ($policy.MaxAgeSeconds % 86400 -eq 0 -and $policy.MaxAgeSeconds / 86400 -le 999) { [int]($policy.MaxAgeSeconds / 86400) } else { $null }
  [pscustomobject]@{
    Available = $true; Policy = $policy; Value = $days
    GuiCompatible = [bool]($policy.MinAgeSeconds -le (998 * 86400) -and ($forever -or ($null -ne $days -and $policy.MaxAgeSeconds -gt $policy.MinAgeSeconds)))
    EffectivePolicy = 'Local SAM currently applied field; local definitions and managed source not inspected'
    Interpretation = $(if ($forever) { 'Never expires' } elseif ($null -ne $days) { "$days days" } else { "Custom native value: $($policy.MaxAgeSeconds) seconds" })
  }
}

function Set-RideLocalPasswordAgeState {
  <#
  .SYNOPSIS
    Set only maximum age after complete local-authority/context preflight.
  .PARAMETER Operation
    Catalog entry with NoExpiry or Days1..Days999 state values.
  .PARAMETER State
    Explicit catalog state; not a baseline or full security-policy reset.
  .PARAMETER ExpectedState
    Engine's saved pre-change state; native/context drift prevents writes.
  .OUTPUTS
    None. Native errors/readback drift propagate for saved-run partial recovery.
  #>
  [CmdletBinding()]
  param([hashtable] $Operation, [string] $State, $ExpectedState)
  $seconds = ConvertTo-RideLocalPasswordAgeSeconds $Operation $State
  Assert-RideLocalPasswordAgeRecord $ExpectedState.Policy
  $before = Get-RideLocalPasswordAgeState $Operation
  if ($before.Policy.MinAgeSeconds -gt (998 * 86400)) { throw 'Current minimum password age exceeds the documented GUI range; no implicit policy repair is permitted.' }
  if (-not (Test-RideLocalPasswordAgeContext $before.Policy $ExpectedState.Policy -IncludeMaximum)) { throw 'Local password policy changed after capture; no maximum-age write performed.' }
  if ($seconds -ne [uint32]::MaxValue -and $seconds -le $before.Policy.MinAgeSeconds) { throw 'Explicit maximum password age must be greater than the current minimum age; minimum age is never changed implicitly.' }
  if ($before.Policy.MaxAgeSeconds -eq $seconds) { return }
  Set-RideLocalPasswordAgeNative $seconds
  $after = Get-RideLocalPasswordAgeState $Operation
  if ($after.Policy.MaxAgeSeconds -ne $seconds -or -not (Test-RideLocalPasswordAgeContext $before.Policy $after.Policy)) {
    throw 'Maximum-age readback or unrelated policy context changed; partial changes may remain. Restore the saved run after reviewing the conflict.'
  }
}

function Restore-RideLocalPasswordAgeState {
  <#
  .SYNOPSIS
    Recover exact prior raw seconds without replaying unrelated policy fields.
  .PARAMETER Operation
    Original catalog operation; local SAM and domain-controller gates still apply.
  .PARAMETER Snapshot
    Version 1 record with Prior and ExpectedMaxAgeSeconds. Changed authority,
    unrelated modal context or an independently changed maximum age blocks recovery.
  .OUTPUTS
    None. No password or account state is captured, displayed or reconstructed.
  #>
  [CmdletBinding()]
  param([hashtable] $Operation, $Snapshot)
  if ($Snapshot.SnapshotVersion -ne 1 -or $Snapshot.OperationId -cne $Operation.Id -or
      ($Snapshot.ExpectedMaxAgeSeconds -isnot [int] -and $Snapshot.ExpectedMaxAgeSeconds -isnot [uint32] -and $Snapshot.ExpectedMaxAgeSeconds -isnot [long])) { throw 'Invalid local password-age snapshot identity/version.' }
  Assert-RideLocalPasswordAgeRecord $Snapshot.Prior
  $expected = [long]$Snapshot.ExpectedMaxAgeSeconds
  if ($expected -ne [uint32]::MaxValue -and ($expected -lt 86400 -or $expected -gt (999 * 86400) -or $expected % 86400 -ne 0)) { throw 'Invalid expected maximum-age capture.' }
  $before = Get-RideLocalPasswordAgeState $Operation
  if ($before.Policy.SamDomainSid -cne $Snapshot.Prior.SamDomainSid) { throw 'Saved maximum age belongs to a different local SAM authority.' }
  if ($before.Policy.MaxAgeSeconds -eq $Snapshot.Prior.MaxAgeSeconds) { return }
  if ($before.Policy.MaxAgeSeconds -ne $Snapshot.ExpectedMaxAgeSeconds -or
      -not (Test-RideLocalPasswordAgeContext $before.Policy $Snapshot.Prior)) { throw 'Local maximum age or related policy context changed; refusing stale recovery.' }
  Set-RideLocalPasswordAgeNative ([uint32]$Snapshot.Prior.MaxAgeSeconds)
  $after = Get-RideLocalPasswordAgeState $Operation
  if ($after.Policy.MaxAgeSeconds -ne $Snapshot.Prior.MaxAgeSeconds -or
      -not (Test-RideLocalPasswordAgeContext $before.Policy $after.Policy)) { throw 'Local password-age recovery readback failed; partial changes may remain.' }
}

Export-ModuleMember -Function Get-RideLocalPasswordAgeState, Set-RideLocalPasswordAgeState, Restore-RideLocalPasswordAgeState
