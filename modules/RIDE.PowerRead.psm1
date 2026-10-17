<#
.SYNOPSIS
  Read power scheme identities and unsigned indexes without localized text parsing.
.DESCRIPTION
  Internal read-only PowrProf bridge. Initialization compiles interop declarations;
  only explicit reads invoke Windows. No setters, capability provisioning or sleep.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7. Requires PowrProf
  and kernel32. Native target acceptance remains pending; API presence is not
  hardware support or effective managed-policy evidence.
  Recovery: No Windows state change; allocated active-scheme memory is freed.
  Version: 0.1.0.
  Changelog: 0.1.0: Add typed AC/DC reads, numeric errors and bounded GUID ownership.
.LINK
  ../docs/setting-presentation.md
#>
$ErrorActionPreference='Stop'

function Initialize-RidePowerReadNative {
  if('Ride.PowerReadV1.Reader' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Ride.PowerReadV1 {
  public interface IReadApi {
    uint Active(out IntPtr memory);
    IntPtr Free(IntPtr memory);
    uint Index(Guid scheme, Guid subgroup, Guid setting, bool ac, out uint value);
  }
  public sealed class NativeApi : IReadApi {
    [DllImport("powrprof.dll", ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint PowerGetActiveScheme(IntPtr root, out IntPtr scheme);
    [DllImport("powrprof.dll", ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint PowerReadACValueIndex(IntPtr root, ref Guid scheme, ref Guid subgroup, ref Guid setting, out uint value);
    [DllImport("powrprof.dll", ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint PowerReadDCValueIndex(IntPtr root, ref Guid scheme, ref Guid subgroup, ref Guid setting, out uint value);
    [DllImport("kernel32.dll", ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);
    public uint Active(out IntPtr memory) { return PowerGetActiveScheme(IntPtr.Zero, out memory); }
    public IntPtr Free(IntPtr memory) { return LocalFree(memory); }
    public uint Index(Guid scheme, Guid subgroup, Guid setting, bool ac, out uint value) {
      return ac ? PowerReadACValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, out value)
                : PowerReadDCValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, out value);
    }
  }
  public sealed class IndexResult {
    public bool Available;
    public uint ErrorCode;
    public uint Value;
  }
  public static class Reader {
    public static Guid Active(IReadApi api) {
      if(api == null) throw new ArgumentNullException("api");
      IntPtr memory=IntPtr.Zero;
      try {
        uint error=api.Active(out memory);
        if(error != 0) throw new Win32Exception(unchecked((int)error), "PowerGetActiveScheme failed with code " + error);
        if(memory == IntPtr.Zero) throw new InvalidOperationException("PowerGetActiveScheme returned no GUID.");
        Guid value=(Guid)Marshal.PtrToStructure(memory, typeof(Guid));
        if(value == Guid.Empty) throw new InvalidOperationException("PowerGetActiveScheme returned an empty GUID.");
        return value;
      } finally {
        if(memory != IntPtr.Zero && api.Free(memory) != IntPtr.Zero)
          throw new InvalidOperationException("PowerGetActiveScheme memory release failed.");
      }
    }
    public static IndexResult Read(IReadApi api, Guid scheme, Guid subgroup, Guid setting, bool ac) {
      if(api == null) throw new ArgumentNullException("api");
      if(scheme == Guid.Empty || subgroup == Guid.Empty || setting == Guid.Empty)
        throw new ArgumentException("Power read requires nonempty GUID identities.");
      uint value;
      uint error=api.Index(scheme, subgroup, setting, ac, out value);
      // ERROR_FILE_NOT_FOUND is absent configuration, never proof of absent hardware.
      if(error == 2) return new IndexResult { Available=false, ErrorCode=error, Value=0 };
      if(error != 0) throw new Win32Exception(unchecked((int)error), "Power index read failed with code " + error);
      return new IndexResult { Available=true, ErrorCode=0, Value=value };
    }
  }
}
'@
}

function Get-RideNativeActivePowerScheme {
  <#
  .SYNOPSIS
    Read the active local power scheme GUID and release its native allocation.
  .OUTPUTS
    String. Canonical GUID; native failures throw numeric error diagnostics.
  .NOTES
    Internal read-only bridge, not a capability or effective-policy probe.
  #>
  [CmdletBinding()]param()
  Initialize-RidePowerReadNative
  [Ride.PowerReadV1.Reader]::Active([Ride.PowerReadV1.NativeApi]::new()).ToString('D')
}

function Get-RideNativePowerIndex {
  <#
  .SYNOPSIS
    Read the literal AC or DC index from an explicitly identified power scheme.
  .PARAMETER SchemeGuid
    Exact scheme GUID; never an alias or implicit current-plan selection.
  .PARAMETER SubgroupGuid
    Exact setting subgroup GUID.
  .PARAMETER SettingGuid
    Exact setting GUID.
  .PARAMETER PowerIndex
    AC or DC. Finite completion performs no Windows query.
  .OUTPUTS
    PSCustomObject. Availability, numeric error and nullable unsigned index.
  .NOTES
    File-not-found reports Unavailable; access denied and other errors throw.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][guid]$SchemeGuid,
    [Parameter(Mandatory)][guid]$SubgroupGuid,
    [Parameter(Mandatory)][guid]$SettingGuid,
    [Parameter(Mandatory)][ValidateSet('AC','DC')][string]$PowerIndex)
  Initialize-RidePowerReadNative
  $result=[Ride.PowerReadV1.Reader]::Read([Ride.PowerReadV1.NativeApi]::new(),$SchemeGuid,$SubgroupGuid,$SettingGuid,($PowerIndex -eq 'AC'))
  [pscustomobject]@{Available=$result.Available;ErrorCode=$result.ErrorCode;Index=$(if($result.Available){$result.Value}else{$null})}
}
Export-ModuleMember -Function Get-RideNativeActivePowerScheme,Get-RideNativePowerIndex
