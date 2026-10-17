<#
.SYNOPSIS
  Observe the intended user's default/LAN WinINet proxy configuration.
.DESCRIPTION
  Queries documented connection options without decoding registry blobs, resolving
  a proxy or fetching a PAC file. Retains manual proxy, bypass, URL and all flag
  bits. No setter, refresh, WinHTTP call or automatic connection selection exists.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7. Native acceptance
  remains pending. Requires an explicitly identified interactive user/session.
  File/environment inputs: Expected machine, user SID and session; no file reads.
  Recovery: Observation only; not an engine snapshot or authorization to mutate.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded default/LAN option capture and native memory ownership.
.LINK
  ../docs/user-proxy-inventory.md
.LINK
  https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw
#>
$ErrorActionPreference='Stop'

function Get-RideUserProxyContext {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $process=[Diagnostics.Process]::GetCurrentProcess()
  try {
    [pscustomobject]@{ComputerName=[Environment]::MachineName;UserSid=$identity.User.Value;SessionId=$process.SessionId;UserInteractive=[Environment]::UserInteractive}
  } finally {$identity.Dispose();$process.Dispose()}
}

function Initialize-RideUserProxyNative {
  if('Ride.UserProxyInventoryV1.Reader' -as [type]){return}
  # ABI follows wininet.h. FILETIME is two DWORDs, not an alignment-changing Int64.
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Ride.UserProxyInventoryV1 {
  [StructLayout(LayoutKind.Sequential)] public struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Explicit)] public struct OptionValue {
    [FieldOffset(0)] public uint Number;
    [FieldOffset(0)] public IntPtr Text;
    [FieldOffset(0)] public FileTime Time;
  }
  [StructLayout(LayoutKind.Sequential)] public struct Option { public uint Id; public OptionValue Value; }
  [StructLayout(LayoutKind.Sequential)] public struct OptionList {
    public uint Size; public IntPtr Connection; public uint Count; public uint ErrorIndex; public IntPtr Options;
  }
  // Injectable boundary permits memory/failure tests without loading WinINet.
  public interface IQueryApi {
    bool Query(ref OptionList options, ref uint length, out int error);
    void FreeReturnedString(IntPtr text);
  }
  internal sealed class NativeApi : IQueryApi {
    [DllImport("wininet.dll", ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetQueryOptionW(IntPtr handle, uint option, ref OptionList list, ref uint length);
    [DllImport("kernel32.dll", ExactSpelling=true)] private static extern IntPtr GlobalFree(IntPtr memory);
    public bool Query(ref OptionList options, ref uint length, out int error) {
      bool result=InternetQueryOptionW(IntPtr.Zero,75,ref options,ref length);
      error=result ? 0 : Marshal.GetLastWin32Error(); return result;
    }
    public void FreeReturnedString(IntPtr text) {
      if(GlobalFree(text)!=IntPtr.Zero) throw new InvalidOperationException("Unable to release returned proxy option memory.");
    }
  }
  public sealed class Snapshot {
    public uint Flags; public string FlagsSource; public int? UiQueryError;
    public string ProxyServer; public string ProxyBypass; public string AutoConfigUrl;
  }
  public static class Reader {
    private static readonly int OptionSize=Marshal.SizeOf(typeof(Option));
    private static readonly int ListSize=Marshal.SizeOf(typeof(OptionList));
    public static void ValidateLayout() {
      bool x64=IntPtr.Size==8;
      if(OptionSize!=(x64?16:12) || ListSize!=(x64?32:20) ||
        Marshal.OffsetOf(typeof(Option),"Value").ToInt32()!=(x64?8:4) ||
        Marshal.OffsetOf(typeof(OptionList),"Options").ToInt32()!=(x64?24:16))
        throw new PlatformNotSupportedException("Unexpected WinINet option structure layout.");
    }
    private static string ReadText(IntPtr text) {
      if(text==IntPtr.Zero) return null;
      // Native API guarantees a NUL-terminated allocation; bound retained output.
      for(int i=0;i<=32768;i++) {
        if(Marshal.ReadInt16(text,checked(i*2))==0) return Marshal.PtrToStringUni(text,i);
      }
      throw new InvalidOperationException("Proxy option string exceeds 32768 characters.");
    }
    private static Snapshot Query(IQueryApi api,uint flagOption,bool includeStrings) {
      uint[] ids=includeStrings ? new uint[]{flagOption,2,3,4} : new uint[]{flagOption};
      IntPtr memory=Marshal.AllocHGlobal(checked(OptionSize*ids.Length));
      // Initialize every union before the call; returned strings can exist on failure.
      for(int i=0;i<ids.Length;i++) {
        var option=new Option();option.Id=ids[i];
        Marshal.StructureToPtr(option,IntPtr.Add(memory,i*OptionSize),false);
      }
      try {
        var list=new OptionList {Size=(uint)ListSize,Connection=IntPtr.Zero,Count=(uint)ids.Length,ErrorIndex=0,Options=memory};
        uint length=(uint)ListSize;int error;
        if(!api.Query(ref list,ref length,out error)) throw new Win32Exception(error,"WinINet connection option query failed.");
        if(length!=(uint)ListSize || list.Size!=(uint)ListSize || list.Connection!=IntPtr.Zero || list.Count!=(uint)ids.Length || list.Options!=memory)
          throw new InvalidOperationException("WinINet option response changed its buffer contract.");
        var values=new Option[ids.Length];
        for(int i=0;i<ids.Length;i++) {
          values[i]=(Option)Marshal.PtrToStructure(IntPtr.Add(memory,i*OptionSize),typeof(Option));
          if(values[i].Id!=ids[i]) throw new InvalidOperationException("WinINet returned a different option identity.");
        }
        var result=new Snapshot {Flags=values[0].Value.Number};
        if(includeStrings) {
          result.ProxyServer=ReadText(values[1].Value.Text);
          result.ProxyBypass=ReadText(values[2].Value.Text);
          result.AutoConfigUrl=ReadText(values[3].Value.Text);
        }
        return result;
      } finally {
        Exception releaseError=null;
        var released=new HashSet<IntPtr>();
        // Ownership is determined by requested string slots, never returned IDs.
        for(int i=1;i<ids.Length;i++) {
          var value=(Option)Marshal.PtrToStructure(IntPtr.Add(memory,i*OptionSize),typeof(Option));
          if(value.Value.Text!=IntPtr.Zero && released.Add(value.Value.Text)) {
            try {api.FreeReturnedString(value.Value.Text);} catch(Exception ex) {releaseError=ex;}
          }
        }
        Marshal.FreeHGlobal(memory);
        if(releaseError!=null) throw new InvalidOperationException("Proxy query memory cleanup failed.",releaseError);
      }
    }
    public static Snapshot ReadWithApi(IQueryApi api) {
      if(api==null)throw new ArgumentNullException("api");
      ValidateLayout();
      uint option=10;int? fallback=null;Snapshot first;
      try {first=Query(api,option,false);}
      catch(Win32Exception error) {fallback=error.NativeErrorCode;option=1;first=Query(api,option,false);}
      Snapshot complete=Query(api,option,true);
      if(first.Flags!=complete.Flags)throw new InvalidOperationException("Proxy flags changed during collection; discard the observation.");
      complete.FlagsSource=option==10 ? "FlagsUi" : "FlagsFallback";
      complete.UiQueryError=fallback;return complete;
    }
    public static Snapshot ReadDefaultLan() {
      if(Environment.OSVersion.Platform!=PlatformID.Win32NT)throw new PlatformNotSupportedException("Windows WinINet is required.");
      return ReadWithApi(new NativeApi());
    }
  }
}
'@
}

function Get-RideUserProxyNativeSnapshot {
  Initialize-RideUserProxyNative
  [Ride.UserProxyInventoryV1.Reader]::ReadDefaultLan()
}

function Get-RideUserProxyObservation {
  <#
  .SYNOPSIS
    Capture default/LAN proxy options for an explicitly identified interactive user.
  .PARAMETER ExpectedComputerName
    Intended local machine name. No remote execution or network request is initiated.
  .PARAMETER ExpectedUserSid
    Intended execution account SID, checked before and after the native query.
  .PARAMETER ExpectedSessionId
    Intended nonzero interactive process session, not proof of desktop ownership.
  .PARAMETER ConnectionKind
    Explicit DefaultLan scope. Named RAS/VPN connections are not covered.
  .EXAMPLE
    Get-RideUserProxyObservation -ExpectedComputerName '<target>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -ConnectionKind DefaultLan
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Literal schema-1 proxy observation; query failures throw.
  .NOTES
    No policy/effective-route claim, PAC execution, refresh or saved-state mutation.
    Null strings remain distinct from empty strings. Native call duration is unbounded.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId,
    [Parameter(Mandatory)][ValidateSet('DefaultLan')][string]$ConnectionKind
  )
  $before=Get-RideUserProxyContext
  if($before.ComputerName -ine $ExpectedComputerName -or $before.UserSid -cne $ExpectedUserSid -or $before.SessionId -ne $ExpectedSessionId -or -not $before.UserInteractive){throw 'Proxy observation identity differs from the expected interactive machine/user/session.'}
  $started=[DateTime]::UtcNow.ToString('o')
  $native=Get-RideUserProxyNativeSnapshot
  if($null -eq $native -or $native.Flags -isnot [uint32] -or $native.FlagsSource -cnotin @('FlagsUi','FlagsFallback')){throw 'Invalid proxy option observation.'}
  foreach($name in @('ProxyServer','ProxyBypass','AutoConfigUrl')) {
    $value=$native.$name
    if($null -ne $value -and ($value -isnot [string] -or $value.Length -gt 32768 -or $value.Contains([string][char]0))){throw 'Invalid proxy string observation.'}
  }
  if(($native.FlagsSource -ceq 'FlagsUi' -and $null -ne $native.UiQueryError) -or ($native.FlagsSource -ceq 'FlagsFallback' -and $native.UiQueryError -isnot [int])){throw 'Invalid proxy flags-source observation.'}
  $after=Get-RideUserProxyContext
  foreach($field in @('ComputerName','UserSid','SessionId','UserInteractive')){if($before.$field -cne $after.$field){throw 'Proxy observation identity changed during collection; discard the observation.'}}
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserProxyObservation';Status='Captured'
    ComputerName=$before.ComputerName;UserSid=$before.UserSid;SessionId=[int]$before.SessionId
    ConnectionKind='DefaultLan';ConnectionName=$null;ConnectionIdentityVerified=$false
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o')
    Flags=$native.Flags;FlagsSource=$native.FlagsSource;UiQueryError=$native.UiQueryError
    DirectFlag=(($native.Flags -band 1) -ne 0);ManualProxyFlag=(($native.Flags -band 2) -ne 0)
    SetupScriptFlag=(($native.Flags -band 4) -ne 0);AutoDetectFlag=(($native.Flags -band 8) -ne 0)
    UnknownFlagBits=[uint32]($native.Flags -band [uint32]4294967280)
    ProxyServer=$native.ProxyServer;ProxyBypass=$native.ProxyBypass;AutoConfigUrl=$native.AutoConfigUrl
    PolicyStatus='NotInspected';EffectiveRoutingVerified=$false;DesktopVerified=$false
    Consistency='Sequential flag preflight and complete option query; not an atomic configuration snapshot'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}

Export-ModuleMember -Function Get-RideUserProxyObservation
