<#
.SYNOPSIS
  Load the bounded WLAN profile API adapter used by wireless lifecycle handlers.
.DESCRIPTION
  Loading the adapter makes no WLAN call. The adapter isolates native profile
  list/read/set/delete/position calls, numeric errors and allocation cleanup.
  It is a provider boundary, not an independently recoverable import command.
  Lifecycle callers must capture durable recovery and validate identity, ownership,
  permissions, profile order and ShouldProcess before invoking a writer.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: WLAN service/interface for native use; none for loading the type.
  Secrets: Read can return encrypted XML or explicitly requested plaintext keys.
  Keep both forms private; never write XML to ordinary output or test evidence.
  Recovery: No state is captured here. Native acceptance remains pending.
  Version: 0.1.0.
  Changelog: 0.1.0: Add a fakeable native boundary for profile lifecycle and recovery.
.LINK
  ../docs/wireless-profile-inventory.md
#>
$ErrorActionPreference='Stop'

function Initialize-RideWirelessProfileNative {
  <#
  .SYNOPSIS
    Load the WLAN profile provider without querying or changing Windows.
  .EXAMPLE
    Initialize-RideWirelessProfileNative
  .INPUTS
    None.
  .OUTPUTS
    None. Loads Ride.WirelessProfileV1.Client for lifecycle handlers.
  .NOTES
    The provider requires a guarded lifecycle caller; no standalone import is exposed.
  #>
  [CmdletBinding()]
  param()
  if ('Ride.WirelessProfileV1.Client' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Ride.WirelessProfileV1 {
  public interface IProfileApi {
    uint Open(out uint version,out IntPtr handle);
    uint Close(IntPtr handle);
    void Free(IntPtr buffer);
    uint List(IntPtr handle,Guid id,out IntPtr buffer);
    uint Read(IntPtr handle,Guid id,string name,out IntPtr xml,ref uint flags,out uint access);
    uint Set(IntPtr handle,Guid id,string xml,string security,bool overwrite,out uint reason);
    uint Delete(IntPtr handle,Guid id,string name);
    uint Position(IntPtr handle,Guid id,string name,uint position);
  }
  internal sealed class NativeApi : IProfileApi {
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanOpenHandle(uint version,IntPtr reserved,out uint negotiated,out IntPtr handle);
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanCloseHandle(IntPtr handle,IntPtr reserved);
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void WlanFreeMemory(IntPtr buffer);
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanGetProfileList(IntPtr handle,ref Guid id,IntPtr reserved,out IntPtr buffer);
    [DllImport("wlanapi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanGetProfile(IntPtr handle,ref Guid id,string name,IntPtr reserved,out IntPtr xml,ref uint flags,out uint access);
    [DllImport("wlanapi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanSetProfile(IntPtr handle,ref Guid id,uint flags,string xml,string security,[MarshalAs(UnmanagedType.Bool)]bool overwrite,IntPtr reserved,out uint reason);
    [DllImport("wlanapi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanDeleteProfile(IntPtr handle,ref Guid id,string name,IntPtr reserved);
    [DllImport("wlanapi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanSetProfilePosition(IntPtr handle,ref Guid id,string name,uint position,IntPtr reserved);
    public uint Open(out uint version,out IntPtr handle) { return WlanOpenHandle(2,IntPtr.Zero,out version,out handle); }
    public uint Close(IntPtr handle) { return WlanCloseHandle(handle,IntPtr.Zero); }
    public void Free(IntPtr buffer) { WlanFreeMemory(buffer); }
    public uint List(IntPtr handle,Guid id,out IntPtr buffer) { return WlanGetProfileList(handle,ref id,IntPtr.Zero,out buffer); }
    public uint Read(IntPtr handle,Guid id,string name,out IntPtr xml,ref uint flags,out uint access) { return WlanGetProfile(handle,ref id,name,IntPtr.Zero,out xml,ref flags,out access); }
    // Only all-user profiles are written. Policy and per-user flags are never set.
    public uint Set(IntPtr handle,Guid id,string xml,string security,bool overwrite,out uint reason) { return WlanSetProfile(handle,ref id,0,xml,security,overwrite,IntPtr.Zero,out reason); }
    public uint Delete(IntPtr handle,Guid id,string name) { return WlanDeleteProfile(handle,ref id,name,IntPtr.Zero); }
    public uint Position(IntPtr handle,Guid id,string name,uint position) { return WlanSetProfilePosition(handle,ref id,name,position,IntPtr.Zero); }
  }
  public sealed class ProfileRow { public string Name; public uint Flags; public int Position; }
  public sealed class ProfileContent { public bool Present; public string Xml; public uint Flags; public uint GrantedAccess; }
  public static class Client {
    private const int MaxXml=262144;
    private static void Check(uint result,string operation) {
      if(result!=0)throw new Win32Exception(unchecked((int)result),operation+" failed with native code "+result);
    }
    private static void Identity(Guid id,string name) {
      if(id==Guid.Empty)throw new ArgumentException("A nonempty WLAN interface GUID is required.");
      if(name!=null && (name.Length<1 || name.Length>255 || name.IndexOf('\0')>=0))throw new ArgumentException("Invalid WLAN profile identity.");
    }
    private static void Open(IProfileApi api,out IntPtr handle) {
      uint version;Check(api.Open(out version,out handle),"WlanOpenHandle");
      if(handle==IntPtr.Zero || version!=2)throw new InvalidOperationException("WLAN version-2 handle unavailable.");
    }
    private static string Text(IntPtr at,int maximum) {
      if(at==IntPtr.Zero)throw new InvalidOperationException("WLAN returned no text buffer.");
      for(int n=0;n<=maximum;n++) {
        if(Marshal.ReadInt16(at,checked(n*2))==0) {
          string value=Marshal.PtrToStringUni(at,n);
          new System.Text.UnicodeEncoding(false,false,true).GetByteCount(value);
          return value;
        }
      }
      throw new InvalidOperationException("WLAN text exceeds its bound.");
    }
    public static ProfileRow[] ListWithApi(IProfileApi api,Guid id) {
      Identity(id,null);IntPtr handle=IntPtr.Zero,buffer=IntPtr.Zero;
      try {
        Open(api,out handle);Check(api.List(handle,id,out buffer),"WlanGetProfileList");
        if(buffer==IntPtr.Zero)throw new InvalidOperationException("WLAN returned no list buffer.");
        uint count=unchecked((uint)Marshal.ReadInt32(buffer));
        if(count>256)throw new InvalidOperationException("WLAN profile count exceeds its bound.");
        var result=new List<ProfileRow>();var seen=new HashSet<string>(StringComparer.Ordinal);
        for(int i=0;i<count;i++) {
          IntPtr row=IntPtr.Add(buffer,checked(8+i*516));string name=Text(row,255);
          if(name.Length==0 || !seen.Add(name))throw new InvalidOperationException("Empty or duplicate WLAN profile identity.");
          result.Add(new ProfileRow{Name=name,Flags=unchecked((uint)Marshal.ReadInt32(row,512)),Position=i});
        }
        return result.ToArray();
      } finally { try {if(buffer!=IntPtr.Zero)api.Free(buffer);} finally {if(handle!=IntPtr.Zero)Check(api.Close(handle),"WlanCloseHandle");} }
    }
    public static ProfileContent ReadWithApi(IProfileApi api,Guid id,string name,bool plaintext) {
      if(name==null)throw new ArgumentNullException("name");Identity(id,name);
      IntPtr handle=IntPtr.Zero,buffer=IntPtr.Zero;uint flags=plaintext ? 4u : 0u,access;
      try {
        Open(api,out handle);uint error=api.Read(handle,id,name,out buffer,ref flags,out access);
        if(error==1168)return new ProfileContent{Present=false};
        Check(error,"WlanGetProfile");string xml=Text(buffer,MaxXml);
        if(xml.Length==0)throw new InvalidOperationException("WLAN returned empty profile XML.");
        return new ProfileContent{Present=true,Xml=xml,Flags=flags,GrantedAccess=access};
      } finally { try {if(buffer!=IntPtr.Zero)api.Free(buffer);} finally {if(handle!=IntPtr.Zero)Check(api.Close(handle),"WlanCloseHandle");} }
    }
    public static void SetWithApi(IProfileApi api,Guid id,string xml,string security,bool overwrite) {
      Identity(id,null);
      if(string.IsNullOrEmpty(xml) || xml.Length>MaxXml || xml.IndexOf('\0')>=0)throw new ArgumentException("Invalid bounded WLAN XML input.");
      if(security!=null && (security.Length==0 || security.Length>8192 || security.IndexOf('\0')>=0))throw new ArgumentException("Invalid WLAN security descriptor input.");
      IntPtr handle=IntPtr.Zero;
      try { Open(api,out handle);uint reason;uint error=api.Set(handle,id,xml,security,overwrite,out reason);if(error!=0)throw new Win32Exception(unchecked((int)error),"WlanSetProfile failed with native code "+error+" and reason "+reason); }
      finally {if(handle!=IntPtr.Zero)Check(api.Close(handle),"WlanCloseHandle");}
    }
    public static void DeleteWithApi(IProfileApi api,Guid id,string name) {
      if(name==null)throw new ArgumentNullException("name");Identity(id,name);IntPtr handle=IntPtr.Zero;
      try {Open(api,out handle);Check(api.Delete(handle,id,name),"WlanDeleteProfile");}
      finally {if(handle!=IntPtr.Zero)Check(api.Close(handle),"WlanCloseHandle");}
    }
    public static void PositionWithApi(IProfileApi api,Guid id,string name,uint position) {
      if(name==null)throw new ArgumentNullException("name");Identity(id,name);if(position>255)throw new ArgumentException("WLAN position exceeds its bound.");IntPtr handle=IntPtr.Zero;
      try {Open(api,out handle);Check(api.Position(handle,id,name,position),"WlanSetProfilePosition");}
      finally {if(handle!=IntPtr.Zero)Check(api.Close(handle),"WlanCloseHandle");}
    }
    private static IProfileApi Native() {if(Environment.OSVersion.Platform!=PlatformID.Win32NT)throw new PlatformNotSupportedException("Windows WLAN is required.");return new NativeApi();}
    public static ProfileRow[] List(Guid id) {return ListWithApi(Native(),id);}
    public static ProfileContent Read(Guid id,string name,bool plaintext) {return ReadWithApi(Native(),id,name,plaintext);}
    public static void Set(Guid id,string xml,string security,bool overwrite) {SetWithApi(Native(),id,xml,security,overwrite);}
    public static void Delete(Guid id,string name) {DeleteWithApi(Native(),id,name);}
    public static void Position(Guid id,string name,uint position) {PositionWithApi(Native(),id,name,position);}
  }
}
'@
}

Export-ModuleMember -Function Initialize-RideWirelessProfileNative
