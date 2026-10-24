<#
.SYNOPSIS
  Observe the intended user's default/LAN WinINet proxy configuration.
.DESCRIPTION
  Queries documented connection options without decoding registry blobs, resolving
  a proxy or fetching a PAC file. Retains manual proxy, bypass, URL and all flag
  bits. A low-level default/LAN writer boundary is included with a bounded,
  read-only check for documented policies; durable state, compare-and-set and
  effective-route verification remain unimplemented.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7. Native acceptance
  remains pending. Requires an explicitly identified interactive user/session.
  File/environment inputs: Expected machine, user SID and session; no file reads.
  Recovery: The low-level writer is not a lifecycle; prior state is not retained.
  Version: 0.3.0.
  Changelog: 0.3.0: Detect documented proxy policies and refuse guarded writes when blocked/unknown.
  0.2.0: Add a ShouldProcess-gated WinINet writer boundary for flags/PAC URL.
  0.1.0: Add bounded default/LAN option capture and native memory ownership.
.LINK
  ../docs/user-proxy-inventory.md
.LINK
  https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw
.LINK
  https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options
.LINK
  https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-internetexplorer#disableproxychange
.LINK
  https://learn.microsoft.com/en-us/windows/client-management/mdm/networkproxy-csp#proxysettingsperuser
#>
$ErrorActionPreference='Stop'

function Get-RideUserProxyContext {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $process=[Diagnostics.Process]::GetCurrentProcess()
  try {
    [pscustomobject]@{ComputerName=[Environment]::MachineName;UserSid=$identity.User.Value;SessionId=$process.SessionId;UserInteractive=[Environment]::UserInteractive}
  } finally {$identity.Dispose();$process.Dispose()}
}

function Get-RideUserProxyCurrentIdentity {
  Get-RideUserProxyContext
}

function Get-RideUserProxyCurrentState {
  $context=Get-RideUserProxyContext
  if(-not $context.UserInteractive){throw 'The current process is not in an interactive user session.'}
  $observation=Get-RideUserProxyObservation -ExpectedComputerName $context.ComputerName -ExpectedUserSid $context.UserSid -ExpectedSessionId $context.SessionId -ConnectionKind DefaultLan
  [pscustomobject]@{Available=$true;Identity=$context;Observation=$observation}
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
  public interface IWriteApi {
    bool Set(ref OptionList options, ref uint length, out int error);
    bool Notify(uint option, out int error);
  }
  internal sealed class NativeApi : IQueryApi, IWriteApi {
    [DllImport("wininet.dll", ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetQueryOptionW(IntPtr handle, uint option, ref OptionList list, ref uint length);
    [DllImport("wininet.dll", ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOptionW(IntPtr handle, uint option, ref OptionList list, uint length);
    [DllImport("wininet.dll", ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOptionW(IntPtr handle, uint option, IntPtr buffer, uint length);
    [DllImport("kernel32.dll", ExactSpelling=true)] private static extern IntPtr GlobalFree(IntPtr memory);
    public bool Query(ref OptionList options, ref uint length, out int error) {
      bool result=InternetQueryOptionW(IntPtr.Zero,75,ref options,ref length);
      error=result ? 0 : Marshal.GetLastWin32Error(); return result;
    }
    public void FreeReturnedString(IntPtr text) {
      if(GlobalFree(text)!=IntPtr.Zero) throw new InvalidOperationException("Unable to release returned proxy option memory.");
    }
    public bool Set(ref OptionList options, ref uint length, out int error) {
      bool result=InternetSetOptionW(IntPtr.Zero,75,ref options,length);
      error=result ? 0 : Marshal.GetLastWin32Error(); return result;
    }
    public bool Notify(uint option, out int error) {
      bool result=InternetSetOptionW(IntPtr.Zero,option,IntPtr.Zero,0);
      error=result ? 0 : Marshal.GetLastWin32Error(); return result;
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
  public sealed class WriteResult {
    public bool ConfigurationSet; public int ConfigurationError;
    public bool SettingsChangedNotified; public int SettingsChangedError;
    public bool Refreshed; public int RefreshError;
  }
  public static class Writer {
    private static readonly int OptionSize=Marshal.SizeOf(typeof(Option));
    private static readonly int ListSize=Marshal.SizeOf(typeof(OptionList));
    public static WriteResult WriteWithApi(IWriteApi api,uint flags,string autoConfigUrl,bool ownsAutoConfigUrl) {
      if(api==null)throw new ArgumentNullException("api");
      Reader.ValidateLayout();
      if(ownsAutoConfigUrl && (String.IsNullOrEmpty(autoConfigUrl) || autoConfigUrl.Length>32768 || autoConfigUrl.IndexOf('\0')>=0))
        throw new ArgumentException("Owned automatic-configuration URL must be a bounded nonempty string.","autoConfigUrl");
      int count=ownsAutoConfigUrl ? 2 : 1;
      IntPtr options=Marshal.AllocHGlobal(checked(OptionSize*count));
      IntPtr url=IntPtr.Zero;
      try {
        var flagOption=new Option();flagOption.Id=1;flagOption.Value.Number=flags;
        Marshal.StructureToPtr(flagOption,options,false);
        if(ownsAutoConfigUrl) {
          url=Marshal.StringToHGlobalUni(autoConfigUrl);
          var urlOption=new Option();urlOption.Id=4;urlOption.Value.Text=url;
          Marshal.StructureToPtr(urlOption,IntPtr.Add(options,OptionSize),false);
        }
        var list=new OptionList {Size=(uint)ListSize,Connection=IntPtr.Zero,Count=(uint)count,ErrorIndex=0,Options=options};
        uint length=(uint)ListSize;int error;
        var result=new WriteResult();
        result.ConfigurationSet=api.Set(ref list,ref length,out error);result.ConfigurationError=error;
        if(!result.ConfigurationSet)return result;
        result.SettingsChangedNotified=api.Notify(39,out error);result.SettingsChangedError=error;
        result.Refreshed=api.Notify(37,out error);result.RefreshError=error;
        return result;
      } finally {
        if(url!=IntPtr.Zero)Marshal.FreeHGlobal(url);
        Marshal.FreeHGlobal(options);
      }
    }
    public static WriteResult SetDefaultLan(uint flags,string autoConfigUrl,bool ownsAutoConfigUrl) {
      if(Environment.OSVersion.Platform!=PlatformID.Win32NT)throw new PlatformNotSupportedException("Windows WinINet is required.");
      return WriteWithApi(new NativeApi(),flags,autoConfigUrl,ownsAutoConfigUrl);
    }
  }
}
'@
}

function Get-RideUserProxyNativeSnapshot {
  Initialize-RideUserProxyNative
  [Ride.UserProxyInventoryV1.Reader]::ReadDefaultLan()
}

function Invoke-RideUserProxyNativeWrite {
  param([uint32]$Flags,[AllowNull()][string]$AutoConfigUrl,[bool]$OwnsAutoConfigUrl,$Api)
  Initialize-RideUserProxyNative
  if($null -ne $Api){return [Ride.UserProxyInventoryV1.Writer]::WriteWithApi($Api,$Flags,$AutoConfigUrl,$OwnsAutoConfigUrl)}
  [Ride.UserProxyInventoryV1.Writer]::SetDefaultLan($Flags,$AutoConfigUrl,$OwnsAutoConfigUrl)
}

function Read-RideUserProxyPolicyValue {
  param([ValidateSet('CurrentUser','LocalMachine')][string]$Hive,[string]$SubKey,[string]$Name)
  $root=if($Hive -ceq 'CurrentUser'){[Microsoft.Win32.Registry]::CurrentUser}else{[Microsoft.Win32.Registry]::LocalMachine}
  $key=$root.OpenSubKey($SubKey,$false)
  try {
    if($null -eq $key){return [pscustomobject]@{Hive=$Hive;SubKey=$SubKey;Name=$Name;Exists=$false;Kind=$null;Value=$null}}
    $names=@($key.GetValueNames()|Where-Object {$_ -ieq $Name})
    if($names.Count -gt 1){throw 'Proxy policy value identity is ambiguous.'}
    if(-not $names.Count){return [pscustomobject]@{Hive=$Hive;SubKey=$SubKey;Name=$Name;Exists=$false;Kind=$null;Value=$null}}
    $actual=$names[0]
    [pscustomobject]@{Hive=$Hive;SubKey=$SubKey;Name=$Name;Exists=$true;Kind=$key.GetValueKind($actual).ToString();Value=$key.GetValue($actual,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
  } finally {if($null -ne $key){$key.Dispose()}}
}

function Get-RideUserProxyPolicyObservation {
  [CmdletBinding()]
  param()
  $restrictionPath='Software\Policies\Microsoft\Internet Explorer\Control Panel'
  $scopePath='Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
  $values=@(
    (Read-RideUserProxyPolicyValue -Hive CurrentUser -SubKey $restrictionPath -Name Proxy),
    (Read-RideUserProxyPolicyValue -Hive LocalMachine -SubKey $restrictionPath -Name Proxy),
    (Read-RideUserProxyPolicyValue -Hive LocalMachine -SubKey $scopePath -Name ProxySettingsPerUser)
  )
  $unknown=[Collections.Generic.List[string]]::new()
  $blocked=[Collections.Generic.List[string]]::new()
  foreach($value in $values){
    if(-not $value.Exists){continue}
    if($value.Kind -cne 'DWord' -or $value.Value -isnot [int] -or $value.Value -lt 0){$unknown.Add("$($value.Hive)\$($value.SubKey)\$($value.Name)");continue}
    if($value.Name -ceq 'Proxy' -and $value.Value -ne 0){$blocked.Add("$($value.Hive)\$($value.SubKey)\$($value.Name)")}
    if($value.Name -ceq 'ProxySettingsPerUser' -and $value.Value -eq 0){$blocked.Add("$($value.Hive)\$($value.SubKey)\$($value.Name)")}
    if($value.Name -ceq 'ProxySettingsPerUser' -and $value.Value -notin @(0,1)){$unknown.Add("$($value.Hive)\$($value.SubKey)\$($value.Name)")}
  }
  $status=if($blocked.Count){'Blocked'}elseif($unknown.Count){'Unknown'}else{'Clear'}
  [pscustomobject]@{KnownPolicyStatus=$status;InspectedValues=$values;BlockingValues=@($blocked);UnknownValues=@($unknown);Scope='Documented WinINet proxy-change and per-user/per-machine policy values; not a complete effective-policy inventory'}
}

function Set-RideUserProxyNativeConfiguration {
  <#
  .SYNOPSIS
    Write selected default/LAN WinINet flag and PAC URL values for the current user.
  .DESCRIPTION
    Low-level writer boundary. Requires an explicit current interactive computer,
    SID and session, refuses detected or unreadable documented proxy policies,
    then honors ShouldProcess. It does not capture prior state, perform atomic
    compare-and-set or establish all effective policy; use only from a lifecycle
    that supplies those controls and verifies readback/recovery.
  .PARAMETER Flags
    Complete desired INTERNET_PER_CONN_FLAGS bitmask, including preserved bits.
  .PARAMETER AutoConfigUrl
    Exact HTTP/HTTPS PAC URL to write when OwnsAutoConfigUrl is true.
  .PARAMETER OwnsAutoConfigUrl
    Whether this write includes the URL field; false writes only the flags.
  .PARAMETER ExpectedComputerName
    Current local computer name expected by the caller.
  .PARAMETER ExpectedUserSid
    Current user SID expected by the caller.
  .PARAMETER ExpectedSessionId
    Current interactive session expected by the caller.
  .EXAMPLE
    Set-RideUserProxyNativeConfiguration -Flags 13 -AutoConfigUrl 'https://proxy.example/pac' -OwnsAutoConfigUrl $true -ExpectedComputerName $env:COMPUTERNAME -ExpectedUserSid $sid -ExpectedSessionId $session -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Configuration-write, settings-changed notification and refresh outcomes.
  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Version: 0.3.0. Policy inspection reads only documented values. No RAS,
    WinHTTP, PAC retrieval or network connection is used.
  .LINK
    https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param(
    [Parameter(Mandatory)][ValidateRange(0,4294967295)][uint32]$Flags,
    [AllowNull()][string]$AutoConfigUrl,
    [Parameter(Mandatory)][bool]$OwnsAutoConfigUrl,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9]+(?:-[0-9]+)+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  $context=Get-RideUserProxyContext
  if($context.ComputerName -ine $ExpectedComputerName -or $context.UserSid -cne $ExpectedUserSid -or $context.SessionId -ne $ExpectedSessionId -or -not $context.UserInteractive){throw 'Proxy write identity differs from the expected interactive machine/user/session.'}
  $policy=Get-RideUserProxyPolicyObservation
  if($policy.KnownPolicyStatus -cne 'Clear'){throw "Proxy write refused because documented policy status is $($policy.KnownPolicyStatus)."}
  $target="$($context.ComputerName) / $($context.UserSid) / session $($context.SessionId) / DefaultLan"
  if(-not $PSCmdlet.ShouldProcess($target,'Write selected WinINet proxy flags/PAC URL and notify refresh')){return [pscustomobject]@{Status='WhatIf';ConfigurationSet=$false;SettingsChangedNotified=$false;Refreshed=$false}}
  Invoke-RideUserProxyNativeWrite -Flags $Flags -AutoConfigUrl $AutoConfigUrl -OwnsAutoConfigUrl $OwnsAutoConfigUrl
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

Export-ModuleMember -Function Get-RideUserProxyObservation,Get-RideUserProxyPolicyObservation,Get-RideUserProxyCurrentIdentity,Get-RideUserProxyCurrentState,Set-RideUserProxyNativeConfiguration
