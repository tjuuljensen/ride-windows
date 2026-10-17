<#
.SYNOPSIS
  Observe wireless interface identities and stored profile names without secrets.
.DESCRIPTION
  Uses only WLAN interface/profile-list APIs. Does not retrieve profile XML, keys,
  EAP data, scan results or active SSIDs, and never connects, imports or removes a
  profile. Import and saved-data completion make no native calls. Native provider
  and hardware acceptance remain pending; this is not a recoverable profile export.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Available Windows WLAN service/API and explicit intended user/session.
  File/environment inputs: Expected machine/build/edition/SID/session; no file I/O.
  Recovery: Observation only. Native allocations and the client handle are released.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded, secret-free profile-list capture and saved lookup.
.LINK
  ../docs/wireless-profile-inventory.md
#>
$ErrorActionPreference='Stop'

function Get-RideWirelessContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $process=[Diagnostics.Process]::GetCurrentProcess()
  try {
    [pscustomobject]@{
      ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber
      EditionId=[string]$version.EditionID;UpdateBuildRevision=$version.UBR
      NativeProcess=([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)
      UserSid=$identity.User.Value;SessionId=$process.SessionId;UserInteractive=[Environment]::UserInteractive
    }
  }finally{$identity.Dispose();$process.Dispose()}
}

function Initialize-RideWirelessNative {
  if('Ride.WirelessInventoryV1.Reader' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace Ride.WirelessInventoryV1 {
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
  public struct InterfaceInfo {
    public Guid Id;
    [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string Description;
    public uint State;
  }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
  public struct ProfileInfo {
    [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string Name;
    public uint Flags;
  }
  public interface IReadApi {
    uint Open(out uint version,out IntPtr handle);
    uint Interfaces(IntPtr handle,out IntPtr list);
    uint Profiles(IntPtr handle,Guid id,out IntPtr list);
    void Free(IntPtr memory);
    uint Close(IntPtr handle);
  }
  internal sealed class NativeApi : IReadApi {
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanOpenHandle(uint version,IntPtr reserved,out uint negotiated,out IntPtr handle);
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanEnumInterfaces(IntPtr handle,IntPtr reserved,out IntPtr list);
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanGetProfileList(IntPtr handle,ref Guid id,IntPtr reserved,out IntPtr list);
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void WlanFreeMemory(IntPtr memory);
    [DllImport("wlanapi.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WlanCloseHandle(IntPtr handle,IntPtr reserved);
    public uint Open(out uint version,out IntPtr handle) { return WlanOpenHandle(2,IntPtr.Zero,out version,out handle); }
    public uint Interfaces(IntPtr handle,out IntPtr list) { return WlanEnumInterfaces(handle,IntPtr.Zero,out list); }
    public uint Profiles(IntPtr handle,Guid id,out IntPtr list) { return WlanGetProfileList(handle,ref id,IntPtr.Zero,out list); }
    public void Free(IntPtr memory) { WlanFreeMemory(memory); }
    public uint Close(IntPtr handle) { return WlanCloseHandle(handle,IntPtr.Zero); }
  }
  public sealed class ProfileRow { public int Position; public string Name; public uint Flags; }
  public sealed class InterfaceRow { public string Id; public string Description; public uint State; public ProfileRow[] Profiles; }
  public static class Reader {
    public static void ValidateLayout() {
      if(Marshal.SizeOf(typeof(InterfaceInfo))!=532 || Marshal.OffsetOf(typeof(InterfaceInfo),"Description").ToInt32()!=16 || Marshal.OffsetOf(typeof(InterfaceInfo),"State").ToInt32()!=528 ||
         Marshal.SizeOf(typeof(ProfileInfo))!=516 || Marshal.OffsetOf(typeof(ProfileInfo),"Flags").ToInt32()!=512)
        throw new PlatformNotSupportedException("Unexpected WLAN fixed-array layout.");
    }
    private static void Check(uint error,string operation) {
      if(error!=0)throw new Win32Exception(unchecked((int)error),operation+" failed with code "+error);
    }
    private static uint Count(IntPtr memory,uint limit) {
      if(memory==IntPtr.Zero)throw new InvalidOperationException("WLAN returned no list buffer.");
      uint count=unchecked((uint)Marshal.ReadInt32(memory));
      if(count>limit)throw new InvalidOperationException("WLAN list exceeds its observation bound.");
      // dwIndex is application bookkeeping, not connection/selected-profile state.
      return count;
    }
    private static string Text(IntPtr memory,bool required) {
      for(int i=0;i<256;i++) {
        if(Marshal.ReadInt16(memory,i*2)==0) {
          string value=Marshal.PtrToStringUni(memory,i);
          if(required && value.Length==0)throw new InvalidOperationException("Empty WLAN profile name.");
          new UnicodeEncoding(false,false,true).GetByteCount(value);
          return value;
        }
      }
      throw new InvalidOperationException("WLAN text is not terminated within its fixed buffer.");
    }
    private static ProfileRow[] ReadProfiles(IReadApi api,IntPtr handle,Guid id) {
      IntPtr memory=IntPtr.Zero;
      try {
        Check(api.Profiles(handle,id,out memory),"WlanGetProfileList");
        uint count=Count(memory,256);var rows=new List<ProfileRow>();var names=new HashSet<string>(StringComparer.Ordinal);
        for(int i=0;i<count;i++) {
          IntPtr item=IntPtr.Add(memory,checked(8+i*516));string name=Text(item,true);
          if(!names.Add(name))throw new InvalidOperationException("Duplicate WLAN profile name.");
          rows.Add(new ProfileRow {Position=i,Name=name,Flags=unchecked((uint)Marshal.ReadInt32(item,512))});
        }
        return rows.ToArray();
      } finally { if(memory!=IntPtr.Zero)api.Free(memory); }
    }
    public static InterfaceRow[] ReadWithApi(IReadApi api) {
      if(api==null)throw new ArgumentNullException("api");ValidateLayout();
      IntPtr handle=IntPtr.Zero;IntPtr memory=IntPtr.Zero;
      try {
        uint version;Check(api.Open(out version,out handle),"WlanOpenHandle");
        if(handle==IntPtr.Zero || (version & 65535)!=2)throw new InvalidOperationException("WLAN requires a valid version-2 client handle.");
        Check(api.Interfaces(handle,out memory),"WlanEnumInterfaces");
        uint count=Count(memory,64);var rows=new List<InterfaceRow>();var ids=new HashSet<Guid>();
        for(int i=0;i<count;i++) {
          IntPtr item=IntPtr.Add(memory,checked(8+i*532));Guid id=(Guid)Marshal.PtrToStructure(item,typeof(Guid));
          if(id==Guid.Empty || !ids.Add(id))throw new InvalidOperationException("Missing or duplicate WLAN interface identity.");
          rows.Add(new InterfaceRow {Id=id.ToString("D"),Description=Text(IntPtr.Add(item,16),false),State=unchecked((uint)Marshal.ReadInt32(item,528)),Profiles=ReadProfiles(api,handle,id)});
        }
        return rows.ToArray();
      } finally {
        // Release the handle even if a test/provider reports a memory-release error.
        try {if(memory!=IntPtr.Zero)api.Free(memory);}
        finally {if(handle!=IntPtr.Zero)Check(api.Close(handle),"WlanCloseHandle");}
      }
    }
    public static InterfaceRow[] Read() {
      if(Environment.OSVersion.Platform!=PlatformID.Win32NT)throw new PlatformNotSupportedException("Windows WLAN is required.");
      return ReadWithApi(new NativeApi());
    }
  }
}
'@
}

function Get-RideWirelessNativeRows {
  Initialize-RideWirelessNative
  [Ride.WirelessInventoryV1.Reader]::Read()
}

function ConvertTo-RideWirelessGuid {
  param($Value)
  if($Value -isnot [string] -or $Value -cnotmatch '^(?:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\})$' -or [guid]$Value -eq [guid]::Empty){throw 'Invalid wireless interface GUID.'}
  ([guid]$Value).ToString('D')
}

function ConvertTo-RideWirelessRows {
  param($Rows)
  if($null -eq $Rows -or $Rows -is [string] -or $Rows -isnot [Collections.IEnumerable]){throw 'Wireless capture requires a row collection.'}
  $interfaces=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($row in $Rows){
    if($interfaces.Count -ge 64){throw 'Wireless interface bound exceeded.'}
    $id=ConvertTo-RideWirelessGuid $row.Id
    if(-not $seen.Add($id)){throw 'Duplicate wireless interface identity.'}
    if($row.Description -isnot [string] -or $row.Description.Length -gt 255 -or $row.Description.Contains([string][char]0)){throw 'Invalid wireless interface description.'}
    if($null -eq $row.State -or $row.State -is [bool] -or $row.State -is [string] -or $row.State -lt 0 -or $row.State -gt [uint32]::MaxValue -or [decimal]$row.State -ne [uint32]$row.State){throw 'Invalid wireless interface state.'}
    if($null -eq $row.Profiles -or $row.Profiles -is [string] -or $row.Profiles -isnot [Collections.IEnumerable]){throw 'Wireless profiles require a collection.'}
    $profiles=[Collections.Generic.List[object]]::new();$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($profile in $row.Profiles){
      if($profiles.Count -ge 256 -or $null -eq $profile.Position -or $profile.Position -is [bool] -or $profile.Position -is [string] -or $profile.Position -ne $profiles.Count){throw 'Invalid wireless profile order or bound.'}
      if($profile.Name -isnot [string] -or [string]::IsNullOrEmpty($profile.Name) -or $profile.Name.Length -gt 255 -or $profile.Name.Contains([string][char]0) -or -not $names.Add($profile.Name)){throw 'Invalid or duplicate wireless profile name.'}
      $flags=$profile.Flags
      if($null -eq $flags -or $flags -is [string] -or $flags -is [bool] -or $flags -lt 0 -or $flags -gt [uint32]::MaxValue -or [decimal]$flags -ne [uint32]$flags){throw 'Invalid wireless profile flags.'}
      $profiles.Add([pscustomobject]@{Position=$profiles.Count;Name=$profile.Name;Flags=[uint32]$flags;GroupPolicyFlag=([bool]($flags -band 1));PerUserFlag=([bool]($flags -band 2));UnknownFlagBits=([uint32]$flags -band [uint32]4294967292);MutationAuthorized=$false})
    }
    $interfaces.Add([pscustomobject]@{Id=$id;Description=$row.Description;State=[uint32]$row.State;Profiles=@($profiles.ToArray())})
  }
  ,@($interfaces.ToArray())
}

function Get-RideWirelessProfileInventory {
  <#
  .SYNOPSIS
    Capture visible WLAN interface/profile-list metadata for an expected user/session.
  .PARAMETER ExpectedComputerName
    Independently supplied local target name; remote collection is unsupported.
  .PARAMETER ExpectedBuild
    Exact expected Windows build number.
  .PARAMETER ExpectedEditionId
    Expected Windows EditionID.
  .PARAMETER ExpectedUserSid
    Intended interactive execution account SID; no other-user profile query.
  .PARAMETER ExpectedSessionId
    Intended nonzero process session.
  .EXAMPLE
    Get-RideWirelessProfileInventory -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 observation, including Captured-empty or Unavailable.
  .NOTES
    Maximum 64 interfaces and 256 profiles each; native duration has no hard timeout.
    Any collection failure discards partial rows. Profile names may reveal private
    network names; no SSID, profile XML, key or authentication material is requested.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  $context=Get-RideWirelessContext
  if(-not $context.NativeProcess -or -not $context.UserInteractive -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId -or $context.UserSid -ine $ExpectedUserSid -or $context.SessionId -ne $ExpectedSessionId){throw 'Wireless inventory target differs from the expected native machine/build/edition/user/session.'}
  $started=[DateTime]::UtcNow.ToString('o');$status='Unavailable';$rows=$null;$errorId=$null;$nativeError=$null
  try{$rows=ConvertTo-RideWirelessRows @(Get-RideWirelessNativeRows);$status='Captured'}
  catch{
    $rows=$null;$errorId=$_.Exception.GetType().FullName
    $cause=$_.Exception
    while($cause){if($cause -is [ComponentModel.Win32Exception]){$nativeError=$cause.NativeErrorCode;break};$cause=$cause.InnerException}
  }
  $after=Get-RideWirelessContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','NativeProcess','UserSid','SessionId','UserInteractive')){if($after.$field -cne $context.$field){throw 'Wireless inventory target changed during collection; discard the observation.'}}
  [pscustomobject]@{
    SchemaVersion=1;Kind='WirelessProfileObservation';WindowsContext=$context;Status=$status
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');Interfaces=$rows;ErrorId=$errorId;NativeError=$nativeError
    Coverage='Enabled WLAN interfaces and basic profile lists visible to this execution account'
    Consistency='Sequential observation; interface/profile membership can change during or after collection'
    SecretsRequested=$false;ProfileContentCaptured=$false;ConnectionVerified=$false;ReadyForMutation=$false;RecoverySupported=$false
  }
}

function Find-RideWirelessProfileObservation {
  <#
  .SYNOPSIS
    Find one exact profile name on an explicit interface in saved metadata.
  .PARAMETER Inventory
    Schema-1 WirelessProfileObservation or its saved JSON representation.
  .PARAMETER InterfaceId
    Explicit interface GUID; completion reads only the supplied inventory.
  .PARAMETER ProfileName
    Case-sensitive exact profile name, not an SSID or display alias. Completion
    filters the selected saved interface without querying or connecting to Windows.
  .EXAMPLE
    Find-RideWirelessProfileObservation -Inventory $saved -InterfaceId '<interface-guid>' -ProfileName 'Reviewed profile'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Observed, InterfaceNotObserved, NotObserved or Unavailable.
  .NOTES
    Names are mutable local identities. No matching by SSID, fuzzy name or default
    adapter, and no recoverability/permission claim follows from a matching row.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $data=$fakeBoundParameters.Inventory
        if($data.SchemaVersion -ne 1 -or $data.Kind -cne 'WirelessProfileObservation' -or $data.Status -cne 'Captured' -or @($data.Interfaces).Count -gt 64){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $prefix=([string]$wordToComplete).Trim("'",'"','{','}')
        foreach($row in @($data.Interfaces)){
          $id=[guid]::Empty
          if([guid]::TryParse([string]$row.Id,[ref]$id) -and $id -ne [guid]::Empty){$text=$id.ToString('D');if($text.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($text)){[Management.Automation.CompletionResult]::new($text,$text,'ParameterValue',$text)}}
        }
      }catch{return}
    })][string]$InterfaceId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $data=$fakeBoundParameters.Inventory;$id=[guid]::Empty
        if($data.SchemaVersion -ne 1 -or $data.Kind -cne 'WirelessProfileObservation' -or $data.Status -cne 'Captured' -or @($data.Interfaces).Count -gt 64 -or -not [guid]::TryParse([string]$fakeBoundParameters.InterfaceId,[ref]$id) -or $id -eq [guid]::Empty){return}
        $matches=@($data.Interfaces|Where-Object {$_.Id -ieq $id.ToString('D')})
        if($matches.Count -ne 1 -or @($matches[0].Profiles).Count -gt 256){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$prefix=([string]$wordToComplete).Trim("'",'"')
        foreach($row in @($matches[0].Profiles)){
          $name=$row.Name
          if($name -is [string] -and $name.Length -gt 0 -and $name.Length -le 255 -and $name -notmatch '[\x00-\x1f\x7f]' -and $name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($name)){[Management.Automation.CompletionResult]::new(("'"+$name.Replace("'","''")+"'"),$name,'ParameterValue',$name)}
        }
      }catch{return}
    })][string]$ProfileName
  )
  $id=ConvertTo-RideWirelessGuid $InterfaceId
  if($ProfileName.Length -gt 255 -or $ProfileName.Contains([string][char]0)){throw 'Invalid wireless profile name.'}
  if($Inventory.SchemaVersion -ne 1 -or $Inventory.Kind -cne 'WirelessProfileObservation' -or $Inventory.Status -cnotin @('Captured','Unavailable')){throw 'Invalid wireless observation schema.'}
  $status='Unavailable';$found=$null
  if($Inventory.Status -ceq 'Unavailable'){
    if($null -ne $Inventory.Interfaces){throw 'Unavailable wireless observation cannot contain partial rows.'}
  }else{
    $rows=ConvertTo-RideWirelessRows $Inventory.Interfaces
    $adapter=@($rows|Where-Object {$_.Id -ceq $id})
    if(-not $adapter.Count){$status='InterfaceNotObserved'}
    else{$found=$adapter[0].Profiles|Where-Object {$_.Name -ceq $ProfileName};$status=if($found){'Observed'}else{'NotObserved'}}
  }
  [pscustomobject]@{InterfaceId=$id;ProfileName=$ProfileName;Status=$status;Observation=$found;WindowsContext=$Inventory.WindowsContext;ReadyForMutation=$false;RecoverySupported=$false}
}

Export-ModuleMember -Function Get-RideWirelessProfileInventory,Find-RideWirelessProfileObservation
