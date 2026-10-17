<#
.SYNOPSIS
  Inspect playback endpoints without changing audio configuration.
.DESCRIPTION
  Collects opaque render endpoint IDs, state, default roles and readable mute/volume
  observations in an explicitly identified execution account and session. No device
  is selected automatically. Import and completion do not query Core Audio.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Core Audio and the intended user's desktop session for live evidence.
  File/environment inputs: Explicit expected SID/session; no files read on import.
  Recovery: Read-only observations; this is not a saved-run or mute setter.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog: 0.1.0: Add bounded render inventory and explicit saved-data selection.
.LINK
  ../docs/audio-service.md
.LINK
  https://learn.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nn-mmdeviceapi-immdeviceenumerator
#>
$ErrorActionPreference = 'Stop'

function Get-RideAudioInventoryContext {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $process = [Diagnostics.Process]::GetCurrentProcess()
  try {
    [pscustomobject]@{ UserSid=$identity.User.Value; SessionId=$process.SessionId; UserInteractive=[Environment]::UserInteractive }
  } finally { $identity.Dispose(); $process.Dispose() }
}

function Initialize-RideAudioInventoryNative {
  if ('Ride.AudioInventoryV1.Reader' -as [type]) { return }
  # COM slots follow the Windows SDK mmdeviceapi.h/endpointvolume.h contracts.
  # Unused slots are private declarations only; the reader calls no setters.
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace Ride.AudioInventoryV1 {
  [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] internal class EnumeratorClass { }
  [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  internal interface Enumerator {
    [PreserveSig] int EnumAudioEndpoints(int flow, uint mask, out Collection result);
    [PreserveSig] int GetDefaultAudioEndpoint(int flow, int role, out Device result);
  }
  [ComImport, Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  internal interface Collection {
    [PreserveSig] int GetCount(out uint count);
    [PreserveSig] int Item(uint index, out Device result);
  }
  [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  internal interface Device {
    [PreserveSig] int Activate(ref Guid iid, uint context, IntPtr parameters, [MarshalAs(UnmanagedType.IUnknown)] out object result);
    [PreserveSig] int OpenPropertyStore(uint access, out PropertyStore result);
    [PreserveSig] int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);
    [PreserveSig] int GetState(out uint state);
  }
  [StructLayout(LayoutKind.Sequential)] internal struct PropertyKey { public Guid Format; public uint Id; }
  [StructLayout(LayoutKind.Explicit, Size=24)] internal struct Variant {
    [FieldOffset(0)] public ushort Type;
    [FieldOffset(8)] public IntPtr Pointer;
  }
  [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  internal interface PropertyStore {
    [PreserveSig] int GetCount(out uint count);
    [PreserveSig] int GetAt(uint index, out PropertyKey key);
    [PreserveSig] int GetValue(ref PropertyKey key, out Variant value);
  }
  [ComImport, Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  internal interface EndpointVolume {
    [PreserveSig] int Unused01(IntPtr pointer);
    [PreserveSig] int Unused02(IntPtr pointer);
    [PreserveSig] int GetChannelCount(out uint count);
    [PreserveSig] int Unused04(float value, IntPtr context);
    [PreserveSig] int Unused05(float value, IntPtr context);
    [PreserveSig] int GetMasterVolumeLevel(out float value);
    [PreserveSig] int GetMasterVolumeLevelScalar(out float value);
    [PreserveSig] int Unused08(uint channel, float value, IntPtr context);
    [PreserveSig] int Unused09(uint channel, float value, IntPtr context);
    [PreserveSig] int GetChannelVolumeLevel(uint channel, out float value);
    [PreserveSig] int GetChannelVolumeLevelScalar(uint channel, out float value);
    [PreserveSig] int Unused12([MarshalAs(UnmanagedType.Bool)] bool value, IntPtr context);
    [PreserveSig] int GetMute([MarshalAs(UnmanagedType.Bool)] out bool value);
  }
  public sealed class Endpoint {
    public string Id; public string Name; public uint State;
    public string NameStatus; public string ObservationStatus;
    public bool? Muted; public float? VolumeScalar;
    public string NameError; public string ObservationError;
  }
  public sealed class Role {
    public string Name; public string Id; public string Status; public string Error;
  }
  public sealed class Snapshot { public Endpoint[] Endpoints; public Role[] DefaultRoles; }
  public static class Reader {
    [DllImport("ole32.dll")] private static extern int PropVariantClear(ref Variant value);
    private static void Check(int result) { if (result < 0) Marshal.ThrowExceptionForHR(result); }
    private static void Release(object value) { if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value); }
    private static string Error(Exception error) { return "HRESULT 0x" + error.HResult.ToString("X8"); }
    public static Snapshot Read() {
      if (Environment.OSVersion.Platform != PlatformID.Win32NT) throw new PlatformNotSupportedException("Windows Core Audio is required.");
      Enumerator enumerator = null; Collection collection = null;
      var endpoints = new List<Endpoint>(); var roles = new List<Role>();
      try {
        enumerator = (Enumerator)new EnumeratorClass();
        Check(enumerator.EnumAudioEndpoints(0, 15, out collection));
        uint count; Check(collection.GetCount(out count));
        if (count > 256) throw new InvalidOperationException("Audio endpoint count exceeds the bound.");
        for (uint index = 0; index < count; index++) {
          Device device = null; PropertyStore store = null; object volumeObject = null;
          try {
            Check(collection.Item(index, out device));
            string id; uint state; Check(device.GetId(out id)); Check(device.GetState(out state));
            var row = new Endpoint { Id=id, State=state, NameStatus="Unavailable", ObservationStatus="Inactive" };
            try {
              Check(device.OpenPropertyStore(0, out store));
              var key = new PropertyKey { Format=new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), Id=14 };
              Variant value = new Variant();
              try {
                Check(store.GetValue(ref key, out value));
                if (value.Type != 31 || value.Pointer == IntPtr.Zero) throw new InvalidOperationException("Friendly name is unavailable.");
                row.Name = Marshal.PtrToStringUni(value.Pointer); row.NameStatus = "Captured";
              } finally { PropVariantClear(ref value); }
            } catch (Exception error) { row.NameError = Error(error); }
            if (state == 1) {
              try {
                var iid = new Guid("5CDF2C82-841E-4546-9722-0CF74078229A");
                Check(device.Activate(ref iid, 23, IntPtr.Zero, out volumeObject));
                var volume = (EndpointVolume)volumeObject; bool muted; float scalar;
                Check(volume.GetMute(out muted)); Check(volume.GetMasterVolumeLevelScalar(out scalar));
                if (float.IsNaN(scalar) || float.IsInfinity(scalar) || scalar < 0 || scalar > 1) throw new InvalidOperationException("Invalid endpoint volume.");
                row.Muted=muted; row.VolumeScalar=scalar; row.ObservationStatus="Captured";
              } catch (Exception error) { row.ObservationStatus="Unavailable"; row.ObservationError=Error(error); }
            }
            endpoints.Add(row);
          } finally { Release(volumeObject); Release(store); Release(device); }
        }
        string[] names = { "Console", "Multimedia", "Communications" };
        for (int index = 0; index < names.Length; index++) {
          Device device = null; var role = new Role { Name=names[index], Status="Unavailable" };
          try {
            int result = enumerator.GetDefaultAudioEndpoint(0, index, out device);
            if (result == unchecked((int)0x80070490)) role.Status="None";
            else { Check(result); string id; Check(device.GetId(out id)); role.Id=id; role.Status="Captured"; }
          } catch (Exception error) { role.Error=Error(error); }
          finally { Release(device); }
          roles.Add(role);
        }
        return new Snapshot { Endpoints=endpoints.ToArray(), DefaultRoles=roles.ToArray() };
      } finally { Release(collection); Release(enumerator); }
    }
  }
}
'@
}

function Get-RideAudioEndpointNativeSnapshot {
  Initialize-RideAudioInventoryNative
  [Ride.AudioInventoryV1.Reader]::Read()
}

function Assert-RideAudioEndpointInventory {
  param($Inventory)
  if ($null -eq $Inventory -or $Inventory.SchemaVersion -ne 1 -or $Inventory.Kind -cne 'AudioEndpointObservation' -or $Inventory.Flow -cne 'Render') { throw 'Invalid audio inventory schema or flow.' }
  if ($Inventory.UserSid -notmatch '^S-1-[0-9-]+$' -or ($Inventory.SessionId -isnot [int] -and $Inventory.SessionId -isnot [long]) -or $Inventory.SessionId -le 0 -or $Inventory.SessionId -gt [int]::MaxValue) { throw 'Invalid audio inventory execution identity.' }
  if ($null -eq $Inventory.Endpoints -or @($Inventory.Endpoints).Count -gt 256 -or @($Inventory.DefaultRoles).Count -ne 3) { throw 'Invalid audio inventory collection bounds.' }
  $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($endpoint in @($Inventory.Endpoints)) {
    if ($endpoint.Id -isnot [string] -or [string]::IsNullOrWhiteSpace($endpoint.Id) -or $endpoint.Id.Length -gt 2048 -or $endpoint.Id -match '[\x00-\x1f]' -or -not $ids.Add($endpoint.Id)) { throw 'Invalid or duplicate opaque endpoint identity.' }
    if ($endpoint.State -notin @(1,2,4,8) -or $endpoint.NameStatus -cnotin @('Captured','Unavailable') -or $endpoint.ObservationStatus -cnotin @('Captured','Inactive','Unavailable')) { throw 'Invalid endpoint observation status.' }
    if ($endpoint.NameStatus -ceq 'Captured' -and ([string]::IsNullOrWhiteSpace($endpoint.Name) -or $endpoint.Name.Length -gt 4096)) { throw 'Invalid endpoint friendly name.' }
    if ($endpoint.ObservationStatus -ceq 'Captured') {
      $numericVolume = $endpoint.VolumeScalar -is [single] -or $endpoint.VolumeScalar -is [double] -or $endpoint.VolumeScalar -is [decimal] -or $endpoint.VolumeScalar -is [int] -or $endpoint.VolumeScalar -is [long]
      if ($endpoint.State -ne 1 -or $endpoint.Muted -isnot [bool] -or -not $numericVolume -or [double]::IsNaN([double]$endpoint.VolumeScalar) -or [double]::IsInfinity([double]$endpoint.VolumeScalar) -or $endpoint.VolumeScalar -lt 0 -or $endpoint.VolumeScalar -gt 1) { throw 'Invalid captured endpoint mute or volume.' }
    } elseif ($null -ne $endpoint.Muted -or $null -ne $endpoint.VolumeScalar -or ($endpoint.ObservationStatus -ceq 'Inactive' -and $endpoint.State -eq 1)) { throw 'Unavailable observations must not invent mute or volume.' }
  }
  $roles = @{}
  foreach ($role in @($Inventory.DefaultRoles)) {
    if ($role.Name -cnotin @('Console','Multimedia','Communications') -or $roles.ContainsKey($role.Name) -or $role.Status -cnotin @('Captured','None','Unavailable')) { throw 'Invalid default audio role.' }
    $roles[$role.Name]=$true
    if ($role.Status -ceq 'Captured') {
      if ([string]::IsNullOrWhiteSpace($role.Id) -or $role.Id.Length -gt 2048 -or $role.Id -match '[\x00-\x1f]') { throw 'Invalid default endpoint identity.' }
    } elseif ($null -ne $role.Id) { throw 'Unavailable default role must not invent a device.' }
  }
}

function Get-RideAudioEndpointInventory {
  <#
  .SYNOPSIS
    Capture a read-only playback inventory for an explicit user and session.
  .PARAMETER ExpectedUserSid
    Intended execution SID; mismatch refuses before any audio query.
  .PARAMETER ExpectedSessionId
    Intended nonzero Windows session; mismatch or noninteractive execution refuses.
  .EXAMPLE
    Get-RideAudioEndpointInventory -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Version-1 observation, not a recovery record or support declaration.
  .NOTES
    No elevation, playback, mute/volume/default-device setter or service start.
    Collection is bounded to 256 render endpoints but native driver calls are not
    hard-time-limited. Sequential observations are not an atomic snapshot.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid,
        [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId)
  $context = Get-RideAudioInventoryContext
  if ($context.UserSid -cne $ExpectedUserSid -or $context.SessionId -ne $ExpectedSessionId -or -not $context.UserInteractive) { throw 'Audio inventory execution identity differs from the expected interactive user/session.' }
  $started = [DateTime]::UtcNow.ToString('o')
  $native = Get-RideAudioEndpointNativeSnapshot
  $after = Get-RideAudioInventoryContext
  if ($after.UserSid -cne $context.UserSid -or $after.SessionId -ne $context.SessionId -or -not $after.UserInteractive) { throw 'Audio inventory execution identity changed during capture.' }
  $inventory = [pscustomobject]@{
    SchemaVersion=1; Kind='AudioEndpointObservation'; Flow='Render'
    UserSid=$context.UserSid; SessionId=[int]$context.SessionId
    StartedAtUtc=$started; CompletedAtUtc=[DateTime]::UtcNow.ToString('o')
    Consistency='Sequential observations; not atomic'; DesktopVerified=$false
    Endpoints=@($native.Endpoints); DefaultRoles=@($native.DefaultRoles)
  }
  Assert-RideAudioEndpointInventory $inventory
  $inventory
}

function Select-RideAudioEndpointObservation {
  <#
  .SYNOPSIS
    Select exactly one opaque endpoint ID from already captured data.
  .PARAMETER Inventory
    Version-1 observation from Get-RideAudioEndpointInventory or saved JSON.
  .PARAMETER EndpointId
    Exact opaque ID. Completion uses only Inventory and performs no live query.
  .EXAMPLE
    Select-RideAudioEndpointObservation -Inventory $inventory -EndpointId '<observed endpoint ID>'
    Replace the placeholder with the exact ID the operator has identified.
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Selected observation with ReadyForMutation always false.
  .NOTES
    Friendly names/default roles are not identity. Missing IDs never fall back.
    Saved observations may be stale and never authorize an audio change.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try {
        $data=$fakeBoundParameters['Inventory']
        if ($null -eq $data -or @($data.Endpoints).Count -gt 256) { return }
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($item in @($data.Endpoints)) {
          $id=[string]$item.Id
          if (-not [string]::IsNullOrWhiteSpace($id) -and $id.Length -le 2048 -and $id -notmatch '[\x00-\x1f]' -and $id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($id)) {
            [Management.Automation.CompletionResult]::new(("'"+$id.Replace("'","''")+"'"),$id,'ParameterValue',$id)
          }
        }
      } catch { return }
    })][string]$EndpointId)
  Assert-RideAudioEndpointInventory $Inventory
  $matches=@($Inventory.Endpoints | Where-Object { [string]::Equals($_.Id,$EndpointId,[StringComparison]::Ordinal) })
  if ($matches.Count -ne 1) { throw 'The exact endpoint is missing or ambiguous; no default-device fallback is allowed.' }
  [pscustomobject]@{ Endpoint=$matches[0]; UserSid=$Inventory.UserSid; SessionId=$Inventory.SessionId; CapturedAtUtc=$Inventory.CompletedAtUtc; ReadyForMutation=$false; RecoverySupported=$false }
}

Export-ModuleMember -Function Get-RideAudioEndpointInventory, Select-RideAudioEndpointObservation
