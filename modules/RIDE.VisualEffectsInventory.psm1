<#
.SYNOPSIS
  Observe selected session visual preferences without changing them.
.DESCRIPTION
  Uses five fixed SystemParametersInfo GET requests under an expected native
  interactive user/session identity. Keeps Boolean preferences and unsigned menu
  delay separate from stored registry values, GUI evidence and policy enforcement.
  Imports do not compile or invoke native code. No SET request, refresh or fallback.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Intended interactive desktop user; user32 from System32.
  Recovery: Read-only schema-1 observations, not recovery snapshots.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded session observations and typed injectable GET bridge.
.LINK
  ../docs/setting-presentation.md
#>
$ErrorActionPreference='Stop'

function Initialize-RideVisualEffectsRead {
  if('Ride.VisualEffectsV1.Reader' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Ride.VisualEffectsV1 {
  [StructLayout(LayoutKind.Sequential)]
  public struct AnimationInfo { public uint Size; public int MinAnimate; }
  public interface IReadApi {
    bool Scalar(uint action, out uint value, out int error);
    bool Animation(ref AnimationInfo value, out int error);
  }
  public sealed class Result {
    public string Kind;
    public uint Action, RawValue;
    public bool Available;
    public int ErrorCode;
  }
  public sealed class NativeApi : IReadApi {
    [DllImport("user32.dll", EntryPoint="SystemParametersInfoW", ExactSpelling=true, SetLastError=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ScalarNative(uint action, uint parameter, out uint value, uint flags);
    [DllImport("user32.dll", EntryPoint="SystemParametersInfoW", ExactSpelling=true, SetLastError=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AnimationNative(uint action, uint parameter, ref AnimationInfo value, uint flags);
    [DllImport("kernel32.dll", ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void SetLastError(uint error);
    public bool Scalar(uint action, out uint value, out int error) {
      // Guard the interop entry itself: callers cannot supply a SET action.
      if(action != 0x0026 && action != 0x006A && action != 0x103E && action != 0x1042)
        throw new ArgumentException("Only reviewed visual GET actions are allowed.");
      SetLastError(0);
      bool ok=ScalarNative(action, 0, out value, 0);
      error=ok ? 0 : Marshal.GetLastWin32Error();
      return ok;
    }
    public bool Animation(ref AnimationInfo value, out int error) {
      uint size=(uint)Marshal.SizeOf(typeof(AnimationInfo));
      if(value.Size != size) throw new ArgumentException("Invalid ANIMATIONINFO size.");
      SetLastError(0);
      bool ok=AnimationNative(0x0048, size, ref value, 0);
      error=ok ? 0 : Marshal.GetLastWin32Error();
      return ok;
    }
  }
  public static class Reader {
    public static Result Read(IReadApi api, string kind) {
      if(api == null) throw new ArgumentNullException("api");
      uint action;
      switch(kind) {
        case "DragFullWindows": action=0x0026; break;
        case "MenuShowDelay": action=0x006A; break;
        case "MinimizeAnimation": action=0x0048; break;
        case "UiEffects": action=0x103E; break;
        case "ClientAreaAnimation": action=0x1042; break;
        default: throw new ArgumentException("Unknown visual observation kind.");
      }
      uint value=0; int error; bool ok;
      if(action == 0x0048) {
        AnimationInfo info=new AnimationInfo { Size=(uint)Marshal.SizeOf(typeof(AnimationInfo)) };
        ok=api.Animation(ref info, out error);
        if(ok && info.Size != (uint)Marshal.SizeOf(typeof(AnimationInfo)))
          throw new InvalidOperationException("ANIMATIONINFO size changed during read.");
        value=unchecked((uint)info.MinAnimate);
      } else { ok=api.Scalar(action, out value, out error); }
      // Never expose a partial/out-buffer value after API failure, including error 0.
      return new Result { Kind=kind, Action=action, Available=ok,
        RawValue=ok ? value : 0, ErrorCode=ok ? 0 : error };
    }
  }
}
'@
}

function Get-RideVisualEffectsContext {
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

function Get-RideVisualEffectsRow {
  param([string]$Kind)
  Initialize-RideVisualEffectsRead
  [Ride.VisualEffectsV1.Reader]::Read([Ride.VisualEffectsV1.NativeApi]::new(),$Kind)
}

function Get-RideVisualEffectsInventory {
  <#
  .SYNOPSIS
    Observe explicitly selected visual preferences for the expected user/session.
  .PARAMETER Kind
    DragFullWindows, MenuShowDelay, MinimizeAnimation, UiEffects or ClientAreaAnimation.
    Select one or more without duplicates. Completion makes no native queries.
  .PARAMETER ExpectedComputerName
    Independently established target computer name.
  .PARAMETER ExpectedBuild
    Expected Windows build number.
  .PARAMETER ExpectedEditionId
    Expected Windows EditionID.
  .PARAMETER ExpectedUserSid
    Expected interactive account SID.
  .PARAMETER ExpectedSessionId
    Expected nonzero interactive process session ID.
  .EXAMPLE
    Get-RideVisualEffectsInventory -Kind DragFullWindows,MenuShowDelay -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 VisualEffectsObservation with per-provider availability.
  .NOTES
    Reads are sequential, not an atomic session snapshot. Failed GET requests have
    no value and retain a numeric error when available; zero is not success.
    No registry fallback, setter, refresh, shell restart, policy query or file write.
    Native API/layout and actual GUI acceptance remain pending on target Windows.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('DragFullWindows','MenuShowDelay','MinimizeAnimation','UiEffects','ClientAreaAnimation')][string[]]$Kind,
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateLength(1,255)][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9]+(?:-[0-9]+)+$')][string]$ExpectedUserSid,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$ExpectedSessionId
  )
  if(-not $Kind.Count){throw 'Select at least one visual observation.'}
  $selected=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($item in $Kind){if(-not $selected.Add($item)){throw 'Select each visual observation only once.'}}
  $context=Get-RideVisualEffectsContext
  if($context.NativeProcess -isnot [bool] -or -not $context.NativeProcess -or
      $context.UserInteractive -isnot [bool] -or -not $context.UserInteractive -or
      $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or
      $context.EditionId -ine $ExpectedEditionId -or $context.UserSid -ine $ExpectedUserSid -or
      $context.SessionId -isnot [int] -or $context.SessionId -ne $ExpectedSessionId -or
      ($context.UpdateBuildRevision -isnot [int] -and $context.UpdateBuildRevision -isnot [uint32]) -or
      $context.UpdateBuildRevision -lt 0){throw 'Visual observation target differs from expected native machine/build/edition/user/session.'}
  $started=[DateTime]::UtcNow.ToString('o')
  $providers=@(foreach($item in $Kind){
    $canonical=switch($item){DragFullWindows{'DragFullWindows'}MenuShowDelay{'MenuShowDelay'}MinimizeAnimation{'MinimizeAnimation'}UiEffects{'UiEffects'}ClientAreaAnimation{'ClientAreaAnimation'}}
    $action=switch($canonical){DragFullWindows{0x0026}MenuShowDelay{0x006A}MinimizeAnimation{0x0048}UiEffects{0x103E}ClientAreaAnimation{0x1042}}
    $result=[pscustomobject]@{Kind=$canonical;Scope='UserSession';Status='Unavailable';Action=[uint32]$action;Value=$null;RawValue=$null;NativeError=$null;ErrorId=$null;GuiEffectVerified=$false}
    try {
      $rows=[Collections.Generic.List[object]]::new()
      Get-RideVisualEffectsRow -Kind $canonical | ForEach-Object {
        if($rows.Count -ge 1){throw 'Visual provider returned multiple rows.'}
        if($_.Kind -cne $canonical -or $_.Action -isnot [uint32] -or $_.Action -ne $action -or
            $_.Available -isnot [bool] -or $_.RawValue -isnot [uint32] -or $_.ErrorCode -isnot [int]){throw 'Malformed visual provider result.'}
        $rows.Add($_)
      }
      if($rows.Count -ne 1){throw 'Visual provider returned no result.'}
      $row=$rows[0]
      if($row.Available){
        if($row.ErrorCode -ne 0){throw 'Successful visual result has a contradictory error.'}
        $result.RawValue=$row.RawValue
        $result.Value=if($canonical -ceq 'MenuShowDelay'){$row.RawValue}else{$row.RawValue -ne 0}
        $result.Status='Captured'
      }else{$result.NativeError=$row.ErrorCode;$result.ErrorId='SystemParametersInfoFailed'}
    }catch{
      $result.Value=$null;$result.RawValue=$null;$result.NativeError=$null
      $result.ErrorId=$_.Exception.GetType().FullName
    }
    $result
  })
  $after=Get-RideVisualEffectsContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','NativeProcess','UserSid','SessionId','UserInteractive')){
    if($after.$field -cne $context.$field){throw 'Visual observation target changed during collection; discard the observation.'}
  }
  [pscustomobject]@{
    SchemaVersion=1;Kind='VisualEffectsObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');Providers=$providers
    Consistency='Sequential session GET results; no stored-registry, policy-source or actual GUI proof'
    ReadyForMutation=$false;RecoverySupported=$false
  }
}
Export-ModuleMember -Function Get-RideVisualEffectsInventory
