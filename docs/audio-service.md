# Windows Audio service and playback mute

To mute one playback device, use the [native mute workflow](#mute-a-selected-playback-device).
RIDE's service operation controls the whole device's audio service and is an
advanced maintenance choice. Event sound schemes and the startup sound have
[separate setting and recovery contracts](setting-presentation.md#input-and-audio-choices).

## Audio service choices

`windows.audio-service` is an advanced, experimental **machine/admin** service
operation. It keeps the accepted legacy service intent separate from the pending
selected playback-device Mute/Unmute operation:

| State | Startup configuration | Requested runtime |
| --- | --- | --- |
| `AutomaticRunning` | Automatic | Running |
| `ManualStopped` | Manual | Stopped |

Manual is not Disabled. Another caller can subsequently start a Manual service;
RIDE does not continuously enforce its runtime state. The operation affects the
whole device and potentially all users/sessions. It does not promise silence,
working playback or a current-user-only audio change.

## Primary service and dependency boundary

Only the exact SCM service **Audiosrv** is owned. Read-only inspection includes
the primary startup/runtime and bounded related-service identities/statuses.
The handler refuses unavailable, duplicate, excessive or transitional dependency
inspection. Load-order group dependencies require separate review.

Before startup/delay/runtime mutation, required services must already be Running
for a start/resume; dependents must already be Stopped for a stop. No Force is
used, no required service is implicitly started as a repair step, and no
AudioEndpointBuilder or other dependent startup type is written. Related state is
checked again before runtime transition and compared after the operation. A
primary service that already reached the requested runtime after configuration
does not receive another start/stop request. Changed dependencies cause a partial
failure report; they are never adopted for automatic recovery.

Do not edit services concurrently with apply/restore. Windows does not expose
an atomic configuration/dependency/runtime transaction here, so preflight and
readback do not establish exclusive control over other tools or triggers. Native
errors and observed drift remain explicit failures.

The engine saves the primary startup/runtime, effective SCM delayed-start flag
and exact literal delay value/type/absence before mutation. The existing service
snapshot version 2 is retained; earlier service snapshots keep their existing
compatibility path. Saved restore changes the captured primary service only and
uses the same dependency refusal. An active dependent introduced since capture
can block restore and must be reviewed separately; RIDE never force-stops or
reconstructs it. No universal baseline/unset state is invented.

Microsoft's [audio architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/windows-audio-architecture)
distinguishes the audio service and endpoint builder.
[Service management](https://learn.microsoft.com/en-us/powershell/scripting/samples/managing-services)
documents required/dependent services. These references do not prove a complete
audio outcome from a service flag round trip.

## Acceptance

Windows 11 and Windows Server 2025 are candidates with **empty supported
targets**, so normal apply is blocked, including preview. No recommended profile
selects this operation. Applicable service availability, dependency/group mapping,
GUI, trigger/repeat behavior, staged failure and exact target recovery need VM
acceptance. Actual render/capture, endpoint/session effects and Server audio
availability remain separate evidence. Local tests mock every service, registry,
CIM and native SCM call and do not play or capture audio.

Automated playback-device mute remains deferred pending native endpoint-ID recovery
and intended interactive-user scope. This service operation changes no volume,
microphone, app setting, default device, driver, feature or license. Recorded
service lifecycle evidence and outstanding acceptance are tracked in the
[settings validation ledger](migrations/settings-validation-resume.md).

## Mute a selected playback device

Use this manual workflow in the intended user's signed-in Windows 11 desktop,
with a connected, identifiable output device and working audio controls. No
PowerShell session or repository working directory is required. This workflow
does not require elevation; stop if Windows requests administrative changes or
the device is unavailable. Server audio availability and GUI behavior need
separate acceptance.

1. Open **Settings > System > Sound > More sound settings > Playback**.
   Inspect the intended speakers or headset and open **Properties** without
   changing the default device. Microsoft documents this
   [device-properties route](https://support.microsoft.com/en-us/windows/hardware/audio/fix-sound-or-audio-problems-in-windows).
2. Confirm the device by its name and connection/controller details. Similar
   names alone are insufficient. Note its current mute state and volume, and
   the existing default playback and communications devices. If the device
   disappears or cannot be distinguished, stop rather than use another output.
3. Where the device's **Levels** page exposes a speaker mute button, use that
   button to select Mute or Unmute. Leave the volume slider, balance, default
   roles, app mixer and Recording devices unchanged. If the driver does not
   expose a distinct mute control, leave it unchanged; setting volume to zero
   or disabling the device is not this workflow.
4. Reopen the same device's properties and check the mute indicator, unchanged
   volume and default roles. If you choose an audible check, use a short local
   clip already routed to that output at the previously safe volume; do not
   change routing or raise volume to make the check pass. An indicator alone
   does not establish the actual playback result.

The device-properties mute route is a conditional UI procedure: its exact
button placement and effect still need confirmation on the selected build and
driver. Avoid the taskbar mute shortcut when the intended output is not the
current default, and avoid any UI selection that switches the default output.
Mute affects the selected endpoint and can affect other applications or users
sharing it; it is not a microphone or per-app privacy control. Software endpoint
mute can be bypassed by exclusive-mode audio when hardware mute is unavailable.
See Microsoft's [endpoint-volume behavior](https://learn.microsoft.com/en-us/windows/win32/api/endpointvolume/nn-endpointvolume-iaudioendpointvolume).

### Recover the previous mute state

Return to the same device and set its recorded prior mute state explicitly.
Do not blindly toggle it or substitute the new default device. Confirm that
volume, default roles, app settings and microphone state remain unchanged. If
the original device is missing or ambiguous, recovery is pending until it can
be identified again. Do not start services, install drivers or alter another
device as an automatic repair.

These manual actions create no RIDE snapshot or completed apply record;
`restore -RunId` cannot undo them. Automated mute support still needs stable
endpoint identity, prior-boolean capture, session ownership, disappearance and
conflict handling. Migration acceptance must use a disposable Windows target
with a usable output and retain GUI/playback and recovery observations; a VM
with no audio endpoint cannot provide that evidence.

## Read-only endpoint inventory

`tools/Export-RideAudioEndpointInventory.ps1` prepares an observation of render
endpoints without playing sound or changing mute, volume, default roles, drivers
or services. Run from the repository root in the intended user's interactive
Windows session, using Windows PowerShell 5.1 or PowerShell 7 without elevation.
Core Audio must be available; actual device/driver acceptance is still pending.

Identify the SID and session in that intended desktop first. Do not copy values
from an administrator or remote service session. Read the current SID with
`[Security.Principal.WindowsIdentity]::GetCurrent().User.Value` and session with
`(Get-Process -Id $PID).SessionId`, then supply those reviewed values:

```powershell
.\tools\Export-RideAudioEndpointInventory.ps1 -ExpectedUserSid <user-sid> -ExpectedSessionId <session-id> -OutputPath .\audio-observation.json -WhatIf
# Remove -WhatIf to collect read-only data and create the new JSON file.
```

The directory must exist; existing output is refused, including a file created
concurrently during collection. Use a new filename for each observation. Output
contains device names and the user's SID; retain it locally unless appropriate
to share. Remove only the exported file when no longer needed; there is no audio
state to recover.

The version-1 observation records up to 256 playback endpoints with opaque ID,
friendly-name availability, native state, mute/volume availability, execution
identity, timestamps and three observed default roles. Native states are 1 active,
2 disabled, 4 not present and 8 unplugged. Inactive/unreadable mute is null, never
an assumed false. A missing default differs from a failed default-role query.
Enumeration failure stops collection. Sequential queries are not an atomic
snapshot; a device/default can change during capture. Matching SID/session does
not prove a usable desktop. Native driver calls have no hard timeout.

To inspect saved data:

```powershell
Import-Module .\modules\RIDE.AudioEndpointInventory.psm1
$inventory = Get-Content -LiteralPath .\audio-observation.json -Raw | ConvertFrom-Json
$inventory.Endpoints | Format-Table Id, Name, State, ObservationStatus, Muted, VolumeScalar
Select-RideAudioEndpointObservation -Inventory $inventory -EndpointId '<observed endpoint ID>'
```

Tab completion for `-EndpointId` reads only the supplied inventory, filters the
typed prefix without case sensitivity and quotes the literal ID safely. Selection
requires the exact opaque ID, rejects duplicates/missing IDs and never substitutes
a default or a similarly named device. This selects saved data. `ReadyForMutation`
and `RecoverySupported` remain false; old JSON or successful enumeration never
authorizes a setter or proves playback acceptance. Import and completion make no
live queries. No catalog setting or supported target is added by this tool.

The collector uses Microsoft's [endpoint enumeration](https://learn.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nn-mmdeviceapi-immdeviceenumerator),
[opaque ID](https://learn.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nf-mmdeviceapi-immdevice-getid),
[read-only properties](https://learn.microsoft.com/en-us/windows/win32/coreaudio/device-properties)
and [mute readback](https://learn.microsoft.com/en-us/windows/win32/api/endpointvolume/nf-endpointvolume-iaudioendpointvolume-getmute)
contracts. Automated mute and intended-desktop/hardware acceptance remain separate.
