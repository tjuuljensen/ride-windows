# Windows Audio service

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

Playback-device mute remains deferred pending native endpoint-ID recovery and
intended interactive-user scope. This operation changes no volume, microphone,
app setting, default device, driver, feature or license. Disposable VM execution
remains held until manual user confirmation.
