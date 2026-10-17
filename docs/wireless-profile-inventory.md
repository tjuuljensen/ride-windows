# Read-only wireless profile inventory

Capture basic stored Wi-Fi profile metadata visible to an explicitly identified
user. The tool records enabled WLAN interface GUIDs, descriptions, literal state,
profile names, preference order and flags. It does not retrieve profile XML, keys,
EAP user data or active SSIDs, scan networks, connect, import or remove profiles.
Native service, user-visibility and hardware acceptance remain pending.

## Capture and inspect

Start in the repository root in native Windows PowerShell 5.1 or PowerShell 7,
in the intended user's interactive session. Supply machine/build/edition and
SID/session independently. Create a private local evidence directory first.
No elevation prompt, WLAN service start or component installation is performed.

```powershell
.\tools\Export-RideWirelessProfileInventory.ps1 `
  -ExpectedComputerName '<target>' -ExpectedBuild '<build>' `
  -ExpectedEditionId '<edition>' -ExpectedUserSid '<intended-user-sid>' `
  -ExpectedSessionId 1 -OutputPath 'C:\Evidence\wireless-profiles.json' -WhatIf
```

Remove WhatIf only to perform the read-only query and create new JSON. Preview
queries nothing. Existing output or a file created during collection refuses;
retain partial output on failure and choose a new filename. Profile names can
disclose private network names even though secrets are not requested. Keep the
evidence local with appropriate access controls; the exporter does not set ACLs.

The version-1 observation distinguishes Captured with zero interfaces/profiles
from Unavailable. Any provider, bounds, malformed-data or cleanup failure discards
all partial rows. Only error type and an available native numeric code are retained.
Pre/post machine/build/edition/update/SID/session/native/interactive drift refuses
the whole observation. This does not verify ownership of the desktop.

The reader uses [WlanEnumInterfaces](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanenuminterfaces)
and [WlanGetProfileList](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofilelist),
with a version-2 client handle and explicit allocation/handle cleanup. RIDE limits
capture to 64 interfaces and 256 profiles each; native calls have no hard timeout.
Missing service/API/access is an unavailable prerequisite, not permission to
install, start or repair anything. Enabled-interface coverage does not enumerate
every disabled adapter or profiles belonging to other accounts.

## Identity, order and scope

| Field | Meaning |
| --- | --- |
| Interface Id | Observed WLAN interface GUID; a description or adapter index is not a substitute. |
| Profile Name | Exact, case-sensitive stored profile identity, not guaranteed to equal an SSID. Renames require fresh review. |
| Position | Zero-based preference position returned by the API; not the currently connected profile. |
| Flags | Complete unsigned bitmask, retaining unknown bits. |
| GroupPolicyFlag | The documented group-policy bit; those profiles are read-only. |
| PerUserFlag | The documented per-user bit; when clear the API describes an all-user profile. |
| UnknownFlagBits | Bits outside the two reviewed flags; no new meaning is invented. |

Microsoft defines [profile-name and flag semantics](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_profile_info).
The list header's dwIndex is application bookkeeping, not active connection state.
Neither a missing policy flag nor a returned profile establishes permission to
change it. Basic metadata contains no complete content or credentials for recovery.
`ReadyForMutation`, `RecoverySupported` and `ConnectionVerified` remain false.

Import the module and use saved metadata without a new native query:

```powershell
Import-Module .\modules\RIDE.WirelessInventory.psm1
$saved = Get-Content -LiteralPath 'C:\Evidence\wireless-profiles.json' -Raw |
  ConvertFrom-Json
Find-RideWirelessProfileObservation -Inventory $saved `
  -InterfaceId '<reviewed-interface-guid>' -ProfileName 'Reviewed profile'
```

InterfaceId and ProfileName completion read only supplied saved rows, filter by
prefix and never connect. Names complete only for the explicitly selected interface;
case variants remain distinct and quotes are escaped. Control-character names
remain literal observations but are omitted from completion. Lookup distinguishes
missing interface, missing exact profile and unavailable capture. It revalidates
row bounds, order, GUIDs and duplicate names after JSON roundtrip.

## Acceptance and next work

`tests/WirelessInventory.Tests.ps1` uses fake allocated native buffers and mocked
identity, plus temporary evidence files. It proves field handling and cleanup,
not an actual service/API, permissions or hardware result. Interface/profile
membership can change during or after the sequential calls; no atomic snapshot
or current connection is claimed.

On a disposable target with suitable WLAN hardware and an already available
service, compare observed GUIDs and profile preference order with the intended
user's native UI. Include no-profile, per-user, all-user, policy, missing-service,
disappearance and alternate-user cases. Do not create networks, expose keys or
enable components just to obtain a green inventory result.

Q12 still owns future profile scope/connection behavior; credentials, profile
content protection and exact restore need separate design before an importer or
setter. Q30 still owns resource selection. This metadata does not approve either.
Source rollback removes this isolated tool/module/tests/docs; it needs no network
recovery. The [migration record](migrations/remaining-migrations-follow-up.md#b02-wireless-profile-identity-inventory-2026-10-17)
retains implementation and native-acceptance status.
