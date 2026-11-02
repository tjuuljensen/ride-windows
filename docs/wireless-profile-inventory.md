# Wireless profile generation and inventory

## Generate XML from supplied settings

RIDE generates the profile file; an existing production XML file is not a
prerequisite. From the repository root in native Windows PowerShell 5.1 or
PowerShell 7, use an existing local directory and a new `.xml` filename:

```powershell
Import-Module .\modules\RIDE.WirelessProfile.psm1
$key = Read-Host 'Wi-Fi key' -AsSecureString
try {
    New-RideWirelessProfileFile -ProfileName 'Office profile' -Ssid 'Office' `
        -Security WPA2Personal -Key $key -ConnectionMode manual `
        -OutputPath 'C:\Private\wifi.xml' -WhatIf
} finally {
    $key.Dispose()
}
```

Repeat with a fresh secure key and without `-WhatIf` to generate the file. This
requires no elevation or WLAN adapter. Profile generation does not import,
connect, scan, change a service or select an interface. The output object reports
file-generation status only; it contains no XML, password or password digest.
`Security` and `ConnectionMode` complete from their declared valid values.

The implemented security choices are `WPA2Personal` (WPA2PSK/AES) and `Open`
(open/none, with no key). A WPA2 key is an 8-63 printable ASCII passphrase or a
64-digit hexadecimal network key. Enterprise/EAP, WPA3, WEP and WPA are not
implemented. `manual` is the default; automatic connection is an explicit profile
preference and can take effect only after a later import. `-HiddenNetwork` sets
the non-broadcast flag. MAC randomization is not overridden by this generator.

`-Ssid` uses strict UTF-8 without normalization, limited to 1-32 bytes. Use
`-SsidBytes` instead for an exact binary SSID. XML contains the authoritative hex
SSID; profile identity is supplied separately through `-ProfileName`. An XML
writer escapes text rather than interpolating it into markup.

The file is created exclusively with a protected DACL for the current user and
SYSTEM, and those permissions are checked through the open handle before any
profile bytes are written. Existing files are never overwritten; parent reparse
points, UNC/device/alternate-stream paths and mapped network drives are refused.
The filesystem must support the requested permissions. A failure can leave a new
empty or private partial file; inspect it and choose a new filename for a retry.

WLAN import XML contains **unencrypted key material** (`protected=false`). File
permissions protect access; they do not encrypt the key. Keep real output out of
Git, ordinary logs, transcripts and shared evidence, and remove it after its
intended use. SecureString input avoids a plaintext command argument; generation
necessarily creates plaintext in process memory and does not promise complete
memory erasure. Real credentials belong in an interactive secure prompt or local
secret source, never in committed settings or a chat message.

The implementation follows Microsoft's [WLAN v1 schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpwl/34054c93-cfcd-44df-89d8-5f2ba7532b67),
[SSID byte semantics](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-ssid-ssidconfig-element)
and [shared-key rules](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-sharedkey-security-element).
The XML namespace is the literal `http://www.microsoft.com/networking/WLAN/profile/v1`
identifier from the protocol schema, not an HTTP acquisition URL.

### Synthetic testing

`tests/fixtures/wireless-profile.synthetic.psd1` supplies a clearly synthetic SSID,
profile name and public test-only key. `tests/WirelessProfile.Tests.ps1` generates
files from those settings and exercises private output, invalid settings, byte
identity, escaping, preview and collision handling. No real network or credential
is needed. For an explicit synthetic output, from the repository root:

```powershell
Import-Module .\modules\RIDE.WirelessProfile.psm1
$fixture = Import-PowerShellDataFile .\tests\fixtures\wireless-profile.synthetic.psd1
$key = ConvertTo-SecureString $fixture.SyntheticKey -AsPlainText -Force
try {
    New-RideWirelessProfileFile -ProfileName $fixture.ProfileName -Ssid $fixture.Ssid `
        -Security $fixture.Security -Key $key -ConnectionMode $fixture.ConnectionMode `
        -HiddenNetwork:$fixture.HiddenNetwork -OutputPath 'C:\Private\synthetic-wifi.xml'
} finally {
    $key.Dispose()
}
```

Native import/repeat/remove/restore remains pending. That scenario must use the
synthetic profile in manual mode, a disposable target with suitable WLAN support,
an explicit interface and the selected machine/all-user scope. Verify exact
profile settings and scope, preserve existing profiles, and prove recovery before
checkpoint cleanup. Do not connect to a real network. No adapter is needed for
generation tests; no suitable adapter means native import is untested, not passed.

The isolated `RIDE.WirelessNative.psm1` provider now supplies bounded profile
list/read/set/delete/order calls for the future lifecycle handler. Its fake-API
tests verify call arguments, error reporting and allocation/handle cleanup in
both PowerShell editions. Loading it performs no WLAN calls. It does not expose
an independently recoverable import command or establish native acceptance.

Recovery must distinguish replacement from deletion: `WlanSetProfile` with a null
security descriptor preserves permissions on an existing all-user profile,
whereas deletion/recreation needs the original permissions as well as XML and
order. `WlanGetProfile` returns granted access flags, not the complete per-profile
security descriptor. Do not label an XML-only delete/recreate round trip exact
recovery. The synthetic fixture can establish explicit known permissions; native
lifecycle integration and ownership/conflict checks remain required.
See Microsoft's [profile set semantics](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofile)
and [profile retrieval semantics](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofile).

## Read-only wireless profile inventory

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

Q12 still owns native profile scope/connection behavior and exact restore before
an importer or setter. Generated XML now supplies the selected input; the tests
use synthetic settings. Q30 still owns interface selection. Inventory metadata
alone does not establish recoverable profile content or import acceptance.
Source rollback removes this isolated tool/module/tests/docs; it needs no network
recovery. The [migration record](migrations/remaining-migrations-follow-up.md#b02-wireless-profile-identity-inventory-2026-10-17)
retains implementation and native-acceptance status.
