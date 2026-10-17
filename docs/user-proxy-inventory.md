# Read-only user proxy observation

This tool captures literal default/LAN WinINet proxy options for an explicitly
identified interactive account. It preserves manual proxy, bypass and PAC strings
and all flags, including unknown bits. It does not fetch a PAC file, resolve a proxy,
test connectivity, refresh settings or change network configuration. Native target
acceptance remains pending; it introduces no active catalog operation.

## Capture the intended user and scope

Start in the repository root in native Windows PowerShell 5.1 or PowerShell 7,
in the intended user's interactive session. Supply the expected machine name,
SID and nonzero session independently. Do not substitute an administrator's account
to bypass an identity refusal. Create a private local evidence directory first.
No elevation prompt is part of this workflow.

```powershell
.\tools\Export-RideUserProxyObservation.ps1 `
  -ExpectedComputerName '<target>' `
  -ExpectedUserSid '<intended-user-sid>' -ExpectedSessionId 1 `
  -ConnectionKind DefaultLan -OutputPath 'C:\Evidence\proxy.json' -WhatIf

# Remove -WhatIf only for this read-only query and new evidence file.
```

Preview performs no provider query and creates no output. Capture checks machine,
execution SID, session and interactive status before and after collection. These
checks do not verify ownership of the current desktop; `DesktopVerified` remains
false. Use the [intended-user workflow](intended-user-handoff.md) when arranging a
separate user process. The inventory is not an authorization record for that handoff.

`DefaultLan` explicitly means the null connection-name scope in the
[connection option list API](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_listw).
It does not mean the current network adapter, every connection, or a selected VPN.
Named RAS/dial-up/VPN options and their identity/phonebook handling remain separate
work. The finite scope completes without querying Windows. No service or background
server use is supported by this WinINet reader.

## Interpret the record

The reader uses [InternetQueryOptionW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetqueryoptionw)
with per-connection option 75. It first requests UI flags; on native failure it
retries the documented legacy flags option and retains the original numeric error.
It then queries flags, manual proxy, bypass and PAC URL together, rejecting flags
that changed between calls. A later failure produces no successful record and does
not silently retry another scope. This is still sequential, not atomic evidence.

| Field | Interpretation |
| --- | --- |
| Flags / UnknownFlagBits | Complete unsigned literal bitmask and the bits outside the four documented flags. |
| FlagsSource | `FlagsUi`, or `FlagsFallback` with the first query's `UiQueryError`; fallback is not a verified modern UI observation. |
| DirectFlag / ManualProxyFlag | Documented flag presence, not an effective route or successful proxy connection. |
| AutoDetectFlag / SetupScriptFlag | Documented detection/PAC flag presence; no discovery or script execution is performed. |
| ProxyServer / ProxyBypass / AutoConfigUrl | Literal Unicode strings, with null and empty retained separately. Disabled configurations may still contain saved text. |
| PolicyStatus | `NotInspected`; this reader does not identify managed policy or consumer precedence. |
| ReadyForMutation / RecoverySupported | Always false; this is not a saved engine recovery record. |

The [option structure reference](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw)
defines these values, the UI-flags fallback and GlobalFree ownership of returned
strings. The reader releases all returned string slots on success and partial
failure. It bounds each retained string to 32,768 characters; native call duration
has no hard timeout. The ABI includes FILETIME's two DWORD fields so x86/x64 union
alignment remains correct. Tests exercise allocated buffers through a fake API.

Existing browsers and applications can have their own proxy configuration and
policies. Machine WinHTTP is a separate API/configuration scope and is not queried.
No claim is made that these flags alone determine the effective Windows Settings UI,
application behavior or network route. Microsoft's
[internet options guidance](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)
is the API basis; packed registry connection bytes are not decoded or changed.

## Prepare an edit and recovery in memory

Import the separate preparation module and pass an already captured record. The
following example operates only on objects; it does not query or write Windows.

```powershell
Import-Module .\modules\RIDE.UserProxyPreparation.psm1
$saved = Get-Content -LiteralPath 'C:\Evidence\proxy.json' -Raw | ConvertFrom-Json
$patch = New-RideUserProxyConfigurationPatch -Observation $saved `
  -AutomaticDetection Disabled -SetupScript Unchanged
$patch.DesiredValues

# Given a separately supplied current observation of the same context:
$recovery = Restore-RideUserProxyConfigurationPatch `
  -Observation $current -Snapshot $patch.Snapshot
$recovery.DesiredValues
```

Both choice parameters complete `Unchanged`, `Enabled` and `Disabled` from their
declared sets. Detection edits only its flag. SetupScript Disabled clears only its
flag and retains the address. SetupScript Enabled requires a valid retained address
or an explicit `-ScriptUrl`; providing that parameter with another choice refuses.
This preparation accepts absolute HTTP/HTTPS URLs without whitespace or embedded
credentials, preserving their exact spelling. It neither downloads nor validates
the script's contents. Other URL schemes and named RAS connections are outside this
first contract. An invalid historical address can still be retained while disabling.

Manual server/bypass strings and direct/unknown flags remain unchanged. No implicit
direct-mode or automatic-detection fallback is invented. FlagsFallback observations
refuse preparation because their current UI meaning is unverified. Policy, desktop,
connection identity and effective routing remain unverified for FlagsUi as well.
`ReadyForMutation` and `MutationAuthorized` are always false.

The version-1 snapshot records the original observation, request and exact changed
bits/URL. Already-matching requested fields are unowned. Recovery reconstructs the
edit to check snapshot consistency, binds the same machine/SID/session/default-LAN
scope, and refuses conflicting owned values. It preserves later edits to manual
proxy, bypass, unrelated flags and an unowned URL. Null and empty originals remain
distinct. A no-op snapshot does not acquire ownership of later changes.

This is a preparation snapshot, not an authenticated or durable engine manifest.
It assumes the supplied current observation is accurate and cannot perform a live
compare-and-set. After actual recovery, owned values no longer match the prepared
edit; a later engine integration must track completion rather than infer another
write from this snapshot. Same-session binding deliberately refuses later sessions;
cross-session recovery requires its own identity/state contract.

## Evidence, acceptance and recovery

The exporter exclusively creates a new UTF-8 JSON file and refuses an existing path,
including one created during collection. Output may contain private hostnames and
PAC query tokens. Keep the complete evidence locally with appropriate permissions;
review/redact a separate copy before sharing. The tool does not change directory
ACLs. On write failure, retain any partial output and use a new filename.

`tests/UserProxyInventory.Tests.ps1` verifies identity/drift guards, native layout,
fallback/error paths, high bits, null/empty/Unicode, memory cleanup, string bounds,
completion and output races without a real WinINet query. Disposable-target
acceptance must compare the intended user's default/LAN UI with the captured
options, include disabled-but-retained strings and verify policy/alternate-account
limitations. Do not use a developer workstation as a mutation test target.

`tests/UserProxyPreparation.Tests.ps1` additionally checks owned-field preservation,
URL syntax, null/empty recovery, JSON round trips, identity mismatch, conflicting
current edits and inconsistent snapshots using supplied data only.

Next implementation must bind the prepared edits to fresh native observations and
durable saved state, prove managed-source refusal, apply/repeat/partial-failure
behavior, documented refresh and conflict-aware live recovery. Test PAC consumers against a controlled local fixture.
Named RAS identity and machine WinHTTP require separate coverage. No live setter
exists here, and removing this preparation needs no proxy-state recovery. See the
[capture record](migrations/settings-post-migration-review.md#b04-defaultlan-proxy-observation-2026-10-16)
and [edit-preparation record](migrations/settings-post-migration-review.md#b04-proxy-edit-and-recovery-preparation-2026-10-16).
