# User proxy inventory and lifecycle

This tool captures literal default/LAN WinINet proxy options for an explicitly
identified interactive account. It preserves manual proxy, bypass and PAC strings
and all flags, including unknown bits. It does not fetch a PAC file, resolve a proxy,
test connectivity, refresh settings or change network configuration. The catalog
includes a pending-acceptance automatic-detection operation with no supported
targets until native acceptance succeeds.

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

## Native write boundary candidate

`RIDE.UserProxyInventory` 0.2.0 now contains a low-level writer for the default/LAN
connection. It writes `INTERNET_PER_CONN_FLAGS` and includes
`INTERNET_PER_CONN_AUTOCONFIG_URL` only when the caller marks that URL as owned.
It leaves the manual proxy server and bypass options untouched, then reports the
separate `INTERNET_OPTION_SETTINGS_CHANGED` and `INTERNET_OPTION_REFRESH` results.
The setter requires the expected current computer, user SID and interactive
session, and honors `ShouldProcess`.

This is a native write boundary, not a complete setting lifecycle or a command for
direct use. It has no durable pre-change store, complete managed-policy coverage, atomic
compare-and-set, post-write readback, partial-failure compensation, conflict-aware
restore or RIDE engine/catalog integration. It can therefore change proxy behavior
if invoked and approved, while recovery remains unimplemented. Do not invoke it
outside a future lifecycle wrapper. WinHTTP, named RAS/VPN connections, PAC
retrieval and PAC consumer behavior remain separate. Microsoft documents the
[per-connection option structures](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw)
and the [set/refresh sequence](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options).

The 0.3.0 candidate adds a read-only policy check before that low-level writer.
It checks the documented `Proxy` policy value in the current-user and local-machine
`Software\Policies\Microsoft\Internet Explorer\Control Panel` keys, and the
local-machine `ProxySettingsPerUser` policy value under
`Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`. A
nonzero `Proxy` restriction or `ProxySettingsPerUser=0` reports `Blocked`; malformed
values report `Unknown`; a denied registry read throws, so the write does not proceed.
Microsoft maps `DisableProxyChange` to the `Proxy` registry value and documents that
it prevents proxy changes; Microsoft also documents `ProxySettingsPerUser=0` as
machine-wide configuration. See the [InternetExplorer policy mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-internetexplorer#disableproxychange)
and [NetworkProxy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/networkproxy-csp#proxysettingsperuser).

`Clear` means only that these inspected values were absent or nonblocking. It is
not a complete effective-policy inventory and does not prove desktop ownership,
effective routing or that an application consumes WinINet settings. The policy
observation is not durable state. The low-level writer itself has no compare,
readback or recovery; the separate guarded lifecycle candidate below supplies
local compare/readback behavior but still lacks engine integration.

## Guarded apply and restore candidate

The RIDE.UserProxyLifecycle module adds Set-RideUserProxyConfigurationPatch and
Restore-RideUserProxyConfigurationSnapshot. Apply validates the version-1
preparation snapshot, checks the explicit current machine/SID/session, compares a
fresh default/LAN observation with the full prepared literal values, checks the
documented policy values, honors ShouldProcess, writes the changed flags and
owned PAC URL, then reads the result back. It returns the preparation snapshot and
distinct statuses for success, no-op, refused drift, native failure, incomplete
refresh, mismatch and unverified readback.

If the native setter reports success but a notification fails, the candidate
rechecks current values and policy, then attempts to restore the complete
pre-operation literal values. It verifies that compensation and reports whether it
completed. If post-write values conflict, or two readback attempts fail, it reports
an unverified/partial result and does not overwrite unknown current data. Restore
reconstructs the owned flag mask and URL from the supplied preparation snapshot,
refuses changed owned values, and retains unowned current flags, manual proxy,
bypass and URL values.

The lifecycle persists its version-1 preparation snapshot as a create-new
JSON record under `%LOCALAPPDATA%/RIDE/State/UserProxy/<RunId>.json` after
`ShouldProcess` approval and before calling the WinINet setter. `WhatIf` creates no
record. Engine apply supplies its saved `RunId` to the lifecycle, so the proxy snapshot and restore-completion marker use the same run identity. Apply returns `RunId` and `SnapshotPath`; restore accepts either the
in-memory snapshot or `-RunId`, validates the saved machine/SID/session binding,
then performs the same fresh compare, policy check, owned-field recovery and
readback. A successful `-RunId` restore writes a create-new completion sidecar;
a repeat returns `AlreadyRestored` if the owned values still match the captured
prior state, and refuses if they drifted. If sidecar creation fails after verified
restoration, the result is `AppliedCompletionUntracked` for explicit inspection.
The state and completion files are user-writable and schema-validated, not
authenticated. The engine integrates automatic detection as
`windows.proxy-auto-detect`, captures the prior owned flag in the saved run, and
uses conflict-aware recovery. Windows 11 remains a candidate target; the catalog
declares no supported target until disposable Windows acceptance.

The compare before a WinINet set is not atomic against other applications. RIDE
does not claim an atomic compare-and-set across Windows applications; it rechecks
literal values and documented policy immediately before its setter and refuses
detected conflicts. Complete effective-policy coverage, controlled PAC-consumer
checks and native Windows acceptance remain open. Focused tests use fake
observations, policies and setters; they make no registry or WinINet calls. No
proxy setting has been changed by this implementation work.

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

The setup-script/address control remains separate because enabling it needs an
explicit PAC address. Continue by completing effective-policy coverage, testing
PAC consumers against a controlled local fixture, and running disposable Windows
11 lifecycle/recovery acceptance before declaring a supported target. Preview the
pending automatic-detection operation with:

```powershell
.\ride.ps1 set -Id windows.proxy-auto-detect -State Disabled -WhatIf
```

The fake writer and lifecycle tests validate buffers, comparisons, durable
snapshot ordering, restore by run ID, readback and compensation only; no WinINet
setter was called.
Named RAS identity and machine WinHTTP require separate coverage. No live setter
exists here, and removing this preparation needs no proxy-state recovery. See the
[capture record](migrations/settings-post-migration-review.md#b04-defaultlan-proxy-observation-2026-10-16)
and [edit-preparation record](migrations/settings-post-migration-review.md#b04-proxy-edit-and-recovery-preparation-2026-10-16).
