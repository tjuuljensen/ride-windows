# Owned power-plan copies

The experimental creation operations are separate from
`windows.active-power-scheme`, which continues to select existing Balanced or
High Performance plans and restore the captured active GUID. Creating a copy
does not select it, change Settings power mode or establish Ultimate Performance
availability. No recommended profile includes these candidates.

| Catalog ID | Exact source template GUID |
| --- | --- |
| `windows.owned-balanced-power-plan` | `381b4222-f694-41f0-9685-ff5bb260df2e` |
| `windows.owned-high-performance-power-plan` | `8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c` |
| `windows.owned-ultimate-performance-power-plan` | `e9a42b02-d5df-448d-aa00-03f14749eb61` |

Each exposes only `Create`. Source availability is checked by exact GUID, with
no English-name matching, fallback, adoption of an existing destination or
reset of built-in plans. Ultimate's previously queryable GUID failed activation
in recorded VM evidence; duplication is a separate pending scenario. Power Saver
appears in legacy fallback code but has no separate legacy selector migrated by
this batch. No additional selection state is introduced.

## Capture and ownership

The engine captures a proposed destination GUID and a random owner token in
its protected machine-scoped saved run before the handler changes Windows.
An operation-specific record under `%ProgramData%\RIDE\State\OwnedPowerPlans`
records that same identity with stage `Intent` before `/duplicatescheme` runs.
A per-operation exclusive file lock prevents concurrent RIDE creation/recovery.
Ownership records are bounded to 16 KiB; reparse paths and mismatched identities
are rejected. A name is a user-visible label, never proof of ownership.

After explicit-GUID duplication, the handler labels the copy, verifies that it
is inactive and fingerprints logical data in native `/export` files. New version-2
records use `LogicalExportV1`: the complete sorted key hierarchy, key classes,
raw named value types/bytes and owner/group/DACL from a private read-only
[application-hive handle](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeyw).
Names retain their UTF-16 code units; values are not expanded or retyped. Subkey
links are opened without following them. Two consecutive logical comparisons must
agree before finalizing ownership. Native parsing, bounds or stability failure
retains Intent. Import performs no native inspection.
A successful record is marked `Ready`. Transport headers and key timestamps are
excluded through the documented API, without masking byte ranges. SACL, policy
provenance and effective inherited or hardware-dependent behavior are outside
this logical-data comparison. It does not certify Windows registry security policy
or complete feature behavior. Temporary exports are limited to 1 MiB and cleaned up;
their content is not stored in logs or snapshots. Inspection reports ownership,
presence, source availability and active state. It writes no export, lock,
directory or ownership record, and explicitly reports that unchanged
configuration has not been checked. Repeated satisfied `Create` runs produce no
additional copy.

## Bounded recovery

Restore uses the trusted engine state directory, never a snapshot-supplied path.
It requires the captured operation, source, destination and owner token to match
a finalized ownership record. The same destination must be inactive and its
new logical export must match the recorded configuration SHA-256 before `/delete`
is allowed. Raw export SHA-256 is retained as creation evidence. Version-1 records
retain their original raw-file comparison contract, with no automatic conversion
or weaker fallback; unstable legacy exports can therefore still refuse recovery.
The active GUID is checked again immediately before deletion. Restore removes
the ownership record only after native deletion is confirmed; failed deletion
retains it for retry. It never changes the active plan to make deletion possible.

Recover an existing-plan selection run first if the owned copy has been selected.
Do not edit power plans through another tool concurrently with recovery: the
RIDE lock cannot lock external Windows writers. Active, changed, orphaned,
unfinalized or differently owned copies are retained for manual review. An
interruption after duplication but before `Ready` may leave an inactive copy
and an `Intent` record; RIDE does not infer safe deletion from intent alone.
This is declared **compensating** recovery, rather than unconditional exact
rollback. Restore of a run that captured pre-existing ownership does not delete
or reconstruct that pre-existing plan.

## Native handoff and acceptance

Native Power Options can be opened separately in the intended user's session.
Microsoft documents [canonical Control Panel launching](https://learn.microsoft.com/en-us/windows/win32/shell/executing-control-panel-items)
and the [Microsoft.PowerOptions name](https://learn.microsoft.com/en-us/windows/win32/shell/controlpanel-canonical-names).
The manual PowerShell handoff uses the current Windows directory:

```powershell
& (Join-Path $env:SystemRoot 'System32\control.exe') /name Microsoft.PowerOptions
```

Opening the panel does not create or select a plan. After owned creation has
been accepted for the target, inspect the
reported destination GUID; selecting or customizing it is a separate user
action. The catalog now includes the pending current-user operation
windows.power-options-shortcut, which creates a desktop shortcut targeting
%SystemRoot%\System32\control.exe /name Microsoft.PowerOptions. Its
SupportedTargets remains empty until the current Windows 11 launcher and UI
behavior pass disposable-target acceptance; it is not in a recommended profile.
It provides native access only and never selects or creates a plan.

The old merged-HKCR submenu is not recreated, and direct quick-selection remains
deferred until it can invoke the maintained plan-selection workflow with saved
state capture and current-GUID validation. The shortcut uses the current user's
desktop, not an all-users location. Creation itself needs machine administrator
rights; shortcut presence is a separate user-scoped setting.

Microsoft documents explicit destination GUIDs for
[/duplicatescheme, /export and /delete](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#duplicatescheme).
That command contract does not establish hardware/edition availability or
binary export reproducibility. Current candidate targets are Windows 11 and
Windows Server 2025; `SupportedTargets` remains empty, blocking normal apply,
including preview, until target acceptance is recorded. Local mocked tests
prove control flow and ownership boundaries only. Required VM scenarios include
repeat create, localized discovery, hidden-setting/name changes, reproducible
exports, active-copy refusal, staged failure, selection-first recovery and
Ultimate availability. See the [remaining settings ledger](migrations/remaining-settings-decisions.md)
for current lifecycle and desktop-menu acceptance work.
