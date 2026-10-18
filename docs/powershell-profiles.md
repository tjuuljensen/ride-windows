# PowerShell profile settings in RIDE v3

## Scope and migration decisions

PowerShell startup profiles are executable `.ps1` files. RIDE selection profiles
under `profiles/` are declarative `.psd1` files. The engine reads selections; a
focused handler manages individual startup settings without evaluating the profile.

The legacy inventory has two writers: `AddUserBinToPath` in
`legacy/v2/lib-windows.psm1` and `components/scripts/Write-Profile-File.ps1`.
The former combines directory creation and process/startup PATH changes; the
latter appends user-bin and WindowsApps snippets. Neither provides v3 recovery.

| Behavior | v3 disposition |
| --- | --- |
| Create a missing startup profile | Internal behavior when a selected setting needs a file; resolve each runtime's intended-user ConsoleHost profile. |
| Add user-bin to PowerShell PATH | Pending optional `UserBinPath` renderer, separately selectable per runtime: existing directories, normalized case-insensitive matching, no duplicate append. Startup process PATH is distinct from persistent user-environment PATH. Known unmarked legacy snippets block enablement until reviewed. Native startup acceptance remains pending. |
| Create the bin directory | Separate provisioning operation and dependency with its own recovery. Legacy `$FolderInPath` is undefined. `GetFolderPath("USERPROFILE")` does resolve the current user's profile directory; the missing directory variable, unconditional appends and absent recovery are the reasons to replace the writer. |
| Append WindowsApps | Optional future repair only when missing from applicable PATH. Preserve entries and app-alias choices; do not append unconditionally or select by default. |
| Edition colors and administrator blue | Two optional ProfileSetting operations, accepted on Windows 11 and Server 2025 Desktop Experience. |
| Terminal default shell | Separate accepted Terminal configuration work; this handler does not edit settings.json or elevation choices. |
| Titles, prompt functions, arbitrary startup scripts, all-users profiles | Outside this increment. Future settings need independently useful effects, an allowlisted renderer, declared states and lifecycle tests. Arbitrary script text is not catalog data. |

The legacy PATH outcome stays in the accounts/configuration migration estimate.
The new color IDs represent one requested appearance outcome outside that inventory.
This increment closes no user-bin, directory, WindowsApps or Terminal-shell outcome.

## Handler architecture

`modules/RIDE-ProfileSettings.psm1` owns file mechanics and dispatches an allowlisted
`ProfileSetting` renderer. `TerminalColors` and the pending `UserBinPath` share
the same file lifecycle with separate renderer/schema checks. External
library API 1 remains unchanged and does not accept this operation kind yet.

Each catalog operation declares ProfileRuntime, ProfileSetting, named States,
UnsetState, BaselineState, references and targets. Runtime is part of operation
identity: installing PowerShell 7 does not silently extend a saved 5.1 run.

| Command | Contract |
| --- | --- |
| Get-RideProfileSettingState | Query each installed runtime with NoProfile/NonInteractive, a thirty-second timeout, and no execution-policy changes. Read at most 1 MiB; report availability, SID, path and managed state. |
| Get-RideProfileSettingSnapshot | Snapshot version 1 captures runtime/setting/SID/path, original file presence/bytes/block/offset, and expected post-change bytes/block. The engine saves it before writing. |
| Set-RideProfileSettingState | Render declared data, validate resulting syntax and captured preconditions, then compare bytes again under an exclusive file handle. Honor ShouldProcess. |
| Restore-RideProfileSettingState | Preflight identity/version/path and saved byte relationships. Recover the predecessor or report a conflict; ValidateOnly checks a run before any restore writer. Honor ShouldProcess. |

Discovery uses runtime-reported CurrentUserCurrentHost paths, including redirected
Documents. Missing runtimes are unavailable, not successful no-ops. Profile
directories, redirecting/unknown reparse ancestors, invalid syntax, duplicate markers and edited
managed blocks fail explicitly. Existing profiles are never sourced.
Known Microsoft cloud placeholder tags are allowed after metadata-only tag
inspection; OneDrive placeholders do not mean symbolic-link redirection. Symlinks,
junctions and unknown tags remain rejected. Cloud hydration/write behavior remains
unverified beyond the accepted ordinary/redirected local Documents scenarios. See Microsoft's
[reparse tag reference](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags).

Versioned begin/end comments identify the operation and state. The parser verifies
real top-level comments rather than markers inside strings or nested code. The
leading separator belongs to the block, preserving files without a final newline.
UTF-8 with/without BOM, BOM-marked UTF-16 LE/BE, single-byte files and existing
block line endings are preserved. Binary/UTF-32 text is rejected.

Default and unset remove only the selected block. Restore recovers exact original
bytes when no unrelated edits occurred; otherwise it replaces only the expected
managed block and retains edits before/after it. Following unset, reinsertion
allows an unchanged original boundary and appended content; other changes require
review. Modified managed content is never silently overwritten.

Restore deletes a newly created profile only if it still contains exclusively
the expected RIDE content, marking deletion on the locked Windows handle. New user
content is retained. Created parent directories remain; timestamps and other file
metadata are outside the exact managed-content/file-presence recovery contract.
A caught write failure attempts byte recovery under the same lock. Interruption or
unrecoverable I/O failure retains original bytes in the saved run for manual
recovery; do not execute saved bytes as a recovery shortcut.

## Colors and lifecycle states

| Runtime | Recommended normal session | Elevated session |
| --- | --- | --- |
| Windows PowerShell 5.1 | Campbell | Campbell PowerShell blue (#012456) |
| PowerShell 7 | One Half Dark | Campbell PowerShell blue (#012456) |

Recommended applies these palettes. AdminBlue preserves normal-session configured
appearance and applies blue only when elevated. Default removes the block;
Baseline resolves to Default. This means no RIDE override, not a universal Windows
Terminal color default. Saved-run restore recovers the predecessor.

Startup checks WindowsPrincipal.IsInRole on the actual token, covering a normal
Terminal profile opened in an elevated window. Guards require local interactive
ConsoleHost, WT_SESSION, the matching major version and unredirected output;
remote and NonInteractive sessions return without emitting colors. WT_SESSION
alone is insufficient to enable the behavior in a hosted shell.

The renderer emits OSC 4 for sixteen ANSI colors, OSC 10/11 for foreground and
background, and OSC 12 for the cursor. Reviewed fixed presets live in
`components/profiles/terminal-color-schemes.psd1`; Microsoft's MIT notice is retained
beside the data and in generated blocks. These are RIDE presets, not a selector
for custom Terminal schemes. Selection color, transparency/background images,
fonts, titles and prompts retain their existing host configuration. NoProfile,
blocked profile execution, other shells and later tool/profile overrides can bypass
or replace the colors. Changes affect new shells; existing tabs are not restarted.
Apply in the intended user's context: alternate administrator credentials select
that administrator's own profile and RIDE state store.

## Existing user-bin startup PATH candidate

The optional `powershell.windows-powershell51-user-bin-path` and
`powershell.powershell7-user-bin-path` candidates manage the selected runtime's
current-user ConsoleHost profile. They have no supported targets and are excluded
from selection profiles until disposable Windows 11 startup acceptance. Inspect
their catalog metadata with `list profile-settings` or `show <id>`; normal apply
remains blocked. No runtime or bin directory is installed by either candidate.

`Enabled` writes a fixed startup block. When that profile runs in a matching
local ConsoleHost, it resolves the current user's profile directory with
`Environment.GetFolderPath(UserProfile)` and checks its `bin` child. If the
directory exists, the block appends it to process PATH only when no equivalent
entry exists. Comparison ignores case, normalizes full paths and trailing
separators, and recognizes quoted entries and expanded environment variables.
Existing PATH bytes and ordering stay intact, including pre-existing duplicates;
RIDE does not deduplicate unrelated entries. Appending preserves earlier command
search precedence. Review the contents of your bin directory before enabling it.

Missing/inaccessible directories, invalid profile-directory text or an overlong
result leave PATH unchanged. Remote/mismatched runtimes return without inspection.
The block does not require Windows Terminal or emit colors. It uses a local script
scope, creates no profile variables outside that scope, and does not provision
directories, repair WindowsApps or write persistent user/machine environment data.
Applying the setting edits only the profile file; it does not change the running
RIDE process's PATH. NoProfile and blocked profile execution bypass startup code.

`Default`, unset and Baseline remove only this managed block. Saved-run restore
recovers the previous managed profile content using snapshot version 1. Neither
workflow removes entries already inherited by running shells or child processes.
For a clean startup comparison, launch from a parent whose PATH was not modified
by the prior block; opening a child from an affected shell can retain the entry.
Inspection reports configured startup state, not another process's effective PATH
or whether the bin directory currently contains usable commands.

Both legacy writers use the variable `UserBinaries`. Enablement and snapshot
preparation reject executable references to that variable outside the selected
managed block. Comments and literal examples alone do not trigger this check.
RIDE does not execute, adopt or delete unmarked profile code. Back up and review
that code manually, including custom PATH writers which this narrow detector
cannot identify. Default/unset preserve it. Later profile statements can still
replace or append PATH after the RIDE block; arbitrary startup scripts are outside
its ownership. Bin provisioning and persistent PATH selection remain separate
open decisions, as does legacy WindowsApps repair.

Source checks use isolated profile files and restored test-process PATH only.
`tests/UserBinProfile.Tests.ps1` covers normalized duplicates, missing directories,
runtime/remote guards, read-only completion, legacy conflicts, color coexistence,
repeat apply and exact recovery. Existing color acceptance runners explicitly
select TerminalColors so they cannot silently admit this new renderer. Next
acceptance requires intended-user/runtime discovery and new-shell behavior on a
disposable target, including missing/existing bin, inheritance, NoProfile, blocked
startup, unmarked writers and exact recovery. Q08 now accepts persistent user PATH as a separate explicit setting. Its
implementation and recovery remain open; removing either setting must preserve
the bin directory and contents. See the [decision record](migrations/decision-session-2026-10-17.md#q08-separate-powershell-startup-and-persistent-user-path-choices).

Microsoft documents [startup profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
and [process environment behavior](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables).
The user-bin selection, duplicate handling and managed-block recovery are RIDE's
implementation, not a Microsoft-documented Windows default.

## Persistent user PATH preparation

Q08 accepts persistent user PATH as a separate explicit setting. The startup
renderer above remains independent. RIDE.UserPathPreparation 0.1.0 provides a
literal read-only observation and in-memory append/recovery contract; no registry
setter, environment refresh or catalog operation is enabled yet.

From the repository root in native PowerShell 5.1 or 7, on the explicitly intended
interactive user's target, no elevation is required. Replace the identity values
with independently verified values; do not substitute another user's hive:

```powershell
Import-Module .\modules\RIDE.UserPathPreparation.psm1
$observed = Get-RideUserBinPathObservation -ExpectedComputerName '<computer>' -ExpectedUserSid '<intended SID>' -ExpectedSessionId 1
$patch = New-RideUserBinPathPatch -Observation $observed
$patch | Select-Object Entry,ChangeRequired,ReadyForMutation
```

Observation reads only HKCU Environment/Path through a read-only handle and
DoNotExpandEnvironmentNames. Missing key, missing value, empty data and String
versus ExpandString remain distinct. Machine, user SID, interactive session and
known profile directory are checked before and after reading. Read errors fail;
they are never interpreted as absent configuration. This is sequential evidence,
not an atomic snapshot or proof of the effective process PATH.

Preparation proposes the absolute bin directory beneath that observed profile.
It preserves all original text, ordering, empty entries and value kind, appending
one owned token only when an equivalent token is absent. Existing equivalent
entries, including pre-existing duplicates, remain unowned no-ops. Comparisons
recognize case, slash/trailing-separator, surrounding quote/space and the supplied
profile's USERPROFILE reference. They never use the calling process environment
for expansion. Unknown variable references, malformed quoting and ambiguous
local-path syntax require review. Relative/UNC entries are preserved literally;
physical identity through shares, junctions or aliases is not established. The
32766-character limit is conservative and does not prove merged environment size.

The version-1 snapshot reconstructs the append and binds recovery to the same
computer, SID, session and profile. To prepare recovery against a later observation:

```powershell
$recovery = Restore-RideUserBinPathPatch -Observation $current -Snapshot $patch.Snapshot
$recovery.DesiredValue
```

Exact expected data restores original absence, kind and text. If unrelated tokens
changed, recovery removes only one exact owned token and its adjacent separator.
Changed spelling, equivalent duplicates or value-kind changes conflict; an already
removed/restored token is a no-op. A pre-existing unowned entry is never removed.
An Environment key or bin directory is never owned or deleted. New unrelated
content keeps the value present even when it was originally absent. Matching text
cannot prove that another actor did not remove and recreate the same token.

ReadyForMutation, MutationAuthorized and EffectivePathVerified remain false.
Snapshot schema checks do not authenticate operator-supplied records or prove
that a proposed append occurred. Durable private state, actual bin availability,
fresh identity/registry guards, write/post-state verification, interruption
recovery, inherited/machine PATH coexistence and refresh behavior still need
implementation and disposable acceptance. No running process environment changes
automatically from this API. Preserve the folder and contents for both choices.

Microsoft describes [process environment inheritance](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
and [literal registry retrieval](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registrykey.getvalue).
RIDE's append/ownership rules are implementation constraints. See the
[dated validation](migrations/settings-post-migration-review.md#b03-persistent-user-path-observation-and-recovery-2026-10-17).

## Color usage and acceptance

Both color operations are accepted on Windows 11 and Windows Server 2025 Desktop
Experience with Windows Terminal and the selected runtime installed. The declared
literal default is Default (no RIDE-managed block); the effective default is the
configured Terminal appearance. The optional selection profile requires both
runtimes and is not selected by profiles/default.psd1. See the
[dated VM acceptance record](archive/migrations/powershell-profile-acceptance.md) for tested
versions, retained runs, recovery and remaining cloud/alternate-launch scenarios.

```powershell
.\ride.ps1 list profile-settings
.\ride.ps1 show powershell.windows-powershell51-terminal-colors
.\ride.ps1 plan -Profile .\profiles\powershell-colors.psd1
.\ride.ps1 status -Profile .\profiles\powershell-colors.psd1

.\ride.ps1 set powershell.windows-powershell51-terminal-colors Recommended -WhatIf
.\ride.ps1 set powershell.powershell7-terminal-colors AdminBlue -WhatIf
.\ride.ps1 set powershell.powershell7-terminal-colors Default -WhatIf
.\ride.ps1 unset powershell.powershell7-terminal-colors -WhatIf
.\ride.ps1 restore -RunId <saved-run-id> -WhatIf

# Apply both recommended palettes when both runtimes are installed:
.\ride.ps1 apply -Profile .\profiles\powershell-colors.psd1 -WhatIf
.\ride.ps1 apply -Profile .\profiles\powershell-colors.psd1
```

Tab completes IDs, profile paths and each operation's states from catalog metadata, without
runtime/profile inspection. show/status report startup configuration, not another
tab's token or observed colors. Missing runtimes are reported as unavailable.

`tests/ProfileSettings.Tests.ps1` exercises isolated files and mocked discovery.
The focused disposable VM runner uses an existing idle controller configuration,
exclusive worker lock, pinned checkpoint and guest credential through PowerShell
Direct. Its guest scripts verify real lifecycle, redirected Documents,
alternate-account identity/recovery and 22 interactive Terminal cases per target,
including inherited elevation, NoProfile, blocked startup, PSReadLine and selection.
It retains hash-correlated source, JSON run state and screenshots before checkpoint
recovery. Use `tests/integration/Invoke-RideProfileVmAcceptance.ps1`; its optional
PowerShellArtifactPath accepts publisher acquisition JSON for a cached signed MSI.
No workstation integration or production target-bypass flag is provided.

For the separate pending user-bin candidates, select `-Scenario UserBinPath` on
the same VM runner. This Windows 11 case requires both runtimes already installed
and an initially absent user bin directory. It acquires no prerequisite and
does not change UAC. It checks real ConsoleHost startup with missing/existing bin,
equivalent inherited PATH entries, NoProfile, repeat apply, Default and exact
saved-profile restoration. The fixture creates and removes only its own sentinel
and empty bin directory; unexpected content stops cleanup. Existing profile code
that changes PATH can make the case fail and must be reviewed, not erased.
Use the existing idle controller configuration, guest credential and a fresh
output directory; omit PowerShellArtifactPath for this scenario. Collection of
source hashes, evidence and saved runs precedes pinned-checkpoint recovery.
This scenario is prepared, not yet accepted; it does not expand supported targets.

References: [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles),
[Terminal color schemes](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/color-schemes),
[Terminal elevation](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/profile-general#automatically-run-as-administrator),
and [Terminal escape handling](https://github.com/microsoft/terminal/blob/main/src/terminal/parser/OutputStateMachineEngine.cpp).
