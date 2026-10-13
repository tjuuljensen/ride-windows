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
| Add user-bin to PowerShell PATH | Future optional `UserBinPath` renderer: existing directories, normalized case-insensitive matching, no duplicates. Process/startup PATH is distinct from persistent user-environment PATH. Existing unmarked snippets require explicit review. |
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
`ProfileSetting` renderer. `TerminalColors` is implemented first; another setting
adds a renderer and schema checks, not another whole-profile writer. External
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

## Usage and acceptance

Both catalog operations are accepted on Windows 11 and Windows Server 2025 Desktop
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

Tab completes IDs, profile paths and all four states from catalog metadata, without
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

References: [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles),
[Terminal color schemes](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/color-schemes),
[Terminal elevation](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/profile-general#automatically-run-as-administrator),
and [Terminal escape handling](https://github.com/microsoft/terminal/blob/main/src/terminal/parser/OutputStateMachineEngine.cpp).
