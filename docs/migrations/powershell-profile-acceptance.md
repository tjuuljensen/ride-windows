# PowerShell profile color acceptance - 2026-10-12

This record covers the two optional `ProfileSetting` operations described in
[the handler and migration analysis](../POWERSHELL-PROFILES.md). It accepts a
current-user startup preference. It does not accept the deferred legacy user-bin
or WindowsApps writers, or the PowerShell package operation on Server.

## Disposable target evidence

| Target | Retained run | Terminal | Windows PowerShell | PowerShell 7 | Result |
| --- | --- | --- | --- | --- | --- |
| Windows 11 | `cd91b3d8ed31438f9cb331dc25a8a2b4` | 1.18.10301.0 | 5.1.26100.9444 | 7.6.6 | Passed: lifecycle, identity, 22 visual cases, collection and checkpoint recovery. |
| Windows Server 2025 Desktop Experience | `236988fcb1284353b35c84fc43560bfc` | 1.24.12741.0 | 5.1.26100.33438 | 7.6.6 | Passed: lifecycle, identity, 22 visual cases, collection and checkpoint recovery. |

The tested profile module is version **0.1.2**, SHA-256
`4DDA86F421B69D96B9C39F5F25A6906E29C2C98CF75259410B54FCFFB108BD5F`.
The runner retains a hash manifest and the source snapshot for every run.
Local evidence is under ignored `.local/profile-vm-win11/<run-id>` and
`.local/profile-vm-server/<run-id>`; it is supplementary checkout evidence,
not a release artifact. Keep this dated record with the implementation.

Each edition passed real runtime/path discovery, preview without writes, captured
JSON run recovery, repeat apply without a new record, Recommended/AdminBlue,
Default/unset, baseline application and restore preview. A read-only profile
caused the expected partial failure with a recoverable saved run. Final recovery
verified original file bytes and presence; both original profiles were absent.

The redirected-Documents test changed only the disposable account's known-folder
values, discovered each runtime's resulting path and restored profile content
and registry values. A newly generated administrator account ran a separate
password-logon task: it used its own SID and paths, rejected a foreign snapshot,
and restored its profiles. The owned account/task were removed. This verifies
alternate-account inspection and recovery; interactive Terminal registration and
launch under alternate credentials were not exercised.

The visual cases use a controlled normal Terminal profile with `elevate=false`
and a distinctive `#101820` configured background. For each edition and actual
limited/high token, they verify Recommended, AdminBlue, Default, NoProfile and
Restricted startup. High-token tests also create an elevated window and open
that normal profile as another tab. The probe records token, SID, ConsoleHost,
session, unredirected output and runtime version. Screenshot pixels independently
verify background colors. Recommended normal backgrounds were `#0C0C0C` in 5.1
and `#282C34` in 7; both elevated editions rendered `#012456`. Bypassed/removed
startup overrides retained `#101820`.

Every visual case includes ordinary, warning and error output, an unexecuted
command entered at the actual PSReadLine prompt, cursor and selected-text
screenshots. Sample captures were visually reviewed. Terminal 1.18 uses a
translucent selection overlay; 1.24 renders an opaque selection with dark text.
The acceptance script recognizes both observed behaviors. Selection, fonts,
opacity and titles remain Terminal configuration, outside the profile renderer.
Color-query replies were unavailable to the 1.18 console probe; screenshot
measurement establishes the rendered result. The 1.24 probe also returned colors.

## Harness corrections and recovery

Early cold discovery exceeded the original ten-second deadline. The handler now
allows thirty seconds without evaluating the startup profile. Recovery was also
corrected to remove an empty RIDE-created profile after a subsequent unset.

An initial OSC-only check failed despite the correct captured appearance; the
check now measures screenshot backgrounds. A solid-selection-only assumption
failed on Terminal 1.18 and was corrected for its observed overlay behavior.
These failures were retained and recovered, not reported as successful runs.

Server run `777e52e60e054d5fa299046c0e61eafb` passed its guest lifecycle, identity,
22 visual/selection cases and profile recovery. Saved-state collection then failed
because a piped copy reused a still-busy remote session. Its visual/recovery
evidence was retained; the overall runner result is Failed. The collector now
materializes all remote paths before copying through that session. The final
Server run passed acceptance and collection with this correction. Both catalog
operations now declare these supported targets, PendingAcceptance=false and
explicit defaults: no RIDE-managed block and configured Terminal appearance.

All completed attempts returned their exact registered VM to its pinned clean
checkpoint and Off state. Host UAC remained enabled; no workstation profile,
Terminal configuration, execution policy or account was modified. Guest UAC and
the signed PowerShell MSI were disposable test prerequisites. Repeated downloads
used the earlier publisher acquisition metadata, exact SHA-256 and a verified
Microsoft signature to avoid GitHub API rate limits.

## Scope and remaining checks

Target acceptance covers the tested desktop guests, ordinary/redirected local
Documents and the installed runtime/Terminal versions above. OneDrive/cloud
placeholder hydration, network-backed Documents, other Terminal rendering modes
and interactive alternate-credential launches remain additional acceptance work.
The handler recognizes known Microsoft cloud tags, but this record does not
establish cloud-provider behavior. Modified managed blocks, unknown redirections
and recovery identity conflicts fail explicitly.

Profiles disabled by NoProfile or execution policy do not run the preference.
Later startup/tool overrides and user-selected background images/transparency
can change the visible result. These are startup preferences for new supported
shells, not a universal administrator indicator for every process or shell.

Local regression passed **215 checks per edition** on Windows PowerShell
5.1.26100.9549 and PowerShell 7.6.5: 37 profile checks, six acceptance entry-point
checks and 172 related catalog/discovery/presentation/preview/Shell-folder checks.
The unrelated state-changing WindowsIntegration test was excluded. Native
parser/catalog/profile/generated-document validation passed. This addition closes
no legacy feature outcome; all migration estimate ranges remain unchanged.

Before publishing all current changes, the complete mocked repository suite
passed **1,248 tests per edition**, with zero failures or skips. Both editions
also passed validation of 303 operations, three groups, five profiles, all 106
PowerShell files and current generated documentation. These workstation checks
do not extend the disposable target or visual acceptance scope above.
