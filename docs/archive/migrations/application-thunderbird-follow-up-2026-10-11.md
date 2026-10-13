# Thunderbird current-user migration, 2026-10-11

Archived run evidence. Counts, support and remaining-work statements below are
as recorded on the report date. Use the [current migration plan](../../MIGRATION-PLAN.md)
and [active application ledger](../../migrations/application-migration-review.md)
for current disposition; archiving does not close pending acceptance.


Latest disposition: accepted for deployment lifecycle on Windows 11 and Windows
Server 2025 Desktop Experience. The final correlated results and recovery
limits are recorded [below](#accepted-migration-after-resumed-validation).

The user confirmed Release x64 in UK English (`en-GB`) for current-user scope.
This replaces the legacy download's explicit x86 choice while preserving its
literal UK locale. The choice does not change Windows display language,
formats, keyboard, location or Office languages.

`package.thunderbird` is optional and retains one stable product ID with an
`installed` variant. Its destination resolves during planning to
`%LocalAppData%\Programs\Mozilla Thunderbird`. The resolved destination,
installer options, source, architecture, locale, channel, scope and execution
restriction are retained with the saved package selection. Removal and restore
use that selection. Profiles retain their existing bytes.

## Scope and recovery contract

Mozilla's [shared registration code](https://github.com/mozilla/releases-comm-central/blob/HEAD/mail/installer/windows/nsis/shared.nsh)
attempts HKLM registration and falls back to HKCU when machine writes are
unavailable. An elevated custom-directory install can therefore become a
machine registration. RIDE requires a non-elevated PowerShell session for this
package, including removal and restore, before capturing state or invoking an
installer. Preview remains read-only.

The installer receives an explicit writable user destination and disables the
maintenance service and default-agent registration. It preserves distribution
configuration and requests no reboot. These options follow Mozilla's
[common NSIS option parser](https://github.com/mozilla-firefox/firefox/blob/main/toolkit/mozapps/installer/windows/nsis/common.nsh)
and [Thunderbird installer](https://github.com/mozilla/releases-comm-central/blob/HEAD/mail/installer/windows/nsis/installer.nsi).
The publisher's uninstaller handles installed application files and shortcuts;
RIDE preserves the Roaming Thunderbird directory through its existing
journaled user-data preservation handler. A running Thunderbird process or
unfinished preservation journal blocks removal.

Machine registrations, other architectures/locales, ESR, unverifiable update
channels and different destinations require individual review. Unregistered
content at the destination and reparse-point destinations block installation.
The installed `channel-prefs.js` must identify Release. No mailbox is opened,
no account is configured and no default-mail-client selection is requested.
Restoring prior presence is compensating recovery using the saved distribution
selection and its publisher-selected installer; a matching retained cache is
reused when available. The engine explicitly warns that exact prior-version
recovery is unavailable. Mailbox contents and exact registration/association
state are not backed up by this package handler.

## Acquisition and validation

The shared Mozilla adapter resolves
[the official version feed](https://product-details.mozilla.org/1.0/thunderbird_versions.json),
`LATEST_THUNDERBIRD_VERSION`, `win64/en-GB` and the matching exact member of the
release's SHA256SUMS. Checksums must match downloaded and retained bytes.
Available checksum signatures and Authenticode evidence are recorded without
claiming detached-signature verification. Upstream notices remain in the
publisher distribution. The [MPL 2.0 reference](https://www.mozilla.org/en-US/MPL/2.0/)
does not substitute for owner-specific local licensing review.

Read-only inspection at 09:56 UTC resolved Release **157.0.1**. The official
84,279,464-byte installer matched publisher SHA-256
`4b346e97e782cfc03f374ec1e132dcb639b7366f0e8830d56aa75214ef4eebca`
and had a Valid Mozilla Corporation Authenticode signature, certificate
thumbprint `6663D5C4FDAF9EFD5F823A26C9C410DC9928C44A`. This observation is
acquisition evidence; it does not establish Windows lifecycle support.

Native parser/catalog/profile and mocked lifecycle checks cover the selection,
elevated execution rejection, preview, user destination and conflicting
registrations. Disposable-VM tests create a temporary standard account and its profile through
[Windows CreateProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createprofile),
then run a limited task authenticated with that temporary account. They verify SID, profile identity
and a non-administrator token, collect its package state before removing the
task and account, and retain profile files until checkpoint reset. Parent
controller execution remains elevated; host accounts and UAC policies are unchanged.
Lifecycle scenarios include preview, repeat install/remove, profile fixture
preservation, uninstall recovery and restoration of original absence.

The initial attempts left target acceptance pending with candidate targets
only. The resumed validation below passed the applicable Windows 11 and Windows
Server 2025 Desktop Experience scenarios. Server Core and application/mail
functionality remain separate acceptance boundaries.

The first Server request `e970aa5b23f1446bb37b3749e83834ef` passed
240 guest checks, then the limited-worker coordinator treated Task Scheduler's
Running result (0x41301) as a completed failure. The coordinator now waits for
both the task state and result to complete, and uses the parent guest runner's
process-local execution-policy option. Collected failure evidence is retained;
checkpoint cleanup succeeded and host UAC values were unchanged. This failed
request provides no application acceptance evidence.

Subsequent bootstrap diagnostics confirmed that the same-account S4U task
received an administrator token even with RunLevel Limited. The scope guard
rejected it before application execution. Tests therefore use a separately
created standard account with Users membership and no Administrators membership.
Both initial Windows 11 requests also passed 240 guest checks before their
worker-coordinator failure. Those failures are retained and excluded from
acceptance; their controllers completed checkpoint recovery successfully.

The test scaffolding also corrected the local-group member argument to pass
the LocalUser object. Server rejected cross-account S4U task registration;
the worker now authenticates with a generated temporary password passed only
to local account/task APIs, never to the worker command line or exported evidence.
The account and task are removed after collecting results; checkpoint recovery
cleans the remaining disposable profile. These setup failures are excluded from
application acceptance.

Catalog comparison confirms that all 287 pre-existing operations and both groups
are unchanged. All four profile files match the start-of-turn byte hashes.

## Final disposition at 13:00 Copenhagen

Implementation awaits acceptance. `PendingAcceptance` remains true, supported
targets remain empty and Windows 11 / Server 2025 remain candidate targets.
No Thunderbird installation ran in these attempts and no lifecycle observations
were admitted to shared acquisition evidence.

Final Windows-native focused Pester runs passed on PowerShell 5.1.26100.9549
and 7.6.5: 266 passed, zero failed, with one VM-only test excluded in each run.
Parser/catalog/profile validation passed for 288 operations, two groups, four
profiles and 87 PowerShell files. The focused workspace review preserved all
162 original files and all four profile byte hashes; `git diff --check` passed.

The final Server request `f0c7f137cfc74be39ba18048fa86c126` passed 240 guest
checks, then failed because the temporary standard-user scheduled worker never
started: Task Scheduler reported 0x41303 (has not run). The final Windows 11
request `54b4531cdd8b4d85b82bf9565814847e` timed out; its process tree was
terminated, and partial evidence collection also failed. Its final guest summary
is unavailable; earlier Windows 11 requests passed 240 guest checks. These
results establish no Thunderbird target acceptance.

Both controllers restored their clean checkpoints, shut their VMs down and
returned Ready with empty queues and no recovery block. Final identity/recovery
inspection was recorded at 10:53 UTC. Host UAC values were unchanged.

The coordinator now permits operation on battery and stops waiting after 60
seconds when a task never starts. These final scaffolding changes have not been
tested live; battery conditions are a hypothesis, not an established root cause.
Next, inspect scheduled-task run conditions, logon rights and event logs for the
temporary standard account; verify its SID and non-administrator token before
running the application lifecycle. Investigate the Windows 11 partial-evidence
collector separately. Complete install/repeat/remove, profile preservation and
saved-selection recovery on both targets before publishing support.

## Resumed validation after the user requested continuation

Native PowerShell 5.1 and 7 focused checks passed again: 268 passed, zero failed,
one VM-only check excluded per runtime. Two added collector regressions verify
that a locked transcript does not discard other saved evidence, and that paths
outside the correlated result directory are refused. Source collector 0.3.0
records file omissions explicitly. Deploying it to protected controller copies
requires a later elevated refresh; it has not been deployed during this run.

Server requests `4c2f550d6d564b6cb50d5d40a0b35606` (240 guest checks) and
`7eb2476e9ff34e18887b2741a7498dbd` (242 guest checks) reproduced the startup
failure with battery gating disabled. The latter's task history recorded events
101 and 104 with error 2147943785 / 0x80070569. Microsoft's
[error reference](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1300-1699-)
identifies the requested logon type as not granted. The task was enabled, allowed
demand starts and used a limited Password principal. Battery gating and task
name lookup did not resolve the failure.

Runner 0.4.4 grants `SeBatchLogonRight` solely to the newly created temporary
standard account inside the guarded disposable guest, then removes that right
before deleting the account. It uses the documented
[LsaAddAccountRights](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights)
and [LsaRemoveAccountRights](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights)
APIs; existing accounts, deny policies, group rights and host security settings
are not changed. Success evidence must include `BatchLogonRightCleanup`.
The native helper compiled on the host without invoking its policy APIs.

Windows 11 request `d7a6e316f81947aaa7d1bda4c7fe9dd0` passed 242 guest checks
and failed before worker execution. Its older installed controller also included
299 `.local` scratch files in the frozen snapshot, delaying staging. The Server
controller and maintained source exclude that directory. Include this older
Windows 11 controller in the next elevated refresh; no protected binaries were
changed during this continuation.

## Accepted migration after resumed validation

Both final requests passed, including the six previously accepted installed
applications and Thunderbird. Their complete results were audited before
promoting `package.thunderbird`: supported targets now include Windows 11 and
Windows Server 2025 with the Desktop Experience requirement; `PendingAcceptance`
is false. The package remains optional and all four profiles retain their bytes.

| Target | Correlated request | Guest Pester | Installed lifecycles | Finished UTC |
| --- | --- | --- | --- | --- |
| Windows Server 2025 Standard Evaluation, build 26100 | `acdc957dae154b7ca4189a4106ecb6b2` | 242 passed, zero failed | Seven passed | 2026-10-11 13:57:21 |
| Windows 11 Enterprise Evaluation, build 26300 | `b38514b4b7174318852cc525c0c972ce` | 242 passed, zero failed | Seven passed | 2026-10-11 14:09:14 |

Thunderbird 157.0.1 was installed as a temporary standard user distinct from the
elevated coordinator. Evidence confirms a non-administrator token, x64/en-GB
registration, Release channel and the selected local-user Programs destination.
Preview, repeat installation/removal, preservation of an existing Roaming
profile fixture, uninstall recovery and restoration of original absence passed.
The two saved user records per target use schema 3 and retain scope, destination,
arguments, variant, architecture, locale, channel and acquisition selection.
The original-absence record binds its applied installer version and SHA-256.

Frozen source manifests match the tested catalog and all eight audited runtime/
test source files. The subsequent catalog change only promotes Thunderbird's
target acceptance and declares its absent platform defaults. Twenty correlated
acquisition observations were admitted using the existing locked importer,
including Download and Cache observations for Thunderbird on each target.
Its exact publisher checksum and Valid Mozilla signature matched the inspected
157.0.1 artifact. Detached checksum-signature verification remains unavailable.

Task, temporary batch-logon right and temporary account cleanup passed before
checkpoint reset. Host UAC values are unchanged; collection/cleanup error fields
are empty. Both controllers are Ready, with empty queues and no recovery block;
both VMs are off at their pinned clean checkpoints. Raw evidence is retained in
the respective controller's `results/<request-id>` directory under
`C:\ProgramData\RIDE\TestAutomation`.

Support covers deployment lifecycle on these tested x64 desktop images using
guest PowerShell 5.1, with native PowerShell 5.1/7 mocked checks also passing.
No mailbox, account, SMTP/IMAP session or application UI was opened. Recovery of
prior presence remains compensating; exact prior-version, mailbox backup and
registration/association restoration are not established by these scenarios.

Infrastructure review remains separate: refresh the older Windows 11 protected
controller's scratch-directory exclusion and deploy collector 0.3.0 when host
elevation is available. The collector fix has native regression coverage but was
not deployed to protected controllers during this continuation.

Final review preserved all 118 earlier acquisition records and admitted exactly
20 audited records, bringing the shared store to 138. All 287 other operations
and both groups are unchanged; Thunderbird's four acceptance metadata fields
are the only catalog differences from the resumed baseline. Final Windows-native
validation passed on PowerShell 5.1 and 7 for 288 operations, two groups, four
profiles and 88 maintained PowerShell files. Generated operation documentation
is current and `git diff --check` passes. The application ledger now has ten
earlier migrations, nineteen newly accepted outcomes, 79 review outcomes and
one user-policy exclusion, totaling 109.

One tooling investigation is retained for review: the native PowerShell 7
observation import encountered `File.Replace` reporting "Unable to remove the
file to be replaced." The same locked importer completed under Windows
PowerShell 5.1, and comparison confirms all 118 previous records are unchanged.
Reproduce the PowerShell 7 replacement behavior on an isolated fixture with the
relevant ACL/sharing conditions before changing the importer. No ACL, security
policy or atomic-write behavior was bypassed to complete this merge.
