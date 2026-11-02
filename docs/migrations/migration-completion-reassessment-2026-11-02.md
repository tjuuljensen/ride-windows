# Migration completion reassessment, 2026-11-02

## Status

Migration execution is paused at the user's request. The next step is to reassess
how to close the remaining work before starting another implementation or test
batch.

## Why the completion approach is being reassessed

The user asked to fast-track the remaining tests because the migration appeared
unlikely to finish. Multiple source-test batches were run and committed, but the
overview stayed at **126-180 estimated legacy outcomes**. That estimate is not a
count of tests remaining. The batches established current-source behavior; most
did not resolve, retire, or exclude a legacy outcome. The work therefore needs
an outcome-oriented closure plan, rather than another unprioritized sweep of
passing source suites.

## Durable reporting and completion rules

For each requested workstream, report its concrete components one workstream at
a time. Label each component as one of:

- **Resolved**: the defined legacy outcome is implemented or otherwise met and
  its required acceptance evidence is complete.
- **Open**: implementation or mapping exists, but a stated acceptance or
  recovery requirement remains incomplete.
- **Unmigrated**: a legacy outcome still lacks an implementation or a recorded
  disposition.
- **Candidate**: optional or new work exists in candidate form and has not
  passed its declared acceptance gate. Candidates that are new features do not
  count as completed legacy outcomes.
- **Retired**: a durable decision removes the legacy outcome from the target
  platform scope.
- **Excluded**: a durable scope decision leaves an outcome out of this
  migration; retain its reason and any operational caveat.
- **Partial/deferred**: only some legacy behavior is covered or remaining work
  is intentionally postponed. Keep it visible and counted until reconciled.

Each status report should name the component, link its source-of-record entry,
state the remaining closure evidence, and identify blockers. Keep source
regression, artifact review, activation, and verified Windows behavior separate.

The five estimates in [MIGRATION-PLAN.md](../MIGRATION-PLAN.md#estimated-remaining-migration-work)
count legacy feature/product outcomes, not test cases or catalog IDs. A passing
source test updates validation evidence; it does not reduce an estimate unless
the linked ledger establishes that a legacy outcome was resolved, retired, or
excluded. Partial and deferred outcomes remain visible and counted according to
the migration model. Recalculate the ranges from the reconciled outcome ledger,
not from the number of tests passed.

## Checkpoint at pause

- **Settings:** presentation review is complete at 279/279. The estimate remains
  37-57 outcomes. The [remaining-settings plan](remaining-settings-plan.md) and
  [post-migration review](settings-post-migration-review.md) identify open
  mappings and candidate-only controls, including hibernation, modern BitLocker
  drive-method policies, Storage Sense policy, local password complexity,
  advanced WinHTTP proxy, desktop shortcuts, and File Explorer F1. Their source
  tests do not establish native acceptance. New controls such as Click to Do
  are candidates, not legacy closures.
- **Packages:** the estimate remains 37-52. Current-source package regressions
  cover many pins and file lifecycles. PSScriptTools' generated inert 360-member
  lifecycle passed 7/7; this does not establish package activation or close a
  legacy product outcome. The WFN 531-member case remains incomplete after a
  bounded attempt. Sysinternals licensing is settled under the prior RIDE v2
  specialist approval; Defender exclusions are independent of that decision.
- **Components:** the estimate remains 19-24. Source preparation and mocked
  lifecycle work do not establish Windows feature installation, service
  behavior, or recovery on declared targets.
- **Files/assets:** the estimate remains 25-35. Source checks do not establish
  Explorer menu, desktop, or other native shell behavior.
- **Maintenance:** the estimate remains 8-12. Source checks do not establish
  runtime ACL, scheduled-task, or screen-lock acceptance.

The exact ranges and dated test evidence remain in the migration plan. The
current Windows PowerShell 5.1 source batch passed 331/331; the PSScriptTools
suite passed 7/7; the WFN full synthetic suite did not finish its large case.
The broader 3,698-case aggregate remains incomplete. Native VM acceptance is
blocked because host CIM access fails before VM/checkpoint inspection. Keep
Defender-alerted NirSoft files excluded and do not materialize them during test
work. See the linked per-batch evidence in the [migration plan](../MIGRATION-PLAN.md).

## Settings component register at pause

These rows follow the active 30-row settings ledger. A row can contain multiple
legacy outcomes, so the row count is not an estimate. “Candidate” means target
support remains gated; “partial” means the listed remaining behavior is not
covered by the implemented subset.

| Ledger | Component | Status | Remaining work or closure evidence |
| --- | --- | --- | --- |
| R01 | Existing and owned power plans; desktop Power Options shortcut | Partial; shortcut/owned-copy candidates | Balanced and High Performance owned-plan lifecycle has two-target evidence. Ultimate Performance activation failed previously. Verify selection and recovery on current targets; separately accept shortcut UI, intended session, and file recovery. |
| R02 | LAN proxy detection, setup script, machine WinHTTP proxy detection | Integrated plus candidate | LAN detection/setup is guarded and integrated. WinHTTP automatic detection is candidate-only; exact underlying recovery, effective policy, consumers, RAS/GUI behavior, and target support remain open. The host build lacks `netsh winhttp show advproxy`. |
| R03 | Windows CEIP, conditional App-V CEIP, native/WOW telemetry mirrors | Partial; CEIP candidates | Windows CEIP typed lifecycle is implemented. Verify App-V client/policy/consumer before enabling it. Native and WOW mirrors remain intentionally unexposed until their effect is established. |
| R04 | Paired feedback-frequency values | Partial; mapping unresolved | Resolve current GUI choices, value types and units, managed precedence, and paired restore. Preserve custom or mixed prior values; do not guess the large-period DWORD representation. |
| R05 | Windows RE enable/disable registration | Unmigrated lifecycle | Build read-only OS/image/partition identity capture and exact prior-registration recovery. Refuse identity or servicing conflicts; readiness guidance alone is not lifecycle support. |
| R06 | Browser service `Hidden` override | Legacy selector retired; modern discovery partial | Preserve legacy history and existing values. Complete current Network Discovery peer/profile behavior separately; do not claim it is equivalent to the retired selector. |
| R07 | MusNotification interception; supported update-notification controls | Interception retired; replacement open | Do not restore IFEO interception. Verify replacement warnings, active-hours/deadline combinations, effective policy, and restart behavior without claiming that reboot is prevented. |
| R08 | System Protection / restore-point controls | Guide and inventory only; lifecycle open | Verify enabled-volume inspection, system-drive coupling, storage allowance and asynchronous completion. Turning protection off may destroy history, which setting restore cannot recover. |
| R09 | Storage Sense bundle and machine policy | On/Off implemented; policy candidate | Verify actual switch, policy precedence, default/removal semantics and cleanup choices using disposable files. Never represent registry restoration as recovery of deleted files. |
| R10 | Windows-native Explorer/Desktop F1 suppression | Candidate; manual target acceptance queued | On the prepared Windows 11 Pro laptop, test Explorer/Desktop Help and unrelated-app F1, then both setting states and exact typed-value/key restoration. Do not use IFEO, ACL changes, AutoHotkey, or a download. |
| R11 | Taskbar sizing; Windows Terminal profile | Mapping open; Terminal backend candidate | Observe actual taskbar choices/rollout rather than assuming `TaskbarSmallIcons`. Preserve Terminal profiles and validate its broader normal-launch behavior beyond Win+X. |
| R12 | Shortcut-arrow icon resource | Unmapped cosmetic outcome | Verify resource index 29, type/expansion, actual image resource and Windows 11 rendering. Preserve custom values; do not force an Explorer restart. |
| R13 | Sign-in and post-sign-in NumLock | Setting candidates; hardware/session evidence open | Compare both registry preferences against the user's reliable combined legacy behavior on real boot/sign-in hardware. Preserve type/encoding and unrelated lock-key state; no SendKeys. |
| R14 | Compressed/encrypted file-name colors | Mapping open | Establish the current GUI mapping before choosing between `ShowCompColor` and the legacy value. Check ordinary, compressed and EFS names/themes without changing file attributes. |
| R15 | Explorer start location and experimental Home hiding | Existing start-location control; Home mapping candidate | Test `HubMode` independently from `LaunchTo`, including user/machine precedence. Do not reconstruct namespaces, reset pins/history, or force restart. |
| R16 | Include in Library, Give access to, Share menus | Three accepted outcomes; implementation/recovery open | Identify physical registry roots/views and all bindings. Use bounded reversible changes; if subtree deletion is needed, prove typed content/subkey/ACL recovery and conflict handling. |
| R17 | Five desktop icons and ClassicStartMenu mirrors | Existing IDs retained; mapping/compatibility open | Compare each icon and any conflicting legacy mirror against GUI/rendering. Keep IDs stable and recover old scalar snapshots without inventing omitted history. |
| R18 | Server Manager startup; Shutdown Event Tracker | Server 2025 candidates | Literal and fault-recovery source evidence exists. Verify logon/console precedence and the actual shutdown prompt on Desktop Experience and Core separately. |
| R19 | Local password complexity; maximum password age; IE ESC | Mixed: max-age evidence, complexity candidate, IE ESC unmigrated | Maximum age has both-target lifecycle evidence but remains a candidate pending remaining acceptance. E08 complexity has template/validation work, not an accepted native apply path. IE ESC needs actual Server component/class/profile-effect evidence and separate admin/user controls. |
| R20 | Windows Audio service; selected playback-device mute | Service candidate; endpoint mute unmigrated | Audiosrv lifecycle/fault recovery passed both targets, but dependency/trigger acceptance remains. Implement endpoint mute around stable device identity and session/device-loss recovery without changing volume/default device. |
| R21 | BitLocker enrollment, decryption, TPM+PIN, modern drive-method policies | Multiple candidates; full workflow open | The three OS/fixed/removable drive-method policies remain unsupported candidates. Complete the staged enrollment/decryption/boot workflow, preserve methods/protectors, redact secrets, and verify recovery before any real boot test. |
| R22 | BitLocker recovery-password backup, creation and selected-key display | Guided workflows open | Implement secure selection by protector type/ID, off-device retrieval and redacted output. Never expose secrets in logs/state or implicitly rotate, upload, print, or copy keys. |
| R23 | Failed-sign-in machine lockout | Unmapped security experiment | Verify the local GUI/legacy mapping, real counting and recovery behavior only after OS-volume protection and retrievable recovery backup. Keep Windows sign-ins separate from TPM PIN, Hello, and account lockout. |
| R24 | Windows Photo Viewer Open with and default-app handoff | Open with candidate | Bounded intended-user registration candidate exists. Windows 11 acceptance must verify exact extensions, installed component, visibility, managed behavior, rendering and recovery. Default-app selection remains a separate native UI step. |
| R25 | Radio preset retrieval; Windows Media DRM Internet access | Conditional policy candidates | Verify actual current radio and DRM consumers, effective policy and Server coverage. Typed setting recovery does not restore remote servers/licenses; do not install players or repair license stores. |
| R26 | Keyboard repeat delay; packed visual-effects mask | Delay implementation; effects partial/unmapped | Stored delay positions and typed recovery pass. Compare native effective delay before changing backend. Map each visual effect independently and preserve custom masks; no broad fixed preset. |
| R27 | WAP Push and Windows Search delayed/startup-only states | Implemented lifecycle; boot acceptance open | Stored/runtime lifecycle and controlled recovery pass. Verify boot scheduling, workload, dormant flags, trigger/dependency effects and Server behavior; no reboot or fixed-delay guarantee is implied. |
| R28 | Windows Security startup icon | Guidance/policy exists; intended-user handoff open | Verify the exact startup entry, user/machine scope, managed precedence, tray overflow and visible icon. Keep handoff as a user action; do not reconstruct a historical Run entry automatically. |
| R29 | User .NET assemblies label | Closed as unsubstantiated bookkeeping | No known feature or selector was found. Reopen only if a concrete source/use case appears; do not invent an assembly operation or deduct a numeric outcome. |
| R30 | Store app selection, policy and user uninstall | Five guarded group candidates; native acceptance open | Solitaire's basic registration lifecycle passed. Complete Clipchamp next when elevation is available, then GUI/full handoff, group behavior, policy, app/data recovery, sign-in and other-target acceptance. Keep existing apps installed meanwhile. |

Additional settings/control candidates outside those legacy rows include the
Domain/Private/Public and all-profile Windows Firewall operations. Their basic
lifecycle evidence exists, but effective ActiveStore state, active-network,
connection/GUI and target evidence remain open. Click to Do is a new-feature
candidate, not a legacy outcome. These and other candidate declarations are not
support claims merely because they appear in the catalog.

## Resume criterion

Resume when the completion approach has been reviewed. Start with an explicit
legacy-outcome inventory for the workstream being discussed, separating
implemented-but-open outcomes from unmigrated outcomes, candidates, and accepted
or retired outcomes. Prioritize batches by the number of outcomes they can
actually close and the acceptance resources they require. Preserve the existing
authorization to run approved batches without pauses between them and commit
each completed batch separately; do not resume automatically while this
reassessment is pending.
