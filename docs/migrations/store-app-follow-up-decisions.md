# Store app acceptance tasks and follow-up decisions

Reviewed: **2026-10-14**. Five approved groups and 22 app identities now have
guarded catalog declarations and an explicit app workflow. Current apps remain
installed; packages remain paused. This document separates remaining decisions
from technical work and successful preflight from actual app lifecycle acceptance.

## Decisions already answered

Group membership is fixed in the [group guide](../store-app-groups.md). Multimedia
includes Media Player and Sound Recorder. Xbox/gaming components are reviewed
together; shared frameworks and non-removable Xbox Game Callable UI are retained.
Device removal policy is a separate workflow, with reciprocal links. Reinstall
has explicit source/partial-result limits and no exact app-data/version guarantee.
Alternate-administrator execution uses a separate process for the signed-in user
in the current desktop session; other/no desktop sessions are refused.

## Protection evidence decision - answered

The captured Appx records omit IsPartOfSystem. Read-only Windows Runtime inspection
can expose package type, stub and certificate category, but certificate category
does not supply a missing system-protection flag. IsPartOfSystem stays visibly
unknown; it is never inferred from certificate category. Targets stay unpublished.

On 2026-10-14 the user approved known native NonRemovable=false, complete
framework/resource/bundle/stub observations, exact reviewed identity/family/source
and consumer checks for these 22 catalog identities. StoreApps 0.3.1 implements
the explicit ReviewedIdentityRemovabilityV1 rule. Missing review metadata,
incomplete required flags, known system/protected/framework registrations,
identity drift, unavailable/conflicting runtime type proof and stub payloads still refuse. Unknown IsPartOfSystem remains
null in the live plan and captured removal evidence. This rule requires isolated
native lifecycle/partial-failure acceptance; it does not permit arbitrary observed
apps or publish supported targets.

## Technical acceptance and resources

The revised Windows 11 preflight verified runtime descriptors for all 11 consumer
registration rows. Clipchamp and Solitaire have inspectable main-manifest proof;
News and Weather have two stub registrations each and no full-source proof.
The user also decided on 2026-10-14 that uninstall must wait for a usable local
reinstall source. News and Weather therefore remain blocked; acquisition is still
paused. Clipchamp and Solitaire are the initial lifecycle candidates once desktop
acceptance is ready. A source inspection does not prove source survives removal.

Server preflight 8de2401ea49c49cfb82b47a1073d1904 verified guard/absence handling
and checkpoint recovery with the earlier 0.2.0 source. All four consumer apps are
absent there. Its managed-enrollment uncertainty and unavailable desktop remain
visible; it supplies no uninstall/reinstall or handoff acceptance.

| Work | Current boundary and next evidence |
| --- | --- |
| Runtime/source inspection | Verify current-user SDK identity/type/stub observations and main-manifest capture separately from bundle removal. Windows PowerShell 5.1 supplies the runtime projection; unavailable PS7 evidence stays unknown. Signature kind remains reporting evidence |
| Current desktop and alternate administrator | Source handoff and mocked refusal/source-drift checks implemented. Existing unattended WinRM execution has no current desktop; add an explicit isolated interactive actor/fixture or use a prepared guest desktop. Preserve SID/session/shell checks, UAC and user-owned Store records. Launch is not completion |
| Client management source | Use the documented client registration API without UPN collection; generic enrollment keys alone are insufficient. Domain/enrollment/active removal-policy conflicts remain refusals; Server's native proof is separate |
| Actual app lifecycle | The protection rule is decided. After desktop acceptance, use Clipchamp or Solitaire as a sacrificial group-1 app in a disposable fixture. Verify repeat removal, inspection, partial native failure and record/source-bound recovery. News/Weather wait for usable local source. Server's absent apps provide no lifecycle evidence. Do not change the workstation |
| Retained payload and resources | Source may be deleted after removal. Prove available payload/dependency/resource behavior; report unavailable or changed source. Do not claim captured source guarantees successful reinstall or data recovery |
| Acquisition-dependent reinstall | Deferred while packages are paused; no Store/download fallback is enabled |
| Device policy | Static/dynamic serviced schema, actual management/applicability/sign-in behavior and configuration recovery remain a separate implementation/acceptance batch. Clearing policy does not restore apps/data |
| Later groups | Catalog/shared-backend candidates implemented; utility/session preservation, personal-data and gaming consumer/dependency checks need their own applicable acceptance |

## Next selected acceptance batch

1. Prepare a settings-only isolated guest actor in an actual signed-in desktop.
   Record the real SID, current session and unelevated shell identity; refuse
   absent/mismatched desktops. A WinRM session must not impersonate that desktop.
2. Exercise source-bound Plan handoff first, including changed-source, changed-shell,
   wrong-SID and other-session refusal. Launch alone is not success. Actual
   alternate-administrator GUI acceptance stays pending until its actor is ready.
3. Use a private disposable source/catalog fixture for Clipchamp or Solitaire;
   approve only its explicit pending target there. Keep the published catalog's
   SupportedTargets empty and preserve the retained original source hash.
4. Capture exact registrations, manifest/source/dependency proof and intent before
   removal. Check repeat removal/inspection, unavailable-source refusal, retained
   registration when available, interrupted intent and partial native failure.
   Report checkpoint cleanup separately from RIDE's best-effort recovery.
5. Accept the later groups in order: core utilities, multimedia, productivity,
   gaming. Preserve session/recovery tools, personal data limits and external
   consumers/shared frameworks. Server absence is not an applicable lifecycle pass.

Read-only probe 2f461c696aea46f18a36277740ab14af accepted one expected-SID
Explorer candidate in session 1, with source/checkpoint recovery verified. It does
not establish active connection, token elevation or handoff completion.

Questions/resources to retain for follow-up: the native desktop actor is not yet
prepared or accepted. If preparing its real session or alternate administrator
requires interactive credentials/UAC, postpone that part while the user is away;
record the exact prerequisite rather than bypassing the session guard. No further
app-selection, protection-rule or missing-source decision is outstanding.
State-changing acceptance uses the established pinned disposable controller and
current source snapshots/hashes. Postpone interactive elevation/credentials when
the user is unavailable; retain the task here instead of weakening identity or
protection checks. Completed guard fixtures need no repeat unless source changes
or evidence concerns justify it.

No whole legacy app outcome closes from these declarations or refusal checks.
The five migration estimate ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180. See [dated implementation evidence](../archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

### Desktop actor preparation proposal

The read-only schema-6 probe observes existing Explorer candidates for the expected
pinned guest SID. A unique candidate is a prerequisite to preparing an actor, not
proof of an active/unelevated desktop. The production handoff still refuses a
caller in another session; a WinRM coordinator does not receive a bypass.

If a matching signed-in guest exists, prepare a disposable test-only scheduled
actor with Interactive logon and Limited run level, no supplied credentials,
no service-account/S4U fallback and no automatic logon configuration. Microsoft
exposes these settings in [New-ScheduledTaskPrincipal](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal?view=windowsserver2025-ps)
and describes the interactive principal in the [Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-logontype-principaltype-element).
The schema-7 Plan-only actor is implemented as an isolated candidate. Request
`080d9d9404274f349857f1e06166fe80` passed on the separately prepared UAC-enabled
desktop; this accepts the actual unelevated desktop and read-only worker Plan.
It does not accept the full production launcher or app lifecycle.
This is not a production route.

The actor must verify the actual SID/session/shell token and source hash before
read-only Plan, then report correlated completion separately from task launch.
Use a RunId-owned transient task and bounded evidence/timeout; stop and unregister
only that fixture's task in finally and retain failure evidence. Do not choose
among ambiguous sessions. Missing sign-in, unknown elevation, another session or
failed cleanup keeps native handoff/lifecycle pending. Start with Plan only;
actual alternate-administrator and app mutation are later distinct scenarios.

### First app lifecycle fixture design

Start with Solitaire in the Windows 11 reference after successful desktop worker
Plan. Use a separate explicit lifecycle schema/selection and a RunId-owned private
source/catalog copy that approves only this pending app's target. Retain original
and private source hashes; never mutate published SupportedTargets or test an
older snapshot as current implementation.

Capture actual current-user registrations, runtime/removability/source/consumer
proof, source manifest identity/hash and user-owned intent. Exercise uninstall
preview, real exact-identity removal, inspection and repeat removal. Reinstall is
explicit and source-bound: source survival/dependency availability must be checked
after removal; retain Source unavailable as partial evidence if it fails. Prove
re-registration/repeat inspection when available, without claiming app data/prior
version recovery. Keep RIDE best-effort registration and checkpoint cleanup apart.
A later explicit fault scenario should interrupt after a native operation and
retain owned intent/partial results before recovery. Do not substitute a mocked
failure for native acceptance or count app absence on Server as a lifecycle pass.

News and Weather wait for usable local source. Clipchamp follows separately,
then core utilities/multimedia/productivity/gaming with their preservation and
consumer checks. Acquisition, default profiles and package work stay paused.

<a id="desktop-resource-decision---postponed-while-afk"></a>

## Desktop resource decision - separate resource authorized

On 2026-10-14 the user authorized preparation of a separate UAC-enabled disposable
test desktop, including elevation when needed. The earlier AFK elevation hold is
resolved for this preparation. Existing VM/controller pins remain unchanged;
packages remain paused. Export the existing Windows 11 clean checkpoint locally,
import an independent VM identity and disks, and disconnect its network before
boot. Enable UAC only inside that copy, reboot it, and capture a separate clean
checkpoint. Require source-bound read-only Plan evidence from the actual
unelevated signed-in desktop before app lifecycle acceptance.

Diagnostic d62ee7a8b55c4c2aa0b2352147901e87 established the precise prerequisite:
the expected and actual SID/account match, and both session IDs are 1, but the
worker has AdministrativeToken=true. The pinned Windows 11 guest reports
EnableLUA=0, ConsentPromptBehaviorAdmin=5 and PromptOnSecureDesktop=1. An
Interactive/Limited task therefore did not supply the required unelevated actor.
The guard refused before any app inspection; task and checkpoint cleanup passed.
UAC and the pinned resource were not changed.

Required follow-up decision/resource: prepare a separately reviewed disposable
UAC-enabled desktop, or another genuine supported unelevated signed-in desktop
resource, for the expected actor. Keep the current controller configuration and
pin unchanged. Resource preparation requiring interactive elevation/credentials
or a new checkpoint was postponed while the user was away; the direct
authorization above now permits the separate resource. Do not
simulate acceptance by disabling the elevation guard, changing UAC, guessing a
session or supplying a service/S4U token. Full launcher, alternate-administrator,
app removal/reinstall and Solitaire lifecycle remain pending.

The [separate test desktop](store-test-desktop.md) is now prepared and its actual
unelevated actor/Explorer proof passed with current source hashes, owned task
cleanup and separate checkpoint recovery. Existing UAC/controller/pin settings
remain unchanged. The next Store migration step is the explicit isolated
Solitaire lifecycle fixture described above. Full launcher and
alternate-administrator acceptance remain separate. The independent maximum-age
Days1/Days2/Days998 and minimum-conflict follow-ups already passed on both targets.

## Solitaire native validation follow-up

The isolated fixture is implemented. Runs `dfd6c2c94edd4eb09bd6457194f3bb82`
and `10a640b3ab10400ba06eb99f0aefa3e5` passed Solitaire preview/uninstall/repeat,
but failed at reinstall preview before any native registration. The diagnostic
run proved the manifest hash and all five dependencies remained available, and
unrelated registrations stayed unchanged. The defect was a read-only dependency
member projection suppressed by WhatIf; handler 0.3.3 uses Select-Object instead.
Both PowerShell editions passed 37 focused regression checks, including retained
refusal when a dependency is actually missing. Guard semantics and schema-1
records are unchanged. See [dated evidence](../archive/evidence/store-solitaire-validation-2026-10-14.md).

The first repaired rerun was canceled at elevation at 14:40:57 UTC. The user then
resumed it. Run `3899597cd74e477195a35b280b201308` passed at 14:53:26 UTC on
handler 0.3.3/actor 0.1.1 with fresh current-source hashes. Both previews, native
uninstall/reinstall and repeats, retained-source registration recovery, owned
schema-1 records and unchanged unrelated registrations passed. Actual worker and
Explorer were unelevated in the expected session. Task cleanup, bounded evidence
hashes and separate checkpoint recovery passed; the desktop is Off on its
unchanged clean pin, with no network adapter.

This accepts the basic Solitaire registration lifecycle on this Windows 11
reference. GUI/application data, interruption, full production launcher,
alternate administrator, other editions and Server acceptance remain pending.
Published support stays closed and packages paused; original pins/controllers
are unchanged. The user requested this result before another app, so no next
app is started. Clipchamp is the next independent full-payload candidate after
this result is reported. News and Weather still await usable local sources.
