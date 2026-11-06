# Disposable VM controller acceptance

## Windows 11 Pro local controller closeout, 2026-11-05

**All local pilot checks are complete for the pinned Pro build 26300
registration, controller 1.27.0. Formal status is `NotValidated`.**
The [full UnitOnly regression](#pro-full-unitonly-regression-passed-2026-11-05)
and [three consecutive Full integration runs](#three-consecutive-pro-full-integration-passes)
passed. The latter exercised ordinary-shell submission, a locked host session
and the repository watcher. Each passed native integration and 4,497 tests
with zero failures and 40 skips.

The [refusal checks](#pro-watchdog-and-checkpoint-recovery-verified-2026-11-05),
[timeout and Local/CI overlap](#pro-timeout-and-overlapping-localci-submissions)
and [explicit recovery and resumed service](#pro-interrupted-worker-recovery-and-resumed-service-2026-11-05)
complete the local fault cases. Interrupted-worker detection passed on the
second task start. The [first-start diagnosis](#first-worker-stopped-during-configuration-loading-2026-11-05)
and the original failed journal remain part of the evidence. After recovery,
the registered controller passed 206/206 tests and returned the VM to its
pinned checkpoint.

The protected `acceptance.md` beside the `RIDEWin11ProTest` registration
contains the local closeout and run IDs. Its closeout revision had SHA-256
`8BFDA96E0F623B979646A593643A482958EF4112AAE9BD90AB3C7803B4A398B4`.
The prior record was backed up and verified, and the file permissions were
preserved. At save time the VM was Off at its pinned parent, the task Ready,
both active queues empty, the worker lock available and the recovery block
absent. The configuration and registration evidence hashes were verified.

**Local-only Pro component testing is authorized on this pinned registration.**
The [operator decision and scope](component-edition-support-decisions-2026-11-04.md#operator-authorization-for-local-only-pro-component-testing)
permit focused batches with evidence export and checkpoint recovery. The
protected record now includes that authorization. Its verified SHA-256 is
`F3EF74B330E2E5712202CA16CA6DE6F9C582CAC57B8BAD96C82DE9D93C8369A3`.
The closeout revision was preserved as a verified backup with the original
record permissions retained on the active file. When the
[RC and replication gates](#remaining-work-and-sequence) resume, validate
the reviewed published RC in both PowerShell editions and reconcile source
changes with the accepted tests. Verify manual dispatch and trusted
default-branch push delivery, then repeat applicable acceptance on the second
host. Record the resulting certification decision beside the registration.
Both gates remain deferred. The local authorization is independent of that
formal decision.
The local closeout establishes no additional component support or legacy
feature closure.

On November 6 the [first authorized local component batch](component-edition-support-decisions-2026-11-04.md#first-local-pro-batch-openssh-client-2026-11-06)
passed OpenSSH Client on the pinned Pro VM after a guest evidence correction.
Both attempts exported their terminal results and recovered the checkpoint.

## Windows 11 Pro controller validation started, 2026-11-04 16:21 UTC

The registered configuration at
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11ProTest\configuration.json`
parses and pins `RIDE-W11P-Test` and checkpoint
`RIDE-clean-test-base` by GUID. `evidence.json` remains `NotValidated`. The
registration records 11 controller-file hashes; all 11 match both the
installed protected copies and current checkout files. Read-only checks found
empty pending/running queues and no recovery block. The controller advertises
`HostPreparationWatchdogV1` and fixed package/settings suites.

The bounded `Test-RideVmHostPreparation.ps1` probe was attempted, but the
current process is the registered account without an elevated token. The
escalated command runner also returned a non-administrator token, and the probe
stopped at its explicit elevation guard before host preparation, output
creation, VM inspection or state change. Task state, live VM state and live
checkpoint identity therefore remain unverified; no request was submitted and
the controller remains `NotValidated`.

Next, from an elevated Windows PowerShell session for the registered account,
run the host-only probe from the repository root:

```powershell
.\tests\integration\Test-RideVmHostPreparation.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11ProTest\configuration.json'
```

Only after that probe confirms the VM is Off, the registered task is idle, the
checkpoint and lab pins match, and the current checkout is copied successfully
should a `UnitOnly` pilot run through the registered task. It runs guest
generation/validation/Pester without the state-changing integration suite, then
follows the registered checkpoint recovery. Review its source/result hashes
and recovery before deciding whether any controller validation status can
change. Do not bypass the `NotValidated` record manually.

The attended probe attempt `08b397f8aa3b4419a0a405783f82e22e` then failed at
`Validate host and import dependencies`; its report has `VmChanged=False` and
the stage receipt has `VmMayHaveChanged=False`. The error said Pester 5.7.1 had
drifted. Read-only inventory in 64-bit Windows PowerShell 5.1 found the exact
pinned Pester 5.7.1 installed (alongside 3.4.0 and 6.2.0), and every other
configured dependency version installed. The probe process had not loaded
Pester, while `Assert-RideAutomationHost` checked only loaded modules. This was
a false drift failure; the probe stopped before lab, VM, checkpoint or task
inspection.

The host check now requires the exact pinned version to be installed and still
rejects a conflicting version if that module is already loaded. A focused
Windows PowerShell 5.1 mock harness passed both the installed-but-unloaded
Pester 5.7.1 case and refusal when the pinned version was absent. The focused
Pester run was blocked before its test cases because Pester could not create
its own `HKCU\Software\Pester` test key under the current host token; no
registry permission was changed. Parser and diff checks passed. These results
do not complete host preparation.

Next, rerun the host-only probe above under the registered elevated account.
If it passes, refresh the protected controller once so its installed
`RIDE.TestAutomation.psm1` includes this correction, verify the refreshed file
hashes, then run the `UnitOnly` pilot through the registered task. Keep the
controller `NotValidated` until the pilot and recovery evidence are reviewed.

The retry `363eb25f98f04e43b9ee0d1e55377a42` also stopped at dependency
validation with `VmChanged=False`; its stage receipt confirms no VM, lab,
checkpoint or task inspection occurred. The no-profile child diagnostic then
confirmed Pester 6.2.0 loaded after importing the host modules, while Pester
5.7.1 is installed alongside it. Pester 5.7.1 is the guest test-runner pin;
the host does not run it. The prior check incorrectly rejected the unrelated
host-loaded Pester version. The focused fix now requires exact guest Pester
5.7.1 to be installed but permits another Pester version loaded by host
integration modules; conflicting loaded versions for other pinned host
dependencies remain rejected. Parser and diff checks passed; focused Pester
execution remained blocked by the local HKCU restriction. The retry result is
recorded below.

The corrected host-only probe `d346695c26134d02b5a6f457ecfe22f7` passed on
2026-11-04 at 17:07 UTC. Its child receipt records VM `Off`, task `Ready`,
2,299 copied files and `VmChanged=False`; host preparation, including the
pinned VM/checkpoint checks, completed. The protected-controller refresh then
succeeded from the registered elevated session. All 11 installed controller
file hashes match both `evidence.json` and current source. The evidence remains
`NotValidated` pending the UnitOnly pilot and recovery review.

The UnitOnly client could not create its temporary request file under
`queue/pending` from the Codex execution context (Access denied). No request
file remained, the pending/running queues stayed empty, and no VM change
occurred. The installed queue ACL grants Modify to the registered SID, but
Task Scheduler/CIM and protected queue writes are unavailable to this
execution context. Submit the approved client request from a normal PowerShell
session for the registered account, then review its correlated result and
checkpoint recovery:

```powershell
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11ProTest\configuration.json' -UnitOnly -TimeoutMinutes 90
```

UnitOnly request `6e37123cd6b14439800f2b332c981533` was queued and reached the
Windows 11 Pro guest, but failed before repository validation because the
pinned checkpoint did not contain Pester 5.7.1 for the test account. The guest
progress and transcript identify the failed Pester import; Pester XML was not
produced. The controller collected partial guest evidence and completed its
checkpoint recovery path with no recorded cleanup, collection or evidence
export error; the request is terminal and there is no recovery block.

The test runner now installs exact Pester 5.7.1 from PowerShell Gallery for the
current guest user only when absent, records the setup action in the guest
summary/progress, and then restores the pinned checkpoint through the
controller. This preserves the existing checkpoint identity and supports
adopted Pro VMs whose clean checkpoint predates the test dependency. The new
guest dependency tests pass 3/3; the controller orchestration suite passes
182/182 with five platform-skipped cases, and `tools/validate.ps1` passes
(479 operations, 9 groups, 6 profiles, 411 PowerShell files). These local
checks used Pester 5.7.1 with its registry plugin disabled for the restricted
host token. They do not prove guest PowerShell Gallery access or guest tests.
Refresh the protected controller from elevated PowerShell, verify hashes, and
submit UnitOnly again to verify actual dependency acquisition and guest recovery.

### UnitOnly reached guest but failed the full Pester suite, 2026-11-05

UnitOnly request `71d37e0d44494852a9132d58660f5c2f` reached the Windows 11 Pro
guest and completed guest dependency setup, catalog export and repository
validation. Pester 5.7.1 ran 4,528 tests: 4,319 passed, 169 failed and 40 were
skipped. The request is Failed, so this is not Pro controller acceptance.
The host recorded the checkpoint-recovery phase; result fields report no
cleanup, collection or evidence-export error. Keep the controller
`NotValidated` and inspect the archived guest report at
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11ProTest\results\71d37e0d44494852a9132d58660f5c2f`.

The failure report groups 154 failures under invalid call-operator/module-scope
dispatch, five under same-name automation-module selection, two under missing
wallpaper-image input, and eight other assertions. These counts are diagnostic
categories, not confirmed root causes or independent component rejection.
The full run used the modern Pester configuration because it produced the
correlated `pester.xml`; an isolated Windows PowerShell 5.1 run of
`DefaultImagesEngine.Tests.ps1` passed 21 of 22 tests and showed no module-scope
dispatch errors. Its remaining test attempted a real CIM query and was blocked
by the restricted Codex host token, not by the VM. This contrast points to
full-suite test-context/module selection as the next diagnosis; do not attribute
the 154 failures to Pro behavior yet. The deleted
`components/wallpaper/img0.png` is a working-tree deletion and was preserved;
the two image-source failures need an approved fixture or profile update.

Do not spend another full VM run on an unmodified test set. First reproduce the
module-selection failures with a bounded subset or a short discovery
diagnostic, then fix the harness or individual regressions and verify them in
focused Pester runs. Refresh the protected controller only after the source
change is validated; then use the registered UnitOnly route and confirm
checkpoint recovery again. Do not mark Pro acceptance complete until a full
UnitOnly pass.

### Pro controller regression repair, 2026-11-05

Native Windows PowerShell 5.1 and Pester 5.7.1 reproduced the invalid module
call with three test files. Removing the engine during a test for engine-free
export removed a dependency from an already-loaded retained guest module's
lookup scope. Separately, reloading the engine invalidated an existing
wallpaper caller's module lookup. Checks for an unloaded engine now use fresh
runspaces, and the engine and image tests reuse their image dependencies.
The five same-name credential probes also reproduced together. Each now installs
synthetic commands in its caller's actual module instance, introduces the
same-name decoy, and disposes its own runspace.

Profile membership and preview checks supply an in-memory pin for operator
image paths. Automatic hash checks still use generated PNGs in TestDrive.
The wallpaper asset deletion is preserved. The lock-screen recovery fixture
now models the native reader's sorted value names and checks recovery from
intent after a failed policy write. Focused image tests also exposed missing
Hyper-V guest checks in the acceptance wrappers and wallpaper account fixture.
These entry points now check the guest attestation before writes. Lock-screen
acceptance checks the selected edition's policy destination and, on Pro, the
inbox file bytes. Native Pro image acceptance remains open.

Before retry, all 11 protected controller hashes matched their registration
record and checkout. The registered task was Ready, VM Off, both queues empty,
worker lock available and recovery block absent. The live checkpoint GUID
matched pin `74c1c858-c6bb-40ab-97ed-61c1eea74c9f`. No protected file
required replacement. The [pilot checklist](../../tests/integration/automatedlab-tasks.md#pilot-acceptance-and-replication-evidence)
also requires ordinary, locked-session and watcher runs, CI delivery and
serialization, fault handling and independent replication. Historical records
for a different configuration cannot certify this Pro registration. Default-
branch publication and CI activation remain subject to the RC decision.

The combined failure-area selection passed 355 tests under Windows PowerShell
5.1 and Pester 5.7.1. Local NUnit XML SHA-256 is
`B0A110FABFC4E6A58DF3062BCC5BAD44F20E09274E6A85EF602196F73FC9EBD3`;
the engine reload probe passed separately. Repository validation passed for
479 operations, nine groups, six profiles and 412 PowerShell files. The
registered Local UnitOnly retry is `314581130b1e4cdfb06b91ea94286ab3`.
All 2,302 staged source hashes verified against its manifest (SHA-256
`85C90736F8933536212E69DA84CA768914D831C95880A4CD48518F0AD163CA9A`).

The retry finished Failed at 08:25 UTC on Pro build 26300. Guest validation
passed. Pester 5.7.1 reported 4,491 passed, one failed and 40 skipped from
4,532. All prior dispatch, name-selection and image failures cleared.
The remaining failure occurred at the first saved removal restore in
`tests/MachineFonts.Tests.ps1`. The synthetic lifecycle failed on the same
call in both guest runs and passed on the host. The guest summary, XML,
transcript, progress and source manifest were exported. Collection omissions
were empty and cleanup, export and state collection reported no errors.
Live inspection verified VM Off, task Ready, matching checkpoint GUID, free
worker lock, empty queues and no recovery block. Registration is `NotValidated`.

The repair source records the underlying font restore error and differing
file/registration fields on failed readback. The fixed `MachineFontRegression`
unit selection runs that test file through the registered queue; it requires a
protected registration advertising `MachineFontRegressionV1`. A focused pass
cannot close the full regression gate. No new legacy outcome was resolved,
retired or excluded. Native font and other component acceptance remain open.

After protected refresh, configuration SHA-256 is
`BF5FE7FF029F93DEC6BD59FA154223CA8F9B10549595AD42C9F221C587C7FC57`;
all 11 installed hashes matched source and the evidence record. Focused request
`0beb5f0e5f6d45c6b5167477a35e0b87` reproduced the failure in seven minutes.
Only the security descriptor differed on both recreated fonts. A negative test
also reported its deliberately changed timestamp. The handler now leaves a
recreated file's already-exact inherited descriptor intact and applies a saved
descriptor when it differs. The exact final readback still checks all fields.
Local font tests passed 20/20. On the same Pro guest, registered focused
request `41ebc9f976964bcab2a30629fccfa855` passed validation and all 20
tests with no skips, including differing protected ACL restoration and drift
refusal. Guest XML SHA-256 is
`AF2B81A2E56011745E7E60776C5044DCCAC2752908CA67A64581B46636F80FF4`.
Both focused runs exported their results and completed checkpoint recovery.

Full UnitOnly retry `84d13c059cb24c24a218ade4def24ef2` completed on Pro
build 26300 at 10:12 UTC. All 2,302 staged files matched the source manifest
(`6AF9E26F7925F37CD09ED717740F4285BF0C5D58E33A9630EE46F77592A3257D`).
Guest validation passed. Pester 5.7.1 passed 4,494 tests, failed one and
skipped 40. Font recovery passed. The concurrent watchdog writer exceeded
the one-second lock bound, also seen in the original 169-failure run.
Collection omissions were empty and cleanup and evidence export reported no
errors. Keep this result Failed. The operator deferred RC/default-branch
delivery and second-host replication on 2026-11-05.

A deterministic Windows PowerShell test reproduced a reader holding the sibling
lock while parsing its private copy of the JSON. Parsing and sharing-retry
delays now run outside the lock. The concurrent fixture runs its reader and
writer in independent native processes and verifies the first and last updates.
The retained one-second contention guard still applies. Six focused
concurrency checks passed locally, including the new lock-lifetime test.

Windows canceled the subsequent elevation request before the protected
watchdog refresh or either isolated refusal probe started. Final read-only
inspection verified the prior configuration hash, all 11 installed file
hashes against registration, the VM Off at the pinned checkpoint, task Ready,
empty queues, free worker lock and no recovery block. Three protected files
differ from the repair source: `Invoke-RideVmTest.ps1`,
`Invoke-RideVmTestTask.ps1` and `RIDE.TestAutomation.psm1`.
`ControllerRegressionV1` and the protected Pro `acceptance.md` are pending.
The refreshed capability is required before a focused guest watchdog rerun.

### Pro watchdog and checkpoint recovery verified, 2026-11-05

The operator approved the UAC retry. The refreshed registration advertises
`ControllerRegressionV1`; all 11 protected files matched the checkout and
registration evidence. Configuration SHA-256 is
`E6C20362645D44E62C81AC1EB1748C81CFE40CB07A694B6356ECD3C36B272C15`.
The isolated missing-checkpoint probe `946387f42e00475e89d6419a6973724e` and
expired-request probe `1b19d3bb0c6f4a9d8bc76913f0116c30` each refused the
request for the expected reason before VM use. The protected Pro
`acceptance.md` records both probes and their configuration and file hashes.

Registered Local UnitOnly request `ebabc98a5d38495e982d2492a805a710` ran
`ControllerRegression` on Windows 11 Pro build 26300. Guest validation passed.
Pester 5.7.1 passed all 206 selected tests with zero skips, including all six
concurrency cases. The reader released the lock before parsing, and the
independent reader observed complete snapshots during repeated writer updates.
All 2,303 staged files matched source manifest SHA-256
`F10054D5F2B314961B9D9CD5192C262E6B9AEBD994F6D6AA4FAE759BDEC01C80`.
The exported guest XML SHA-256 is
`58229501B1D5241B709F9E8C0E702FE1260D9177512AF6700AAD65AE2B66EFF2`.

The host recorded checkpoint restoration at 13:17 UTC. The correlated result
reported Passed with no cleanup, collection or evidence-export errors. Live
Hyper-V inspection found the VM Off with parent checkpoint
`RIDE-clean-test-base`, GUID `74c1c858-c6bb-40ab-97ed-61c1eea74c9f`.
The request was in the finished queue, the task was Ready, both active queues
were empty, the worker lock was free and no recovery block existed.

This closed the focused Pro watchdog regression. The full UnitOnly retry is
recorded below.

### Pro full UnitOnly regression passed, 2026-11-05

Registered Local request `24b9cc547aaa473c966148bf9d62caa9` ran from
13:45 to 14:52 UTC on Windows 11 Pro build 26300. The guest passed repository
validation. Pester 5.7.1 under Windows PowerShell 5.1 reported 4,497 passed,
zero failed and 40 skipped out of 4,537. The exported XML confirms all six
watchdog concurrency tests and the synthetic machine-font removal/restore
lifecycle passed in the full suite.

All 2,303 staged files matched the request's source manifest. Evidence is in
`results/24b9cc547aaa473c966148bf9d62caa9` under the registered Pro controller
root. SHA-256 for `source-files.json` is
`0484B640EA44CE866241DCC2ADF30434A66D9F675C58EBF95692BF694E4B7D14`;
SHA-256 for `guest/pester.xml` is
`ABB3E8738B71050C48EB5B73AF64E74BD558DCAFE4EA24492D77B2F9E8F2131E`.

The controller recorded checkpoint restoration at 14:52 UTC and returned
Passed with no collection, export or cleanup error. Live Hyper-V inspection
then verified `RIDE-W11P-Test` Off with parent `RIDE-clean-test-base`,
GUID `74c1c858-c6bb-40ab-97ed-61c1eea74c9f`. The request was in the
finished queue. The task was Ready, both active queues were empty, the worker
lock was free and no recovery block existed.

This closes the full UnitOnly gate for the recorded source and controller
hashes. Broader registration remains `NotValidated`. RC/default-branch
delivery and second-host replication remain deferred by the operator.
This regression closed no legacy product or feature outcome, so all five
migration ranges carry forward.

### Pro controller evidence reuse review, 2026-11-05

The comparison uses the retained Windows 11 trigger and Server overlap
snapshots, the protected October 13 acceptance records, published host source
`3107711e3c6dd27bc67a61c50e1cb33866c15880`, and the installed Pro 1.27.0
controller at migration revision `6097db8fd300b4d9e38c982b90b60d3b2e8db625`.
The frozen guest CI revision for the October 13 candidate was `a156475`.
Its guest source and installed host controller were versioned independently.

| Registration | VM and checkpoint boundaries | Controller and image |
| --- | --- | --- |
| RIDEWin11Test | VM `6a5c9f91-91f9-44c5-924a-d1b5f863e16f`; October 13 checkpoint `a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9`; subsequently repinned to `91369e82-5ff2-49ef-87c4-c4518a77ae7b` | Enterprise Evaluation, build 26300; ISO SHA-256 `BC3F24086EBADC94489066B5AD78089E2CF5C3491E90E790BB81A2B199C10E38`. October 13 module 0.4.6; installed at review 1.25.1. |
| RIDESrv2025Test | VM `06c2ae01-bf82-4634-9215-f240f3ea4147`; checkpoint `4a5b49ba-0795-480a-8d01-6f4f670577c8` | Server 2025 Standard Evaluation, build 26100; ISO SHA-256 `7B052573BA7894C9924E3E87BA732CCD354D18CB75A883EFA9B900EA125BFD51`. October 13 module 0.4.6; installed at review 1.1.0. |
| RIDEWin11ProTest | VM `7690a0b8-8190-4f56-91ad-c744fb081b1c`; checkpoint `74c1c858-c6bb-40ab-97ed-61c1eea74c9f` | Pro, build 26300; ISO SHA-256 `BD4307DF32BC8AF33B39CCECB1174AEB345386630F89A2B86C7A4E36B55EA650`. Installed module 1.27.0, SHA-256 `0C94DD4F57E73969AE25226DCFDAAB232CA2D5181E901F4C5077658116575E7F`. |

All three current registrations use the same host account SID, Local and CI
checkout paths and guest repository path. The native scheduled tasks use
interactive logon, highest privilege, Windows PowerShell and IgnoreNew.
The four dependency versions recorded by the other current registrations
match Pro (AutomatedLab.Common 2.3.37, AutomatedLabCore 5.61.0, PSFramework
1.14.457, PSLog 5.61.0). Pro enumerates 16 pins, including guest Pester
5.7.1. The earlier four-entry lists do not prove the other twelve.

| Case | Reuse decision and remaining test |
| --- | --- |
| Ordinary shell, locked session and watcher | Retain the October 9 Enterprise three-pass sequence for host trigger behavior. Its watcher differs only in two help-link capitalizations. Task parameters and watch-path predicate have identical executable tokens. The changed supervisor and Pro guest needed an ordered sequence on this registration. All three passed below with a host lock observation covering the second request. |
| Serialization | Retain the Server Local/CI pair for exclusive worker locking and source separation. The exclusive lock function is unchanged. Claim now normalizes timestamps; the worker waits on a supervised child. Check overlapping submissions with distinct source manifests and recovery before the next execution. |
| Unit failure, collection and normal recovery | Reuse the deliberate, pre-repair Pro font reproduction `0beb5f0e5f6d45c6b5167477a35e0b87`: the guest returned failing assertions, client exit 1, correlated XML and clean recovery. Current Pro full-unit request `84d13c059cb24c24a218ade4def24ef2` independently demonstrates failure propagation. The repaired full pass and both Pro refusal probes above remain accepted. No duplicate fault injection or unit-only gate. |
| Timeout | October 13 expected timeouts and later Enterprise supervised timeouts remain evidence for their original versions. Termination, failure collection and watchdog coordination changed. Exercise one deliberate deadline under the installed Pro worker and check partial export, terminal status and recovery. |
| Interrupted worker and explicit recovery | Retain Server `dc7cd7ae496d4527a9f0f9dd0c28bfef` for detecting a stale running request; its recovery record was reconstructed. Enterprise `c029135dbae34c30b1e68a820fc8fd09` has a contemporaneous explicit recovery on another pin. Pro unit tests cover a hung child and uncertain termination. Verify the installed Pro registration refuses new work, persists evidence before unblocking, explicitly recovers the exact Pro pin and resumes. One simulated stale record suffices; do not terminate a live worker. |
| CI publication and portability | Retain published bridge, hosted validation and upload results with their original revisions. A local CI-source submission exercises the registered worker only. RC validation, default-branch delivery, renewed bridge acceptance if applicable, and second-host replication stay deferred. |

For the October 9 trio, the **guest snapshot** controller module SHA-256 was
`885C072139061853045A37FD77D388F4878C1E871DC69E9433D92236757D95A5`;
for the Server overlap snapshot it was
`9735F65A50C59714CAD412564F57272A4A62BA944FBBD16CF028C4B7BA41E454`.
The separately recorded October 13 **installed** hash was
`2920E1BCF41EB61564F74315FC1D004872DC0BD2DF1697CC65420A30293F2507`.
PowerShell token comparison (excluding comments and newlines) found the task
parameters, exclusive lock, watch-path predicate, lab/VM validation and
checkpoint reset functions match Pro in all three comparisons. The claim
function matches October 13. Snapshot copying, request execution, process
termination and failure collection differ. See the
[historical scoped record](../archive/evidence/controller-046-scoped-acceptance-2026-10-13.md)
and the [pilot runbook](../../tests/integration/automatedlab-tasks.md#pilot-acceptance-and-replication-evidence)
for the original trigger and fault evidence.

#### Pro timeout and overlapping Local/CI submissions

| Source and case | Request | Submitted UTC | Terminal UTC | Evidence |
| --- | --- | --- | --- | --- |
| Local, deliberate ten-minute timeout | `659216734e4044c1abd5cec9331ff49a` | 16:22:53 | 16:33:29 | TimedOut as intended, client exit 1. Guest validation completed and Pester had started. The controller terminated its child process tree, exported partial evidence and identified the locked transcript as an omission. Recovery began at 16:32:54; checkpoint restore was recorded at 16:33:27. |
| CI, ControllerRegression | `35285a6d7a494671bf6516466c13796a` | 16:27:41 | 16:41:26 | Queued during Local execution. The supervisor started at 16:33:29.446 UTC, after the Local terminal record at 16:33:29.063. Guest validation and 206/206 tests passed, followed by recovery. |

Both finished queue entries match their distinct results; cleanup, collection
and evidence-export errors were empty. All 2,303 Local snapshot hashes and all
2,298 CI snapshot **and checkout** hashes verified. Source manifest SHA-256s,
respectively, are `6E2764D772181368940F1D008710909C5344663D396329D3F12B6B2585E01532`
and `A9283D6F476A2CCB273C71CD4C455094D3A8AA558EF1F05CBB9F920B0A41A592`.
With operator approval and the runner idle, the CI checkout temporarily used
published `6097db8f` detached. The original clean migration branch and exact
`a15647590a1324681bbe4a69cbb55e498a623522` were verified after restoration.
The live Pro VM was Off at its registered parent checkpoint, task Ready, queues
empty, worker lock free and recovery block absent. These runs close the Pro
timeout and serialized Local/CI cases without a new GitHub delivery run.

#### Three consecutive Pro Full integration passes

Three successive finished queue entries were registered Local requests with
`UnitOnly=false` and `IntegrationSuite=Full`. Each guest passed validation,
Pester 5.7.1 (4,497 passed, zero failed, 40 skipped) and native Windows
integration on Pro build 26300. The 2,303 staged files in **each** snapshot
verified against the same manifest, SHA-256
`12EEA7F6BC62343FADBF99B7C2FF77D2589AF1776FB0FA7FCB1D3A4294026DFB`.

| Trigger | Run ID | Execution UTC, November 5 | Checkpoint recovery UTC |
| --- | --- | --- | --- |
| Ordinary-shell submission | `ca41d5bc8a6843709debc309d737271c` | 16:44:37-18:08:32 | 18:08:31 |
| Locked host session | `f80db90e804e4dbd94fcc2423ac3397e` | 18:09:12-19:33:07 | 19:33:05 |
| Repository watcher | `03102f6d77864d26b9a709804ee21af3` | 19:34:30-20:56:53 | 20:56:52 |

The first case measures ordinary-shell submission; the operator was free to
lock the host after submission. The second request was submitted at 18:09:10
UTC after the registered host session was observed locked at 18:09:09 UTC.
Across 2,510 samples through 19:33:08 UTC, session 1 returned zero unlocked
samples and zero query errors. The copied `host-lock-observation.json` is
retained alongside that request. For the third request, the watcher observed
a timestamp-only change to `tests/fixtures/Test-RideConcurrentProgress.ps1`
after establishing its baseline. It submitted one Full request after its
normal 30-second debounce. All three requests had a 180-minute budget.
The watcher was stopped after its terminal result; the fixture timestamp was
restored and its bytes verified. The request directory retains `host-watcher.log`.

All three correlated results reported clean collection, export and cleanup.
Live checks after each run confirmed VM Off at parent `RIDE-clean-test-base`
(`74c1c858-c6bb-40ab-97ed-61c1eea74c9f`), task Ready, empty active queues,
free worker lock and no recovery block. The frozen CI checkout was rechecked
clean at its original revision after the sequence.

#### Pro interrupted-worker recovery and resumed service, 2026-11-05

After the watcher finished, the operator approved elevation for simulation
`548647cbfa834609b44e2f8151b18b2b`. The first task start returned Ready
with exit code zero, but the 60-second probe observed no interruption block.
The synthetic running record remained, the VM was Off at the pinned checkpoint
and the pending queue was empty. The original failed
`interruption-simulation.json` is retained. Task Scheduler operational history
was disabled. The later PowerShell event review below identifies where the
first worker stopped.

A second start of the registered task detected the **same** record and wrote a
block naming it. The ordinary registered client refused a new request before
queue admission. With the worker lock held and the controller idle, explicit
recovery restored checkpoint `74c1c858-c6bb-40ab-97ed-61c1eea74c9f` at
22:17:15 UTC. The recovery helper verified the live parent checkpoint and
persisted the recovery journal before archiving the synthetic record and
clearing its verified block. The separate `explicit-recovery.json` SHA-256 is
`6E350F1464DE78A7E6E7D8B854A0EF345253CAEA4F71EB097A20E0B7A729F49E`.
Both journals are in the simulation's registered result directory.

Post-recovery Local request `9f44b5762eeb469684c2b4ec1f27f443` passed guest
validation and all 206 ControllerRegression tests with zero skips. All 2,303
staged source hashes verified. The exported XML SHA-256 is
`7EBBFC81389561085D7584446005368FF1893B6A37295B5B672F2846489FACD1`.
The controller recorded checkpoint restoration at 22:27:20 UTC and completed
without collection, export or cleanup errors. Live inspection verified VM Off
at the pinned parent, task Ready, empty active queues, free worker lock and no
recovery block.

This closes the local blocking, explicit recovery and resumed-service case
**on retry**. Registration remains `NotValidated`. RC/default-branch
delivery and second-host replication remain deferred. No legacy feature or
product outcome changed; all five migration ranges carry forward.

#### First worker stopped during configuration loading, 2026-11-05

The existing classic `Windows PowerShell` log on the Pro host retained both
launches of the protected worker. All times below are UTC. The configuration
input recorded for both processes was identical (4,977 characters) and parsed
as the expected Pro registration. The scheduled action had no execution time
limit or battery-stop condition.

| Worker | PowerShell event 800 records | Observation |
| --- | --- | --- |
| First start, PID 33496 | 61815211, 61815214, 61815215 | Read the configuration at 22:12:58.761. Both the configuration call and the outer worker pipeline recorded `The pipeline has been stopped.` at 22:12:58.842-844. The engine then exited. Execution ended before worker-lock acquisition or queue inspection. |
| Retry, PID 51444 | 61816783, 61816807-61816810, 61816814 | Read the same JSON at 22:15:11.328, acquired the lock and scanned the running directory at 22:15:11.485-496, then wrote the block naming the original simulation. |

The first scan never happened. The retained events do not identify what
initiated the pipeline stop. No competing lock owner, invalid configuration
or queue-enumeration fault was established.

`tests/WorkerStartup.Tests.ps1` reproduces this sequence in an isolated
TestDrive queue. It runs the unmodified worker script, redirects the test
module's storage root, and stops a disposable runspace just after JSON parsing.
The worker did not create a lock file or a block; the stale record retained
its hash. A fresh runspace detected that exact record and published the
expected block. The test passed under Windows PowerShell 5.1.26100.9818 and
PowerShell 7.6.5 with Pester 5.7.1. This reproduces the interruption point;
the deliberate stop in the test does not identify the historical sender.

The host-local simulation helper now records each wake and permits one bounded
retry after verifying the same stale record and an idle controller. Seven
isolated probe-policy cases covered immediate success, success on retry,
two misses, no new launch, nonzero result, a busy task and a changed marker.
The [recovery runbook](../../tests/integration/automatedlab-tasks.md#recovery-and-teardown)
documents the checks. No production worker change or VM replay was needed.
Final inspection verified all 11 protected hashes, VM Off at its pinned parent
checkpoint, task Ready, empty active queues, free lock and no recovery block.
RC and second-host gates remain deferred; the five migration ranges carry
forward because this investigation closed no legacy outcome.

## Supervised Project Maker success, 2026-10-30

Corrected request 2ecfe2bb51b447a7ae586a860d7123da passed in approximately
13 minutes. Parent/guest correlation, validation and all eight deployment checks
passed, with 435 tests passed and four skipped. CleanupError, CollectionError and
EvidenceExportError are null. The final host stages record checkpoint recovery;
the request is archived, queues are empty and no recovery block is present.
The operator subsequently confirmed VM Off / Operating normally and task Ready
from elevated P52, completing final recovery verification. No lifecycle rerun is
needed for this milestone.

This adds successful runtime evidence for the installed supervisor and resolves
Project Maker's installer-completion blocker for this Windows 11 route. It does
not deliberately test a host-preparation stall or complete broader certification;
ValidationStatus remains NotValidated. No extra UnitOnly/full/manual feature run
is required for the selected installation milestone. All five migration estimates
remain unchanged because the larger legacy MiTeC collection is still partial.

Evidence: [passed supervised lifecycle](../archive/evidence/project-maker-win11-lifecycle-passed-2026-10-30.json).

## Supervised Project Maker timeout returned normally, 2026-10-30

Request 0fdbadf304d447a7b3e38e974da4e4a5 entered execution after 77 seconds
of host preparation and returned a correlated terminal TimedOut result in about
21 minutes including cleanup. CollectionError, CleanupError and EvidenceExportError
are null. Host stages record collection and checkpoint restoration; request
archival, empty queues and no recovery block were independently read back.
Live Off/Ready will be checked before the next dispatch. This is evidence for
the installed supervised path and normal execution timeout/recovery, not a
deliberate production host-preparation hang test. Certification stays NotValidated.

Project Maker's setup reports successful installation and launches its application
before closing the log; application lifecycle progress never leaves installation.
The scoped process-completion fix and pending corrected VM acceptance are tracked
in the [migration plan](../MIGRATION-PLAN.md#project-maker-completion-wait-corrected-2026-10-30).
No legacy outcome closes, and all five estimate ranges remain unchanged.

Evidence: [bounded timeout and package diagnosis](../archive/evidence/project-maker-installer-completion-fix-2026-10-30.json).

## Protected host watchdog installed, 2026-10-30

The operator completed registration 0.13.0. Read-back confirms
HostPreparationWatchdogV1, matching module/worker/request-child/controller/client/
collector hashes, unchanged VM/checkpoint pins, empty queues and no recovery
block. The previously passed host-only probe remains applicable to module 1.17.1.
Configuration ValidationStatus remains NotValidated: protected installation is
verified, while the first supervised VM request and broader certification remain
open. Live VM/task state will be checked by the elevated operator before dispatch.

Next submit one Source Local ApplicationsBatch10 request with a 20-minute limit
and retain the receipt. Use existing runner 0.19.4 stage/installer diagnostics;
inspect terminal evidence before any retry. This review submitted no request and
closed no legacy outcome. All five migration estimate ranges remain unchanged.

Evidence: [installed watchdog verification](../archive/evidence/controller-host-watchdog-installed-2026-10-30.json).

## Host-only preparation passed, 2026-10-30

Probe 2f5fb9b79e954335b3c1387985c7b965 passed in approximately 98 seconds
with module 1.17.1. Host dependencies, lab/VM/checkpoint checks, idle-task
inspection and copying 1,819 source files completed. Parent/child receipts
correlate; VmChanged is false, the child observed Off/Ready, the error log is
empty, and progress records contain no VM mutation marker. Four captured
controller/probe source hashes match the checkout.

This completes the bounded host-only preparation check. Next refresh protected
registration 0.13.0 once, verify HostPreparationWatchdogV1 and installed hashes,
then choose one focused migration request. The protected worker has not been
updated by this probe. Installed watchdog activation, VM recovery behavior and
broader certification remain separate; certification is still NotValidated.
Project Maker remains unresolved, and no legacy outcome or estimate changes.

Evidence: [passed probe](../archive/evidence/controller-host-preparation-probe-passed-2026-10-30.json).

## Host progress sharing correction, 2026-10-30

Host-only probe 2f9f5afa7cb845759ee05365ba666393 completed host validation
and lab/checkpoint checks, then failed while reading host-phase.json during a
concurrent update. No VM change or termination error was recorded; read-back
found no recovery block. Source copying was not established by this probe.

Module 1.17.1 serializes progress reads and writes with a bounded sibling-file
lock instead of replacing a file while the parent reads it. Lock acquisition
and sharing retries each stop after one second; invalid data remains a failure.
Focused Windows PowerShell 5.1 concurrency/watchdog and stage-order checks are
recorded in the linked evidence. No VM or installer was run for the correction,
and no protected controller files were changed.

Next repeat the host-only probe once and inspect its result before registration
or another migration request. Earlier controller tests retain their scope;
certification remains NotValidated and Project Maker acceptance is unresolved.
No legacy outcome closes; all five estimate ranges remain unchanged in the
[migration overview](../MIGRATION-PLAN.md).

Evidence: [probe failure and progress-file correction](../archive/evidence/controller-host-progress-sharing-fix-2026-10-30.json).

## Host preparation watchdog prepared, 2026-10-30

Worker 0.2.0, module 1.17.0 and registration 0.13.0 add independent supervision
of the fixed request child, including host preparation and checkpoint recovery.
The existing submitted deadline is retained; preparation is capped at five
minutes, recovery at three minutes, and process-tree termination is bounded.
Progress records identify the last stage and possible VM changes. Unknown cleanup
produces a recovery block instead of another unbounded host call.

Local Windows PowerShell 5.1 checks passed: 11 inert-process watchdog cases and
158 controller regressions; repository validation passed for 312 PowerShell
files, 451 operations, eight groups and five profiles. The process-tree checks
required execution outside the sandbox after sandboxed taskkill stalled. No VM,
installer or installed task/configuration was changed. This is prepared source,
not runtime controller acceptance.

Next use the [bounded host-only probe](../../tests/integration/automatedlab-tasks.md#bounded-host-preparation)
under the elevated registered host account, with VM Off and idle queues. On a
pass, refresh registration once, check installed hashes/capability, then select
one focused runtime acceptance request. Broader certification remains
NotValidated. Project Maker retries remain deferred until this boundary is
activated and reviewed. No new legacy outcome closes; all five migration ranges
remain unchanged, as recorded in the [migration overview](../MIGRATION-PLAN.md).

Evidence: [watchdog preparation](../archive/evidence/controller-host-preparation-watchdog-2026-10-30.json).

## Project Maker interrupted worker recovered, 2026-10-30

Diagnostic request c029135dbae34c30b1e68a820fc8fd09 produced no controller log or original terminal result. The client stopped waiting, while the host task remained Running and the VM was Off. The operator disabled/stopped the task and confirmed zero remaining worker/observed child processes. Recovery then held the exclusive worker lock, verified the exact configured VM/checkpoint and isolated request, restored checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b through Hyper-V, and persisted an explicitly reconstructed failure plus operator-recovery.json before archiving the request. The receipt records restoration at 2026-10-30 10:20:50 UTC. Final operator output confirms VM Off, task Ready, both queues empty, no recovery block and the interrupted request archived. Archived-request placement and retained recovery files were independently read back.

Controller recovery is complete. This was an interrupted host-worker attempt, not a completed Project Maker acceptance run. The earlier a30a4f653eec4a7891b6a9839be6c458 request reached package integration and downloaded the pinned installer before timing out; that lifecycle stall remains unresolved. The second attempt does not identify its cause. The 20-minute watchdog did not cover all host preparation, so it was not an overall request bound. Do not automatically retry Project Maker. Keep its candidate unsupported and record runtime acceptance unresolved; improve bounded host preparation/progress diagnostics before relying on another timed VM request. No additional recovery command is required for this request.

No legacy outcome is resolved, retired or newly excluded. Project Maker remains partial with further runtime retries deferred; other scope is unchanged. All five estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12: exact 126-180, rounded 125-180/about 155. Recovery restores the test environment but does not close a legacy product outcome.

Evidence: [interruption and completed recovery](../archive/evidence/project-maker-interrupted-worker-recovery-2026-10-30.json).

## Project Maker lifecycle timeout and bounded diagnosis, 2026-10-30

ApplicationsBatch10 run a30a4f653eec4a7891b6a9839be6c458 timed out after the 90-minute controller limit. Validation and 432 tests passed (four skipped). Integration started at 07:20:30 UTC and the 9,944,720-byte PMInstall.exe download was recorded at 07:20:33 UTC with the exact pinned SHA-256 ee2a74e34c0c0ad97c58163b2f4f114876252317cb52fffbf9fa11e2afe13419. The last retained progress is Windows integration started. No application summary was collected; transcript.log was locked. The evidence cannot distinguish installation from removal/recovery as the stalled step. Do not claim a confirmed installer defect or repeat an unchanged 90-minute run. Controller cleanup, collection and evidence-export errors are null, with the transcript omission explicitly recorded.

Runner 0.19.4 adds closed-handle machine lifecycle progress in application-progress.jsonl, preserves application-user-progress.jsonl for limited users, and adds documented Inno Setup logging to Project Maker's existing silent install arguments. The installer log can be overwritten during recovery or unavailable while locked; stage records provide a separate observation. No production catalog, handler or install/uninstall behavior was changed. Fourteen focused tests pass, including actual logger execution for both contexts and installer-argument preservation. The guest changes travel in the Local snapshot; re-registration is unnecessary.

Next submit one diagnostic ApplicationsBatch10 request with TimeoutMinutes 20 after idle Off/Ready checks. Evidence collection and checkpoint recovery follow that limit. Do not add a separate UnitOnly run. Inspect the resulting stage/log evidence before any further retry; decide whether a focused correction or deferral is appropriate rather than extending the timeout. No claim of product acceptance follows from instrumentation.

No legacy outcome is resolved, retired or newly excluded. Project Maker remains partial; other deferred scope is unchanged. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12: exact 126-180, rounded 125-180/about 155. A timeout and diagnostic preparation do not reduce estimates.

Evidence: [timeout and diagnostics](../archive/evidence/mitec-project-maker-timeout-diagnostics-2026-10-30.json).

## NTCore Explorer Suite Windows 11 lifecycle accepted, 2026-10-30

Corrected ApplicationsBatch12 run ed4f857b82314e70ad72a807266a5282 passed from 06:46:24 to 06:57:30 UTC. Repository validation passed; Pester XML confirms 436 total, 432 passed, zero failures/errors and four skipped. The pinned 3,613,174-byte ExplorerSuite.exe was downloaded from its declared publisher source, then reused from cache for recovery; both observations match SHA-256 94f4348ec573b05990b1e19542986e46dc30a87870739f5d5430b60072d5144d. The artifact is unsigned, consistent with the retained source evidence; this is not a signature-validity claim.

The intended elevated guest administrator passed installation/presence, repeat install, removal preview, removal, repeat removal, saved-removal presence recovery and saved-install recovery. The six named repeat/removal/recovery checks are recorded; initial install/presence is required by the runner before reaching them. Recovery=true. Controller execution, collection, cleanup and evidence-export errors are null. This closes the agreed Windows 11 installation-lifecycle blocker; do not repeat it without a relevant change or failure. Live Off/Ready state is not independently observed by this evidence review.

Installed DisplayVersion and RemovalRecoveryVersion are null, so the accepted artifact identity is the exact installer pin, not an asserted installed display version. Recovery is compensating presence recovery of the declared installer. No suite utility was launched, and no manual utility testing is added to this milestone. Detailed installed component/shortcut inventory and broader product functionality remain separate from this accepted lifecycle scope; the catalog is not promoted to full product support by this record.

No whole legacy outcome is resolved, retired or newly excluded. The wider NTCore collection/product review remains partial; other deferred work is unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged: exact 126-180, rounded 125-180/about 155. The accepted lifecycle sub-milestone does not close the entire legacy collection outcome.

Evidence: [Windows 11 lifecycle pass](../archive/evidence/ntcore-explorer-suite-win11-lifecycle-pass-2026-10-30.json).

## NTCore Explorer Suite candidate gate correction, 2026-10-30

ApplicationsBatch12 run 0e00f4de264540fe9449214b0f63ec82 failed before installer execution. Repository validation and 428 Pester tests passed, with zero failures and four skipped. The first installation plan rejected the still-pending Explorer Suite Windows 11 candidate. Exact-package scenario selection worked, but the guest-only catalog preparation omitted its reviewed-collections migration group. This is a runner defect, not evidence of publisher or installer failure. Controller collection, cleanup and evidence-export errors are null; live Off/Ready state remains an operator preflight.

Invoke-RideApplicationBatch.ps1 0.19.3 admits the exact Explorer Suite candidate only in Batch 12 and only for its declared target. The production catalog remains pending. Review also found Batch 12 absent from the existing vendor removal/repeat/removal-recovery branch; it is now included, with lifecycle check reporting. Four focused regression cases pass using the actual preparation/removal blocks: declared Windows 11 admission, rejection outside Batch 12, rejection of Server support, unchanged production metadata and simulated vendor removal/recovery. Twelve affected version/package regression tests pass. Repository validation passes for 451 operations, eight groups, five profiles and 309 PowerShell files. No installer or Windows state change occurred in local checks.

Next: one normal Source Local ApplicationsBatch12 retry after VM Off/controller Ready and idle-queue checks. The existing protected controller matches the checkout and advertises the required capability; the corrected guest runner travels in the Local source snapshot, so registration and a separate UnitOnly run are unnecessary. Require passed install/repeat/remove/recovery evidence and host checkpoint cleanup. Bundled utility functionality remains outside this installation-lifecycle milestone.

No legacy outcome is resolved, retired or newly excluded. Explorer Suite remains partial pending Windows acceptance; other deferred work is unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged: exact 126-180, rounded 125-180/about 155. A failed run and local correction do not justify reducing estimates.

Evidence: [failure and focused correction](../archive/evidence/ntcore-explorer-suite-candidate-gate-fix-2026-10-30.json).

## HashCheck Windows 11 acceptance complete, 2026-10-30

HashCheck 2.6.3 (installed version 2.6.3.0) is complete for the intended signed-in Windows 11 administrator workflow. The pinned official installer, publisher checksum and valid signature were verified. Maintained ApplicationsBatch11 run 77f50d48b54c4f5c9b5393208f54987e passed all eight install/remove/repeat and saved-state presence recovery checks, with 428 Pester tests passed, zero failed and four skipped. Recovery reinstalls the declared version, not an arbitrary historical version.

Feature run 4b1d874246f44009b360753c6a64ad78 passed matching-manifest verification, deliberately changed-file mismatch detection and SHA-256 manifest creation. Explorer observations are operator-reported; the exported generated manifest and installation records were independently verified. Ten guest evidence files passed transfer hash comparison and host rehashing. The retained recovery receipt records checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b restored at 2026-10-30 06:05:05 UTC, VM Off, controller Ready and ten verified files. The operator also confirmed this final state.

The catalog now declares Windows 11 support and clears PendingAcceptance. Installation and removal require the intended user's elevated interactive session. Session 0, SYSTEM, another intended user and Windows Server remain unsupported. No further HashCheck acceptance retry is required for this scope. Broader controller certification remains NotValidated and other Windows acceptance work remains separate.

One requested v3 addition is completed. HashCheck was tracked separately from legacy estimates, so no legacy outcome is resolved, retired or newly excluded by this closure. Other partial and deferred scope is unchanged. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12: exact 126-180, rounded 125-180/about 155. Two focused Windows PowerShell 5.1 metadata tests passed, one each in Catalog and ApplicationPackages; unrelated tests were not selected.

Evidence: [completed acceptance](../archive/evidence/hashcheck-windows11-acceptance-complete-2026-10-30.json).

## HashCheck Explorer feature preparation, 2026-10-30

Feature evidence export completed at 2026-10-30 06:00:56 UTC for run 4b1d874246f44009b360753c6a64ad78. Ten guest files were copied and compared with guest SHA-256 records, then independently rehashed on P52. Exported console result confirms admin Session 1, installer exit zero; the log confirms successful native and sparse registrations/provisioning. The exported Create/sample.txt.sha256 exactly matches the independent expected SHA-256 and filename. Positive/negative UI results remain explicitly attributed to the operator; generated-file contents are independently verified. Prepared Reset-HashCheckFeatureAcceptance.ps1 0.1.0 to require these ten files and recorded observations, pinned VM/checkpoint and disabled idle controller, then shut down gracefully, restore the clean checkpoint, leave the VM off and re-enable the controller. Its Windows PowerShell 5.1 parser and actual read-only preflight passed against all ten retained files; no recovery mutation has executed. Next run that helper from elevated P52 and retain the Off/Ready receipt. No whole legacy outcome is counted closed until this session recovery is complete; ranges remain unchanged.

Explorer checksum creation passed as reported: the operator used the instructed Create Separate Checksum Files action for Create/sample.txt and returned sample.txt.sha256 containing ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad *sample.txt. This matches the independent SHA-256 fixture expectation. Matching, tampered-file and creation checks are now all reported passed. Prepared Export-HashCheckFeatureAcceptance.ps1 0.1.0 to retain guest files, compare guest/host hashes, validate generated bytes and installation records, and preserve separately attributed operator UI observations. Its parser/version entry point passed; export has not executed. Next close HashCheck windows, export from elevated P52, review retained evidence, then restore the pinned checkpoint and re-enable the controller. The current feature session remains running with controller disabled. No whole legacy outcome is counted closed until evidence and recovery are complete; all five estimate ranges remain unchanged.

Explorer tampered-manifest check passed: the operator opened Tampered/sample.sha256 as instructed and pasted zero matches, one MISMATCH, zero unreadable and zero remaining. The actual SHA-256 a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9 matches the independently prepared abd fixture and differs from the declared abc checksum. Both positive and negative verification checks now pass. Next exercise Explorer checksum creation on Create/sample.txt and compare the generated SHA-256 manifest with the independent expected hash. UI evidence is operator-reported; export and final checkpoint recovery remain pending. No whole legacy outcome is closed and all five ranges remain unchanged.

Explorer matching-manifest check passed: the operator opened Match/sample.sha256 as instructed and pasted HashCheck results showing one MATCH, zero mismatches, zero unreadable and zero remaining. Expected and actual SHA-256 both equal ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad. This is user-reported UI evidence; guest evidence export remains pending. Next check Tampered/sample.sha256 for one mismatch, then checksum creation. Feature acceptance remains partial; no legacy outcome is closed and all five estimates remain unchanged.

After completing the normal-controller lifecycle and final Off/Ready verification, the operator checked empty queues and no recovery block, disabled the host controller and started the restored VM. Current operator evidence reports VM Running / Operating normally and task Disabled. This begins a separate feature-acceptance session; the earlier lifecycle pass remains valid.

Prepared `.local/acceptance-input/Stage-HashCheckFeatureAcceptance.ps1` 0.1.0. It validates host/VM/checkpoint identity, disabled idle controller and the retained installer hash/signature, then uses PowerShell Direct to copy a unique fixture directory plus installer. It rejects an existing native HashCheck installation and verifies every transferred file. It executes no installer and makes no GitHub request. Native Windows PowerShell 5.1 parser and actual fixture-generation checks passed: known SHA-256 of the three ASCII bytes abc, deliberately changed abd bytes, exact ASCII checksum manifests, independent creation fixture and duplicate-directory refusal. Staging run 4b1d874246f44009b360753c6a64ad78 completed: six fixture files plus the retained installer were transferred to C:\RIDE\ManualAcceptance\HashCheckFeature-4b1d874246f44009b360753c6a64ad78. All seven guest hashes match the host manifest, and retained host files were independently rehashed. Installer signature remains Valid. Staging did not execute the installer. The operator then installed from the elevated guest admin console in Session 1: exit code zero, both native shell registrations zero, valid MSIX signature, sparse-package registration zero and provisioning completed. Package IDRIX.HashCheck_2.6.3.0_neutral__hd6jbvhf8esfw was reported installed. These installation findings come from pasted console/log output; feature-install.log and feature-install-result.json remain in the guest pending export. Explorer matching-manifest, tampered-file and creation checks are next. The VM remains running and the controller disabled.

The publisher's v2.6.3 README was read through the connected GitHub tool (blob 8fa088a7bb40c54960f96625c8f3fcc8e0ab4262). It documents opening checksum manifests in Explorer, copying verification results, SHA-256 checksum creation and separate checksum files. Planned acceptance uses the existing admin's ordinary Explorer session: confirm the matching manifest, deliberately changed-file mismatch, and checksum creation against independently computed expected bytes. These are future checks, not passed evidence. Console installation is complete; retain installer/identity evidence and perform and record UI checks next. Export evidence before restoring checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b and re-enabling the controller.

No whole legacy outcome is resolved, retired or excluded by preparation. HashCheck lifecycle is accepted but feature behavior remains partial; other deferred work is unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged: exact 126-180, rounded 125-180/about 155. Preparation does not close a whole product outcome.

Evidence: [feature preparation](../archive/evidence/hashcheck-explorer-feature-preparation-2026-10-30.json).

## HashCheck maintained controller lifecycle passed, 2026-10-30 05:17 UTC

Ordinary Local ApplicationsBatch11 request 77f50d48b54c4f5c9b5393208f54987e passed from 05:06:11 to 05:17:19 UTC. Repository validation and integration passed; Pester XML confirms 432 total, 428 passed, zero failures/errors and four skipped. The corrected guest process ran as the intended elevated administrator in interactive Session 1. The temporary task exited zero and was removed, and the worker reported correlated success. The host interactive evidence validator also passed when re-run against the exported records.

HashCheck 2.6.3.0 passed all eight recorded checks: managed install, pinned version, repeat install, removal preview, removal, repeat removal, saved removal recovery and saved install recovery. Recovery=true and RemovalRecoveryVersion=2.6.3.0. The retained installer log confirms successful signed sparse-package registration/provisioning. Recovery remains compensating presence recovery using the declared installer; arbitrary historical versions are not guaranteed.

The final controller result reports no execution, collection, cleanup or evidence-export error. Both queues are empty and no recovery block exists. This closes the maintained remote installation/lifecycle blocker for the tested signed-in Windows 11 administrator route. The operator subsequently confirmed VM Off / Operating normally and host task Ready from elevated P52; final recovery verification is complete. No further controller re-registration or lifecycle retry is needed for this recorded source. Next isolate the idle controller, boot the restored disposable guest, and prepare a separate Explorer/checksum feature check for full HashCheck product acceptance. Use synthetic files with independently computed expected hashes, verify a matching manifest and a deliberately altered-file mismatch, retain results, and restore the pinned checkpoint before re-enabling the controller. These feature checks are planned, not yet executed. Logged-out installation, Explorer behavior, broader controller certification and support metadata promotion are not established by this pass. ValidationStatus must not be manually promoted from this scoped result.

No whole legacy product outcome is newly closed, retired or excluded: HashCheck progresses from lifecycle pending to lifecycle accepted with feature behavior still partial. Other deferred work is unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged: exact 126-180, rounded 125-180/about 155. The narrowed blocker closes without counting the remaining product feature acceptance as complete.

Evidence: [maintained controller lifecycle pass](../archive/evidence/hashcheck-maintained-controller-pass-2026-10-30.json).

## HashCheck maintained-route Pester scope failure and correction, 2026-10-30

Reviewed ordinary controller run b3cf882824014db2982fcf8efdf67f3c, executed 2026-10-29 18:08-18:22 UTC. The interactive worker reached the intended elevated guest administrator in Session 1 with UserInteractive=true. Repository validation passed. Pester reported 432 total, 426 passed, two failed and four skipped; the integration phase and HashCheck installation did not run. Failures were exported package variant completion and the UWP per-app override fixture's missing Get-RideSettingState command. The temporary task exited 1 and was removed; controller collection and cleanup errors were null. Both queues are empty and no recovery block exists. Current VM/task CIM reads were unavailable to the assistant process; confirm Off/Ready in the elevated host shell before retrying.

The maintained wrapper introduced the failure by invoking the suite inside its module scope. Native Windows PowerShell 5.1 reproduced both failures with the relevant preceding settings-import test retained. The same three selected tests passed outside module scope. RIDE.InteractiveGuestTests 0.1.1 now starts the existing guest suite in a fresh Windows PowerShell process, inheriting the scheduled task's user, desktop, elevation and VM marker. It propagates nonzero exit codes and retains summary validation. The actual corrected function passed all three selected tests (228 unrelated tests not run); 16 interactive regression tests also passed, including real child-process scope/session/identity and nonzero-exit checks. Both changed PowerShell files parsed. No publisher or lifecycle assertion was weakened and no installer was executed in local validation.

The protected host runner and automation module still match the checkout, ApplicationsBatch11InteractiveV1 remains present, and LocalRepositoryPath points to this checkout. This correction is in the guest source copied per request, so another controller registration is not required. Next verify VM Off and task Ready on P52, then resubmit ApplicationsBatch11 with Source Local, the existing configuration and a unique receipt. Keep the failed run's evidence. Require passed suite/task/worker evidence and checkpoint recovery before closing maintained-route acceptance. Explorer behavior and broader controller certification remain open.

No whole legacy outcome is resolved or retired, and no exclusion is added. HashCheck remains partial pending a successful normal-controller retry and feature acceptance; other deferred scope is unchanged. All ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12: exact 126-180, rounded 125-180/about 155. A regression failure and its source correction do not close a whole product outcome.

Evidence: [failure and process-scope correction](../archive/evidence/hashcheck-controller-pester-scope-fix-2026-10-30.json).

## HashCheck protected controller refresh, 2026-10-29 18:03 UTC

The operator successfully re-registered the controller on P52. Read-back confirms ApplicationsBatch11InteractiveV1, the intended VM and checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b, and SHA-256 matches between installed and checkout copies of Invoke-RideVmTest.ps1, RIDE.TestAutomation.psm1 and Invoke-RideVmTestTask.ps1. ValidationStatus remains NotValidated. Registration is complete; ordinary ApplicationsBatch11 runtime acceptance is still pending. Next submit that suite with the existing configuration and a unique receipt, then verify interactive worker/task evidence and checkpoint recovery.

This refresh closes no whole legacy outcome and retires or excludes none. HashCheck remains partial pending the normal controller run and Explorer behavior; other deferred scope is unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged: exact 126-180, rounded 125-180/about 155. Evidence: hashcheck-maintained-interactive-controller-2026-10-29.json in the linked archive.

## HashCheck checkpoint recovery and maintained controller preparation, 2026-10-29

The operator completed final recovery for diagnostic d43ef603fde042588104e3128f13e245 at 17:40:11 UTC. The retained receipt identifies checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b, FinishAcceptance=true, VM Off, host task Ready and 24 verified files. Those 24 retained files were independently rehashed again. The successful remote interactive lifecycle and its checkpoint recovery are complete.

The maintained ApplicationsBatch11 path now dispatches the existing suite through one temporary elevated interactive guest task. It selects one desktop for the remote administrator SID and verifies the actual worker machine, SID, session and elevation. Exclusive dispatch/worker claims prevent replay; AutomatedLab uses one dispatch attempt and explicit completion output. The task has a 30-minute execution limit, retains request/task/worker/output evidence and must be removed. Collected task and worker evidence are checked on the host independently of remoting error propagation; a successful lifecycle summary cannot hide task failure or incomplete removal. No automatic sign-in is configured and logged-out installation is not supported by this route.

Source versions: Invoke-RideVmTest 0.19.0, RIDE.TestAutomation 1.16.0, registration 0.12.0 and interactive launcher/module 0.1.0. Registration adds ApplicationsBatch11InteractiveV1; stale controllers are rejected before queueing. Native Windows PowerShell 5.1 validation passed 14 mocked interactive tests and 157 controller tests, with no failures or skips; all eight focused PowerShell files parsed. Tests cover identity/session rejection, single execution, timeout cleanup, failure propagation, collected evidence correlation and stale capabilities. The initial new-fixture discovery issue was corrected before this final passing run. No installer, VM reset or task registration was performed by these source tests.

Next, from an elevated host shell in the checkout, refresh the idle controller using `tests/integration/Register-RideVmTestTask.ps1 -ConfigurationPath <existing-configuration.json>`. Confirm ApplicationsBatch11InteractiveV1 and matching protected copies, then submit the ordinary `Invoke-RideVmTestTask.ps1 -IntegrationSuite ApplicationsBatch11 -TimeoutMinutes 90` request with that configuration and a unique receipt. Its Local source must include the new guest files. Require a correlated Passed result, task exit zero/removal, exact intended interactive worker identity and successful checkpoint recovery. The protected controller has not yet been refreshed and this ordinary entry point has not yet passed native acceptance. Explorer feature behavior, full controller certification and published support promotion remain separate.

No whole legacy outcome is newly resolved or retired, and no new exclusion is introduced. HashCheck remains partial pending maintained-route acceptance and user-visible feature checks; other deferred scope is unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged: exact 126-180, rounded 125-180/about 155. Preparation and scoped recovery do not close a whole legacy product outcome.

Evidence: [maintained controller preparation](../archive/evidence/hashcheck-maintained-interactive-controller-2026-10-29.json).

## HashCheck full remote interactive lifecycle pass, 2026-10-29 16:54 UTC

Run d43ef603fde042588104e3128f13e245 passed the complete ApplicationsBatch11 RIDE lifecycle through the remote-triggered interactive guest task. Source verification confirmed all 1,794 recorded files and runner 0.19.2 before execution. The intended elevated guest admin ran in interactive Session 1. Repository validation passed; Pester XML confirms 426 total, 422 passed, zero failures/errors and four skipped. Summary Status=Passed, ValidationPassed=true and IntegrationPassed=true, with no run or state collection error. Application evidence confirms all eight checks, version 2.6.3.0, Recovery=true and RemovalRecoveryVersion=2.6.3.0. Recovery remains compensating presence recovery using the declared installer, not a promise to recover arbitrary previous versions.

The launcher completed successfully, dispatch returned completion, task LastTaskResult=0 and TaskRemoved=true with no task error. The retained publisher log confirms Valid MSIX signature and successful sparse registration/provisioning plus both native registrations. All 24 exported files, including saved machine state, were hash-checked against the guest manifest and independently reverified on P52. Integration completed at 16:54:10 UTC. This establishes the interactive execution route for the full recorded RIDE lifecycle; the ordinary registered controller command has not yet adopted it, and logged-out installation and Explorer behavior remain unaccepted. Support metadata is unchanged.

Next run `.local/acceptance-input/Reset-HashCheckDiagnosticVm.ps1 -DiagnosticRunId d43ef603fde042588104e3128f13e245 -FinishAcceptance` from elevated P52. The updated recovery helper verifies nested evidence and the correlated passed suite/task before restoring the exact clean checkpoint, leaving the VM off and re-enabling the host controller. Its parser and actual read-only evidence preflight passed under Windows PowerShell 5.1 for all 24 files; guest recovery is still pending. After recovery, integrate the verified interactive dispatch into the maintained controller path with explicit identity/session requirements and regression coverage, then validate that ordinary entry point. Full controller certification and user-visible feature acceptance remain separate.

No whole legacy outcome is newly resolved or retired and no new exclusion is added. HashCheck advances to a verified remote interactive RIDE lifecycle, with controller integration and feature acceptance partial; other deferred acceptance is unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged, exact 126-180 and rounded 125-180/about 155. The acceptance scope is narrower than the full legacy product outcome.

Evidence: [full remote interactive lifecycle result](../archive/evidence/hashcheck-remote-interactive-lifecycle-pass-2026-10-29.json).

## HashCheck remote interactive RIDE lifecycle preparation, 2026-10-29

The operator restored the clean checkpoint after the successful interactive installer diagnostic at 14:36:15 UTC, with 18 evidence files verified, guest Running and controller Disabled. Host helper 0.3.0 now accepts `-ExecutionMode InteractiveTask -RideLifecycle`; launcher 0.2.0 verifies the recorded source archive, manifest and all 1,794 files before invoking the existing guest entry point with ApplicationsBatch11. It uses the same source snapshot and application runner 0.19.2 as the attended lifecycle pass. Both modified helpers parsed in Windows PowerShell 5.1, the actual source-verification function passed all 1,794 files and the lifecycle launcher rejected the developer host before operations. No host installer or guest lifecycle execution occurred during preparation.

The temporary task retains explicit signed-in admin/session/elevation checks, one dispatch, no password storage, a 30-minute execution limit and cleanup evidence. The suite performs repository validation, focused Pester and real HashCheck install/repeat/remove/recovery checks. RIDE may acquire its pinned publisher payload. The host exports root correlation files and the complete results/state tree with hash comparison; the expanded working source tree is excluded because the verified archive and manifest are retained. This is an acceptance helper; the ordinary registered controller path and support metadata remain unchanged.

Next run `.local/acceptance-input/Invoke-HashCheckRemoteDiagnostic.ps1 -ExecutionMode InteractiveTask -RideLifecycle` from elevated P52. Keep the guest admin signed in and controller disabled. Require correlated source verification, summary Passed with IntegrationPassed=true, application recovery evidence, task result 0 and task removal. Preserve exported results before recovering the configured checkpoint. Full controller integration, logged-out execution and Explorer behavior remain separate. No whole legacy outcome is resolved or retired and no new exclusion is added. HashCheck remains partial and other deferred acceptance is unchanged. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12, exact 126-180 and rounded 125-180/about 155; preparation does not complete a product outcome.

Evidence: [remote interactive lifecycle preparation](../archive/evidence/hashcheck-remote-interactive-lifecycle-preparation-2026-10-29.json).

## HashCheck remote interactive dispatch pass, 2026-10-29 14:32 UTC

After confirmed checkpoint recovery at 14:28:45 UTC, diagnostic 0f917eb5f99f40699db5435b843a6df3 passed through the corrected remote interactive route. The elevated guest admin ran in Session 1 with UserInteractive=true. Installer exit 0, no timeout/error/collection errors, valid MSIX signature, successful sparse registration/provisioning and both native registrations exit 0 are retained. AppX evidence confirms IDRIX.HashCheck 2.6.3.0 installed for the intended admin. The launcher completed successfully, the host received DispatchCompleted=true, task LastTaskResult=0 and TaskRemoved=true with no task error. No repeated launcher invocation is observed. All 18 exported files were hash-checked on transfer and independently reverified on P52.

This verifies remote-triggered installation in a signed-in interactive user session. It does not enable installation while logged out or change the normal registered ApplicationsBatch11 path. Next recover the successful diagnostic installation with `.local/acceptance-input/Reset-HashCheckDiagnosticVm.ps1 -DiagnosticRunId 0f917eb5f99f40699db5435b843a6df3`, then run the full RIDE install/repeat/remove/recovery acceptance through the verified interactive route using recorded source. The controller remains disabled during that comparison. Require source/evidence correlation, suite pass, task result and cleanup, and final checkpoint recovery before integrating or certifying the ordinary controller route. Explorer behavior and published support remain separate; no support metadata changed.

No whole legacy outcome is resolved or retired and no new exclusion is added. HashCheck is partial with remote interactive installation now verified, while integrated lifecycle and feature acceptance remain; other deferred acceptance is unchanged. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12, exact 126-180 and rounded 125-180/about 155. A successful diagnostic route is progress but does not complete the product outcome.

Evidence: [remote interactive dispatch pass](../archive/evidence/hashcheck-remote-interactive-dispatch-pass-2026-10-29.json).

## HashCheck interactive install pass and dispatch replay repair, 2026-10-29 14:06 UTC

Run 5f2fb83f1eec4c0399ba3da4abb46791 installed HashCheck successfully in elevated interactive Session 1: installer exit 0, no timeout/error/collection error, valid MSIX signature, sparse registration/provisioning success and both native registrations exit 0. AppX evidence confirms version 2.6.3.0 installed for the intended guest admin. The diagnostic body and payload are unchanged from the Session 0 failure. This validates the interactive installation comparison, not the complete remote workflow.

The final task result was 1 because the remote helper returned no output. Installed AutomatedLabWorker 5.61.0 tracks successful sessions through returned RunspaceId values; a no-output invocation remained eligible for retry. A second launcher began at 14:06:54 UTC after the installer finished at 14:06:29 UTC, then stopped at `Diagnostic already ran.` before a second installation. It overwrote the first launcher result. The temporary task was removed. All 18 exported guest files were hash-checked during copy and independently reverified on P52.

Host helper 0.2.1 now requests exactly one dispatch with `-Retries 1`, claims the run atomically before task creation and returns completion output. Launcher 0.1.1 refuses to overwrite existing diagnostic or launcher evidence. A Windows PowerShell 5.1 regression executed the actual installed AutomatedLab retry loop with mocked commands: no-output/retries=3 dispatched three times, retries=1 dispatched once, and completion output dispatched once. Duplicate exclusive claims were rejected and all three changed helpers parsed. No host installer or task was executed by these checks. Runtime verification of the repaired orchestration is pending.

Next run `.local/acceptance-input/Reset-HashCheckDiagnosticVm.ps1 -DiagnosticRunId 5f2fb83f1eec4c0399ba3da4abb46791` from elevated P52, then repeat the interactive diagnostic once on the clean baseline. The controller stays disabled. Require installer exit 0, interactive session/elevation, task result 0, task removal and preserved evidence before advancing to integrated RIDE lifecycle and Explorer acceptance. Logged-out execution remains unsupported by this proposed route. No whole legacy outcome is resolved or retired and no new exclusion is added; HashCheck remains partial and other deferred acceptance is unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged (exact 126-180; rounded 125-180/about 155).

Evidence: [interactive install and replay repair](../archive/evidence/hashcheck-interactive-install-pass-dispatch-replay-fix-2026-10-29.json).

## HashCheck interactive-task comparison preparation, 2026-10-29

The operator recovered the Session 0 diagnostic at 13:36:54 UTC: all 13 exported evidence files were reverified, exact checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b was restored and the clean guest booted, with controller Disabled. Host helper 0.2.0 now offers `-ExecutionMode InteractiveTask`. It identifies exactly one Explorer session owned by the pinned guest admin, registers a uniquely named temporary guest task with Interactive logon and Highest run level, and validates the actual account/session/elevation before executing the byte-identical installer diagnostic. No password is stored and no persistent trigger is created. The task has a 13-minute execution limit and 14-minute completion deadline; the installer retains its 10-minute timeout. Temporary-task removal and any cleanup error are recorded, and evidence is exported with guest-to-host hash comparison. Three scripts parsed in Windows PowerShell 5.1, the launcher rejected the host before guest operations, and payload hash/signature checks passed. No interactive-task installation has run yet.

Next run `.local/acceptance-input/Invoke-HashCheckRemoteDiagnostic.ps1 -ExecutionMode InteractiveTask` from elevated P52 with the guest admin signed in and the controller disabled. Inspect both diagnostic and temporary-task results; task exit 0 alone is not an installer pass. Require installer ExitCode=0, expected identity/session/elevation, no diagnostic error and verified task removal. Preserve evidence before checkpoint recovery. A passing comparison must be followed by integrated RIDE lifecycle validation and explicit signed-in-session requirements; logged-out execution and Explorer behavior remain unaccepted.

No whole legacy outcome is resolved or retired and no new exclusion is added. HashCheck remains partial; deferred acceptance elsewhere is unchanged. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12; exact 126-180, rounded 125-180/about 155, because preparation and baseline recovery do not complete a legacy product outcome.

Evidence: [interactive-task comparison preparation](../archive/evidence/hashcheck-interactive-task-comparison-preparation-2026-10-29.json).

## HashCheck remote Session 0 deployment denial, 2026-10-29 13:29 UTC

Focused diagnostic e4a26c18d81844c7a9cead4c09457b5c reproduced installer exit 2 in an elevated guest-admin process, SessionId=0 and UserInteractive=false. No timeout or collection errors were reported. AppX deployment event 718 records failure to initialize PLM with 0x80070005; event 605 locates the failure in PackagesInUseClosed, followed by deployment errors 401/404. MSIX signature validation and native 64-bit registration succeeded. The same guest admin already had an active console session 1, and its profile was loaded with Status=0. Therefore merely having a signed-in user does not resolve this observed failure. The execution context is the leading explanation; the precise permission mechanism is not established and no ACL or security-policy change is justified by these logs.

All 13 exported diagnostic files were copied with guest-to-host hash comparison and independently rehashed on P52. Preserve the evidence, then run the prepared `.local/acceptance-input/Reset-HashCheckDiagnosticVm.ps1` from elevated P52 to discard the partial guest installation, restore exact checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b and boot for comparison while leaving the controller disabled. The helper parsed in Windows PowerShell 5.1; recovery has not yet been executed. Next test remote-triggered execution through a temporary elevated task bound to the intended interactive guest user. This is a proposed comparison, not a verified fix; a successful installer test must still be followed by full RIDE lifecycle acceptance and explicit session requirements.

No whole legacy outcome is resolved or retired and no new exclusion is added. HashCheck remains partial, with remote workflow, Explorer behavior and broader certification open; other deferred acceptance is unchanged. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12; exact 126-180, rounded 125-180/about 155. A reproduced failure with improved diagnosis does not close the product outcome.

Evidence: [remote deployment result](../archive/evidence/hashcheck-remote-session0-plm-denial-2026-10-29.json).

## HashCheck remote diagnostic preparation, 2026-10-29

Following completed attended acceptance and checkpoint recovery, the operator disabled the idle controller and booted the clean guest. A task-specific host/guest helper pair now prepares one focused remote installation through AutomatedLab and a fresh noninteractive Windows PowerShell process, using the retained publisher installer at the same guest cache path. Both helpers parsed under Windows PowerShell 5.1; the retained 2,157,368-byte payload still matches the pin and has Valid Authenticode. No new installer execution occurred during preparation. The attempt captures identity/session/profile information, publisher output and time-filtered AppX deployment/packaging event XML and JSON, then exports evidence with guest-to-host hash comparison. The installer has a ten-minute process-tree timeout. No GitHub API request, ACL/policy change or automatic checkpoint restore is introduced.

Next run `.local/acceptance-input/Invoke-HashCheckRemoteDiagnostic.ps1` once from elevated P52 Windows PowerShell. Keep the guest without a new manual sign-in for the first comparison; session evidence will identify any existing session. Inspect retained errors even if preflight stops. Keep the VM running and controller disabled until logs are reviewed and exported; recover through the exact configured clean checkpoint afterward. Preparation is not a remote fix or acceptance pass. No legacy outcome is resolved or retired and no new exclusion is introduced; HashCheck remains partial, with deferred feature and other acceptance unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged (exact 126-180; rounded 125-180/about 155).

Evidence: [remote diagnostic preparation](../archive/evidence/hashcheck-remote-context-diagnostic-preparation-2026-10-29.json).

## HashCheck attended RIDE lifecycle pass, 2026-10-29

Run `1f771b9f5d8841f1938497458f339c6b` passed ApplicationsBatch11 from an elevated signed-in Windows 11 guest console, using runner 0.19.2 and the source snapshot whose 1,794 files were verified before execution. Operator-pasted output and summary.json report validation passed, 422 Pester tests passed, zero failed and four skipped, IntegrationPassed=true, and no Error or StateCollectionError. The package lifecycle reports Passed with installed version 2.6.3.0. This advances the earlier publisher-only installation observation to an attended RIDE install/repeat/remove/recovery pass. The warning about recovery explicitly limits restoration to the declared catalog installer when an exact previous package version cannot be recovered; it does not establish arbitrary historical-version recovery.

The operator exported the correlated guest result directory to the host. Independent local inspection confirms all eight application checks, Recovery=true and removal recovery version 2.6.3.0; Pester XML confirms 426 total, zero failures/errors and four skipped. The publisher log confirms Valid MSIX signature, sparse registration/provisioning success and both native registrations exiting 0. Local SHA-256 hashes and sizes for all retained files, including saved machine state, are recorded in the structured evidence; a guest-to-host hash comparison was not performed. Integration completed at 10:30:40 UTC. Evidence is retained. The operator shut down the guest, verified the disabled controller, empty queues, absent recovery block and exact VM/checkpoint identities, then restored checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b. Final operator output confirms VM Off / Operating normally and controller task Ready after re-enabling. This attended run and its checkpoint recovery are complete. The remote sparse-registration 0x80070005 failure, Explorer/intended-user feature behavior and full controller certification remain open. No published support metadata changed.

No whole legacy outcome is newly resolved or retired and no new exclusion is introduced. HashCheck remains partial; other deferred/unavailable acceptance remains unchanged. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12 remain unchanged (exact 126-180; rounded 125-180/about 155), because this attended lifecycle pass does not complete the remote route and user-visible product acceptance.

Evidence: [attended lifecycle result](../archive/evidence/hashcheck-attended-ride-lifecycle-pass-2026-10-29.json).

## HashCheck elevated guest-console installation succeeds, 2026-10-29

The operator ran the same SHA-256-pinned HashCheck 2.6.3 installer in an elevated, signed-in `RIDE-WIN11-TEST\admin` guest console. The explicit hostname, elevation and installer-hash guards passed. Installation exited 0. The publisher log at `C:\RIDE\Diagnostics\HashCheck-20261029-094848\hashcheck-install.log` reports native 64-bit registration exit 0, Valid MSIX signature, successful Add-AppxPackage registration of `IDRIX.HashCheck_2.6.3.0_neutral__hd6jbvhf8esfw`, completed sparse-package staging/provisioning, sparse registration exit 0 and native 32-bit registration exit 0. The two raw guest files are now copied to .local/acceptance-input/hashcheck-console-20261029-094848 on P52 and independently verified with hashes in the structured evidence. The installed-state JSON confirms current-user Appx registration and native uninstall registration, both version 2.6.3.0. The runner currently expects catalog PackageVersion 2.6.3 exactly; resolve that additional mismatch before another automated lifecycle run. The operator has now restored exact checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b, confirmed VM Off / Operating normally, and re-enabled the task to Ready with empty/unblocked queues. Runner 0.19.2 now checks exact HashCheck DisplayVersion 2.6.3.0 while retaining release pin 2.6.3; the selected candidate regression passed 1/1 (131 not selected), and parsing passed. The existing desktop handoff is limited to user settings, so it is not reused for elevated package installation. Next prepare an immutable staged-source copy and run the existing RIDE lifecycle suite in the signed-in elevated guest console; unattended execution remains unaccepted.

Compared with registered run `f3a4ab4a87e34ad085b7cb638f9e76b0`, which failed at sparse-package registration with 0x80070005, this strongly indicates execution-context-dependent behavior. It does not isolate the precise permission/session mechanism: the installer path and signed-in session state also differ. Do not claim a generic ACL defect, relax signature checks or suppress the installer failure. The VM/controller infrastructure and package acquisition worked; the automated package execution route still needs correction and acceptance.

Keep the VM running with the manual install and the controller task disabled while capturing current-user Appx and native uninstall registration and exporting the diagnostic directory. Keep the clean checkpoint unchanged. After evidence collection, recover through that checkpoint and re-enable the controller. Manual installation is partial product evidence only; RIDE-managed repeat installation, uninstall/recovery, intended-user registration and Explorer behavior remain open. No published support metadata changed. No legacy outcome is resolved or retired and no new exclusion is added. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12; exact 126-180, rounded 125-180/about 155, because manual installation alone does not complete the legacy product outcome.

Evidence: [operator-observed console comparison](../archive/evidence/hashcheck-elevated-guest-console-install-success-2026-10-29.json).


## HashCheck Windows 11 sparse-package access denial, 2026-10-29 08:37 UTC

Diagnostic ApplicationsBatch11 run `f3a4ab4a87e34ad085b7cb638f9e76b0` failed from 08:25:14 to 08:37:48 UTC (09:25-09:37 Europe/Copenhagen). Repository validation passed and Pester reported 422 passed, zero failed and four skipped. The new vendor-log route worked: collected `hashcheck-install.log` shows 64-bit regsvr32 exited 0, runtime/assets were extracted, and the MSIX signature was Valid. Failure occurred at Add-AppxPackage with ExternalLocation for `IDRIX.HashCheck_2.6.3.0_neutral__hd6jbvhf8esfw`: HRESULT `0x80070005`, Access is denied. The sparse-registration child exited 1 and the outer installer exited 2. The deployment ActivityId is `33b3659a-677f-0000-ee0f-b6337f67dd01`.

This establishes the failing stage, not the underlying permission or execution-context cause. The installer ran elevated as guest admin through the registered remote workflow; a remote-session limitation is a hypothesis, not a proven diagnosis. Do not change ACLs, disable security controls, remove sparse registration or treat exit 2 as success. Package Recovery=false; controller cleanup, collection and export reported no errors. Queues are empty and no recovery block is present; final VM/task state requires elevated operator confirmation. Appx activity events were not exported before automatic checkpoint recovery and are not expected to remain in the restored guest.

Next use a targeted elevated interactive installation in the disposable guest, preserving the vendor log and activity-specific Windows Appx deployment events before recovery. Verify the host controller is idle, temporarily disable its task while the guest is manually inspected, and leave the updated clean checkpoint unchanged. This comparison avoids rerunning the full focused regression merely to reproduce the same installer error. Restore the pinned checkpoint and re-enable the controller after evidence collection. Do not run the installer on P52. HashCheck installation/removal/recovery, intended-user sparse-package registration and Explorer behavior remain unaccepted; published support metadata is unchanged.

Resolved/retired legacy outcomes: none. New exclusions: none. Partial: vendor diagnostics now identify the failure stage. Deferred: the underlying cause and native product acceptance. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12; exact 126-180, rounded 125-180/about 155. This diagnostic advance does not complete a legacy outcome.

Evidence: [structured run record](../archive/evidence/hashcheck-windows-sparse-package-access-denied-2026-10-29.json). Microsoft's [Appx deployment troubleshooting](https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting) describes activity/event-log diagnosis.


## HashCheck native installation failure and diagnostic preparation, 2026-10-29 08:16 UTC

Registered ApplicationsBatch11 run `bf40deb404b848178494030a77656d9b` failed from 08:03:39 to 08:16:28 UTC (09:03-09:16 Europe/Copenhagen). Repository validation passed; Pester reported 422 passed, zero failed and four skipped. The guest acquired the official HashCheck 2.6.3 installer using DirectHttps; correlated acquisition evidence records SHA-256 `cd890774839177b234a1165fd459ddeb830274ef7d81b289ddb70d43ae5983fa`, matching the pin. The installer ran elevated as the guest admin and returned exit code 2 before successful installation was verified. This is an installer failure, not a DNS/download or unit-test failure. The controller collected application evidence, guest summary and transcript. Package Recovery=false; controller cleanup, collection and export reported no errors. Queues are empty and no recovery block is present; elevated operator output confirms VM Off / Operating normally and task Ready after this request.

The exact installer failure step remains unknown. The publisher's tagged installer source supports `/LOG=` and defaults to guest TEMP/HashCheckSetup.log; that vendor log was not collected in this run. Source was read through the connected GitHub file API (blob `4428ff394b820a00efef8898b43c65d63bb4273b`). The guest acceptance runner 0.19.1 now appends `/LOG=` pointing to `hashcheck-install.log` under the existing collected guest result directory. The catalog's `/S` argument, expected hash, success criteria and pending support status remain unchanged. This adds diagnostics, not a runtime fix; a later install/recovery attempt in one run may overwrite the publisher log. The HashCheck candidate regression passed 1/1 selected test in Windows PowerShell 5.1/Pester 5.7.1 (131 not selected), and the runner parsed successfully. No installer was run on the host.

Next verify VM Off/task Ready, then submit one ApplicationsBatch11 diagnostic retry from the updated Local checkout and inspect hashcheck-install.log before deciding a fix. Guest runner changes are staged with the request; this change does not alter protected controller scripts. Do not infer a sparse-package, remote-session or signature cause from exit 2 alone. Installation, uninstall/recovery, intended-user registration and Explorer behavior remain unaccepted. No legacy outcome is resolved or retired, and no new exclusion is introduced. Settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12, exact 126-180 and rounded 125-180/about 155 remain unchanged because a failed install and diagnostic preparation do not complete a legacy outcome.

Evidence: [structured run record](../archive/evidence/hashcheck-windows-install-exit2-and-diagnostic-preparation-2026-10-29.json). Publisher: [tagged installer source](https://github.com/idrassi/HashCheck/blob/v2.6.3/installer/HashCheck.nsi).


## Remaining settings batch 2 native lifecycle pass, 2026-10-29 07:45 UTC

Registered run `37649311827142d0b459e876824f175d` passed from 07:27:15 to 07:45:36 UTC (08:27-08:45 Europe/Copenhagen). Repository validation and all 398 focused Pester tests passed. Native batch 2 verified 18 operations across 43 named states, with zero failures and zero unavailable state variants. Preview, apply, repeated apply, restore preview and exact captured-state recovery passed. IntegrationPassed=true and final guest summary, transcript and Pester XML were collected. Cleanup, collection and export reported no errors. Queues are empty and no recovery block is present; elevated operator output confirms VM Off / Operating normally and controller task Ready for this request.

The passed operations cover seven adapter bindings, SMB2 server protocol, Controlled Folder Access, NCSI policy, NetBIOS, Remote Desktop firewall and connection settings, registered sound scheme, three Edge settings, and active power scheme. `windows.smb1-server-protocol` was unavailable on this guest and is not accepted by this run. No instruction to install or enable SMB1 follows from this coverage gap. Actual network reachability, security enforcement, application/UI behavior and persistence after restart remain separate from the captured-state lifecycle assertions. Published support metadata is unchanged.

Together, batches 1 and 2 passed 41 operation lifecycles across 107 named states, with six unavailable operations and no lifecycle failures. Each run passed the same selected 398-test regression set; do not count these as 796 distinct tests. The five unavailable Windows/Office task operations from batch 1 remain open. No whole legacy outcome is newly resolved or retired and no new exclusion is introduced. Keep feature/fixture acceptance partial or deferred; all five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). Operation lifecycle counts are not legacy outcome counts. Next verify VM Off/task Ready, then select remaining feature/package acceptance from the existing ledgers. Full controller certification and Windows Server acceptance remain open.

Evidence: [structured run record](../archive/evidence/windows-settings-remaining-batch2-pass-2026-10-29.json).


## Remaining settings batch 1 native lifecycle pass, 2026-10-29 06:34 UTC

Registered run `eb595b6052644422a19c45f8cf02d4ab` passed from 06:09:58 to 06:34:03 UTC (07:09-07:34 Europe/Copenhagen). Repository validation and all 398 focused Pester tests passed. Native batch 1 verified 23 operations across 64 named states, with zero failures or unavailable state variants. The runner checked preview, apply, repeated apply, restore preview and exact captured-state recovery. The guest summary records IntegrationPassed=true. Cleanup, collection and export reported no errors; the final guest transcript and Pester XML were collected. Queues are empty and no recovery block is present; elevated operator output confirms VM Off / Operating normally and controller task Ready for this request.

Five operations were unavailable on this guest: `windows.task-compatibility-appraiser`, `windows.task-program-data-updater`, `application.office-task-click-to-run-monitor`, `application.office-task-telemetry-fallback-2016`, and `application.office-task-telemetry-logon-2016`. They are untested here, not successful lifecycle cases or retired outcomes. Preserve them for matching Windows/Office fixtures. The three BitLocker method policies, Click to Do policy, Storage Sense global policy and two desktop shortcut candidates passed their native lifecycle checks; this does not demonstrate actual encryption, effective feature behavior, or successful launch of shortcut targets. Published support metadata is unchanged.

No whole legacy outcome is newly resolved or retired and no new exclusion is introduced. This is partial native acceptance, with unavailable fixtures and feature/UI/restart checks deferred. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155), because operation lifecycle counts cannot substitute for completed legacy outcomes. After verifying recovery, request SettingsRemainingBatch2 without UnitOnly through the registered controller; checkpoint recovery remains the outer boundary. Broader controller certification and Windows Server acceptance remain open.

Evidence: [structured run record](../archive/evidence/windows-settings-remaining-batch1-pass-2026-10-29.json).


## Updated Windows 11 baseline and registered UnitOnly pass, 2026-10-29 06:04 UTC

Run `0c853f5330cb4cc4bec72645370d1aeb` passed from 04:57:00 to 06:04:35 UTC on 2026-10-29 (05:57-07:04 Europe/Copenhagen). Guest repository validation passed; Pester 5.7.1 reported 3,527 passed, zero failed and 40 skipped of 3,567 tests. The runner explicitly skipped native integration because UnitOnly=true; IntegrationSuite=Full is the selected default, not evidence that integration ran. Cleanup, collection and evidence export reported no errors. The source-files manifest and staged snapshot delimit this evidence; concurrent checkout changes are not automatically accepted.

During an operator-observed idle boot, guest event 1074 identified planned servicing restarts from MoUsoCoreWorker.exe and TrustedInstaller.exe. The operator completed updates, verified build 26300.9711 and no reboot-pending flags, shut down the VM, and created checkpoint `91369e82-5ff2-49ef-87c4-c4518a77ae7b` (`RIDE-clean-test-base-26300.9711-20261029`). The original baseline was retained. A second checkpoint with the same name was renamed by exact ID, resolving the registration ambiguity without deletion. Configuration was backed up, both checkpoint pins updated, and registration evidence verified before this run. This does not prove the cause of the earlier failed run's resets.

The registered Windows 11 controller/guest path is demonstrated working for this UnitOnly request. Post-run queues are empty and no recovery block exists. Elevated operator output after the run confirms VM Off/Operating normally and task Ready, completing the recovery check. Direct tool CIM access remains denied; that tool restriction does not negate the successful registered run. Next, request SettingsRemainingBatch1 without UnitOnly through the registered controller, inspect native lifecycle/exact-restore evidence, then assess the remaining batches; do not infer user-visible feature behavior from registry round trips. Registration evidence remains NotValidated. Full controller certification, native Windows feature/package acceptance and Windows Server acceptance remain separate open gates. No legacy outcome was resolved or retired, no new exclusion was added, and existing deferred/partial outcomes remain. Estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12: exact 126-180, rounded 125-180/about 155.

Evidence: [structured run record](../archive/evidence/windows-unitonly-updated-baseline-pass-2026-10-29.json).

## Existing RIDEWin11Test request terminal failure, 2026-10-29 02:27 UTC

The registered request `95bc76d3055f4f17964087ed15422295` moved to `queue/finished` with result `Failed`. The controller error says `New-LabPSSession` could not open a session because the RIDE-Win11-Test port remained closed after 20 retries; evidence collection failed after one retry for the same reason. Guest command dispatch was logged, but no guest summary or Pester XML was collected; test execution/completion is unknown. The reconnect error occurred during result export and does not establish that tests never started. The result's empty `CleanupError` and absent `runtime/blocked.json` do not establish current VM/checkpoint state. A fresh `Get-VM` failed at host CIM. `Test-WSMan` returned identification without an error, but `Invoke-Command` reported guest remoting unsupported and TCP/5985 failed; no usable guest command path was established. Do not queue another request until VM/checkpoint state and session access can be verified. No request was retried, cancelled or changed in this audit; no Defender or Windows setting was changed and no elevation was requested. See [structured terminal-request evidence](../archive/evidence/ride-win11-existing-request-terminal-guest-port-closed-2026-10-29-0227.json).

## Existing request and current host CIM recheck, 2026-10-29 02:08 UTC

The `RIDE-Win11-Test` and `RIDE-S25-Test` queue recheck found request `95bc76d3055f4f17964087ed15422295` in `queue/running`, absent from pending/finished, and without a correlated result artifact. `Get-VM` again failed before returning state with `Access to a CIM resource was not available to the client.` The controller log timestamp is recorded as local file time only and does not prove worker liveness. The request was not cancelled or changed; no duplicate was submitted, no VM/checkpoint state was retrieved, and no guest request, Windows/Defender change or elevation occurred. Keep its outcome unresolved and defer additional VM acceptance until host CIM access is available. See [structured evidence](../archive/evidence/ride-vm-request-cim-recheck-2026-10-29-0208.json).

## Current host CIM recheck and queued request, 2026-10-29 01:55 UTC

Fresh non-elevated `Get-VM` for `RIDE-Win11-Test` and `RIDE-S25-Test` failed before returning VM state with `Access to a CIM resource was not available to the client.` The existing request `95bc76d3055f4f17964087ed15422295` remains in the Win11 running queue without a correlated result artifact. No duplicate was submitted, and the request was not cancelled or modified. No VM state or checkpoint was retrieved, no guest request was dispatched, and no Windows, Defender, or elevation state changed. Keep native acceptance deferred until host CIM access is available; continue independent migration work. See [structured evidence](../archive/evidence/ride-vm-cim-recheck-and-running-request-2026-10-29-0155.json).
## Existing RIDEWin11Test request has no terminal evidence, 2026-10-29 01:44 UTC

Read-only queue inspection found request `95bc76d3055f4f17964087ed15422295` still in `queue/running`: local source, `UnitOnly=true`, `IntegrationSuite=Full`, submitted 01:13 UTC with a 120-minute timeout. No correlated result exists; the controller log last advanced at 01:19 UTC after starting an AutomatedLab guest command. CIM process/task queries and Task Scheduler COM were denied, and PowerShell remoting into the guest is unavailable, so current worker state is unresolved. Do not submit a duplicate or mark this request stopped. It may include NirSoft Pester tests; PasswordScan stays excluded from new runs. No request was cancelled or altered, and no VM/checkpoint/Windows/Defender/elevation state changed during this read-only check. See [structured status evidence](../archive/evidence/ride-win11-existing-unitonly-request-status-2026-10-29-0144.json).
## Current source validation and VM CIM recheck, 2026-10-29 01:34 UTC

`tools/validate.ps1` passed for 451 operations, 8 groups, 5 profiles and 305 PowerShell files; generated catalog documentation is current. A focused Pester 5 suite was not run because only Pester 3.4.0 is available in this environment. Fresh read-only `Get-VM` for `RIDE-Win11-Test` and `RIDE-S25-Test` failed before state retrieval with `Access to a CIM resource was not available to the client.` No checkpoint/task/queue was queried and no guest request was dispatched. Keep native acceptance and full guest regression deferred until host CIM access is restored. No VM, Windows, Defender or elevation state changed. No legacy outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/repository-static-validation-and-cim-block-2026-10-29-0134.json).

## Current VM host CIM recheck, 2026-10-29 01:28 UTC

Fresh read-only `Get-VM` for `RIDE-Win11-Test` and `RIDE-S25-Test` again failed before returning VM state with `Access to a CIM resource was not available to the client.` No checkpoint, task or queue was queried and no guest request was dispatched. Keep full UnitOnly guest regression and native Windows 11/Server 2025 acceptance deferred until host CIM access is restored. No VM, Windows, Defender or elevation state changed. See [structured evidence](../archive/evidence/ride-win11-s25-current-cim-recheck-2026-10-29-0128.json).

## Current VM host CIM recheck, 2026-10-29 01:26 UTC

Fresh read-only `Get-VM` for `RIDE-Win11-Test` and `RIDE-S25-Test` again failed before returning VM state with `Access to a CIM resource was not available to the client.` No checkpoint, task or queue was queried and no guest request was dispatched. Keep full UnitOnly guest regression and native Windows 11/Server 2025 acceptance deferred until host CIM access is restored. No VM, Windows, Defender or elevation state changed. See [structured evidence](../archive/evidence/ride-win11-s25-current-cim-recheck-2026-10-29-0126.json).

## Current VM host CIM recheck, 2026-10-29 01:26 UTC

Fresh read-only `Get-VM` for `RIDE-Win11-Test` and `RIDE-S25-Test` again failed before returning VM state with `Access to a CIM resource was not available to the client.` No checkpoint, task or queue was queried and no guest request was dispatched. Keep full UnitOnly guest regression and native Windows 11/Server 2025 acceptance deferred until host CIM access is restored. No VM, Windows, Defender or elevation state changed. See [structured evidence](../archive/evidence/ride-win11-s25-current-cim-recheck-2026-10-29-0126.json).

## Current VM host CIM recheck, 2026-10-29 01:21 UTC

Fresh read-only `Get-VM` for `RIDE-Win11-Test` and `RIDE-S25-Test` again failed before returning VM state with `Access to a CIM resource was not available to the client.` No checkpoint, task or queue was queried and no guest request was dispatched. Keep full UnitOnly guest regression and native Windows 11/Server 2025 acceptance deferred until host CIM access is restored. No VM, Windows, Defender or elevation state changed. See [structured evidence](../archive/evidence/ride-win11-s25-current-cim-recheck-2026-10-29-0121.json).

## Current VM host CIM recheck, 2026-10-29 01:18 UTC

Fresh read-only `Get-VM` for `RIDE-Win11-Test` and `RIDE-S25-Test` again failed before returning VM state with `Access to a CIM resource was not available to the client.` No checkpoint, task or queue was queried and no guest request was dispatched. Keep full UnitOnly guest regression and native Windows 11/Server 2025 acceptance deferred until host CIM access is restored. No VM, Windows, Defender or elevation state changed. See [structured evidence](../archive/evidence/ride-win11-s25-current-cim-recheck-2026-10-29-0118.json).

## Current VM host CIM recheck, 2026-10-29 01:14 UTC

Fresh read-only `Get-VM` for `RIDE-Win11-Test` and `RIDE-S25-Test` again failed before returning VM state with `Access to a CIM resource was not available to the client.` No checkpoint, task or queue was queried and no guest request was dispatched. Keep full UnitOnly guest regression and native Windows 11/Server 2025 acceptance deferred until host CIM access is restored. No VM, Windows, Defender or elevation state changed. See [structured evidence](../archive/evidence/ride-win11-s25-current-cim-recheck-2026-10-29-0114.json).

## Full guest regression count-assertion follow-up, 2026-10-29

UnitOnly request `8346c1d7660a4fb78e773ef3b57407b7` completed at
2026-10-28 21:56:44 UTC with repository validation passed, 3,502 Pester passes,
two failures and 40 skips. Cleanup, collection and export errors were null;
the inspected queues were empty with no recovery block. This supersedes the
earlier observation that this request lacked a terminal result. The two
failures were fixed-count expectations in HashValueContextMenu.Tests.ps1
(19 versus 21) and RemainingSettings.Tests.ps1 (38 versus 40).

The checkout already contained corrections preserving minimum batch sizes,
required context-menu membership, unique IDs and registry collision checks.
The run's source manifest confirms both test files differ from that corrected
checkout. Both selected assertions passed in Windows PowerShell 5.1 and
PowerShell 7.6.5, with 90 unrelated cases not selected per edition. Current
controller unit tests also passed 151/151 in Windows PowerShell 5.1. No test
or operational source was changed in this follow-up.

Three installed controller files no longer match the checkout, which now adds
ApplicationsBatch12. Refresh the protected registration and verify installed
hashes before the next serialized full UnitOnly run. Source snapshots and run
IDs remain the acceptance boundary; local passes do not turn this failed guest
run into a pass. Keep NotValidated and all feature/native acceptance gates open.
See [run and focused verification evidence](../archive/evidence/windows-unitonly-8346-count-assertion-recheck-2026-10-29.json).
No legacy outcome closed; all five estimate ranges remain unchanged.

## MiTeC focused suite queue write and host CIM block, 2026-10-29 00:39 UTC

The saved RIDEWin11Test configuration advertises the required focused portable MiTeC capabilities and matches the current account, but the authorized suite submission failed before request creation because writing the temporary file under `queue/pending` was denied. No pending/running request or temporary file remained; no scheduled task or guest run started. Direct VM and task-state queries fail at host CIM. Keep the run deferred; do not change task ACLs or request fresh elevation in this batch. See [structured evidence](../archive/evidence/mitec-system-telephony-preregistered-queue-write-block-2026-10-29-0039.json).

## Host CIM access recheck, 2026-10-29 00:24 UTC

A fresh non-elevated Get-VM query for RIDE-Win11-Test and RIDE-S25-Test failed before state retrieval with Access to a CIM resource was not available to the client. No checkpoint/task query or guest request occurred; no state change or elevation. Keep native acceptance deferred. See [structured evidence](../archive/evidence/ride-win11-s25-mitec-acceptance-cim-block-2026-10-29-0024.json).
## Host CIM access recheck, 2026-10-29 00:18 UTC

A fresh non-elevated Get-VM query for RIDE-Win11-Test and RIDE-S25-Test failed before state retrieval with Access to a CIM resource was not available to the client. No checkpoint/task query or guest request occurred; no state change or elevation. Keep native acceptance deferred. See [structured evidence](../archive/evidence/ride-win11-s25-paradox-acceptance-cim-block-2026-10-29-0018.json).

## Host CIM access recheck, 2026-10-29 00:07 UTC

A fresh non-elevated Get-VM query for RIDE-Win11-Test and RIDE-S25-Test failed before state retrieval with Access to a CIM resource was not available to the client. This establishes no current VM/checkpoint state. Scheduled-task, queue and guest state were not queried, and no request or elevation occurred. Keep target acceptance deferred and continue independent local work. See [structured evidence](../archive/evidence/ride-win11-s25-test-cim-access-recheck-2026-10-29-0007.json).

## Existing UnitOnly request lacks terminal status, 2026-10-28 21:48 UTC

RunId `8346c1d7660a4fb78e773ef3b57407b7` remains in `queue/running` and absent
from `queue/finished`. It was submitted from the local checkout at 2026-10-28
20:38:14 UTC with a 120-minute timeout and `UnitOnly` enabled. The controller
log's last recorded state shows a successful Hyper-V lab import, one completed
PowerShell Direct activity and a second activity waiting for completion; the
controller error log was empty. No terminal result or later controller-log
update is visible. `Get-ScheduledTask`, `Get-VM`, local process CIM and the
Task Scheduler event log all denied read access. Thus the queue file does not
prove a live worker and the current VM/task state is unverified. Do not queue a
new request or declare the existing run stopped until a terminal result or
authoritative task/VM state can be read. The latest source snapshot's
`Invoke-RideRemainingSettings.ps1` hash is
`4F5958FB04BE7CC925166844C96F57064CA7CA5B2AE9AF0F59F6956568F7E9B0`, while the
current runner hash is
`0AE511B46FEB4D1ADDE3004149F66B87A2C82673B6ADFA59078A6C148143C119`; therefore
this request does not include the newly prepared Click to Do candidate. No
request, VM, checkpoint or guest state was changed by this inspection.

See [runner-preparation evidence](../archive/evidence/click-to-do-remaining-settings-batch1-runner-preparation-2026-10-28-2140.json).

## Full guest regression and post-restart checks, 2026-10-28

UnitOnly request `b54cfc79499d4e56a0d7bafda51b4179` saved a final Failed result
at 19:05:34 UTC. Repository validation passed; Pester recorded 3,477 passed,
17 failed and 34 skipped. Cleanup, collection and evidence-export errors were
null. After the operator reported a host restart, the saved queues were empty
and no recovery block was present. Elevated operator checks confirmed VMMS
Running, RIDE-Win11-Test Off and operating normally, and the task Ready. WinRM
was Stopped. No manual checkpoint restore or queue deletion was needed or done.

The earlier eight failures were absent from this run's failure list. The new
failures were twelve missing developer-cache ZIP cases, two stale portable
runner version outputs, two incomplete WinPmem test expectations and one stale
setting count. Unit tests now separate NTCore metadata and synthetic file
lifecycle from six explicitly enabled retained-publisher checks. Missing
publisher archives remain unverified; skips are not product acceptance.
Runner version output now matches its documented version, the mock produces
WinPmem evidence, and the metadata test checks every applicable setting without
freezing the catalog's size. No publisher payload was acquired or executed.
Focused checks passed 308 tests in Windows PowerShell 5.1 and 306 in PowerShell
7.6.5, with zero failures. Six retained-archive cases were skipped in each;
PowerShell 7 also skipped two Desktop-only host preflight cases. The host
registry integration test was excluded in both editions.

See [run and repair evidence](../archive/evidence/windows-unitonly-b54c-postrestart-repair-2026-10-28.json)
for focused regression results. Restart WinRM and refresh the protected
controller files before the next serialized UnitOnly request. Retain source
hashes and guest/cleanup evidence. Keep registration NotValidated; feature
acceptance and broader certification remain open. No legacy outcome closed,
and all five migration estimate ranges remain unchanged.

## Windows 11 acceptance recovery, 2026-10-28

Operator-provided elevated checks found VMMS running, RIDE-Win11-Test Off,
the registered task Ready, empty pending/running queues and no recovery block.
WinRM was stopped; the operator started it and confirmed localhost WSMan responds.
This establishes current host readiness, not controller certification. WinRM's
startup configuration was not changed, so recheck it before later requests.

Guest UnitOnly request `8f8965788fb145a3854def3d37ae0480` completed repository
validation and Pester with 3,410 passed, eight failed and 15 skipped. Collection
completed; the request was not a timeout. The eight failures were investigated:
JoeWare completion now resolves the PowerShell location and quoted paths; F1 Help
asserts the selected operation rather than whichever unsupported profile entry
is first; the copied synthetic credential receives the intended file ACL before
request-binding rejection is asserted; and NTCore publisher metadata assertions
are separate from synthetic lifecycle hashes. Neutral synthetic NTCore member
names avoid staging product-named fixture executables. Existing NirSoft tests
already use representative synthetic members rather than the entire inventory.
No publisher payload was renamed, extracted or executed during these checks.

Focused Windows PowerShell 5.1 verification passed across the five affected
suites after correcting a null PortableMembers case in the first repair attempt.
PowerShell 7.6.5 then passed all five suites together: 92 passed, zero failed,
two skipped. The skipped retained NirSoft archive and ScreenWriter MSI checks
remain separate evidence requirements. Defender settings and real credentials
were unchanged. See [repair evidence](../archive/evidence/windows-acceptance-unit-failure-repair-2026-10-28.json).

Next: refresh protected controller files from the reviewed checkout, confirm
their hashes and pinned configuration, then submit one full UnitOnly request.
Retain its source manifest, Pester/summary/progress evidence and recovery result.
A passing UnitOnly request only closes that regression gate. Feature lifecycles,
native effects and applicable controller certification/cutover gates below remain
open. Keep `NotValidated`; do not manually change it to bypass acceptance.
No legacy outcome closed; all five migration estimate ranges remain unchanged.

## Windows 11 controller readiness inspection, 2026-10-26 10:30 UTC

Read-only elevated inspection found the registered `RIDE-Win11-Test` VM Off
with the configured `RIDE-clean-test-base` checkpoint ID still matching. The
`RIDEWin11Test` task is Ready, its pending/running queues are empty, and no
recovery block exists. This host has no `RIDE-Srv2025Test` VM. Registration
evidence still reports `NotValidated`; current protected
`RIDE.TestAutomation.psm1`, `RIDE.PortableAcceptance.psm1` and
`Invoke-RideVmTest.ps1` differ from this checkout, and
`Invoke-RideGuestTests.ps1` is missing from the protected bin. The fixed
portable acceptance allowlist does not include RawCopy. No request or VM
operation occurred. Reconcile and validate the Windows 11 controller before
dispatching current-source package, setting or component acceptance; keep
Server 2025 acceptance deferred until a matching registered VM is available.
See the [structured readiness evidence](../archive/evidence/ride-win11-controller-readiness-recheck-2026-10-26-1030.json).

## Registered task refresh, 2026-10-25

The user refreshed the elevated Windows 11 and Server 2025 task registrations.
Both commands imported their configured Hyper-V lab and registered the task for
the configured account. Each output still says the configuration is not yet
validated and directs the operator to the pilot acceptance checklist. This
refresh updates the installed task files; it does not change either
configuration's **NotValidated** status, complete controller certification or
authorize lab cutover.

The refreshed Windows 11 controller completed two focused settings requests.
SettingsRemainingBatch1 `b5b8e02f408642f78ba8cb53f68281b0` and
SettingsRemainingBatch2 `70f4c7c4d9ff40028155aa88521e88a9` each passed selected
Pester **343/343**. The batches passed 14 and 18 setting lifecycles across 32
and 43 named states; five and one operations were unavailable in the guest.
Cleanup and evidence export completed without errors, and no blocked marker is
present. These operations declare Windows 11 as their only target; the
Server 2025 controller is refreshed but is not applicable to these two batches.
The runs do not validate the controller configurations for cutover.

Controller module **0.4.6**, registration **0.1.3** and failure collector
**0.4.1** have completed scoped source, installation and runtime acceptance on
both pinned configurations. Broader stable-controller certification and
default-branch cutover remain open; registration stays **NotValidated**.
See the [dated candidate evidence](../archive/evidence/controller-046-scoped-acceptance-2026-10-13.md)
for source/configuration boundaries, run IDs, fault results and delta review.
The earlier [anonymous bridge pair gate](../archive/evidence/github-quota-bridge-pair-gate-complete-2026-10-13.md)
remains accepted on its recorded baseline; its heartbeat is disabled.

Full hosted regression also passed for published candidate **f5e3218**, through
an identical-tree review-branch trigger. See the
[hosted validation evidence](../archive/evidence/hosted-final-source-validation-2026-10-13.md).
Master publication remains held until **v3 reaches release-candidate state**.

## Acceptance matrix

| Requirement | Current evidence | Remaining acceptance |
| --- | --- | --- |
| Controller/profile/release mocked regression | Focused 0.4.6 checks passed; full hosted candidate f5e3218: Windows PowerShell 5.1 1,455 passed, PowerShell 7 1,453 passed/two expected host-preflight skips; catalog/syntax checks passed both | Complete for the recorded published candidate; subsequent implementation and eventual RC source require validation |
| Host preflight and result contract | No host registry inspection; elevation and recovery guards retained; fresh registration and normal/timeout/refusal results omit UAC fields | Complete for candidate |
| Queue claim and serialization | Native ordered claims and timestamp regression pass; historical overlapping Local/CI runtime evidence retained with unchanged locking/task logic | Candidate delta reviewed; historical runs retain their actual versions |
| Installed hashes, account and VM/checkpoint pins | Both controllers refreshed from published 3107711; all five hashes match; pins/configurations unchanged | Complete; recheck before future use |
| Normal registered execution | Server 20186578684e4716a1f633a99393fe9d and Windows 11 3c0a98c38c5b42b5991f9a5f8f150e0d: validation, 1,280 tests, 217 hashes and recovery each | Complete for candidate over frozen guest CI source a156475; UnitOnly does not accept newer guest source or add Full bridge passes |
| Timeout collection and recovery | Server e9dbd5a238914edea6915bb6de7eeea7 and Windows 11 c61528bb07394d02aec9430ac17dfa9c: expected TimedOut, process trees terminated, collection under 90 seconds, explicit locked-transcript omissions, clean recovery | Complete for candidate; partial evidence is not Pester completion |
| Missing checkpoint and expired request | Fresh isolated probes on both configurations failed for intended reasons before VM use; full snapshot sets/configuration hashes unchanged | Complete for candidate |
| Ordinary-shell, locked-session, watcher, cleanup block and interrupted-worker recovery | Historical evidence retained; function delta confirms worker locks, checkpoint/reset, termination and collector launcher unchanged | Reuse rationale recorded; no historical case relabeled as a fresh 0.4.6 run |
| GitHub delivery and artifact correlation | Historical trusted migration-push pilots/uploads retained; workflow unchanged | New manual dispatch and trusted master-push acceptance remain deferred behind default-branch publication |
| Per-controller certification records | Both protected acceptance.md records saved 2026-10-13 at 14:16:41 UTC, verified against reviewed hashes; configurations unchanged | Candidate record step complete; keep registration NotValidated until broader applicable gates close |

The default master branch currently lacks the VM workflow. GitHub documents
the [default-branch requirement for manual dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).
No master or activation-variable change was made. The user requires v3 release-
candidate readiness before master publication. Before broader certification,
complete the deferred delivery/cutover gates and reconcile applicable hosted
validation with the final published source; record any unavailable scenario
explicitly. Optional GitHub authentication and newer settings acceptance remain
separate work.

Other migration activity owns its VM tests. Leave busy resources untouched and
recheck readiness before use. ArtCraft Launcher remains closed and must not be
restarted, including when testing or its automation finishes.

## Resume near v3 release candidate

The user will return to this work near the v3 RC milestone. No further run is
scheduled. The completed bridge heartbeat is PAUSED; its historical prompt and
saved retry deadlines are not instructions to restart testing. Resume from this
ledger and the evidence links, rather than from an archived chat or ignored
`.local` state. Do not commit to master before v3 reaches release-candidate state;
RC readiness does not itself enable the VM activation flag or authorize a merge.

### Accepted baselines

| Scope | Published baseline | Evidence and limit |
| --- | --- | --- |
| Anonymous quota/cache/backoff bridge | Guest CI a156475; installed controller 55e97c0/module 0.4.3; collector 0.4.1 | Two consecutive complete Full passes per target, Windows 11 and Server 2025; [pair evidence](../archive/evidence/github-quota-bridge-pair-gate-complete-2026-10-13.md) |
| New host controller | Controller source 3107711/module 0.4.6; registration 0.1.3; collector 0.4.1; guest CI still a156475 | Fresh normal UnitOnly, expected timeout and refusal cases on both configurations; protected records saved; [scoped evidence](../archive/evidence/controller-046-scoped-acceptance-2026-10-13.md) |
| Full hosted regression | Candidate f5e3218; content-identical trigger cc5481f | Both PowerShell editions passed in [run 38413683226](https://github.com/tjuuljensen/ride-windows/actions/runs/38413683226); [source/tree and log evidence](../archive/evidence/hosted-final-source-validation-2026-10-13.md) |

These are different source boundaries. Newer guest source, unfinished migration
fixtures, native/GUI setting effects and future RC revisions were not accepted
by these results. Preserve historical passes with their actual revisions; do not
relabel UnitOnly or hosted regression as new Full integration evidence. The
installed configurations remain NotValidated for broader certification.

### Remaining work and sequence

1. Select the reviewed RC source and compare its engine, controller, workflow
   and tests with the accepted baselines. Run full hosted validation on that
   published revision in both PowerShell editions. Repeat live scenarios where
   changed behavior invalidates earlier evidence; explain any historical reuse.
2. Recheck competing migration activity, both VM/task states, queues, worker
   locks, recovery blocks, five installed controller hashes and pinned VM/
   checkpoint/account/ISO/repository configuration. Leave busy resources alone.
   Preserve unrelated work and repository switches. The previously frozen CI
   checkout must not be reset or silently advanced; coordinate an intentional
   clean published-source update when future CI testing requires it.
3. When renewed Full bridge acceptance is needed, check publisher availability
   once after any current backoff deadline and submit serialized registered-task
   requests with Source CI, IntegrationSuite Full, TimeoutMinutes 90 and correlated
   receipts. The pair gate is two consecutive complete Full passes per target on
   a coherent published source/controller baseline. Failed or quota-deferred
   acceptance clears the affected target's current sequence. Retain diagnostics,
   digest/cache provenance, cleanup and final idle evidence. Schedule retries
   only as authorized; the completed heartbeat stays paused.
4. After RC readiness and an agreed publication/activation decision, publish the
   VM workflow to the default branch. Complete a real workflow_dispatch and then
   a trusted master push, verifying actual source hashes, correlated guest results,
   uploaded evidence and recovery. A manual re-run of an old job is not dispatch
   acceptance. The workflow selects one configuration at a time; serialize the
   coverage required for each configuration being certified.
5. Reconcile the [controller runbook's applicable checks](../../tests/integration/automatedlab-tasks.md),
   record unavailable scenarios explicitly and update acceptance.md beside each
   protected evidence.json before changing broader certification status. The
   runbook also calls for reproduction on another host using pinned dependencies,
   matching ISO/settings and regenerated host/VM IDs; no such portability evidence
   is claimed by this chat's single-host results.

[Optional PAT-based GitHub authentication](../MIGRATION-PLAN.md#optional-github-authentication-v3-scope)
remains approved high-priority v3 work with implementation and acceptance pending.
Anonymous behavior stays supported; explicit protected credential references,
account/cache separation and guest credential boundaries require their own tests.
No credential was configured here. Reusable release-module extraction remains
[deferred downstream work](../../TODO.md#optional-reusable-github-release-discovery-module).
Unrelated settings acceptance belongs to its own migration ledger and holds.

### Knowledge and constraints to retain

- Release metadata is process/module-local for five minutes, bounded to 64
  endpoints and two MiB per response. It does not persist across processes or
  restored checkpoints. Payload caching is separate. Follow the
  [release-discovery contract](../github-release-discovery.md), including no
  expired fallback, silent authentication or token forwarding.
- Host preflight cannot reserve shared-IP quota for a guest. At exhaustion, use
  the later of primary reset plus one second and Retry-After; missing usable
  timing uses the documented conservative one-minute fallback. Do not poll or
  start a knowingly blocked Full test. Saved quota/idle observations are dated,
  not current availability.
- PowerShell 7 can deserialize queue timestamps as DateTime. Controller 0.4.6
  restores UTC round-trip strings before validation; retain the Danish-culture
  regression. It also intentionally removes host-UAC inspection/evidence while
  retaining elevation and recovery guards. Do not reintroduce old UAC reads or
  policy repair from historical automation instructions.
- Collector 0.4.1 has a 90-second bound. Successful partial collection with an
  explicit locked-transcript omission is fault-path evidence, not proof that
  guest Pester or Full integration completed.
- ArtCraft Launcher must not be restarted, including after testing or archiving.
  Only a later explicit user request changes this constraint. Its observed TCP
  connections did not establish API request counts or prove the source of all
  quota consumption; that attribution remains unresolved.
- Detailed raw diagnostics remain in ignored `.local` folders and protected
  controller result roots. Committed dated reports retain run IDs, revisions,
  hashes and outcomes. Preserve raw evidence when moving or rebuilding the host;
  another clone will not contain those local files or credential/configuration
  stores. Runtime pins and availability must be rediscovered on the actual host.
## Settings batch request blocked by pending-queue access, 2026-10-28 22:08 UTC

The UnitOnly RunId `8346c1d7660a4fb78e773ef3b57407b7` is terminal Failed in `queue/finished`; its result reports 3,502/3,544 guest unit tests passing and two stale operation-count assertions failing. It used the Windows 11 build 26300 VM but did not run the SettingsRemainingBatch1 integration suite. The updated `Invoke-RideRemainingSettings.ps1` was locally validated; the current settings Pester suite passes 81/81 in both PowerShell editions. Submitting the focused batch through `Invoke-RideVmTestTask.ps1` failed before a pending request file was created: Windows returned Access denied for the temporary file under `queue/pending`. The visible directory ACL lists Modify for the signed-in account, so the effective access cause remains unknown. A fresh `Get-VM` query still fails at host CIM. No checkpoint was reset for the attempted focused request; no setting was applied. Do not bypass the registered queue. Retry the authorized batch after queue access is repaired. See [structured run and blocker evidence](../archive/evidence/remaining-settings-current-source-cross-shell-and-vm-queue-access-block-2026-10-28-2208.json).
