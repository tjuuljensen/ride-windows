# Windows edition support decisions, 2026-11-04

## Decisions

- Treat Windows release/build and Windows edition as separate support dimensions.
  A `Windows 11` target declaration does not imply that every edition supports
  every operation.
- Reuse shared handler tests across editions. Add focused native acceptance only
  where the backend or Windows behavior is edition-specific; keep Server, Home
  and ARM64 acceptance independent.
- The default wallpaper, machine default lock-screen image, and current-user
  lock-screen image remain separate features. Pro evidence for one does not
  establish the others.
- The machine default lock-screen handler supports the `LockScreenImage` policy
  route on Enterprise/Education editions and now exposes a Pro CSP candidate.
  The first v3 Pro run wrote the CSP tuple to a RIDE-owned `.png`, but did not
  reproduce v2 `SetLockScreen`, which uses an `img0.jpg` path and resets
  ownership/ACLs recursively under `C:\ProgramData\Microsoft\Windows\SystemData`.
  That Pro 26300 run failed visual acceptance and exact native restore passed.
  The operator reports that full v2 works on the same Pro VM, so the run does not
  establish platform-level Pro incompatibility.
- Do not make v2's recursive `SystemData` ACL reset an unbounded default in v3.
  Design a bounded, exact-recovery equivalent of the cache-refresh behavior,
  then repeat Pro visual/lifecycle acceptance before enabling the edition.
- For RSAT, OpenSSH and Store app operations, inventory the exact target before
  mutation. Treat an absent capability or app as unavailable on that image, not
  as successful installation. A Pro acceptance result does not establish Server,
  Home, ARM64 or another Windows build.

## Component scope and remaining acceptance

The catalog component areas comprise 22 RSAT capabilities, OpenSSH Client and
Server capabilities, 23 user-scoped Store app registrations, and three image
settings: machine wallpaper, machine default lock screen, and current-user lock
screen. The RSAT group composes its 22 catalog identities. Read-only
component inventory can also observe optional Windows features and Server
roles/features; that observation does not provide a catalog install/remove
operation for every observed item.

- **Default wallpaper:** keep its current Enterprise/Education target gate.
  Microsoft documents the first-logon theme policy on Pro, but that path differs
  from setting a current user's wallpaper. Test and decide it independently on
  Pro.
- **Default lock screen:** the current v3 Pro CSP candidate uses the v2
  `Windows\Web\Screen\img0.jpg` path. It captures existing file bytes and
  metadata for conflict-checked restore, or records prior absence and removes
  only the exact created file on restore. It omits the broad `SystemData` owner/
  ACL reset because no bounded exact-recovery method is available. Pro visual
  acceptance is still pending to confirm this scoped replacement is sufficient.
  EnterpriseEval 26300.9711 has accepted sign-in image behavior.
- **User lock screen:** the user-scoped operation is implemented against the
  Windows personalization API. Native user-session acceptance remains pending.
  The API exposes the current image URI but not Picture/Slideshow/Spotlight
  mode; use only in Picture mode, and treat mode recovery as outside this image
  operation.
  Other Enterprise/Education builds need candidate acceptance.
- **RSAT:** use Pro/Enterprise x64 as candidate client editions. Inventory all
  catalog identities on the Pro image and use the prepared group lifecycle route
  when servicing availability permits. Do not claim Server roles from client
  RSAT testing.
- **OpenSSH:** test Client capability lifecycle separately from Server
  capability, service activation and firewall exposure. Keep Windows Server
  acceptance separate.
- **Store apps:** inventory per intended user. Run lifecycle acceptance for
  available apps; keep absent, protected, non-removable or source-unavailable
  apps as explicit per-app outcomes. Apply the approved fast-track criterion:
  install/registration succeeds, the app launches without error, and uninstall
  succeeds; deeper product behavior is deferred to v3.1.

## Evidence and recovery

The Pro lock-screen run used the retained AutomatedLab guest `RIDE-W11P-Test`
in lab `RIDEWin11ProTest`, Windows 11 Pro build 26300. Apply returned
`AwaitingVisualVerification`; the user observed the original blue sign-in image.
Restore returned `LifecyclePassedVisualPending`, and a screenshot confirmed the
original image was back. Collect returned `Collected` with a verified export of
13 files. Reset returned `ResetAndOff`, `Stage=Released`,
`RecoveryRequired=False`, and no reported error. The guest was restored to its
pinned checkpoint.

The first v3 Pro attempt differed from the tested v2 method: it wrote the CSP
tuple to a RIDE-owned `.png`, while v2 names the image `img0.jpg`, stores it at
the Windows inbox lock-screen path, then recursively changes protected
`SystemData` ownership and ACLs. The current source candidate replaces the inbox
`img0.jpg` after capturing a bounded private backup, or creates it when absent,
then applies the Pro CSP
tuple; it omits the recursive ACL reset. The exact contribution of that reset
to visible behavior remains unisolated. Microsoft's
[background configuration guide](https://learn.microsoft.com/en-us/windows/configuration/background/)
lists Pro for CSP-based lock-screen configuration; operator native evidence also
confirms the v2 workflow works on this Pro VM. The recursive ACL change still
needs a recoverable design before adding it to v3.

For client RSAT, Microsoft's [installation guidance](https://learn.microsoft.com/en-us/windows-server/administration/install-remote-server-administration-tools)
lists Windows 11 Pro and Enterprise editions. Feature availability and servicing
source remain image-specific; Microsoft documents DISM capability inventory and
servicing in [Features on Demand](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11).

## Pro-first client acceptance decision, 2026-11-04

- Use Windows 11 Pro as the default native acceptance target for ordinary
  Windows client settings and packages. Keep Enterprise tests for Enterprise-
  specific policies, capabilities or workflows. A Pro pass does not establish
  Windows Server, Home, ARM64 or another build.
- Do not add `Windows 11 Pro candidate` indiscriminately to migrated operations.
  A candidate declaration is permission to perform a bounded test, not evidence
  of support. Existing Enterprise evidence does not automatically approve Pro.
- Treat target applicability as the combination of Windows release/build,
  architecture, edition and any required device mode. The current catalog has
  123 package operations: 71 declare the broad `Windows 11` target and 52 remain
  candidate-only. Audit the 71 for edition-specific behavior; do not interpret
  the OS-family label as proof of every edition. Record per-edition support and
  conditions in the authoritative component evidence, and add validated
  catalog/runtime metadata where current fields cannot express the boundary.
- For ordinary user-mode packages, retain the approved fast-track gate: exact
  package/version lifecycle, repeat, bounded startup without observed errors,
  uninstall/recovery and Defender observations. Test each package on Pro as the
  common client route; do not require a second Enterprise run unless its
  installer, prerequisite, policy or runtime is edition-dependent. Record
  deeper product workflows for v3.1 as already decided.
- Pro is eligible for focused approval of settings backed by user-scope APIs or
  Microsoft-documented Pro policies, but the RIDE handler's visible effect and
  recovery still need native evidence before support is promoted. For example,
  Microsoft lists Pro for the first-logon theme policy; verify its theme side
  effects and first-user behavior on Pro. The machine default lock-screen CSP
  remains conditional on Shared PC or Boot to Cloud and is not approved for
  ordinary Pro use by this decision.
- Keep RSAT eligible for Pro/Enterprise x64 acceptance, inventory the exact
  capabilities before install, and report absent capabilities as unavailable.
  Test OpenSSH Client and Server separately. Test Store registrations per user
  and record absent/protected apps individually.

The registered Pro controller completed its host preparation, local pilot and
recovery checks. The [local closeout](controller-certification.md#windows-11-pro-local-controller-closeout-2026-11-05)
records the tested configuration and the remaining formal certification gates.

## Windows 11 Pro implementation and focused acceptance track, 2026-11-05

The user approved completing the RIDE v3 Windows 11 Pro implementation using
the Pro controller under the local authorization below. Keep the edition-support
decision above: this is a Pro-first implementation target, not permission to
add Pro to every migrated operation. Existing Enterprise acceptance, Pro
acceptance and other Windows target claims remain separate evidence.

Use a value-focused test path:

1. Inventory each remaining operation's catalog target, edition-specific API,
   privilege, recovery behavior and known evidence. Classify it as already
   supported on Pro, a Pro implementation gap, unavailable on the current
   image, or outside v3 scope. Make code changes only for a named gap or a
   concrete acceptance failure.
2. For each code batch, run parser/catalog validation and the narrow Pester
   tests for the changed handler, catalog rows and recovery behavior. Do not
   repeat the full repository suite after each component change. Reserve one
   full unit run for the final release gate only if its remaining value
   justifies its runtime; a prior failure must first be explained and repaired.
3. Batch native VM scenarios by shared backend and side effects. For settings,
   exercise one representative Pro apply, readback/status, idempotent repeat
   and exact restore for each distinct behavior path. Test additional rows
   natively only when their Windows API, edition gate, dependency, or recovery
   differs. For downloaded ordinary user-mode packages, retain the approved
   per-package fast-track: verify registration/install, bounded startup without
   observed error, and successful uninstall/recovery; deeper feature behavior
   remains v3.1 work. Group packages by installer/source where practical.
4. Inventory image-dependent Windows capabilities first. The user authorized
   Windows Update as an acquisition source for OpenSSH and RSAT on the test VM;
   report absent capabilities as unavailable, and test OpenSSH Client and
   Server separately. Keep Store registration outcomes per intended user.
5. Keep machine wallpaper, machine default lock screen, current-user wallpaper
   and current-user lock screen as separate behavior paths. Reuse their existing
   focused lifecycle/evidence routes; do not treat one visual result as proof
   for another setting.
6. Export and verify scenario evidence, then restore the intended VM checkpoint
   after native batches. Component restore/uninstall remains an acceptance
   result where required; checkpoint restoration is final VM disposal, not
   proof of the component's own recovery.

### Operator authorization for local-only Pro component testing

The operator authorized focused native component batches on the disposable
`RIDEWin11ProTest` registration using the local checkout. This decision applies
to the registered account, Windows 11 Professional x64 build 26300, VM
`7690a0b8-8190-4f56-91ad-c744fb081b1c`, and checkpoint
`74c1c858-c6bb-40ab-97ed-61c1eea74c9f` (`RIDE-clean-test-base`).
The approved configuration SHA-256 is
`E6C20362645D44E62C81AC1EB1748C81CFE40CB07A694B6356ECD3C36B272C15`.
Check the pins, installed hashes and idle state before dispatch; stop and
reconcile drift. Use the existing family-specific route and its evidence,
ownership and checkpoint recovery guards. Windows Update is authorized inside
the guest for OpenSSH and RSAT. Run one family at a time, starting with OpenSSH
Client. Record unavailable or failed operations explicitly.

Formal registration remains `NotValidated`. RC delivery, second-host
replication and cutover remain deferred. A component requires its own
acceptance on the tested edition and build before any support promotion.

The handoff objective is to finish implementation and record per-operation Pro
support outcomes in the existing catalog/evidence ledgers, while retaining
explicit unsupported, unavailable and deferred results. Keep Enterprise-only
policy checks, Windows Server, Home and ARM64 out of the Pro acceptance claim.

### First local Pro batch: OpenSSH Client, 2026-11-06

The retained guest reported Windows 11 Professional x64 26300.9711 with
`OpenSSH.Client~~~~0.0.1.0` already installed. The test used the local
checkout at `6097db8f` and the declared Windows Update servicing route.
Scope was limited to client capability state, the native client binary and
conditional saved-state recovery on that image. SSH connectivity, the OpenSSH
Server service and firewall, and RSAT have separate acceptance criteria.

Request `8ed2a20202154bc7a514ecbd614604ab` passed preview, installed-state
readback and repeat install. At removal, the evidence writer rejected the
saved snapshot because the report contained an empty catalog ID and capability
name. Collection verified eight files, including the terminal failure. Reset
verified the pinned checkpoint, powered-off VM and released hold.

Windows PowerShell 5.1 reproduced the empty fields when projecting catalog
hashtables with `Select-Object`. The guest scenario now copies the keys
explicitly. The real catalog produced the expected OpenSSH identity, and
all 72 focused tests passed in each of Windows PowerShell 5.1 and PowerShell 7.
The repository validator passed under PowerShell 7. Under Windows PowerShell
5.1 its generated-reference check flagged the ordering of default-image rows in
`docs/OPERATIONS.md`. The comparison found only row-order differences.

Retry `ca1015fda07340678278383018940239` passed all seven checks. The first
install and its repeat found the client present. Removal verified absence.
Saved-run restore put the client back, with a valid Microsoft signature and
file version. Repeat restore preserved the engine journals, and the checks
confirmed the other capabilities retained their original states. Collection
and final reset each verified 16 files. The VM was Off at the pinned parent,
the hold released, the registered task Ready and both active queues empty.
The protected registration evidence still recorded `NotValidated`.
See the [run receipts and digests](../archive/evidence/pro-openssh-client-2026-11-06.json).

This accepts the tested lifecycle on this image. Fresh installation from an
initially absent image and broader catalog support remain separate. RSAT is
the next independent Pro capability batch.
