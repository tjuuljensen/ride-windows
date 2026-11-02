# Windows and Fedora CLI alignment

Machine-readable capability and difference dispositions are maintained in the
[capability register](models/capability-differences.json).

This is a maintainer comparison of the current local source, reviewed on
2026-11-01 after Windows gained `-AllowCandidate`. Recommendations below are
proposed follow-up work, not newly adopted policy or implemented behavior.
Native installers, target acceptance and recovery evidence remain platform-owned.

## Review basis and existing policy

Windows was inspected on `codex/ride-v3-migration`, based on `59d1a80`, with
uncommitted changes including candidate opt-in. Fedora's local branch reference
was `codex/ride-v3-migration` at `5c0ac02`. Fedora Git status was unavailable to
this session, so its checkout is not asserted clean. The
[source evidence](archive/evidence/ride-cli-alignment-2026-11-01.json) records
hashes of the actual files reviewed. This is source inspection, not fresh native
acceptance, and it does not transfer support between platforms.

Fedora already has the explicit policy:

- [AGENTS.md, Ownership and support](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/AGENTS.md#ownership-and-support)
  requires comparing catalog, profile and run-state behavior with Windows at
  every package migration batch and before a release candidate. Differences
  need reasons and review triggers; unexplained drift must be resolved before
  operation promotion.
- [Windows alignment](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/windows-alignment.md)
  is Fedora's dated comparison and exception register. Its opening matrix is
  based on 2026-10-14; later entries are scoped reviews, not proof that every
  current CLI action agrees.
- [GitHub cache contract](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/github-cache-contract.md)
  already treats Windows' [GitHub discovery guide](github-release-discovery.md)
  as its behavior reference while documenting native cache/authentication differences.

Windows [AGENTS.md](../AGENTS.md) and its [documentation model](models/documentation-model.md)
apply the shared portfolio rules, but contain no equivalent reciprocal Fedora
CLI/schema review requirement. The current arrangement is asymmetric and mainly
triggered by package migrations. It can miss changes to flags, preview, settings,
argument parsing and recovery. Neither inspected validation workflow runs a
shared cross-repository CLI conformance suite.

## Current command envelope and actions

Sources: Windows [entry point](../ride.ps1), [engine](../modules/RIDE.Engine.psm1)
and [user handoff](../modules/RIDE.UserHandoff.psm1); Fedora
[entry point](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/ride.sh),
[common gates](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/lib/v3/common.sh),
[catalog helpers](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/lib/v3/catalog.sh)
and [completion](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/completion/ride.bash).
Links follow the development branch; the evidence hashes identify this review.

| Area | Windows now | Fedora now | Recommended direction |
| --- | --- | --- | --- |
| Entry and defaults | PowerShell; no command means `list`; `-Help`, `-Version`. | Bash; no command means `list`; `help`/`--help`, `version`/`--version`. | Keep native spellings and the same default. Do not require identical switches. |
| Shared verbs | `list`, `search`, `show`, `plan`, `apply`, `download`, `install`, `set`, `unset`, `status`, `restore`, `remove`. | Same shared verbs. | Maintain one semantic definition per verb, including unsupported cases. |
| Additional verbs | `prune-state`; PowerShell completion is attached to parameters. | `completion bash`; no matching prune command. | Declare capabilities; no placeholder parity commands. |
| Profiles and state arguments | Profile path via `-Profile`; default PSD1. `set <id> <state>` or `-State`. | Profile name or path via `--profile`; default JSON. `set <id> --state <state>`. | Document paired examples with explicit profile paths and named state options; keep published forms working. |
| Candidate execution | `-AllowCandidate` on apply/install/set/unset/remove/restore; requires PendingAcceptance and declared CandidateTargets when not already supported. | `--allow-candidate` bypasses the non-supported status gate for mutations and download; target checks remain separate. | Same acceptance-only opt-in, no persistent approval or target widening. Reject unsupported use of a flag. |
| Candidate preview | `-WhatIf` previews declared pending targets without `-AllowCandidate` and reports that acceptance remains pending. | `--dry-run` takes the planning path without acceptance opt-in. | Source behavior now aligns; keep target, availability and privilege checks, and verify the paired scenarios. |
| Download | Separate acquisition; `-Destination`, `-WhatIf`; public Save-RidePackage checks kind/action but does not use the engine acceptance/target gate. `-AllowCandidate` is rejected here. | Checks target and supported download handler; actual candidate download requires opt-in; dry-run does not. | Define acquisition eligibility separately from execution acceptance. Prefer no VM-acceptance opt-in merely to acquire; retain source, action, verification and artifact compatibility checks. |
| Target and privilege checks | Supported/candidate Windows targets, optional build and Server edition checks; elevation for machine changes. Some user operations explicitly require unelevated context. | OS/release/architecture/optional variant; root for system and non-root for user changes. | Preserve native target dimensions and actual-user semantics. Preview must report blockers without performing changes; opt-in never grants privilege. |
| User handoff | Explicit `-UserContext Desktop` for bounded user workflows; WhatIf previews launch only. | Run user operations from the intended non-root account; no equivalent handoff. | Keep this platform capability. A launch receipt must not imply child operation acceptance or success. |
| `unset` | Uses declared override-removal semantics or refuses; distinct from baseline and saved restore. | Always requests the state `disabled`. | High priority: make unset catalog-declared in Fedora; use `set ... --state disabled` for explicit disable. Do not relabel disable as removing an override. |
| Profile `remove` | Filters direct selections to Package, WindowsCapability and DefenderExclusion; expands/reverses groups. | Reverses every profile entry and requests `absent`, including settings that may not declare that state. | High priority: define eligible removal actions and preflight the complete result. Explicitly review Windows exclusion removal; it is broader than the help's package wording. |
| Bare `remove` | Falls back to the default profile. | Also falls back to the default profile. | Prefer requiring an ID or explicit profile on both, with a documented compatibility transition. Agreement alone does not make this default desirable. |
| Discovery and status | Rich category/search filters; setting baseline/default/effective-state presentation. `status` positional argument is a view. | Literal search; `status` positional argument is an operation ID; `status --profile` uses plan output. `show` emits metadata plus observation. | Add explicit ID/view selectors where useful and align result meanings. Do not silently reinterpret published positional syntax. |
| Groups and dependencies | Groups are ordered multi-operation solutions with lifecycle expansion; package dependency planning is engine-owned. | `list groups` aggregates each operation's group label; it is not an executable group. | Distinguish categories from executable solutions. Add group lifecycle only when implemented and tested. |
| Package selection | `-Variant` selects a declared package variant; native installed/portable behavior and saved selection. | `--source` chooses a declared acquisition provider for the installed deployment. | Do not alias these options: variant, source, distribution, scope and deployment are different concepts. |
| Restore and failure | Restores captured state subject to handler limits; failures expose run ID and saved/completed/unfinished work. Candidate restore needs opt-in again. | Reverses journal steps marked changed; validates source signature/recovery/conflicts, rejects an already completed restore; actual candidate restore needs opt-in again. | Share recovery guarantees and error categories, not file schemas. Test interrupted/partially applied steps, not just successful inverse actions. |
| Argument validation | Typed parameters plus command-specific checks, including the new candidate restriction; not every irrelevant combination is rejected. | Handwritten parser validates source use, but several other parsed options can be silently irrelevant; direct remove can win over an explicitly supplied profile. | Both should reject ambiguous selectors and irrelevant flags before observing or changing state. |
| Output and completion | PowerShell objects in parts of the engine/CLI; show/status also format output. Catalog-driven parameter completion. | JSON for show, TSV when redirected for tables; static command suggestions and local JSON completion. | Keep native human output; define a small opt-in JSON result contract for tooling. Derive or test command/option completion against the parser. |
| Offline and extensions | Explicit local libraries; narrow offline bundle execution with independent gates. | No equivalent local-library interface or retained-artifact install path in this dispatcher. | Publish capability differences. Offline means no network fallback; do not infer it from a download cache. |

Windows candidate changes and recovery still require explicit per-invocation
opt-in. Candidate preview now reports pending acceptance without requiring that
opt-in. Download eligibility remains a separate source-level difference to
resolve under ALIGN-04.

One additional Fedora review target is `ride_restore`: ordinary dry-run rows
reach `ride_plan_entry` and its target check, but the special iBus hotkey preview
branch prints an observation directly after skipping mutation preflight. Put a
common target/identity preflight before handler-specific preview output. This is
a source finding requiring focused tests, not a reproduced native failure.

## Recommended alignment policy

Keep one shared RIDE behavior contract, with two native implementations and two
local acceptance records. Neither repository should continually chase the other
repository's moving development HEAD.

Use `ride-windows/docs/models/ride-behavior-contract.md` as the initial proposed
canonical home, building on the existing Windows-owned package/GitHub references.
This location is a hosting choice: either repository can originate a change.
Keep portfolio-wide documentation rules in `network-devices`; do not move
RIDE-specific command semantics there or create another policy repository yet.
Link existing topic contracts instead of copying their contents into a new one.
This comparison remains the Windows difference register, and Fedora's existing
`windows-alignment.md` remains its local implementation/evidence register.

The contract should cover verbs, valid argument combinations, read-only preview,
acceptance versus target gates, scope/identity, acquisition versus installation,
unset/baseline/restore, dependency ordering, saved-state guarantees, partial
failure, output fields and compatibility. It should explicitly exclude identical
catalog coverage, installer code, runtime data formats and native target support.

Recommended reciprocal text for both AGENTS.md files, after the contract exists:

> Before changing shared CLI, catalog/profile meaning, acquisition, planning,
> acceptance, privilege or recovery behavior, review the pinned RIDE behavior
> contract and the peer implementation. Record alignment or an intentional
> difference with an owner, reason, linked follow-up and review trigger. Update
> affected help, completion and conformance cases in the same change. Native
> target acceptance remains local; unresolved shared-contract drift blocks the
> affected capability's promotion, not unrelated development.

This broadens Fedora's current package-batch/RC trigger and adds the missing
Windows obligation. Local instructions should link to the shared rules, not
maintain two copies of the contract.

## Working while both repositories change

1. **Declare the impact in each change.** Record `shared behavior: unchanged`,
   `compatible extension`, `intentional platform difference`, or `breaking change`.
   Name affected contract IDs and peer work. Ordinary native handler fixes need
   no second-repository edit when the shared behavior is unchanged.
2. **Pin a reviewed contract revision in each client.** Use a small manifest with
   contract version, exact commit/hash, implemented rule IDs and exception IDs.
   Vendor the small shared scenario data for offline/local tests, with a source
   manifest and explicit update tool; generated copies must not be edited locally.
   CI must never silently test against mutable peer HEAD.
3. **Use paired changes only when needed.** One proposal names both consumers and
   migration/recovery implications. Each repo gets its own implementation and
   native tests, linked by the same decision ID. Additive work can land first as
   an advertised capability; the peer records a tracked gap. Do not force
   synchronized commits or identical release versions.
4. **Keep a bounded compatibility window.** For breaking behavior, define the old
   and new contract versions, temporary aliases/migrations, and explicit removal
   criteria. Preserve old saved-run recovery independently of CLI deprecations.
   Test both agreed versions during transition; do not use an indefinite
   'follow the other repo later' exception.
5. **Test shared scenarios in each native runner.** Windows uses Pester on Windows;
   Fedora uses its mocked Bash/Python harness on Linux. Consume the same fixture
   meanings, with adapters for names and formats. Assert observable behavior and
   side-effect counts, not matching help text or installer implementations.
6. **Detect upstream changes separately.** Add a scheduled/manual read-only CI
   comparison of the pinned contract against its newer published revision and
   peer capability manifest. Report changed rules and stale exceptions. Keep
   reproducible PR checks pinned; do not auto-merge contract updates. No scheduled
   job or external notification is created by this recommendation.
7. **Close the loop before promotion.** Review the affected peer capability on
   shared changes, package batches and each release candidate. A difference entry
   needs ID, owner, reason, affected rules, linked work, reviewed revisions,
   status and a concrete review/removal trigger. Release summaries distinguish
   aligned, intentionally different, pending implementation and native-accepted.

Initial shared scenarios should exercise candidate apply and restore with/without
opt-in; previews on accepted, candidate and undeclared targets; no preview writes
or run creation; wrong privilege; invalid/irrelevant arguments; unset versus
disable; mixed-profile removal; download without install; dependency order;
partial failure with usable recovery; source/ownership conflicts; and read-only
completion. Include Fedora's special restore path and Windows' existing
installed-package no-op exception as explicit cases rather than hidden exceptions.
Machine-readable result tests should cover stable fields and failure categories,
not require PowerShell and Bash to print identical prose or use identical native
exit codes.

## Suggested implementation order

| Priority | Work | Completion evidence |
| --- | --- | --- |
| First | Agree the small shared contract, capability/exception manifest, and reciprocal AGENTS links. | Both clients name the same reviewed rules and every current difference has a disposition. |
| Next | Fix ambiguous/ignored arguments, define profile removal eligibility, and replace Fedora's generic disabled mapping for unset. | Focused mocked tests prove refusal before mutation and preserve published explicit set/recovery paths. |
| Next | Agree candidate preview and acquisition policy; then make the small coordinated behavior changes. | Matching shared scenarios pass, with target/identity checks retained and no preview writes. |
| Then | Add the pinned scenario suite, completion checks and drift-reporting workflow. | Both native CI jobs run the same contract revision; a deliberate mismatch is detected. |
| Later | Improve explicit ID/view status selectors, profile convenience and structured output. | Compatible command examples and versioned output tests; no forced installer or catalog parity. |

No runtime code, policy enforcement, peer checkout or acceptance status is changed
by this review. Documentation/link checks validate this report; implementation
and disposable-target acceptance remain separate follow-up work.

## Fast-track ETL2PCAPNG acquisition review, 2026-11-02

Shared behavior unchanged: RB-05/11, contract 1.0.0. The pinned Microsoft artifact
was downloaded and verified without installation or execution. Fedora source at
`3d9406e3888122d1407652336859e6217c09bcaa` retains distinct acquisition and install
actions; the reviewed `ride.sh` and `lib/v3/common.sh` hashes are in the
[acquisition evidence](archive/evidence/etl2pcapng-fast-track-download-2026-11-02.json).
No target support or shared interface changed. Owner: RIDE Windows maintainer;
next review: the next package batch or acquisition behavior change. Existing
alignment/release gaps remain open; this is not shared conformance automation.

## Unsupported target exploration, 2026-11-02

Intentional Windows difference from RB-08, with RB-02/03/04/09/10/11 safeguards
retained. The user requested a separate `-AllowUnsupportedTarget` for one-run
catalog OS/build/edition exploration. Candidate permission remains a separate
fresh opt-in; target declarations are unchanged. Changed runs and approved
restores retain actual-target/unsupported audit; preview has no writes or launch.
Architecture, source/integrity, privilege, dependencies, handler availability,
offline matching and saved-state recovery checks remain in force.

Compared contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and Fedora revision `3d9406e3888122d1407652336859e6217c09bcaa`:
`ride.sh` SHA-256 `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`,
`lib/v3/common.sh` SHA-256 `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
Fedora's `ride_require_target` still refuses undeclared OS/release/architecture/
variant independently of candidate permission. No Fedora target override is
claimed or implemented, and the canonical contract/digest are not silently revised.

Owner: RIDE Windows maintainer. Reason: user-approved disposable-target
exploration without promoting supported targets. Follow-up **ALIGN-TARGET-01**:
jointly decide whether to retain this Windows-only interface or version the
contract with a shared exploration rule, and add both native conformance cases.
Review trigger: before promoting this capability or a public v3 release, and
whenever target, candidate or recovery semantics change. This difference blocks
its promotion until reviewed; unrelated development can continue.

See [operator behavior and recovery](unsupported-target-exploration.md) and
[source evidence](archive/evidence/unsupported-target-source-validation-2026-11-02.json).

## Sysmon Modular checksum decoding and acquisition, 2026-11-02

Shared behavior unchanged (RB-05/11): decode a bounded UTF-8 byte response in
PowerShell 7 before checking the same exact release checksum entry. Windows
PowerShell string responses, source/tag/asset allowlists and digest verification
remain unchanged. Three pinned XML artifacts were acquired; no consumer ran.
Compared contract 1.0.0 and the Fedora revision/source hashes recorded in the
preceding target-exploration review. Owner: RIDE Windows maintainer; next review:
configuration apply/restore or acquisition policy change. Native acceptance and
shared conformance remain separate. See [evidence](archive/evidence/sysmon-modular-acquisition-2026-11-02.json).

## OpenSSH Client catalog capability, 2026-11-02

Compatible Windows capability extension; shared requirements unchanged
(RB-02/03/04/05/07/08/09/10/11). The existing install/remove/restore verbs now
route the exact OpenSSH Client catalog identity to its declared Windows Update
servicing source. Completion continues to use the catalog. Preview writes no
run and invokes no writer; actual candidate changes and recovery require fresh
opt-in. The source policy is part of the operation and version-2 capability
snapshot, not inferred from an earlier local-media request. No offline fallback
or Windows policy override is added. Recovery is explicitly conditional on
literal state, target/revision and source availability; exact previous payload
bytes/version are not claimed. Old LocalSource records retain their original
reader and strict source validation.

Reviewed contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and Fedora revision `3d9406e3888122d1407652336859e6217c09bcaa`:
`ride.sh` SHA-256 `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`,
`lib/v3/common.sh` SHA-256 `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
The peer still separates target and candidate checks; native Windows capability
servicing is not a Fedora feature-parity claim. No contract version/digest change
or shared conformance result is needed or claimed for this local extension.

Owner: RIDE Windows maintainer. Next review: native capability acceptance,
servicing-source/recovery changes, RSAT integration or the release candidate.
Promotion remains blocked until native install/repeat/remove/RIDE restore and
client identity/version checks pass. See the
[operator workflow](windows-component-inventory.md#openssh-client-catalog-candidate).

## Client RSAT catalog lifecycle, 2026-11-02

Compatible Windows-native extension; shared contract requirements are unchanged
(RB-02/03/04/05/07/08/09/10/11). `install` and `remove` accept the explicit
`solution.rsat-client-tools` group and individual capabilities. The group selects
all reviewed RSAT identities observed on the target; it does not assume every
catalog member is available. Completion remains catalog-only and read-only.
Dependency expansion, stale-inventory refusal and per-member saved state preserve
partial-run recovery. Recovery orders captured transitions by dependencies and
refuses orphaned installed dependents. Source acquisition is explicitly Windows
Update, with no LocalSource fallback, policy override or offline promise.
Conditional literal-state recovery does not promise exact payload versions.

Reviewed contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and Fedora revision `3d9406e3888122d1407652336859e6217c09bcaa`:
`ride.sh` SHA-256 `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`,
`lib/v3/common.sh` SHA-256 `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
The peer's target/candidate separation remains applicable; client FoD provisioning
is a native Windows capability, not Fedora feature parity. No shared contract
version/digest or conformance automation claim changes. The existing saved
OpenSSH Client records and LocalSource compatibility reader remain recoverable.

Owner: RIDE Windows maintainer. Review trigger: native RSAT acceptance, changes to
source/dependencies/recovery or the release candidate. No supported target or
shipped profile is promoted. Follow the
[RSAT native acceptance procedure](windows-component-inventory.md#client-rsat-catalog-candidates)
and the [remaining test strategy](migrations/migration-completion-reassessment-2026-11-02.md#remaining-test-strategy-assessment-2026-11-02).

## Generated Wi-Fi profile input, 2026-11-02

Compatible Windows-native preparation extension; shared contract unchanged
(RB-02/03/08/09/10/11). The user clarified that RIDE generates XML from supplied
settings and tests with synthetic profiles; an externally supplied XML file is
not an input gate. Generation is separate from native profile import, scope,
connection and recovery. It creates only an explicitly selected new local file,
sets and verifies a private DACL before writing, never overwrites, and writes
nothing under WhatIf. Completion uses declared security/connection choices with
no adapter queries. Native machine/all-user import and recoverable prior-profile
capture remain pending; no target support or profile default is promoted.

Reviewed pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`,
Fedora revision `3d9406e3888122d1407652336859e6217c09bcaa`, and peer paths:
`ride.sh` SHA-256 `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`,
`lib/v3/common.sh` SHA-256 `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
These reviewed peer paths contain no WLAN generator; this is not a feature-parity
or automated shared-conformance claim. No shared version/digest changes.

Owner: RIDE Windows maintainer. Review trigger: importer/recovery integration,
additional security modes, scope changes or release candidate. Follow-up and
acceptance: [Wi-Fi generation and synthetic testing](wireless-profile-inventory.md#synthetic-testing).

## Private WLAN lifecycle candidate, 2026-11-02

Difference ID `windows.wlan-private-lifecycle`; compatible Windows-native
extension, with shared requirements unchanged (RB-02/03/04/08/09/10/11).
Explicit interface and expected target selection, candidate opt-in on each actual
apply/remove/restore, mutation-free preview, private prior-state capture and
conflict refusal are implemented. This isolated module does not change published
catalog IDs or shared CLI verbs. Run-ID completion reads local filenames only.

The Windows provider supplies no complete per-profile DACL capture. Existing
all-user replacement preserves permissions; deletion requires a completed RIDE
creation with a recorded descriptor. Exact XML/order recovery is conditional on
unchanged observed state and no external DACL drift. Incomplete runs retain a
private intent and expose a run ID but refuse automatic recovery without a
verified applied record. These limits remain explicit; native acceptance is
pending and no target is promoted.

Reviewed contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and the peer's restore conflict, journal, target and candidate paths in `ride.sh`
and `lib/v3/common.sh`. Their current hashes remain
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266` and
`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
The last verified Fedora revision was
`3d9406e3888122d1407652336859e6217c09bcaa`; this run could read and hash those
sources, but Git revision inspection was denied by the sandbox. No newer HEAD
or contract adoption is inferred. Fedora has no matching WLAN capability in
these paths. This is not feature parity or automated shared conformance.

Owner: RIDE Windows maintainer. Follow-up: the
[candidate native acceptance procedure](wireless-profile-inventory.md#candidate-all-user-profile-lifecycle).
Review trigger: native import/recovery acceptance, controller integration,
permission capture or interrupted-run recovery changes, or the release candidate.
No contract version/digest change is required for this native extension.

## Synthetic WLAN acceptance route, 2026-11-02

Compatible verification extension of `windows.wlan-private-lifecycle`; shared
requirements unchanged (RB-02/03/04/08/09/10/11). The guest entry point requires
exact target identity, correlated request markers, existing elevation and an
explicit interface. Preview creates no evidence or lifecycle run. Actual steps
use the candidate lifecycle with per-call opt-in. Missing prerequisites return
NotRun; failed verification returns Failed with retained recovery IDs. Neither
can be treated as native acceptance. Tests mock all native/system boundaries.

Reused the e287415 review of contract 1.0.0 and unchanged peer target/candidate/
recovery paths, including the exact hashes in the preceding difference entry.
No shared verb, catalog/profile meaning, acquisition or recovery guarantee has
changed. The registered controller does not yet dispatch this entry point;
source readiness is distinct from installed controller capability and native
acceptance. No version/digest or automated shared-conformance claim changes.

Owner: RIDE Windows maintainer. Follow-up and review trigger: permitted
controller integration/refresh, suitable guest WLAN support and execution of the
[synthetic native procedure](wireless-profile-inventory.md#disposable-target-acceptance-entry-point),
or a change to its scope/recovery contract. Font/image, Sysmon and BitLocker
acceptance remain separate, unaffected work.

## Machine-font lifecycle candidate, 2026-11-02

Difference ID `windows.machine-font-lifecycle`; compatible Windows-native
extension, shared requirements unchanged (RB-02/03/04/07/08/09/10/11).
The isolated module consumes explicit hash-pinned font/license data and refuses
unknown fields, collisions and source drift before writers. It does not change
catalog IDs, shared verbs, package removal eligibility or profiles. Existing
matching fonts are preserved, not adopted. Machine intent/applied records are
administrator-owned and private; user-private file defaults remain unchanged.
Preview writes nothing. Each candidate change/recovery requires fresh opt-in;
target, privilege, ownership and conflict checks still apply. Run-ID completion
reads bounded local filenames only.

Recovery is conditional captured file/registration recovery. Incomplete runs
retain an exposed run ID and private intent but refuse automatic restore.
Font caches/reference counts, audit ACLs and cross-session availability are not
silently described as restored. Actual native loading/removal and protected-state
creation remain pending; mocked source checks do not promote targets.

Reviewed pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645` and the peer's
target/candidate/journal/recovery paths from the prior e287415 review. Rechecked
unchanged working-tree hashes: `ride.sh`
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`,
`lib/v3/common.sh`
`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
Last verified Fedora revision remains `3d9406e3888122d1407652336859e6217c09bcaa`;
this run makes no newer revision or automated shared-conformance claim. Native
Windows font registration/GDI behavior is not a Fedora feature-parity claim.
No shared contract version/digest change is required.

Owner: RIDE Windows maintainer. Follow-up: [machine-font native acceptance](machine-fonts.md#recovery-limits-and-native-acceptance).
Review trigger: native guest execution, new font formats/targets, ownership or
partial-recovery changes, or the release candidate. Native support remains gated.

## Machine-font guest acceptance preparation, 2026-11-02

Extends the existing `windows.machine-font-lifecycle` difference with a guarded
native acceptance route; RB-02/03/04/07/08/09/10/11 remain unchanged. Explicit
target/guest/request checks, preview, pre-change evidence, ownership-limited
removal and conflict-aware saved restores preserve the shared behavior. A
current-session pass does not claim cross-session/restart support. Missing
prerequisites, failure and unrun native checks remain distinct from success.

Compared against pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and the prior target/recovery review at `e287415`. Peer source hashes rechecked:
`ride.sh` `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`;
`lib/v3/common.sh` `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
Last verified Fedora revision remains `3d9406e3888122d1407652336859e6217c09bcaa`.
This Windows test route changes no shared contract, catalog/profile schema or
Fedora feature claim; no version/digest update is required. Automated shared
conformance remains pending.

Owner: RIDE Windows maintainer. Follow-up: [font native acceptance](machine-fonts.md#disposable-target-acceptance-entry-point).
Review trigger: controller dispatch/native execution, recovery scope changes or
the release candidate. Native support promotion remains gated by actual results.

## Source-bound Sysmon configuration candidate, 2026-11-02

Difference ID `windows.sysmon-configuration`; compatible Windows-native extension
with shared behavior unchanged, covering RB-02/03/04/05/06/08/09/10/11. Explicit XML
application remains separate from artifact acquisition and package installation.
Exact target/binary identity, recoverable prior source, capture before mutation,
preview without writes, fresh candidate opt-in and conflict-aware recovery apply.
No default reset substitutes for captured restore. Partial runs expose an ID and
retain private state; native outcomes remain unpromoted.

Reviewed pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645` and the peer
target/candidate/journal/recovery review recorded at `e287415`; reread its common
platform checks and rechecked unchanged source hashes: `ride.sh`
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`,
`lib/v3/common.sh`
`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
Last verified Fedora revision remains `3d9406e3888122d1407652336859e6217c09bcaa`.
Windows event/service correlation does not imply Fedora feature parity. Shared
verbs, profiles/catalog schema and contract version/digest remain unchanged;
automated shared conformance remains pending.

Owner: RIDE Windows maintainer. Reason: native Sysmon XML lifecycle requires
Windows service/event evidence. Follow-up: [native configuration acceptance](sysmon-configuration.md#acceptance-still-required).
Review trigger: known-baseline guest preparation, native apply/restore, new
consumer/schema versions, recovery behavior changes or release-candidate review.

## Sysmon guarded guest preparation and acceptance, 2026-11-02

Extends `windows.sysmon-configuration` with isolated test routes. Shared behavior
remains unchanged (RB-02/03/04/05/06/08/09/10/11). Fixture installation is an
explicit separate mode with disposable guest/target checks, existing elevation,
verified source, whole-footprint refusal and pre-change evidence. It does not
change package installation defaults or implicitly apply community XML.
Preparation never claims acceptance. The configuration mode requires all three
reviewed sources, private captured recovery, unchanged repeat and verified
restores; incomplete runs retain evidence without blind cleanup.

Reviewed pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and the peer target/candidate/journal/recovery comparison recorded at `e287415`.
Rechecked unchanged peer hashes: `ride.sh`
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`;
`lib/v3/common.sh` `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
Last verified Fedora revision remains `3d9406e3888122d1407652336859e6217c09bcaa`.
No shared schema/verb/version/digest change or automated shared-conformance claim
is made. The native Sysmon test fixture is not a Fedora feature-parity claim.

Owner: RIDE Windows maintainer. Follow-up: [guarded Sysmon native execution](sysmon-configuration.md#disposable-guest-entry-point).
Review trigger: protected controller dispatch, native fixture/configuration
results, new Sysmon/source versions or release-candidate review. Native support
remains gated by actual execution evidence.

## Bounded image source validation, 2026-11-02

This read-only Windows source gate leaves RB-05 acquisition, RB-06 lifecycle,
RB-09 recovery and RB-11 acceptance boundaries unchanged. A validated byte
snapshot is neither installation nor verified personalization. No shared CLI,
catalog/profile schema, contract version or digest changes. Windows image APIs
and edition-specific policy acceptance remain local and unpromoted.

Reviewed pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`,
the prior peer target/candidate/journal/recovery comparison at `e287415`, and peer
platform checks. Rechecked unchanged hashes: `ride.sh`
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`;
`lib/v3/common.sh` `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
Peer Git access was denied in this sandbox, so the last verified revision remains
`3d9406e3888122d1407652336859e6217c09bcaa`; no newer revision is claimed. Automated
shared conformance remains pending.

Owner: RIDE Windows maintainer. Reason: PNG validation prepares native image
workflows without promoting behavior from source checks. Follow-up:
[image lifecycle and visible acceptance](image-personalization.md#three-separate-acceptance-workflows).
Review trigger: image writer/recovery implementation, supported route/edition
changes, native acceptance or release-candidate review.

## Machine default lock-screen candidate, 2026-11-02

Difference ID: `windows.default-lock-screen`. Classification: native platform
extension; shared behavior unchanged (RB-02/03/04/06/08/09/10/11). The explicit
machine workflow uses the documented edition-specific policy and an owned PNG.
It captures private state before writes, preserves unrelated state, requires
fresh candidate opt-in for apply/restore and refuses conflicting recovery.
No user preference, legacy baseline/reset, cache or visible effect is silently
substituted. Structured results declare schema 1; completion is local/read-only.

Reviewed pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and the prior peer target/candidate/journal/recovery comparison at `e287415`.
Peer candidate/platform checks were reread; unchanged source hashes are
`ride.sh`: `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`,
`lib/v3/common.sh`: `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
Last verified peer revision remains `3d9406e3888122d1407652336859e6217c09bcaa`;
the previously recorded sandbox Git-access limitation remains. No shared schema,
verb, contract version/digest or automated shared-conformance claim changes.

Owner: RIDE Windows maintainer. Reason: Windows machine default-image policy
has native scope, edition and visible-effect semantics. Status: source candidate;
native acceptance remains open. Follow-up:
[machine default lock-screen acceptance](image-personalization.md#three-separate-acceptance-workflows).
Review trigger: guarded native dispatch, actual permissions/visible recovery,
edition/route changes or release-candidate review. This does not imply Fedora
feature parity or close the legacy default-lock reset outcome.

## Retained default-image guest phases, 2026-11-02

Extends `windows.default-lock-screen` with native test preparation. Shared
behavior remains unchanged (RB-03/04/08/09/10/11). Each explicit phase invokes
the selected candidate lifecycle with its guards intact. Apply does not grant
future recovery approval. Preview/completion write nothing; failed runs retain
private evidence. Structured schema-1 reports separate policy/file lifecycle
from visible image acceptance, which remains unverified by the runner.

Reviewed pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and the existing peer target/candidate/recovery comparison. Read-only access outside the filesystem sandbox
reverified Fedora revision `3d9406e3888122d1407652336859e6217c09bcaa`
without requesting Windows UAC or changing files. Compared hashes remain
`ride.sh`: `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`;
`lib/v3/common.sh`: `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
No shared schema/verb/version/digest change or automated shared-conformance claim.

Owner: RIDE Windows maintainer. Reason: visual image verification needs a retained
guest between apply and recovery; the generic reset-per-request worker is not
that route. Follow-up: [retained guest dispatch and native visual acceptance](image-personalization.md#phased-disposable-guest-acceptance).
Status: source preparation only. Review trigger: protected host dispatch, native
directory/file permissions, signed-out image/recovery evidence or release review.

## Retained guest coordination boundary, 2026-11-02

Extends the native test preparation for `windows.default-lock-screen`; shared
behavior is unchanged (RB-03/08/09/10/11). Reservation/release previews write
nothing and do not inspect host services or a VM. Explicit host mutations require
the registered account and existing elevation. Private ownership binds each hold
to a configuration digest, VM/checkpoint and unique lease. A stale recovery
receipt cannot release a later reservation with the same request ID. Neither
reservation nor release is a native acceptance result.

Reviewed contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`.
The preceding retained-phase review reverified peer revision
`3d9406e3888122d1407652336859e6217c09bcaa` and the recorded `ride.sh`/`common.sh`
hashes. That target/candidate/recovery comparison remains applicable; no shared
CLI, catalog, profile, contract version or digest changed. No shared-conformance
automation or Fedora feature parity is claimed.

Owner: RIDE Windows maintainer. Reason: the disposable guest must survive separate
visual apply/recovery phases without an ordinary queued request resetting it.
Status: coordination source only; 16 mocked/file-lock checks pass in each shell.
Follow-up: [retained host dispatch and export](image-personalization.md#retained-host-coordination).
Review trigger: wiring actual dispatch/export/receipt generation, protected
installation, native retained lifecycle or release-candidate review.

## Direct retained default-image host dispatch, 2026-11-02

Extends `windows.default-lock-screen` native test preparation with explicit
Prepare/Apply/Restore/Collect/Reset host phases. Shared behavior remains unchanged
(RB-03/04/08/09/10/11). The direct route requires existing host elevation and
registered identity; no privileged handoff is launched. Read-only preview creates
no hold, snapshot or VM session. Each candidate guest phase preserves its guards.
Explicit checkpoint cleanup remains distinct from captured setting restore and
from independent visual acceptance. Failed phases retain the guest and private
evidence; a reset retry needs a matching pre-reset intent and verified export.

Reviewed pinned contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and the preceding target/candidate/recovery comparison at Fedora revision
`3d9406e3888122d1407652336859e6217c09bcaa`, with its recorded `ride.sh` and
`lib/v3/common.sh` hashes. This native test route changes no shared CLI, catalog,
profile, contract version or digest. No shared-conformance automation is claimed.

Owner: RIDE Windows maintainer. Reason: signed-out image and recovery checks need
one retained guest, verified export and explicit later cleanup. Status: host
source preparation passes 25 new cases, or 41 combined with retained coordination,
in each shell; the real installed Prepare preview passes without elevation or VM
queries. Native transport and visual acceptance remain unrun. Follow-up:
[native retained dispatch](image-personalization.md#retained-host-dispatch).
Review trigger: elevated/protected execution route, native source transfer/ACLs,
visual evidence, recovery behavior changes or release-candidate review.

## Retained Sysmon executable input, 2026-11-02

Extends `windows.sysmon-configuration` test preparation with a pinned local input;
shared acquisition, candidate and acceptance meanings remain unchanged
(RB-05/08/11). The selected AMD64 Sysmon 15.22 executable and publisher notices
match the existing Microsoft Suite acquisition record. Read-only checks cover
actual signature/version/PE identity plus the three XML files, their license and
synthetic baseline. No payload download, executable launch, EULA acceptance,
installation or distribution approval is inferred from this preparation.

The XML artifacts remain targeted at 15.21. The 15.22 consumer selection requires
new native compatibility/recovery evidence; no catalog relabeling or support
promotion occurs. Reviewed contract 1.0.0 digest remains
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`.
The preceding native candidate/acquisition comparison at Fedora revision
`3d9406e3888122d1407652336859e6217c09bcaa`, with its recorded source hashes,
remains applicable; no shared CLI/profile/schema or contract reference changed.
No automated shared-conformance or Fedora parity claim is made.

Owner: RIDE Windows maintainer. Reason: resolve the missing executable prerequisite
without replacing the pinned XML selection or downloading an unreviewed consumer.
Status: complete input checks pass in both shells; native tests remain open.
Follow-up: [fixture installation and three-profile acceptance](sysmon-configuration.md#disposable-guest-entry-point).
Review trigger: different executable/source, native version compatibility,
protected dispatch or release-candidate review.

## Retained Sysmon host dispatch, 2026-11-02

Extends `windows.sysmon-configuration` with fixed Prepare, Configurations,
Collect and Reset test phases. Shared behavior is unchanged (RB-03/04/08/09/10/11).
Existing elevated identity and pinned VM/checkpoint guards apply; no UAC or
protected task mutation is introduced. Preview reads inputs/configuration only.
Preparation, native configuration acceptance and checkpoint cleanup stay distinct.
Captured XML recovery is still required; inaccessible archives prevent reset.

Reviewed contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`
and Fedora revision `3d9406e3888122d1407652336859e6217c09bcaa`.
Rechecked `ride.sh` SHA-256
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`
and `lib/v3/common.sh` SHA-256
`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`;
the peer's target/candidate gate remains consistent with this native test-only
route. No shared CLI, catalog/profile schema, contract version or reference changes.
Automated shared conformance and native Windows acceptance remain unclaimed.

Owner: RIDE Windows maintainer. Reason: connect the pinned fixture and three XML
lifecycles to explicit retained execution and evidence-first checkpoint recovery.
Status: 31 new host cases, 78 combined source cases per shell, real input gates
and installed preview pass. Native transport, archive access and installation
remain unrun; existing host elevation is unavailable.
Follow-up: [native retained Sysmon acceptance](sysmon-configuration.md#retained-host-dispatch).
Review trigger: elevated/protected execution route, native archive permissions,
source/executable changes, recovery changes or release-candidate review.

## Machine first-logon wallpaper candidate, 2026-11-02

Adds `windows.default-wallpaper` source preparation through the documented
machine ThemeFile first-logon policy. Shared behavior is unchanged
(RB-03/04/06/08/09/10/11). Preview writes nothing; actual apply and restore
require candidate opt-in and the exact elevated disposable target. Private
machine state precedes writes. Captured machine policy/assets are recoverable
within declared conflict limits; already-consumed user preferences are not
silently reinterpreted as machine restore. Changed profile identity inventory
refuses automatic removal. No default-user hive or inbox overwrite is used.

Reviewed contract 1.0.0 digest remains
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`.
The preceding native target/candidate/recovery comparison at Fedora revision
`3d9406e3888122d1407652336859e6217c09bcaa` remains applicable. Rechecked
`ride.sh` SHA-256 `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`
and `lib/v3/common.sh` SHA-256 `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
No shared CLI, catalog/profile schema, contract version or reference changes.
Native user initialization and theme behavior are Windows-specific, not a Fedora
parity claim. No automated shared-conformance pass is claimed.

Owner: RIDE Windows maintainer. Reason: provide the requested new-user default
through documented first-logon behavior while preserving existing users and
owned recovery. Status: 35 lifecycle/generator cases plus 16 PNG cases pass in
each shell; selected input and host policy metadata pass read-only checks.
Follow-up: [native new-user and recovery acceptance](image-personalization.md#machine-first-logon-wallpaper-candidate).
Review trigger: first-logon visual or collateral-default results, changed
user-profile handling, source/target changes, native dispatch or release review.

## First-logon wallpaper guest phases, 2026-11-02

Extends the source-prepared `windows.default-wallpaper` candidate with retained
machine apply/restore guest phases. No shared contract, CLI, schema or target
support change; RB-03/04/06/08/09/10/11 retain their existing meaning. An explicit
disposable-guest invocation opts into candidate lifecycle calls for that phase;
saved records alone do not authorize a later phase. Preview/completion are read-only.
Machine lifecycle recovery and independent first-logon visuals remain distinct.

Rechecked contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645` and Fedora files
`ride.sh` SHA-256 `49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`
and `lib/v3/common.sh` SHA-256 `8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
These match the prior comparison at revision
`3d9406e3888122d1407652336859e6217c09bcaa`; the current peer Git revision query was
sandbox-denied, so this review pins the read file hashes, not a newly verified HEAD.
No automated shared-conformance or Fedora visual parity claim is made.

Owner: RIDE Windows maintainer. Reason: retain evidence between the machine
change, separately owned first-logon checks and recovery. Status: 24/24 new source
cases and the real input/parser checks pass in both shells. Native tests are unrun.
Follow-up: [wallpaper guest and first-logon acceptance](image-personalization.md#wallpaper-guest-acceptance-phases).
Review trigger: retained dispatch, account/profile fixture ownership, native visual
or recovery results, changed sources/targets or release review.
