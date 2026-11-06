# Windows and Fedora CLI alignment

Machine-readable capability and difference dispositions are maintained in the
[capability register](models/capability-differences.json).

## Windows ALIGN-03 declared unset, 2026-11-06

Windows CLI 0.23.0 requires an operation to name its override-removal state.
Of 479 operations, 219 qualify. The other 260 refuse `unset`, including on
preview. Windows rejects a separately supplied `-State`. The planner checks
the declaration before observing a target or opening a run. The desktop-user
worker rechecks the declaration before applying its saved plan item. See the
[Windows implementation](https://github.com/tjuuljensen/ride-windows/commit/e195f49b727b80e53947c665d53e6782012266cb)
and the [per-kind review](migrations/settings-post-migration-review.md#per-operation-unset-review-2026-11-06).

At the final implementation revision, Windows PowerShell 5.1 and PowerShell 7
each passed the 16 tests in UnsetDeclaration, BehaviorContract and AlignmentDrift.
They cover plain and preview refusal, legacy library explicit set, malformed
declarations, BCD state selection and completion. Repository validation passed
for 479 operations, nine groups, six profiles and 415 PowerShell files. The
generated operation reference matched the catalog. These checks used planning
and mocked execution boundaries. Native boot and setting acceptance remain
separate.

Fedora's published migration revision `df006ab9237459c588cda675650eae1a89aba26d`
also requires a declared removal state. Both clients retain contract 1.1.0.
Fedora completed its five owned-file reviews. Its [setting lifecycle record](https://github.com/tjuuljensen/ride-fedora/blob/df006ab9237459c588cda675650eae1a89aba26d/docs/windows-alignment.md#align-03-setting-lifecycle-decision-2026-11-05) links the Fedora 44 Workstation and Server removal and recovery results. Pair the
declared and missing-declaration cases under RB06-01, including explicit set
and saved recovery. Native feature acceptance remains tracked separately.

Fedora reported 40 passing mocked Fedora 44 CLI tests at its local commit
`c658c5484b84891e082f2de60319484d0f2e0013`. In both profile orders preview
and execution selected the dependent first. Preview created no journal, the
unrelated package and setting were preserved, and a bad later ID or selected
cycle failed before the first uninstall. Windows published the previous
removal change on its migration branch and reran 88 tests in each
PowerShell edition. Fedora owns publication of its tested commit, followed
by the paired RB07-01 fixture update. See the
[Fedora result](https://github.com/tjuuljensen/ride-windows/issues/8#issuecomment-6686606738)
and [Windows rerun](https://github.com/tjuuljensen/ride-windows/issues/8#issuecomment-6686749175).

## Windows ALIGN-03 explicit removal, 2026-11-06

Windows CLI 0.22.0 implements RB-02/07 under the adopted contract 1.1.0.
The tested implementation is [bcfa38ad](https://github.com/tjuuljensen/ride-windows/commit/bcfa38ad0460987c14387f1dc7a819274c820a85).
Through CLI 0.21.0 bare `remove` selected the default profile. Starting with
0.22.0, callers must name the ID or profile explicitly. To retain the earlier
selection, use `remove -Profile .\profiles\default.psd1`. A missing or blank
selection, a mixed ID/profile selection, or a supplied state fails before the
engine loads, including during preview. Existing explicit ID/profile calls and
saved-run recovery keep their meanings.

| Windows CLI case (mocked handlers) | Result |
| --- | --- |
| Profile lists alpha, then beta; beta depends on alpha | Preview showed beta then alpha, with zero uninstalls and zero run records. Execution removed beta then alpha and recorded both completed. |
| Profile lists beta, then alpha | Same preview, uninstall order and completed journal. In both runs the third installed package remained present and the ordinary setting received zero writes. |
| Valid package followed by unknown ID | Refused before the first uninstall. Both alpha and beta remained installed and no run was created. |

Windows PowerShell 5.1 and PowerShell 7 each passed all 88 cases in the
`ProfileRemoval`, `CliShouldProcess`, `PackageDependencyPlanning`,
`BehaviorContract` and `AlignmentDrift` Pester suites (5.7.1, TestRegistry
disabled). These are CLI and engine tests with synthetic package state.
The Windows owner has completed this removal batch. Fedora revision
`eed301680a9f8d2bf22e107d533b77016ffafa84` already requires an explicit
selector. The [comparison below](#contract-recheck-2026-11-06) records its
ordering failure. Fedora owns its fix and matching results in
[issue #8](https://github.com/tjuuljensen/ride-windows/issues/8). Review again
on the peer result and when adopting paired RB07-01 fixtures under ALIGN-05.
The subsequent [declared unset review](#windows-align-03-declared-unset-2026-11-06) records the Windows result.

## Contract recheck, 2026-11-06

The published `codex/ride-v3-migration` branches matched the reviewed checkouts:
Windows `233633af9213f11750fb1ead835f3c5d2e5390bc` and Fedora
`eed301680a9f8d2bf22e107d533b77016ffafa84`. Since the
[November 5 review](#contract-recheck-2026-11-05), Windows committed that
review and Windows 11 Pro component acceptance work. Fedora's revision and
the Windows CLI, engine and catalog match the previous comparison. Under RB-12
these are documentation and native evidence changes with shared behavior unchanged.

The Windows drift report returned `Current`. Both clients pin contract 1.1.0
(`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`).
Both scenario files and adapter pins match revision 1.1.0
(`9353770486CFC7768F8D2DD4BF0DB646FFF894E591974F07409035DF7F2D3632`).
The eight Windows contract and drift tests passed in PowerShell 7. Fedora's
validators passed for all 12 scenario mappings and 21 register entries.
Both consumer references still have a null `publishedCommit`. The canonical
file at [Windows commit 1871f7bc](https://github.com/tjuuljensen/ride-windows/blob/1871f7bcf0a9374351ffda2f8fc443c4a68cdcf5/docs/models/ride-behavior-contract.md)
has the same Git blob as the current contract and is reachable from the published
Windows branch. The maintainers can use that immutable source for ALIGN-09.

**RB-07 removal recheck.** In a disposable Fedora WSL copy, both synthetic
packages began installed and beta depended on alpha. The same explicit
`remove --profile` invocation produced these results with mocked providers:

| Profile order | Exit | Journal, in execution order | Still installed |
| --- | ---: | --- | --- |
| alpha, beta | 0 | beta changed, alpha changed | Neither |
| beta, alpha | 1 | alpha changed, beta failed | beta |

Keep Fedora profile-removal promotion gated on dependency-safe planning.
Both adapter owners should exercise both orders through explicit profile removal
under ALIGN-03/05. Two Windows `-WhatIf` checks using a copied CLI and a mock
engine confirmed that bare removal plans against `profiles/default.psd1` and
that `remove fake.package -State Enabled` reaches package removal planning.
The explicit-selector transition and irrelevant-option refusal remain open.

## Contract recheck, 2026-11-05

Compared the local migration branches at Windows
`6d7435bc075f61a26c6f6223a0d2d3622de5d60b` and Fedora
[`eed301680a9f8d2bf22e107d533b77016ffafa84`](https://github.com/tjuuljensen/ride-fedora/tree/eed301680a9f8d2bf22e107d533b77016ffafa84).
The Windows drift report returned `Current` against Fedora's consumer reference.
Both adopt contract 1.1.0 at SHA-256
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`.
Both scenario files and adapter pins match revision 1.1.0, 12 scenarios, SHA-256
`9353770486CFC7768F8D2DD4BF0DB646FFF894E591974F07409035DF7F2D3632`.
Both references leave immutable publication open under ALIGN-09.

**Confirmed RB-07 failure.** In Fedora's existing mocked CLI fixture, declare
`package.beta` dependent on `package.alpha` and mark both installed. Supply an
explicit profile listing beta first, then alpha. Running `remove --profile
<fixture> --allow-candidate` exited 1. Its journal recorded alpha as `changed`
and beta as `failed`. Only beta remained installed. `ride_remove_profile` reverses
the input list, so the failure occurs after it has removed the prerequisite.
The current shared case RB07-01 and Fedora's mapped test use the opposite input
order and pass. Fedora owns dependency-safe planning and preflight. Both adapter
owners should cover both input orders before promoting profile removal under
ALIGN-03/05. The [capability register](models/capability-differences.json)
tracks this as `profiles.remove-dependency-order`.

| Area | Behavior at the reviewed revisions | Remaining work |
| --- | --- | --- |
| Explicit selection and removal (RB-02/07) | Fedora requires a package ID or explicit profile and filters profile removal to reversible packages. Windows rejects a mixed ID/profile but bare `remove` selects `profiles/default.psd1`. Windows accepts `-State` on remove and ignores it. Profile removal can include Windows capabilities and Defender exclusions while help describes profile-selected packages. | Windows owns the bare-remove transition, irrelevant-option refusal and accurate help. |
| Unset and restore (RB-06/09) | Fedora requires a declared `unsetState`. Windows uses `UnsetState` for profile settings, chooses the first null state for registry values, and selects states by kind for some other operations. | Review each Windows override-removal mapping and Fedora's remaining owned-file cases. Preserve saved-state recovery. See the [Fedora lifecycle decision](https://github.com/tjuuljensen/ride-fedora/blob/eed301680a9f8d2bf22e107d533b77016ffafa84/docs/windows-alignment.md#align-03-setting-lifecycle-decision-2026-11-05). |
| Preview, acquisition and targets (RB-03/04/05/08) | Both clients preview candidates without execution opt-in and separate eligible downloads from VM execution acceptance. Fedora checks the download target and provider. Its restore-preview identity checks include iBus. Both adapters cover an already-installed package outside its target, with Fedora limiting this exception to eligible RPM handlers. | Retain paired gate and recovery coverage under ALIGN-04/05. Windows' explicit unsupported-target exploration still has a separate [promotion decision](#unsupported-target-exploration-2026-11-02). |
| Discovery and automation (RB-10/11) | Both implement explicit status ID/view selectors and schema-1 stream inspection. Windows returns PowerShell objects and Fedora `show --stdin` emits JSON records. | Add paired show scenarios under ALIGN-05/08 and review completion and output before release. |

**Checks run.** Windows Pester 5.7.1 passed all 86 contract, drift, show and CLI
tests in each of Windows PowerShell 5.1 and PowerShell 7.6.5. The adapter-selected
tests also passed in PowerShell 7 (18 expanded cases). Fedora's validators passed
for all 12 scenario mappings and 21 register entries. In a disposable Linux
copy, 24 mocked Fedora tests passed, covering the adapter, its supplemental cases
and focused show/status/unset cases. The reversed-profile reproduction above was
a separate run. These checks used test doubles. Native target acceptance and
the final release review remain separate.

Classification under RB-12 is shared behavior unchanged. The failures concern
implementation of existing requirements. Recheck on the linked fixes and before
promotion. Earlier dated comparisons below describe their reviewed revisions.

## Automatic local image hashes, 2026-11-04

Windows now calculates a missing image hash during selection for default wallpaper
and lock-screen images. An explicit hash still pins the content. Planning and
profile status may read the selected local PNG; they write nothing. Execution
rechecks the resolved hash, and saved recovery records retain the same identities.
Existing explicitly pinned profiles and saved runs need no migration.

Reviewed contract 1.1.0 SHA-256
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`
and Fedora HEAD `a0558a2c9ea760828a422b7bacdf63c40ce4b36b`, its pinned reference,
and catalog/lib-v3 image-provider coverage (no corresponding provider). This is a
Windows-native input convenience under RB-02/03/07/09, with no shared-contract
revision or package acquisition change. Owner: RIDE-Windows maintainers.
Follow-up: [image input and recovery guidance](image-personalization.md).
Review trigger: shared image provider semantics or changes to execution-time
verification/recovery. Other target acceptance remains unchanged.

## Default-image catalog integration, 2026-11-03

Windows adds native `DefaultImage` providers and optional `ImagePath`/`ImageSha256`
selection fields in schema 1. Existing profiles, IDs and saved snapshots retain
their meaning. CLI `set`, profile `apply`, inspection and saved-run `restore`
use the same pinned local inputs; no network source is introduced. Previews
remain read-only, all selected PNGs are preflighted before mutation, and guarded
recovery binds the outer run to private child receipts. Shared-key image writes
restore in reverse capture order. Older standalone image receipts remain usable
through their original handler entry points.

Compared canonical contract 1.1.0 SHA-256
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`
and Fedora HEAD `419f018e5173a865ee4b263dcc6edc24140d92da`, including its pinned
contract reference and catalog/lib implementation. Fedora has no corresponding
wallpaper/lock-screen provider; native provider coverage is intentionally local.
This is additive provider input and RB-03/04/07/08/09 implementation, not a
change to shared lifecycle meanings. No contract revision or Fedora parity claim.
Owner: RIDE-Windows maintainers. Follow-up: [image scope and evidence](image-personalization.md).
Review trigger: target promotion, shared image selection semantics or recovery
schema changes. The new adapter has mocked both-shell regression coverage;
previous native visual evidence is reused, not represented as a new catalog VM run.

## Native fast-track scope decision, 2026-11-03

The user retired all Windows VMware installation/profile/path support and chose
install, bounded startup without observed errors and uninstall for ordinary
user-mode downloaded-tool fast-track acceptance. Product features move to v3.1;
exact sources, Defender and declared recovery remain required. Earlier file-only
results do not imply startup acceptance. This is Windows-native selection and
acceptance scope under RB-08/09/11, with no shared CLI or state-schema change.

Compared canonical contract 1.1.0, SHA-256
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`, with Fedora
HEAD `1243f36cc27c4b9ef9569cb7f168bd79e1e92c8a` and working-tree `ride.sh`
SHA-256 `A2A49A88D6783CB7D33B103CE27FF5D86A851FB02973C4381BD75CAED22AEC43`.
Fedora retains native candidate opt-in and unsupported-handler refusal; it has
no obligation to copy Windows product coverage. Its existing uncommitted
contract-reference/alignment edits were preserved. No contract amendment or
cross-platform acceptance claim is introduced. Owner: RIDE-Windows maintainers.
Follow-up: [fast-track register](migrations/package-fast-track-register.md).
Review trigger: target promotion or changes to source, privilege or recovery
boundaries. Startup source checks and native acceptance remain separate.
## Portable path validation implementation, 2026-11-03

RB-07/08/09/11 shared behavior is unchanged. Windows replaces repeated provider
lookups with direct filesystem attribute reads while rechecking every ancestor
on every call. No cache or reparse-point exception is introduced; only missing
paths are eligible for creation, and access/I/O failures propagate. Saved-state
schema, exact file recovery and public CLI remain unchanged. The pinned contract
1.1.0 and Fedora archive/owned-directory guards were compared; Fedora also rejects
symlinks in the reviewed archive snapshots and owned-directory paths. This is not
a claim of identical APIs or complete cross-platform conformance.

[Evidence](archive/evidence/portable-path-optimization-2026-11-03.json) records
compared hashes, 185 focused passing cases per shell, full 531-member synthetic
WFN recovery in both shells and 34 native offline Caffeine checks with verified
recovery. WFN native acceptance and other targets remain separate. Owner:
RIDE-Windows maintainers. Follow-up: [remaining package acceptance](migrations/migration-completion-reassessment-2026-11-02.md#component-specific-acceptance-status).
Review trigger: path ownership rules, saved-state schema, filesystem support or
target-promotion changes. No shared-contract amendment is required.

## Expiring client capability acceptance queue, 2026-11-03

Windows-only test transport preparation under RB-03/04/05/08/09/10/11: fixed
OpenSSH Client/RSAT phases bind explicit Windows Update acquisition to the
registered disposable target, pinned source, expiring admission and retained
recovery. No public RIDE command, catalog schema, source fallback or target
support changes. The ordinary-account client starts only a separately registered
fixed task; it does not elevate itself or accept a script callback. Timeout
preserves servicing uncertainty and the native reset guard. The pinned contract
1.1.0 and compared Fedora source hashes are recorded in
[source evidence](archive/evidence/client-capability-queue-source-2026-11-03.json).
No shared-contract amendment is required. Owner: RIDE-Windows maintainers.
Follow-up: [attended activation and native acceptance](windows-component-inventory.md#expiring-capability-queue).
Review trigger: protected activation, source/configuration changes, native
servicing/recovery results or target promotion. Existing overnight tasks remain
unchanged; source tests do not establish that this new task is installed.

## Review basis and policy before adoption

Windows was inspected on `codex/ride-v3-migration`, based on `59d1a80`, with
uncommitted changes including candidate opt-in. Fedora's local branch reference
was `codex/ride-v3-migration` at `5c0ac02`. Fedora Git status was unavailable to
this session, so its checkout is not asserted clean. The
[source evidence](archive/evidence/ride-cli-alignment-2026-11-01.json) records
hashes of the actual files reviewed. This is source inspection, not fresh native
acceptance, and it does not transfer support between platforms.

At the comparison baseline, Fedora already had the explicit policy:

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
applied the shared portfolio rules, but had no equivalent reciprocal Fedora
CLI/schema review requirement. That arrangement was asymmetric and mainly
triggered by package migrations. It could miss changes to flags, preview, settings,
argument parsing and recovery. Neither inspected validation workflow runs a
shared cross-repository CLI conformance suite.

## Current command envelope and actions

This matrix describes the November 1 baseline. Use the
[November 6 recheck](#contract-recheck-2026-11-06) and the subsequent
[Windows removal batch](#windows-align-03-explicit-removal-2026-11-06) for current findings.

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
| Output and completion | PowerShell objects for list/search and schema-1 show results, including show pipeline input; status still formats output. Catalog-driven parameter completion. | JSON for show, TSV when redirected for tables; static command suggestions and local JSON completion. | Keep native human output; define a small opt-in shared JSON result contract for tooling. Windows show objects alone do not complete ALIGN-08. Derive or test command/option completion against the parser. |
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

## Adopted alignment policy, 2026-11-01

The [shared behavior contract 1.0.0](models/ride-behavior-contract.md) is now the
canonical RIDE contract. Both repositories record the same version/SHA-256 and
have reciprocal AGENTS rules covering shared CLI, settings, schema meanings,
acquisition, planning, acceptance, privilege and recovery. Either repository may
originate changes; Windows is the host, not the presumed correct implementation.
The contract owns the review/versioning procedure; do not duplicate it here.

The earlier policy inventory above describes the comparison before adoption.
ALIGN-01 and ALIGN-02 are complete as source policy. Digest references pin the
unpublished contract bytes; immutable publication remains ALIGN-09. Adoption
neither changes runtime behavior nor establishes conformance or native support.

## Remaining final-v3 work

The [Windows task list](../TODO.md#cross-platform-alignment-for-final-v3) and
[Fedora plan](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/MIGRATION-PLAN.md#cross-platform-alignment-for-final-v3)
track paired ALIGN-03 through ALIGN-09 work with completion criteria. These tasks
cover behavior fixes, shared native test scenarios, a structured difference
register, linked-change reviews, drift reporting, usage/output improvements and
final release verification. No synchronized commits or identical release numbers
are required. Temporary gaps need explicit disposition before final v3; ordinary
platform differences and native support remain separate.

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

## Tracked implementation order

| Priority | Work | Completion evidence |
| --- | --- | --- |
| Complete in source | ALIGN-01/02: shared contract, digest references and reciprocal AGENTS links. | Both clients adopt contract 1.0.0. Runtime conformance and the structured difference register remain open. |
| Next | Fix ambiguous/ignored arguments, define profile removal eligibility, and replace Fedora's generic disabled mapping for unset. | Focused mocked tests prove refusal before mutation and preserve published explicit set/recovery paths. |
| Next | Agree candidate preview and acquisition policy; then make the small coordinated behavior changes. | Matching shared scenarios pass, with target/identity checks retained and no preview writes. |
| Then | Add the pinned scenario suite, completion checks and drift-reporting workflow. | Both native CI jobs run the same contract revision; a deliberate mismatch is detected. |
| Later | Improve explicit ID/view status selectors, profile convenience and structured output. | Compatible command examples and versioned output tests; no forced installer or catalog parity. |

The follow-up changes maintainer policy and v3 task records in both repositories.
No runtime code, CI enforcement or acceptance status changes. Documentation,
digest and link checks validate adoption; implementation and disposable-target
acceptance remain separate follow-up work.

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

The 2026-11-03 native-scenario preparation compares adopted contract 1.1.0
(`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`)
with current Fedora `ride.sh`/`common.sh` hashes recorded in
[117-case source evidence](archive/evidence/offline-target-exploration-source-2026-11-03.json).
Fedora still rejects undeclared targets separately from candidate permission.
The existing offline Caffeine route now tests a synthetic minimum-build
restriction with real Windows engine/file recovery, actual-target audit and fresh
opt-in. Offline missing/corrupt/omitted/target mismatch refusals must survive the
override. Native execution is pending; this adds no shared interface or target
support. ALIGN-TARGET-01, its owner and promotion/release review trigger remain open.

The [follow-up native run](archive/evidence/offline-target-exploration-night-native-2026-11-03.json)
passed all 34 checks, including actual-target apply/restore audits, fresh opt-in,
preview, exact original-absence recovery and all offline refusals with the switch.
The fixture only raises Caffeine's minimum build in memory; published source and
support metadata remain unchanged. This resolves that narrow native evidence gap;
ALIGN-TARGET-01 and broader OS/handler acceptance remain open before promotion.

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

## Pro default lock-screen acceptance gap, 2026-11-04

Difference ID: `windows.default-lock-screen`. Classification: Windows-only native
backend/recovery gap under RB-04/08/09/11. A focused Windows 11 Pro build 26300
acceptance applied the candidate CSP registry/file lifecycle, but the selected
image did not appear at the signed-out sign-in screen. Exact native restore
passed and the guest checkpoint was restored after verified evidence export.
That run did not reproduce the full v2 method, which also replaces
`C:\Windows\Web\Screen\img0.jpg` and recursively resets ownership/ACLs under
`C:\ProgramData\Microsoft\Windows\SystemData`. The operator reports that the
full v2 `SetLockScreen` method works on the Pro VM. The v3 source candidate now
captures and replaces Windows `Web\Screen\img0.jpg`, applies the Pro CSP tuple,
and can restore the captured bytes/metadata under conflict checks. It omits the
recursive `SystemData` ownership/ACL reset because exact bounded recovery is
unavailable. Native visual acceptance has not yet been rerun. The initial test
does not establish platform-level Pro incompatibility.
Enterprise and Education continue using the `LockScreenImage` policy route. No shared verb,
catalog schema, profile meaning, contract version/digest or Fedora behavior
changes.

Microsoft's Personalization CSP reference lists managed-use conditions for Pro.
The operator's v2 result establishes that the legacy file replacement,
direct-registry and recursive cache-refresh procedure works on this test image.
It does not establish whether the bounded v3 `img0.jpg` replacement works
without that ACL reset. Reviewed
pinned behavior contract 1.1.0 SHA-256
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938` and the
peer catalog execution boundary. Compared current source hashes: peer `ride.sh`
`06357DA3A869C8F2001A80847E22D0F9A71A166BC4C7F9016C8E310FF12EC863` and
`lib/v3/catalog.sh`
`8897669C1EADAF21D9BE3B8C54FF86AE977B500E7844E617710C79B194C43C6F`. Fedora
has no matching native wallpaper/lock-screen provider; its catalog target and
setting lifecycle stay platform-owned. Git metadata access to the peer checkout
was denied, so no peer revision is asserted. Automated shared conformance remains
pending.

Owner: RIDE Windows maintainer. Reason: the original v3 test omitted v2's
`img0.jpg` replacement and cache-refresh side effect, so it cannot reject Pro
support. Follow-up: [edition-support
decision](migrations/component-edition-support-decisions-2026-11-04.md).
Review trigger: repeatable Pro visual/lifecycle acceptance or a bounded,
exactly recoverable implementation of the remaining SystemData ACL reset.

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

## Owned wallpaper user fixture, 2026-11-02

Adds Windows-only disposable Control/FirstLogon/Recovery account fixtures for the
existing first-logon wallpaper scenario. No shared CLI/catalog/profile schema,
contract or supported-target change. RB-03/08/09/10/11 retain their meaning:
read-only preview/completion, exact guest/privilege checks, private intent before
mutation, owned SID/path cleanup and source/native evidence separation. Each
mutation requires its explicit correlated disposable-target invocation; saved
records alone do not authorize future changes. Fixture deletion is separate from
RIDE's captured setting restore and never serves as a visual acceptance pass.

Rechecked canonical contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645` and the prior
Fedora comparison files: `ride.sh`
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`;
`lib/v3/common.sh`
`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
The reviewed peer privilege/candidate/state boundaries match the preceding
comparison; this run pins the file hashes and does not claim a newly queried peer
HEAD or an automated shared-conformance pass. No Fedora account-fixture parity
or Windows native support is inferred.

Owner: RIDE Windows maintainer. Reason: first-sign-in acceptance requires owned
users and verified profile cleanup while preserving the initialized control user.
Status: 32/32 source cases in each shell, dependency/command-metadata checks and
native-wrapper compilation pass; actual local-account/profile APIs remain unrun.
Follow-up: [owned wallpaper test-user procedure](image-personalization.md#owned-wallpaper-test-users).
Review trigger: retained dispatch/credential handling, native account/profile
behavior, first-logon results, source/target changes or release review.

## Retained wallpaper host dispatch, 2026-11-02

Adds Windows-only host dispatch for the prepared machine and owned-user phases.
No shared CLI/catalog/profile schema, supported-target or contract change.
RB-03/08/09/10/11 preserve preview, target/privilege gates, captured recovery and
source/native evidence separation. Explicit phase invocations use a retained
lease; a verified export precedes owned-user deletion and checkpoint cleanup.
Synthetic SecureString input is separate from descriptors and evidence. Native
transport, account/profile behavior and interactive first desktops remain unrun.

Rechecked contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645` and peer files
`ride.sh` (`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`)
and `lib/v3/common.sh`
(`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`).
These preserve the preceding comparison at previously recorded Fedora revision
`3d9406e3888122d1407652336859e6217c09bcaa`; this run does not claim a freshly
queried peer HEAD, Fedora fixture parity or automated shared conformance.

Owner: RIDE Windows maintainer. Reason: preserve first-sign-in evidence across
machine changes and owned-user cleanup. Status: 34/34 focused source cases per
shell plus actual source/input gates and installed read-only Prepare preview.
Follow-up: [wallpaper host procedure](image-personalization.md#wallpaper-retained-host-dispatch).
Review trigger: native transport/lifecycle/visual acceptance, phase or recovery
changes, target changes or release review. Existing elevated execution remains
unavailable; no new UAC request or installed controller mutation occurred.

## Retained font host dispatch, 2026-11-02

Windows-only acceptance preparation; shared behavior unchanged. No CLI/catalog,
profile, supported-target or contract revision. RB-03/08/09/10/11 retain preview,
native privilege/target guards, captured recovery and separate evidence claims.
The versioned input manifest pins the approved 14 fonts and original license.
One guest invocation keeps install/removal and both restores within the existing
account/session recovery boundary. Current-session acceptance is distinct from
restart, other sessions and active consumers; checkpoint reset is not a restore pass.

Rechecked contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645` and Fedora
`ride.sh` (`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`),
`lib/v3/common.sh`
(`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`).
Reviewed the peer's privilege, target and candidate gates again. Previously
recorded peer revision is `3d9406e3888122d1407652336859e6217c09bcaa`; no fresh
peer HEAD or automated shared-conformance claim is made.

Owner: RIDE Windows maintainer. Reason: stage only exact approved font inputs and
retain evidence through explicit VM cleanup. Status: 32/32 focused cases per
shell, real source-identity gates and installed Prepare preview pass; native
execution remains pending. Follow-up: [font host procedure](machine-fonts.md#retained-host-dispatch).
Review trigger: native dispatch/current-session recovery, cross-session/restart
or consumer evidence, source/target/recovery changes, or release review.

## Retained synthetic WLAN host dispatch, 2026-11-02

Windows-only acceptance preparation; shared behavior unchanged. No public
CLI/catalog/profile, supported-target or contract revision. RB-03/08/09/10/11
retain preview, native privilege/target guards, saved recovery and separate
evidence claims. Prepare returns only guest WLAN interface GUIDs/states; Lifecycle
requires an explicit interface from the same request/lease observation. Missing
service, interface or hardware is NotRun. Saved-data completion queries no VM.
Synthetic profile lifecycle does not establish connectivity or general DACL
drift recovery. Guest/account-bound DPAPI export is not portable recovery.

Rechecked contract 1.0.0 SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645` and Fedora
`ride.sh` (`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`),
`lib/v3/common.sh`
(`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`).
Reviewed the peer privilege, target and candidate gates and pinned contract
procedure again. Previously recorded peer revision is
`3d9406e3888122d1407652336859e6217c09bcaa`; no fresh peer HEAD or automated
shared-conformance claim is made.

Owner: RIDE Windows maintainer. Reason: run generated synthetic settings on an
observed disposable WLAN interface while retaining private recovery evidence.
Status: 37 host-route plus 18 guest-runner source cases pass in each shell;
source dependency/generation checks and installed Prepare preview pass. Actual
WLAN availability, DPAPI/remoting and lifecycle acceptance remain unrun.
Follow-up: [WLAN host procedure](wireless-profile-inventory.md#retained-host-dispatch).
Review trigger: native interface observation, synthetic lifecycle/recovery,
source/target/completion changes, or release review.

## Show pipelines and native output, 2026-11-02

`SHOW-01` / ALIGN-08-W: compatible Windows-native extension under RB-02/03/10/12,
implementing the adopted 1.1.0 show contract. CLI 0.18.0 accepts strings and objects with
`Id` through a show-only pipeline binding. Explicit positional/named IDs keep
their meaning. Other commands reject pipeline input before dispatch. Engine
0.32.0 emits one schema-1 `RIDE.ShowResult` object per selection, with nested
group member observations. The [output contract](catalog-show.md) declares
stable fields and migration from formatting records. Existing metadata and
observation handlers, candidate gates and saved-state recovery are unchanged.

Initially reviewed pinned contract 1.0.0, SHA-256
`80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645`.
The concurrent contract work then deliberately adopted 1.1.0. Rechecked its
show selection/output/error rules and verified the new pinned digest
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`.
Fedora's local branch ref is `3d9406e3888122d1407652336859e6217c09bcaa`;
reviewed working-tree `ride.sh` (`ride_show` and dispatch), SHA-256
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266`,
and `tests/test_v3_cli.py`, SHA-256
`61BDFC027401A64F1CC3248201C6FF82DBCA8E14DCF18F9A0ACAA874A22FE07C`.
Fedora takes an explicit ID and emits JSON with `observedState` and
`availableSources`; it does not consume PowerShell pipeline objects. This
native input/output difference is intentional, owned by the RIDE Windows
maintainer, to support ordinary PowerShell composition. It does not alias
Windows variants to Fedora source providers or claim a shared JSON schema.

Follow-up: [Windows ALIGN-08](../TODO.md#cross-platform-alignment-for-final-v3)
and [Fedora ALIGN-08](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/MIGRATION-PLAN.md#cross-platform-alignment-for-final-v3)
retain the paired usage/shared automation work. Review this difference when
that interface is designed, schema fields change, or final v3 is reviewed.
Validation passed 14/14 isolated show/input tests and 131/131 existing search,
CLI dispatch, setting presentation, BitLocker and Shell-folder cases in each
of Windows PowerShell 5.1 and PowerShell 7. The show fixture was corrected and
rerun after missing validation dependencies in its initial library setup;
all final cases pass. PowerShell parsing and focused diff checks pass. These are native
PowerShell source checks with mocked state, not shared conformance or new
Windows target acceptance. No legacy outcome is migrated by this CLI change.

## Show pipeline contract 1.1.0, 2026-11-02

ALIGN-08-W / owner: RIDE Windows maintainer. Compatible extension of
RB-02/03/10/11, authorized for documentation by the user. The canonical
[show pipeline contract](models/ride-behavior-contract.md#show-pipelines-and-native-structured-output)
now defines ordered read-only ID streams, empty/error behavior and native
PowerShell object / Bash JSON output. Contract 1.1.0 is the completion target;
existing positional syntax and saved-run recovery remain intact. Native transport
and field names are intentional platform differences, not an identical JSON schema.

Windows pipeline input/output is under implementation in the main workstream;
its [native result contract](catalog-show.md) and focused tests own implementation
status. This documentation run makes no new runtime or acceptance claim.
Fedora still requires a positional ID and emits catalog JSON with observedState
and availableSources. Explicit --stdin, compact JSON records, a native result
schema, help/completion and paired tests remain
[ALIGN-08-F](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/windows-alignment.md#show-pipeline-contract-110-2026-11-02).

Reviewed the previous contract 1.0.0 digest
80B912E668F948F77EE9EF05F2D10254F83F08EB42C5FA504FE737AEC25BD645 and Fedora
commit 3d9406e3888122d1407652336859e6217c09bcaa, with ride.sh SHA-256
49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266.
Windows working-tree inputs inspected: ride.ps1 SHA-256
6D31628643179E352C465590389116EDEEE65B845C504416C676EDC2BC4424AF and
modules/RIDE.Engine.psm1 SHA-256
2391564E3028AA32CA74241ACC513B5D87D10C7B58E1B062B8AACFD4BBD4F905.
These are review snapshots; the concurrent implementation may advance them.
Both consumer references adopt the new canonical digest. Existing scenario
revision 1.0.0 is repinned without changing its cases; this does not add show
pipeline coverage or establish automated shared conformance. The capability
register's contract version follows the new pin; unrelated source reviews remain
as previously dated.

That 2026-11-02 snapshot preceded shared scenario revision 1.1.0,
recorded below. Next actions: run the mapped Windows Pester suite,
implement the Fedora show-pipeline sibling, and add paired ALIGN-05
fixtures for the remaining acceptance cases. The Fedora UID 0 namespace
preview case is recorded below. Review when either client changes its
selection, output, or error semantics, when paired fixtures are added,
or before final v3 release. Keep affected capability promotion gated on
the documented gaps. This CLI contract work changes no legacy migration
outcome or estimate.

## Overnight native package evidence, 2026-11-02

Windows-only execution/evidence update; shared behavior unchanged. Reviewed the
currently adopted contract 1.1.0, SHA-256
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`, and peer
privilege, target and candidate gates. Fedora `ride.sh` remains
`49C3F8D987C98F5C8E7FA1F1EBCA662A9AD4CF56B638C43D642A2AB2965E3266` and
`lib/v3/common.sh` remains
`8E8692CAECF10170FAC4388E37CF56D5FE4D0979EF5C5A99FEE3CA064E75B3D1`.
Previously compared revision is `3d9406e3888122d1407652336859e6217c09bcaa`;
no fresh peer HEAD or automated conformance claim is made.

System Information eXtra, TAPI Monitor, EXE Explorer and HexEdit passed native
Windows 11 build 26300 lifecycle and exact owned-file recovery with active/no-alert
Defender evidence. Explicit candidate execution remains separate from published
support. Checkpoint cleanup follows RIDE recovery rather than replacing it.
Owner: RIDE Windows maintainer. Reason: close missing current native/Defender
evidence through the approved unattended route. Follow-up:
[overnight evidence](archive/evidence/overnight-unattended-execution-proof-2026-11-02.json)
and the [remaining-test assessment](migrations/migration-completion-reassessment-2026-11-02.md#overnight-execution-resumed-2026-11-02).
Review trigger: changed source/artifact/target, catalog promotion or release review.

## Retained VM dispatch recovery and Fedora verb review, 2026-11-02

Windows test infrastructure now binds the exact imported automation module,
avoiding ambiguity when the installed controller and checkout module coexist.
Font Prepare can resume its own unstarted preparation only with the matching
private hold/session, unchanged target and font selection, valid cached bytes,
an Off guest and no checkpoint intent. It preserves the original snapshot and
failed-phase record. RB-09 recovery and RB-08 identity boundaries were reviewed
against contract 1.1.0 and the peer hashes recorded above. This changes disposable
test orchestration only; public CLI, catalog and production recovery are unchanged.
The 41 focused source cases pass in both native PowerShell editions; native
retry and lifecycle acceptance remain separate. Owner: Windows maintainer;
follow-up: [font dispatch procedure](machine-fonts.md). Recheck after a change
to hold ownership, retry eligibility, snapshot identity or checkpoint cleanup.

The user also identified Fedora's additional public `deploy` and `update` verbs.
Current `ride.sh` restricts deploy to Docker Engine and update to the whole-system
DNF5 operation. These are production operations, not test states. RB-01 permits
additional native capabilities, so their presence alone is not a contract breach.
However, Fedora's alignment discussion does not explain the choice of separate
verbs or their shared-interface implications. Joint maintainers should review
whether these remain deliberate native extensions or belong under shared verbs,
including compatibility for existing callers. Follow-up: the Fedora
[system/security decision record](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/migrations/system-security-core.md)
and its alignment entry need an explicit disposition before affected CLI promotion
or final release review. No Fedora command is removed by this Windows test run.

## Image policy native readback repair, 2026-11-02

Impact: Windows-only provider repair, with unchanged public command, desired
state, ownership and saved-run schema. After a real default-lock apply wrote the
policy, the second PowerShell-provider lookup for its ACL reported the key absent.
Both image handlers now read values and Owner/Group/Access from the same opened
registry handle. No permissions are weakened and incomplete applies still retain
their records. Guest diagnostic results preserve bounded exception detail.

Reviewed RB-03, RB-08 and RB-09 against contract 1.1.0, digest
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938`.
The peer checkout changed independently during this run; newly compared `ride.sh`
digest is `A2A49A88D6783CB7D33B103CE27FF5D86A851FB02973C4381BD75CAED22AEC43`
and `lib/v3/common.sh` is
`A46FDA2DB3BA37AB22616DB723E11960B4F02043CAF53DD7D3D6AA2106A87878`.
Its root/user privilege, target and candidate gates were re-read. There is no
Fedora Windows-registry provider to change, and no shared contract amendment.
Owner: Windows maintainer. Follow-up: native image apply/repeat/exact restore and
the separate visible-effect requirements in [image personalization](image-personalization.md).
Review trigger: provider, snapshot permission semantics, recovery or supported
target changes. Source regression remains separate from native acceptance.

## Font recovery evidence separation, 2026-11-03

Impact: Windows guest-test reporting only. Exact file, registration and permission
readback now permits the independent saved-restore checks to proceed after a
native font-name mismatch. That mismatch remains a failed overall acceptance
result; durable recovery does not certify native availability. Production handler,
saved-state schema, CLI and support declarations are unchanged.

Reviewed RB-08/09/11 against contract 1.1.0 and the same canonical digest and
Fedora `ride.sh`/`lib/v3/common.sh` hashes recorded immediately above, rechecked
for this run. The peer target/candidate guards remain applicable; Windows GDI
observations have no Fedora counterpart. No shared contract amendment is needed.
Owner: Windows maintainer. Follow-up: the fresh native run and remaining session,
restart and active-consumer checks in [machine fonts](machine-fonts.md).
Review trigger: any change to the native pass criteria or production recovery
semantics. See [source evidence](archive/evidence/font-recovery-separation-source-2026-11-03.json).

## Client capability restart boundary, 2026-11-03

Impact: Windows-only correction to RB-09 partial failure handling. A DISM restart
request now stops apply/recovery after literal-state readback instead of warning
and allowing the engine to continue the group. Existing snapshots, run identity,
candidate opt-in, source policy and conditional recovery semantics are retained.
No automatic restart is introduced; the partial run is not reported as complete.

Reviewed RB-03/04/08/09/11 against pinned contract 1.1.0 and its digest above.
Re-read Fedora target/candidate guards in `lib/v3/common.sh`; the `ride.sh` and
`common.sh` hashes still match the image-policy review above and are recorded in
[source evidence](archive/evidence/client-capability-restart-source-2026-11-03.json).
Fedora has no DISM capability provider. Shared behavior is unchanged and no
contract amendment is needed. Owner: Windows maintainer. Follow-up:
[native capability acceptance](windows-component-inventory.md#client-rsat-catalog-candidates).
Review trigger: native servicing/restart evidence, failure or recovery changes,
or affected capability promotion. Mocked tests do not establish native support.

The subsequent guest scenario adds Windows-owned acceptance evidence under
RB-03/04/08/09/11: exact guest attestation, explicit Windows Update source, normal
engine snapshots, mixed-state recovery and retained partial failures. It does not
change the CLI, catalog support, acquisition policy or saved-run schema. The same
peer source comparison applies. Its 22 isolated cases per shell remain separate
from native acceptance and host-route activation; see the
[guest scenario source evidence](archive/evidence/client-capability-acceptance-source-2026-11-03.json).

The retained host route adds platform-owned VM/checkpoint/source binding and
verified export before reset. Timeout without a terminal guest result leaves the
VM and lease retained; checkpoint cleanup cannot change a failed lifecycle into
success. This applies RB-08/09/11 without changing the shared contract or production
privilege path. The installed task remains unchanged. The same source comparison
applies; review again for queue activation, interrupted-run recovery changes or
native promotion. See [host source evidence](archive/evidence/client-capability-host-source-2026-11-03.json).

## Expanded disconnected bundle acceptance, 2026-11-03

Impact: Windows-owned RB-03/09/11 evidence, with no production CLI, acquisition,
recovery or privilege change. The focused portable scenario now uses the
production assembler and received bundle's CLI, checks byte-preserving guest-local
copy, and records Defender before/after. Pinned contract 1.1.0 and the same peer
source hashes reviewed above apply; the evidence records those hashes. No shared
contract amendment is needed. Owner: Windows maintainer. Follow-up and review
trigger: [cross-machine/full-set delivery](offline-bundles.md#refresh-and-recovery)
or changed offline semantics. The native pass does not establish Fedora support,
cross-machine delivery or broader installer acceptance. See
[native evidence](archive/evidence/offline-caffeine-assembly-night-native-2026-11-03.json).

The fixed NTCoreAdditional and SysinternalsProducts package scenarios now also
require the existing read-only Defender observer. This extends Windows-owned
RB-11 acceptance evidence without changing shared behavior, package handlers or
catalog support. The same contract and peer hashes apply. NTCore Driver List
x64/x86 and Rebel.NET passed native lifecycle/recovery and Defender checks; see
[evidence](archive/evidence/ntcore-additional-night-native-2026-11-03.json).
Owner: Windows maintainer. Review trigger: affected package promotion or changes
to the observer/lifecycle boundary; remaining packages stay in the
[fast-track register](migrations/migration-completion-reassessment-2026-11-02.md#approved-fast-track-execution-2026-11-02).

## Fixed RegRipper and Rufus acceptance routes, 2026-11-03

Impact: Windows-owned RB-03/04/08/09/11 test routing. The two explicit selections
reuse package handlers and saved ownership recovery; they add no production verb,
catalog support, acquisition policy or saved-state schema. The new registered
capability is required before dispatch; source availability does not activate it.
The installed controller remains unchanged. Contract 1.1.0 and Fedora target/
candidate guards were reread with the same `ride.sh`/`common.sh` hashes, recorded
in [source evidence](archive/evidence/regripper-rufus-routes-source-2026-11-03.json).
No shared-contract amendment is needed. Owner: Windows maintainer. Follow-up:
[fixed portable acceptance](../tests/integration/README.md#focused-reviewed-portable-packages).
Review trigger: attended activation, native results, source-pin changes or target
promotion. The 145 selected mocked/source cases per shell do not establish native
Defender or package acceptance.

## Remaining MiTeC portable acceptance routes, 2026-11-03

Windows-only RB-03/04/08/09/11 acceptance preparation: four fixed routes cover
14 products and 20 variants with existing pinned acquisition, candidate gating,
Defender observation and saved-file recovery. No public CLI, catalog pin, target
support or production handler changes. Contract 1.1.0 and unchanged Fedora source
hashes are recorded with 165 passing selected cases per shell in
[source evidence](archive/evidence/remaining-mitec-routes-source-2026-11-03.json).
The capability is absent from the unchanged installed controller; native
activation remains pending. Owner: RIDE-Windows maintainers. Follow-up:
[operator procedure](../tests/integration/README.md#remaining-mitec-portable-acceptance).
Review trigger: attended controller activation, native batch result or pin change.

## ThreadJob runtime origin acceptance correction, 2026-11-03

Windows-only RB-08/11 acceptance correction: a manifest can load a root DLL,
whose path is reported by ModuleInfo. The runner now binds that definition,
ModuleBase, version and GUID while retaining exact-manifest import. No production
or shared interface changes. Contract 1.1.0 and compared Fedora source hashes
remain unchanged; all hashes and 64 passing source cases per shell are recorded
in [source evidence](archive/evidence/threadjob-origin-source-2026-11-03.json).
Owner: RIDE-Windows maintainers. Follow-up: the correlated native rerun in the
[migration ledger](MIGRATION-PLAN.md#threadjob-binary-origin-acceptance-correction-2026-11-03).
Review trigger: native result, prerequisite pin change or target promotion.

The follow-up native run passed exact prerequisite import, PSScriptTools import,
CIM enumeration and drawing. Its next failure was a caller-scope invocation of
the module's private cleanup helper. The corrected probe invokes that helper in
module scope against an explicit synthetic runspace and checks closure/job errors;
69 focused source cases pass per shell. This remains Windows-only acceptance,
with no public GUI workflow or full Core acceptance claim. See
[follow-up evidence](archive/evidence/psscripttools-private-helper-correction-2026-11-03.json)
for the failed native run, unchanged contract/peer hashes and pending rerun.

## Fixed Gpg4win and TMOG installer acceptance, 2026-11-03

Impact: Windows-owned RB-03/04/08/09/11 route narrowing. Existing batch-1 package
and recovery behavior is reused for one named package at a time. Gpg4win's
limited-user SID/profile handoff remains mandatory; TMOG remains machine scoped.
The coordinator records Defender observations and the new capability is required
before protected dispatch. Source selection does not grant installed capability
or target acceptance. Pinned contract 1.1.0 and the same reviewed Fedora target/
candidate guards apply; compared hashes are in
[source evidence](archive/evidence/gpg4win-tmog-routes-source-2026-11-03.json).
No shared-contract amendment is needed. Owner: Windows maintainer. Follow-up:
[focused installer procedure](../tests/integration/README.md#focused-gpg4win-and-tmog-installer-acceptance).
Review trigger: attended activation, native user-data/recovery results, source
changes or target promotion. Compensating package presence and synthetic data
preservation do not establish exact prior-version or all-application-state recovery.

## Fixed Mail Checker installer acceptance, 2026-11-03

Windows-owned RB-03/04/08/09/11 test routing adds one fixed Windows 11 machine
installer selection, exact version and Defender evidence, bounded runtime source
staging, and a separate installed-capability guard. Existing candidate and
compensating package-presence recovery semantics remain unchanged. Contract 1.1.0
and the same Fedora target/candidate source comparison apply; hashes and source
results are recorded in [evidence](archive/evidence/mailchecker-route-source-2026-11-03.json).
No public CLI, supported-target declaration or contract amendment is introduced.
Owner: Windows maintainer. Follow-up: [native procedure](../tests/integration/README.md#mail-checker-installer-acceptance).
Review trigger: attended activation, native result, package pin or recovery change.
The unchanged installed controller lacks the new capability; source preparation
does not establish native acceptance, mail/TLS behavior or exact application-data
recovery. Paradox/BDE acceptance remains separate.

## Fixed WFN portable acceptance, 2026-11-03

Windows-owned RB-03/04/08/09/11 routing adds the exact selected WFN x64 Nightly
archive and full 531-member inventory to the existing package lifecycle fixture.
Candidate metadata, whole-archive pinning, ownership/recovery semantics and the
production CLI remain unchanged. A new installed capability gates both queued
and standalone host routes; no protected activation occurs from source edits.
Contract 1.1.0 and the same compared Fedora target/candidate guards apply; hashes
and source results are in [evidence](archive/evidence/wfn-route-source-2026-11-03.json).
No contract amendment is needed. Owner: Windows maintainer. Follow-up:
[native package procedure](../tests/integration/README.md#windows-firewall-notifier-package-acceptance).
Review trigger: attended activation, native result, archive/member changes or
target promotion. File lifecycle acceptance does not establish WFN application
or firewall behavior, and no shared firewall-setting behavior changes here.

## Font enumeration process evidence, 2026-11-03

Windows-owned RB-11 diagnostic reports now identify the lifecycle/collector
process and session. Production font handling, recovery and acceptance criteria
are unchanged. Contract 1.1.0 and unchanged peer hashes are recorded in
[evidence](archive/evidence/font-process-night-native-2026-11-03.json).
No contract amendment is needed. Owner: Windows maintainer. Follow-up and review
trigger: [remaining native font availability](machine-fonts.md), including the
immediate removal failure and any future session/restart/consumer scenario.
Later clean observations do not erase an earlier failure or grant target support.

## System Information startup selection, 2026-11-03

The later System Information acceptance selection retains both MSIX primary
applications and explicitly defers GetSys execution/report behavior to v3.1,
under the user's startup-only decision. Exact helper files remain in lifecycle
and recovery checks; the earlier GetSys failure is preserved. Shared RB-03/08/09/11
semantics are unchanged. Contract and compared peer hashes are recorded in
[source evidence](archive/evidence/mitec-system-startup-selection-source-2026-11-03.json).
Owner: Windows maintainer. Follow-up/review trigger: corrected native startup
and any later helper execution scenario in the product fast-track register.
No shared contract amendment, conformance or target promotion is claimed.

## Gpg4win and TMOG native corrections, 2026-11-03

Shared behavior is unchanged under contract 1.1.0 (RB-04/08/09/11/12).
Gpg4win's final NSIS destination now follows the documented unquoted `/D=`
syntax. The TMOG acceptance fixture maps pinned release 1.0.1 to observed
registration 1.0.1.0, retaining exact matching for other releases/products.
Native sources, compared Fedora HEAD/provider hashes and 54 passing tests per
PowerShell edition are recorded in [source evidence](archive/evidence/gpg4win-tmog-installer-corrections-source-2026-11-03.json).
Fedora's native package provider has no NSIS argument contract. No public CLI,
pin, target promotion, privilege, component selection or recovery semantics
change; no contract amendment or shared conformance claim is needed.
Owner: Windows maintainer. Follow-up and review trigger: corrected native
install/repeat/remove/recovery runs in the [current assessment](migrations/migration-completion-reassessment-2026-11-03.md).
The prior failed runs remain evidence; the NSIS fix is not proof of crash cause.

## WinPmem file-only native evidence, 2026-11-03

RB-11 Windows-owned evidence adds active/no-alert Defender observation to the
existing file-only route and corrects catalog signature wording using acquired
bytes. The outer wrapper reports NotSigned; its exact publisher hash matches.
No operation ID, pin, privilege, source policy, recovery or support declaration
changes. Contract 1.1.0 and unchanged compared Fedora hashes are recorded in
[evidence](archive/evidence/winpmem-night-native-2026-11-03.json). All 14 native
package/recovery checks passed without executable or driver launch. No shared
contract amendment is needed. Owner: Windows maintainer. Follow-up and review
trigger: [scoped package promotion](migrations/migration-completion-reassessment-2026-11-02.md#catalog-package-candidates)
or any separately requested driver scenario. Native file acceptance does not
transfer to application/driver behavior or another target.

## Shared behavior scenarios 1.1.0, 2026-11-03

ALIGN-05 / owners: RIDE Windows and RIDE Fedora maintainers. The Windows-owned
canonical shared scenario set now pins revision `1.1.0` and adds RB08-01
privilege refusal before state observation and RB07-01 reverse dependency order
for explicit profile removal. The Windows adapter maps these to the existing
`CandidateExecution.Tests.ps1` machine-elevation case and
`PackageDependencyPlanning.Tests.ps1` dependent-removal case. The Windows
contract test now checks the scenario byte digest pinned by its adapter.

Fedora maps the same cases to mocked CLI tests for system privilege refusal and
profile removal ordering. It also runs restore preview as EUID 0 inside an
isolated user/mount namespace with run state on tmpfs; the CLI refuses before
calling the settings observer or writing a new journal. The focused suite
passes. The peer Fedora record is
[Windows alignment](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/windows-alignment.md#align-05-shared-scenario-expansion-2026-11-03).
Windows Pester execution was subsequently completed on Windows PowerShell 5.1
and PowerShell 7. All mapped scenario files ran; one stale search message
assertion was corrected and its complete file passed in both editions. Original
failures remain recorded. See [Windows evidence](archive/evidence/shared-behavior-and-status-windows-pester-2026-11-03.json).
ALIGN-05's wider paired CI and conformance work remains open.

## Status operation and view selectors, 2026-11-03

ALIGN-08 is a compatible CLI extension under RB-01, RB-02, RB-10, and RB-12.
The pinned 1.1.0 contract requires documented native selectors and preservation
of published positional syntax without prescribing identical option spelling.
The paired implementation retains each client's positional form. Linux keeps
`ride.sh status <operation-id>` and adds
`status --id <operation-id>` plus `status --view <view>`. Windows keeps
`ride.ps1 status [view]`, adds `-View <view>` and adds `-OperationId <id>`;
`-OperationId` may be combined with `-Profile` only when that profile selects
the operation. The native option spelling differs, but both clients now provide
explicit operation and view selection without reinterpreting existing syntax.

Windows CLI 0.19.0 forwards the selectors to Engine 0.33.0 and completes
`-OperationId` from the local catalog. Mocked CLI routing, engine filtering, and
completion Pester cases were added. Subsequent native Windows execution passed
the CLI and 15 status-presentation cases per shell; all 38 corrected search cases
also passed per shell. See [Windows evidence](archive/evidence/shared-behavior-and-status-windows-pester-2026-11-03.json).
The broader ALIGN-08 output contract remains open. PowerShell AST parsing,
three fake-engine routing/refusal smoke cases, and a local catalog completion
smoke check passed. The source revision and file hashes are recorded in the
capability-differences register. Paired profile and state-preview examples are
in both READMEs. Review this difference if positional syntax, completion data
sources, or the status row contract changes.

## InfoBar completion diagnostic, 2026-11-03

The pending Windows InfoBar 4.6.2 candidate selects the existing EXE root-process
completion policy after a native installation timeout. Installer exit and
installed-state gates remain; other defaults and uninstall behavior are unchanged.
This is a Windows installer-provider difference, with no shared CLI/schema or
contract revision. Native confirmation is pending and the timeout cause unproven.
Owner: RIDE-Windows maintainers. Follow-up and review trigger: the diagnostic
retry in the [Nov 3 reassessment](migrations/migration-completion-reassessment-2026-11-03.md),
or any future change to installer completion/promotion policy. Compared contract
1.1.0 and Fedora HEAD 1243f36cc27c4b9ef9569cb7f168bd79e1e92c8a;
exact contract/CLI/provider hashes and tests are retained in
[source evidence](archive/evidence/infobar-installer-completion-source-2026-11-03.json).

## Per-user lock-screen image provider, 2026-11-04

Windows adds `windows.user-lock-screen` as an additive `DefaultImage` provider
with `Scope=User`. It uses the signed-in user's Windows personalization API,
captures a readable local prior image, binds recovery to the user SID and
conflict-checks the original image path. The public desktop API does not expose
Picture/Slideshow/Spotlight mode; documentation limits use to Picture mode and
native Windows 11 user-session acceptance remains pending. This follows RB-08/09
identity and recovery without changing shared CLI or saved-run meanings.

Compared pinned contract 1.1.0 SHA-256
`B88967EA5BDE29E0141BCA15134E2DAC63E02FAF7931CB18E83BA08CF5262938` and reused
the Nov 3 Fedora image-provider comparison at HEAD
`419f018e5173a865ee4b263dcc6edc24140d92da`; that reviewed source had no
corresponding wallpaper/lock-screen provider. The Fedora checkout was not
readable in the current sandbox, so no newer source revision or parity claim is
asserted. This operation remains Windows-native. Owner: RIDE-Windows maintainers.
Follow-up: [per-user lock-screen lifecycle and limitations](image-personalization.md#per-user-lock-screen-image).
Review trigger: native Windows acceptance, user-context/recovery changes or a
matching Fedora image provider.
