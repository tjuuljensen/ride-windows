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
