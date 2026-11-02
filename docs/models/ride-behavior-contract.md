# RIDE shared behavior contract

Contract version: **1.1.0**. Adopted: **2026-11-02**.
Owners: RIDE Windows and Fedora maintainers jointly.
Canonical source: `ride-windows/docs/models/ride-behavior-contract.md`.
Consumers: `ride-windows` and `ride-fedora` v3 clients, their CLI documentation,
completion, validation, migration reviews and release checks.

## Authority and adoption

This is the single authoritative RIDE cross-platform behavior contract. Either
repository may originate a proposal. Hosting it in Windows does not make the
Windows implementation correct by definition. Native installers, catalog coverage,
target declarations and runtime acceptance remain owned by each client.
Portfolio-wide rules remain in `network-devices`; do not duplicate them here.

Both clients adopt this contract as their v3 completion target. Adoption is not a
claim of full implementation, automated conformance or native acceptance. Known
gaps are tracked in the [Windows alignment register](../fedora-alignment.md) and
[Fedora alignment register](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/windows-alignment.md).
The shared ALIGN task IDs below identify the current transition. Existing CLI
behavior remains in place until its implementation task is completed.

Each repository's `docs/models/ride-behavior-contract-ref.json` records the adopted
version and SHA-256 of the canonical file's UTF-8 LF bytes. The URL locates the
source; the digest pins it, even while its publication branch moves. A local peer
checkout may supply the file only after checking the digest. Do not silently
adopt different bytes from a newer HEAD. This first adoption has no published
commit yet; ALIGN-09 records the immutable publication reference before release.
No runtime downloader or enforcement job is introduced by these reference files.

## Shared rules

| Rule | Required behavior |
| --- | --- |
| RB-01 Command meanings | No command means read-only list. Shared verbs are list, search, show, plan, apply, download, install, set, unset, status, restore and remove. Native switch spelling and additional capabilities may differ. Catalog/profile inputs are validated data, never executable user content. |
| RB-02 Explicit selection | Reject ambiguous ID/profile selection, invalid states and irrelevant options before mutation. Remove requires an explicit ID or profile rather than an implicit default-profile action. Preserve published forms through a declared compatibility transition; do not silently reinterpret positional arguments. |
| RB-03 Read-only preview | Discovery, planning and completion do not change managed state. Mutation previews invoke no mutation handler, write no payload, create no run or snapshot, and launch no privileged/user handoff. Candidate planning/preview does not need acceptance opt-in. Validate the declared target and applicable contract; report remaining privilege, availability or acceptance blockers without implying the real action has passed them. A handoff preview reports launch preparation only. |
| RB-04 Candidate boundary | Actual candidate changes and recovery require an explicit per-invocation opt-in. It bypasses acceptance only, never target, build, edition, architecture, privilege, source verification, ownership or recovery checks. Saved runs do not grant future approval. A candidate does not become supported through successful opt-in execution alone. |
| RB-05 Acquisition boundary | Download obtains a declared package/artifact without installing it or recording an installation. VM execution acceptance alone is not an acquisition gate. Check action eligibility, declared source, selected artifact compatibility and verification. Preview writes nothing. Offline execution must refuse missing inputs and never fall back to network acquisition. |
| RB-06 Setting lifecycle | Set applies a declared state; baseline is a declared configuration. Unset removes a declared override or refuses when no such operation exists; it must not generically translate to disabled. Restore recovers captured prior state within documented limits. These three meanings remain distinct. |
| RB-07 Package and profile lifecycle | Keep product, distribution, deployment, source/provider, format, scope and destination distinct. Do not alias source selection to edition/variant selection. Expand dependencies and preflight the whole selected plan before mutation. Profile removal includes only explicitly removable operation classes, in dependency-safe reverse order; ordinary settings are not implicitly reset. Document any non-package removable class. |
| RB-08 Identity and targets | Unknown or undeclared targets fail closed. Machine/system changes require the platform's privilege; user changes run in the intended user's context. Document any handoff and its completion boundary. Preview may run without mutation privilege but does not grant it or certify later execution. Target evidence does not transfer across OS, release, edition or architecture. |
| RB-09 State and failure | Capture required prior state before changing it. Record partial completion and expose a usable run identifier and recovery limits. Recovery validates the saved operation/source identity and applicable ownership/conflict constraints before mutation. Preserve recovery for interrupted steps where supported; never claim exact recovery where only presence or conditional recovery is available. Keep old saved-state migration/recovery paths when schemas change. |
| RB-10 Discovery and automation | Show identifies live state and relevant declared baseline/default metadata; status distinguishes observed state, desired state when selected, and support/acceptance. Document native output forms and selectors. Completion is local, read-only, bounded and consistent with execution's catalog/profile/state inputs. Any structured output interface must declare its version and stable fields before consumers rely on it. |
| RB-11 Evidence and capabilities | Advertise implemented capabilities and explicit platform differences, not placeholder parity. Keep source-ready, automated-tested, native-accepted and published status separate. Reuse unchanged relevant evidence; new native support needs the affected disposable-target checks. Errors distinguish invalid input, unsupported target, pending acceptance, privilege failure and operation/recovery failure, without requiring identical prose or native exit codes. |
| RB-12 Change discipline | Apply the review/versioning procedure below for shared changes. Update affected help, completion, tests and difference records in the same implementation change. Unexplained drift blocks promotion of the affected capability; it does not block unrelated native development. Final v3 review must close the alignment checklist or record an explicit owner-approved deferral. |

## Show pipelines and native structured output

Version 1.1.0 adds this compatible extension to RB-02/03/10/11. It is an
implementation target for both clients, not a claim that both already implement
it. Keep `show <catalog-id>` working. Pipeline support does not add shorthand
product aliases, imply matching catalogs, or authorize mutation commands to
consume pipelines. Native parameter spelling and transport may differ.

### Selection and failure behavior

- Accept explicit IDs individually or from a stream. Resolve each ID against
  the selected catalog; incoming discovery objects supply identity only, never
  trusted handler definitions or executable configuration.
- Inspect inputs sequentially in their supplied order. Preserve repeated IDs
  as repeated observations. This is not an atomic snapshot across entries.
- An empty input stream succeeds with no result. Missing selection without
  stream mode, blank/null input records, malformed IDs/objects and unknown IDs
  fail explicitly. Reject a positional/named ID combined with stream input.
- Stop on the first invalid input or inspection failure. Earlier successful
  results may already have been emitted; consumers must also check command
  failure. Emit diagnostics through PowerShell's error stream or Bash stderr,
  never as success-result objects or JSON records. Bash returns nonzero on
  failure; shell pipelines must preserve that status when needed.
- Inspection performs no install, apply, acquisition, saved-run write or
  elevation handoff. Existing target, observation-permission and nonsecret
  output boundaries still apply. An unsupported observation is not acceptance.
- Keep package variant and package source selection distinct. A supplied native
  selector applies to each input and must be valid for that entry; Windows
  `-Variant` and Fedora `--source` are not aliases for one another.

### Native input and output interfaces

| Surface | Windows PowerShell | Fedora Bash |
| --- | --- | --- |
| Single selection | `./ride.ps1 show <catalog-id>` or named `-Id`. | `./ride.sh show <catalog-id>`; preserve existing JSON output. |
| Stream selection | ID strings or objects with a nonblank string `Id` property piped into `show`; explicit `-InputObject` is also supported by the Windows interface. | Planned `show --stdin`: one catalog ID per line on stdin, read literally with `IFS= read -r`, including a final unterminated line. Accept LF or CRLF separators; a blank line is invalid input. Never evaluate or source input. |
| Stream output | One `RIDE.ShowResult` object per successfully inspected ID. Default terminal display must leave objects usable by downstream commands. | Planned `--stdin` output: one compact JSON object per successfully inspected ID, newline-delimited, with no enclosing array or table headers. Ordinary single-ID output may remain pretty-printed JSON. |
| Projection and export | `Select-Object`, `Where-Object`, `ConvertTo-Json`, `Export-Csv`. Apply `Format-List`/`Format-Table` only after data processing. | `jq` projects/filters the JSON stream; `jq -s` explicitly collects records into an array. |

For Fedora, `--stdin` is explicit: do not silently consume redirected stdin for
an ordinary positional invocation. Reject `--stdin` for unrelated commands and
complete it only where valid. Search/list can feed IDs through a documented
projection of their machine-readable output. Any future JSON mode for those
commands needs its own versioned contract; `show --stdin` does not implicitly
change their existing TSV output.

### Result meaning and schema compatibility

Each successful selection yields one result identifying the selected entry and
its live observation. Relevant baseline/default and support/acceptance metadata
retain their distinct meanings. Where a client supports showing groups, keep
member observations associated with the selected group rather than emitting
unlabelled extra top-level results. This does not require identical operation
kinds, catalogs or group support across platforms.

Native result contracts must declare a version, stable fields and types, optional
fields and extension handling. Windows defines schema 1 in
[catalog inspection](../catalog-show.md): `SchemaVersion`, `Id`, `Name`, `Kind`
and applicable observation/group fields. Fedora currently returns catalog JSON
with `observedState` and `availableSources`; its versioned result contract is an
ALIGN-08-F task, not already established by this document. Preserve existing
single-ID fields and meanings when adding its schema marker and stream mode;
breaking changes require the RB-12 transition procedure.

The native field mapping is semantic: Windows `Id`/`Name` correspond to Fedora
`id`/`name`; Windows `CurrentValue`, `CurrentState` where available and package
`Installed` describe aspects of observation that Fedora represents through
`observedState`. They are not interchangeable values. Document kind-specific
mappings before using them in shared tooling. `ConvertTo-Json` serializes the
Windows object contract; it does not create a common cross-platform JSON schema.
Consumers must ignore additional properties and distinguish unavailable state
from absence. No common field casing or identical shell argument syntax is
required.

### Paired examples and acceptance

Run from the respective checkout root with its documented runtime prerequisites;
use an existing ID in that client's catalog. These examples only inspect state
and project output. No recovery action is needed. Windows stream behavior is
under implementation; Fedora `--stdin` examples below describe the required
extension and must not be advertised as currently implemented.

```powershell
# Windows: pipeline-capable show interface.
.\ride.ps1 search autopsy | .\ride.ps1 show | Select-Object Id, Name
'package.autopsy', 'package.firefox' | .\ride.ps1 show |
    Select-Object Id, Name, Installed
```

```bash
# Fedora: existing single-ID JSON projection.
./ride.sh show "$catalog_id" | jq '{id, name, observedState}'

# Fedora: planned stream interface; use two valid catalog IDs.
set -o pipefail
printf '%s\n' "$first_id" "$second_id" |
    ./ride.sh show --stdin | jq -c '{id, name, observedState}'
```

ALIGN-08-W and ALIGN-08-F must test existing positional syntax, ordered multiple
inputs, repeated IDs, empty streams, blank/malformed/unknown inputs, explicit-ID
conflicts, first-error stopping with earlier results retained, applicable native
selectors and zero mutation calls. Verify property/JSON projection, nested group
output where supported, schema markers, diagnostic separation and help/completion.
Fedora additionally tests CRLF and final unterminated input lines, JSON stream
framing and nonzero status propagation. Windows tests strings and discovery
objects and rejects formatting records in success output. Add paired fixtures
under ALIGN-05 before claiming automated cross-platform conformance.

Consumer tasks and evidence:

| Task / owner | Next action and completion boundary |
| --- | --- |
| [ALIGN-08-W / Windows maintainer](../fedora-alignment.md#show-pipeline-contract-110-2026-11-02) | Complete native object/stream implementation, documentation and focused Windows PowerShell 5.1/7 tests; record results separately from this contract update. Retain positional syntax and leave saved-run recovery unchanged. |
| [ALIGN-08-F / Fedora maintainer](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/windows-alignment.md#show-pipeline-contract-110-2026-11-02) | Implement explicit stdin selection and JSON record framing, define the native schema and field mapping, update help/completion and native tests. Preserve single-ID JSON consumers and saved-run recovery. |

Revisit these tasks when either client changes selection, output or failure
semantics, when paired conformance fixtures are added, and before final v3 release.
Contract adoption does not close either implementation task.

## Existing topic authorities

This contract adds shared command meanings and change discipline. The detailed
[package deployment decisions](../migrations/package-deployment-decisions.md) and
[GitHub release discovery rules](../github-release-discovery.md) remain their
topic authorities; Fedora records native adaptations in its
[package deployment decisions](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/package-deployment-decisions.md)
and [GitHub cache contract](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/github-cache-contract.md).
Changes to shared topic behavior also follow RB-12. Native caches, authentication
storage, installer formats and saved-run schemas need not be identical.

## Review and versioning procedure

1. Classify each change as shared behavior unchanged, compatible extension,
   intentional platform difference, or breaking change. Name affected RB rules.
   Review the pinned contract and the peer paths that implement those meanings;
   record source revisions and working-tree hashes when needed. If the peer or
   pinned source is unavailable, record that limitation; do not claim alignment.
2. For shared changes, make one proposal with linked consumer tasks in both
   repositories. Each task names owner, compatibility/recovery implications,
   acceptance and next action. Each repository keeps its own implementation and
   native validation. No duplicate installer implementation is required.
3. Version the contract: patch for clarification without changed requirements,
   minor for compatible additions, major for changed existing requirements.
   Keep stable RB IDs. Update the changelog and both reference files deliberately;
   one client may remain on an older version with a documented transition.
4. For breaking changes, name old/new behavior, deprecation or alias, supported
   transition versions and a concrete removal condition. Preserve saved-state
   recovery separately from CLI compatibility. Unrelated releases need not share
   version numbers or synchronized commits.
5. A difference record needs an ID, owner, reason, affected rules, reviewed
   revisions, linked task, status and review/removal trigger. Distinguish permanent
   platform differences from temporary implementation gaps. A task or exception
   is not evidence of conformance; do not call unresolved work supported.
6. Run the affected native checks and, when available, the pinned shared scenarios.
   Until ALIGN-05 supplies that suite, record manual rule review plus existing
   focused tests; do not claim shared conformance automation. Revisit shared
   changes, each package migration batch and every release candidate.
7. Before final v3 release, complete the applicable ALIGN tasks, or obtain and
   record explicit owner deferral. Keep the affected promotion gate and local
   native acceptance independent. Publishing a contract/tag or moving a release
   branch is a separate action from editing these sources.

## Initial transition tasks

Local task status and completion evidence belong in
[Windows TODO](../../TODO.md#cross-platform-alignment-for-final-v3) and
[Fedora's v3 plan](https://github.com/tjuuljensen/ride-fedora/blob/codex/ride-v3-migration/docs/MIGRATION-PLAN.md#cross-platform-alignment-for-final-v3).
These are engineering/release tasks, not additional legacy outcomes.

| Task | Scope / current adoption boundary |
| --- | --- |
| ALIGN-01 | This versioned canonical contract and matching digest references. Complete as source documentation; publication remains ALIGN-09. |
| ALIGN-02 | Reciprocal AGENTS review rules in both repositories. Complete as maintainer policy; no runtime/CI enforcement implied. |
| ALIGN-03 | RB-02/06/07: strict argument handling, declared unset, explicit profile removal and eligible classes. Current Fedora unset and all-entry removal, Windows exclusion wording, and both bare-remove defaults need transition work. |
| ALIGN-04 | RB-03/04/05/08: converge candidate preview and acquisition with the rules above. Current Windows preview opt-in, Fedora download opt-in and the special Fedora iBus restore preview path remain tracked gaps. Review the Windows installed-package no-op target exception explicitly. |
| ALIGN-05 | Shared pinned scenario data and native adapters/CI, including recovery and completion; no such cross-repository suite exists at adoption. |
| ALIGN-06 | Structured capability/difference register with owners, evidence and triggers; migrate the current prose comparison without duplicating canonical rules. |
| ALIGN-07 | Linked-change review templates and read-only drift reporting against newer contract/peer capabilities; reproducible PR tests remain pinned. |
| ALIGN-08 | Compatible ID/view status selectors, paired explicit-profile/state examples and a scoped versioned machine-output interface. ALIGN-08-W/F add the [show pipeline contract](#show-pipelines-and-native-structured-output); keep native spellings and avoid source/variant aliasing. |
| ALIGN-09 | Final v3 contract/pin publication, gap disposition and scoped consumer verification in both release reviews. |

## Changelog

- 1.1.0 (2026-11-02): Define read-only show stream selection, native object/JSON
  output, compatibility and failure semantics, paired examples and linked
  Windows/Fedora implementation tasks. Fedora stdin/schema work and paired
  conformance coverage remain pending; no runtime behavior changes here.
- 1.0.0 (2026-11-01): Adopt shared CLI/lifecycle requirements, explicit known
  transitions and reciprocal review/versioning rules. Does not change either CLI.
