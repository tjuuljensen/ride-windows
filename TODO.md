# RIDE-Windows tasks

## Active priorities

### Development reliability - high priority

- [ ] Complete **optional GitHub authentication** acceptance: DPAPI enrollment, explicit PAT discovery, shared-account backoff and run-bound guest delivery are implemented in source. Finish dedicated credential enrollment, reviewed controller refresh, focused anonymous/PAT acquisition and failure/timeout cleanup on both VMs, and hosted final-source validation. Keep broad PAT suites and default-branch cutover separate; see the [workflow and acceptance status](docs/github-release-discovery.md#authentication-acceptance-status) and [approved scope](docs/MIGRATION-PLAN.md#optional-github-authentication-v3-scope).

### Engine correctness

- [ ] Review snapshot file ACLs and add safe cleanup/retention for old run records.
- [ ] Add package installer checksum/signature policy and retain installers needed for version-specific recovery.
- [ ] Handle partial failure across a multi-operation apply with per-operation completion reporting and a safe resume path.
- [ ] Add profile parameter validation and package dependency cycle detection.

### Documentation and licensing

- [ ] Before release, refresh [Important to review licensing](docs/package-licensing.md#important-to-review-licensing), including Npcap, KAPE and any newly selected products with restricted free-use terms; keep the final README linked to it.
- [ ] As acceptance closes, move completed reports into the [archive](docs/archive/README.md), retain unresolved work in active ledgers, and keep durable guides free of session narratives. Follow the [documentation model](docs/models/documentation-model.md).

### Migration

- [x] Reconcile accepted Q17/Q20 retirement of planned Volatility 2 and ImproHound deployment; preserve exact selector history and existing installations/data. Remaining package range is 56-71; see the [disposition/estimate record](docs/migrations/application-migration-review.md#accepted-volatility-2-and-improhound-retirements-2026-10-17). Standalone Neo4j/APOC and optional CE backend deployment remain deferred, not retired.

- [x] Complete the authorized implementation window through 2026-10-17 08:00 Europe/Copenhagen and record the [morning handoff](docs/migrations/remaining-migrations-follow-up.md#morning-handoff-2026-10-17). Source-ready work and native acceptance remain distinct; this does not mark the migration complete.
- [ ] Resume from the [morning handoff](docs/migrations/remaining-migrations-follow-up.md#morning-handoff-2026-10-17) (resumed by direct instruction on 2026-10-17; [five batches recorded](docs/migrations/remaining-migrations-follow-up.md#resumed-implementation-results-2026-10-17)): remaining collections/dependencies, 81 setting presentations, durable live ownership/offline integration and serialized native acceptance. Preserve the separate decision ledger, pending resources, existing B01 work and retained source/recovery evidence.
- [ ] Complete native acceptance of the [five implemented optional Store app groups](docs/store-app-groups.md). Solitaire basic registration lifecycle passed; Clipchamp is next when fresh elevation is available. GUI/data, interruption, groups and full intended-user handoff remain pending. The reviewed identity/removability rule is approved; News/Weather wait for usable local reinstall source. Track [remaining acceptance tasks](docs/migrations/store-app-follow-up-decisions.md). The [policy workflow](docs/migrations/store-app-removal-review.md) remains separate and linked. Keep current apps installed and acquisition-dependent reinstall deferred until that app has a reviewed source. [V2 lists](docs/archive/migrations/store-app-v2-historical-coverage-2026-10-14.md) remain history; shared/protected dependencies, AllUsers and image deprovisioning are not automatic group actions.
- [ ] Continue the accepted settings decisions from the [implementation handoff](docs/migrations/settings-implementation-handoff.md) and [remaining settings plan](docs/migrations/remaining-settings-plan.md#recommended-implementation-order). Six-control metadata and explicit user-only desktop handoff are implemented; complete native interactive acceptance and mixed-profile ordering/recovery, retain numbered questions and finish remaining handlers/acceptance before the final walkthrough.
- [ ] Include **Rufus** as an optional v3 tool for bootable USB media creation; see the [requested additions](docs/candidate-tools.md#requested-v3-additions-2026-10-11) for portable acquisition, publisher/license references and acceptance work.
- [ ] Include **HashCheck - idrassi fork** as an optional v3 app; see the [requested additions](docs/candidate-tools.md#requested-v3-additions-2026-10-11) for publisher, license and acceptance work.
- [ ] Include the supplied **Hash value** submenu and corrected **SHA-256 with Certutil** context-menu setting as optional v3 solutions; see the [source and corrected registry example](examples/hash-context-menu/README.md).
- [ ] Inventory the v2 default profile and migrate its high-use settings and installers into v3 operation metadata.
- [ ] Migrate common forensic tools and their remove operations into package handlers and grouped profiles.
- [ ] Review user-scoped settings so elevated runs do not silently target the wrong user.
- [ ] Decide which legacy operations are unsupported, manual-only, or one-way and record that in the catalog.

### Verification

- [ ] Near v3 release-candidate readiness, resume [controller and GitHub bridge certification](docs/migrations/controller-certification.md#resume-near-v3-release-candidate): validate the actual RC source, reconcile changed live scenarios, and complete deferred dispatch/master-push gates after agreed publication. Existing bridge, scoped controller and hosted passes retain their recorded baselines; master publication stays held until RC readiness.
- [ ] Complete the screen-lock comparison on Windows 11 and Server 2025 Desktop Experience using the [procedure and acceptance table](docs/screen-lock-impact.md#acceptance-status). Clean repeated controls, write attribution and behavior/cleanup checks remain open; the guide owns the current findings and evidence links.
- [ ] Run the disposable VM suite on Windows 11 and Windows Server 2025.
- [ ] Add CI result publishing for Pester and test both Windows PowerShell 5.1 and PowerShell 7.
- [ ] Validate operation support declarations against the integration matrix before expanding targets.

## Down the road

- [ ] Add explicit opt-in `search -Regex` with bounded, case-insensitive, culture-invariant matching; preserve literal search by default and reuse field/view filters. Validate invalid patterns and timeouts on Windows PowerShell 5.1 and 7.
- [ ] Implement the accepted [offline bundle workflow](docs/offline-bundles.md): profile-selected/full reviewed variants, pinned engine/profiles/payloads, version retention, explicit omissions and optional supplied servicing sources. Local manifest preflight is source-ready; next derive complete requirements from catalog/profiles, assemble versioned content and integrate a mandatory no-network preflight before any install/apply changes. Preserve Q14's separate installation/publication rules; see [licensing boundaries](docs/package-licensing.md#requested-offline-bundles).

- [ ] Once the CLI commands and operation lifecycle have stabilized, evaluate exposing a public, importable RIDE PowerShell module for interactive use and integration from other scripts. Keep `ride.ps1` as the standalone entry point; define a stable module API only if there is a clear use case.

### Offline profile builder for nontechnical users

**Deferred until after v3.0; concept retained 2026-10-16.** This is a future
development feature, outside v3.0 scope, migration estimates and release
acceptance. Recording it does not start implementation or change package review
priorities.

Provide a Ninite-style web interface where users select packages and Windows
settings, review their effects, and download a RIDE `.psd1` profile. Prefer a
self-contained HTML file that opens locally without a web server, account or
internet connection. Bundle its scripts, styles and catalog data; avoid external
CDNs, fonts and required network requests. Offline profile creation does not
provide offline package installation or an offline redistribution bundle.

#### First version

- Searchable package and setting categories with plain-language descriptions,
  publisher/documentation links and relevant supported-target information.
- Explicit target selection; filter or clearly mark incompatible operations.
  Explain that this is the user's chosen target, not detected machine state.
- Leave operations unselected by default. For settings, explain each declared
  state and its effect; omission means leave it untouched. Distinguish baseline
  application from restoring saved prior state. Offer only states and actions
  supported by profiles, not every command or catalog entry.
- Expose supported package variants and explain group/dependency effects.
  Show scope, elevation, experimental status and material recovery limitations
  before export. Respect existing profile and intended-user constraints.
- Review the complete requested changes, then download a named profile with
  compatible schema, stable IDs, correct PowerShell data-file escaping and
  release/catalog provenance in comments or other already-supported metadata.
- Provide a clear CLI handoff: from the matching RIDE checkout or release,
  preview with `.\ride.ps1 plan -Profile .\my-profile.psd1`, review the result,
  then use `.\ride.ps1 apply -Profile .\my-profile.psd1` in the appropriate
  user/elevation context. Link to RIDE's existing state and recovery guidance.

#### Development follow-up tasks

- [ ] Define the builder's versioned data contract and generate it from
  `catalog/operations.psd1`. Reuse authoritative IDs, states, variants, groups,
  dependencies, support declarations and references. Keep any new explanatory
  metadata with its authoritative source, not in a second hand-maintained web
  catalog. Identify which operations the current profile schema can represent.
- [ ] Design the selection and review flow with nontechnical users, including
  keyboard navigation, accessible labels, understandable state choices,
  incompatible selections and visible dependency effects. Prototype before
  committing to a frontend framework or adding build dependencies.
- [ ] Implement the local/offline interface and deterministic profile export.
  Render catalog and user text safely, serialize only allowed data fields, and
  validate names, IDs, states and variants without executing supplied content.
- [ ] Integrate generation into the existing release workflow. Ship a builder
  tied to that release's catalog, display its version, document compatibility
  with the RIDE engine, and detect stale generated data during validation.
- [ ] Validate exported profiles through the existing profile loader/validator
  without applying operations. Cover apostrophes, Unicode, empty selections,
  duplicate/group selections, dependency conflicts, variants and unsupported
  target/state combinations; use isolated or mocked checks where needed.
- [ ] Verify local-file browser behavior with networking disabled, accessible
  interaction and downloaded file contents. Document the Windows browsers
  actually tested and the preview/apply handoff, including mixed-scope limits.

Acceptance: the release artifact works locally with no required network calls;
every offered choice maps to supported profile metadata; representative exports
load successfully in the matching RIDE engine and express exactly the reviewed
selection; stale or incompatible choices receive clear feedback; and generating
a profile invokes no handlers, installers or Windows configuration changes.
CLI preview remains the final check against live machine state. This work alone
does not expand operation support declarations or establish runtime acceptance.

Later extensions may include importing and editing existing profiles using a
bounded data parser without executing PowerShell, optional custom-library
catalogs, machine detection or direct execution through a separately reviewed
local integration. These are outside the first version. Start the future work
with the generated-data contract and a small selection/review/export prototype.

### Optional reusable GitHub release-discovery module

**Deferred; do not pursue now.** This is a separate downstream opportunity,
outside current v3 migration estimates and release acceptance requirements.

- [ ] Evaluate extracting [GitHub release discovery: cache and backoff](docs/github-release-discovery.md#anonymous-cache-and-backoff-flow) into a reusable PowerShell module for other tools and users.

If explicitly prioritized later, start with public latest-release metadata:
HTTP requests, bounded configurable caching/freshness, rate-limit recognition,
retry deadlines, structured deferral errors and provenance. Keep RIDE catalog
choices, asset selection, payload caching, verification and installation in RIDE.
Have RIDE consume the extracted module so there is one maintained implementation.

Before sharing, define a stable API and license, test Windows PowerShell 5.1/7
compatibility with mocked HTTP/time, and demonstrate use by an independent
consumer. Evaluate explicit client/authentication contexts and concurrent-request
coordination. Conditional requests, persistent cross-process coordination and
bounded retry policies are optional later extensions, not commitments for the
initial extraction. Document that unrelated applications can still exhaust
shared anonymous quota; this would not be a general-purpose GitHub backoff engine.

Legacy outcome estimates, batch decisions and release acceptance live in the
[migration plan](docs/MIGRATION-PLAN.md). The former roadmap is retained as a
[historical snapshot](docs/archive/migrations/roadmap-2026-10-13.md); priorities
are maintained here.
