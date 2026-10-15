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

- [ ] Select the next matching batch from the [full remaining migration analysis](docs/migrations/remaining-migrations-follow-up.md#matching-batches) and answer its grouped follow-up questions. Start with existing setting presentation/native guidance; package deployment identity and state migration precede resumed product work. Keep packages paused and postpone elevation while the user is AFK. Existing subject ledgers retain decision/acceptance ownership.
- [ ] Complete native acceptance of the [five implemented optional Store app groups](docs/store-app-groups.md). Solitaire basic registration lifecycle passed; Clipchamp is next when fresh elevation is available. GUI/data, interruption, groups and full intended-user handoff remain pending. The reviewed identity/removability rule is approved; News/Weather wait for usable local reinstall source. Track [remaining acceptance tasks](docs/migrations/store-app-follow-up-decisions.md). The [policy workflow](docs/migrations/store-app-removal-review.md) remains separate and linked. Keep current apps installed, packages paused and acquisition-dependent reinstall deferred. [V2 lists](docs/archive/migrations/store-app-v2-historical-coverage-2026-10-14.md) remain history; shared/protected dependencies, AllUsers and image deprovisioning are not automatic group actions.
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
- [ ] Evaluate an optional offline bundle exporter with exact-version redistribution review and retained licenses/notices. Local download caches and a local `Reviewed` record do not establish redistribution approval; see [Package licensing](docs/package-licensing.md#optional-future-offline-bundles).

- [ ] Once the CLI commands and operation lifecycle have stabilized, evaluate exposing a public, importable RIDE PowerShell module for interactive use and integration from other scripts. Keep `ride.ps1` as the standalone entry point; define a stable module API only if there is a clear use case.

### Optional reusable GitHub release-discovery module

**Deferred; do not pursue now.** This is a separate downstream opportunity,
outside current v3 migration estimates and release acceptance requirements.

- [ ] Evaluate extracting [GitHub release discovery: cache and backoff](docs/github-release-discovery.md#cache-and-backoff-flow) into a reusable PowerShell module for other tools and users.

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
