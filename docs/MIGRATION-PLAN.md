# Legacy-to-v3 Migration Plan

## Estimated remaining migration work

| Group | Approximate remaining items | Examples |
| --- | ---: | --- |
| Windows and application settings | 38-58 | Deferred UI/Explorer, network, Server and BitLocker work; modern firewall, update-notification, Windows CEIP and separately owned power-plan creation plus conditional radio/WMDRM, Server Manager startup and paired Shutdown Event Tracker policies and guarded Windows Audio service implemented as pending candidates; Security icon startup guidance and registry failure/capture repair implemented; keyboard stored positions 0-3 implemented with Windows 11 literal lifecycle evidence; GUI/native-failure acceptance remains open; WAP Push/Search startup choices implemented with Windows 11 literal lifecycle evidence and corrected key-state recovery; verified bridge backoff and idle-controller evidence lifted the VM hold; focused candidate validation is ongoing; Task Manager and Computer Browser selectors retired; optional PowerShell appearance accepted outside the legacy count; browser/Sysmon configuration remains under review; traditional Python association preservation awaits implementation/acceptance; Windows Update interruption guide implemented; manual GUI/target acceptance remains open; local SAM maximum-age candidate implemented with finite explicit day states and bounded two-target native apply/reverse/fault recovery evidence; GUI/managed/additional-boundary acceptance remains open; native BitLocker recovery backup/retrieval guide implemented; secure custom actions and recovery acceptance remain open; Windows recovery readiness/native entry guide implemented; registration lifecycle and boot evidence remain open; modern Network discovery handoff implemented; profile/peer/target acceptance remains open; Storage Sense native cleanup-choice guidance implemented; GUI/content acceptance remains open; System protection native guidance implemented; volume coupling/history acceptance remains open; Feedback frequency native guidance implemented; paired type/unit/GUI evidence remains open; Latest Presentation 198/279; 81 open; task observation/readback repaired |
| Packages, portable tools and downloadable artifacts | 56-71 | Remaining forensic tools, system-tool entries, general software/artifacts, AD tools, browsers and other products; 19 newly accepted distributions (7 installed, 12 portable), 10 earlier outcomes and Opera excluded; R01/R02 preparation remains partial; current BloodHound CE and both collectors selected, container deployment separate; Volatility 2 and ImproHound planned deployment explicitly retired on 2026-10-17, with historical mapping and existing installations retained; corporate licensing watchlist added, with approvals kept local; independent installed/portable deployments and acquisition kits approved as design, product coexistence and kit acceptance pending; package implementation resumed for the authorized overnight window; Latest Offline declared-source comparison and selected-profile assembly gate ready |
| Windows components and optional features | 20-25 | WSL, Hyper-V, Sandbox, OpenSSH, printing features and built-in app management with reviewed live identities and separate policy/user uninstall; v2 bulk lists archived as historical coverage, both user/provisioning references collected; five optional uninstall/reinstall groups covering 22 apps accepted with device policy separate; all five group handlers implemented as guarded candidates; separate offline UAC desktop prepared and source-bound unelevated read-only Plan accepted; Solitaire basic uninstall/reinstall accepted on isolated Windows 11 reference; GUI/fault/full-launcher/other-app/policy acceptance pending; RSAT remains a component/applicability decision; BloodHound CE selects no automatic Docker/WSL provisioning or Server Docker Desktop support; no new component acceptance; Latest No native component/driver or target expansion |
| Accounts, configuration and deployed files/assets | 25-35 | Users and administrator membership, Wi-Fi, regional settings, language packs, browser preferences, fonts and wallpapers; startup user-bin candidates and persistent PATH observation/recovery preparation are source-ready; native PATH acceptance, bin provisioning and WindowsApps repair remain open; VMware directory/profile-file and Python environment/symbol/plugin ownership remain under review; named deployments, legacy selection mapping and owned-file toolkit update preparation are source-ready; durable state integration and named host-folder toolkit publication remain open, with no completed legacy outcome; Latest Profiles and recovery-resource setup explicitly deferred; source preparation continues |
| Maintenance and operational actions | 8-12 | Cleanup, updates, Sysprep, hostname and execution helpers; quota/cache/backoff bridge passed Windows 11 Full with 1,280 tests, eight network and three real cache observations with matching publisher digests; consecutive acceptance Windows 11 2/2, Server 2025 2/2 on the current controller baseline; collector 0.4.1 bounded failure collection accepted, ArtCraft Launcher remains closed and must not be restarted; controller certification and default-branch cutover remain open; no automatic Python installation-time pip upgrade selected; runtime/rule updates and explicit maintenance remain separate review items; optional GitHub PAT infrastructure implemented in source; dedicated enrollment, controller refresh, hosted CI and live acceptance pending; controller 0.4.6 scoped runtime/records accepted; hosted candidate f5e3218 validation passed both PowerShell editions; delivery/default-branch certification deferred until v3 release candidate; Latest 20 focused task checks per edition; final validation 225 PowerShell files |
| **Total, rounded** | **145-200** | **About 175 for planning** |

Last reviewed: **2026-10-17**. Latest run: [B01 scheduled-task observation and readback](#b01-scheduled-task-observation-and-readback-2026-10-17).
Five resumed batches delivered offline source/assembly checks, 19 presentations and task recovery hardening. Presentation is 198/279, 81 open. Both native editions passed 20 selected task checks and final validation of 358 operations/eight groups/five profiles/225 PowerShell files. Profile selection and BitLocker/recovery setup are explicitly deferred; source work continues under the direct instruction. All five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175. No whole legacy closure or new native acceptance. See the [resumed results and next instructions](migrations/remaining-migrations-follow-up.md#resumed-implementation-results-2026-10-17).

Latest scope review: **2026-10-17**. The [Q17/Q20 retirement reconciliation](#accepted-volatility-2-and-improhound-retirements-2026-10-17) supersedes earlier unresolved retirement wording and estimates; Q18/Q19 retain implementation gates. Q21 Office/Visio/channel/architecture/activation/language and Teams choices are now recorded in the later B10 review; native compatibility, extra-language and recovery gates remain. [Deployment decisions](migrations/package-deployment-decisions.md) now include accepted Q01 explicit deployment names, Q02 adoption/replacement with bulk review and individual ambiguity resolution, and Q03 profile-driven toolkit publication to a named host folder. Toolkit transfer needs no physical-media tracking; the separate offline installation scope now includes selected/full variants, RIDE/profiles, optional supplied servicing sources, partial omissions and retained pinned versions, with local preflight, byte-bound package coverage and explicit-source assembly ready; mandatory install integration and native offline acceptance remain pending. Q04 now accepts verified staging, unchanged-owned-file cleanup and explicit modified-file decisions; concrete ownership/commit/recovery remain open. The earlier [coexistence design](#package-deployment-coexistence-design-recorded-2026-10-14) is retained. Design acceptance does not establish runtime, release or legacy closure. All five ranges are 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175. Package implementation resumed by direct user instruction after the overnight window; normal acquisition backoff and native acceptance boundaries remain.

Latest infrastructure implementation: [GitHub PAT source implementation](#github-pat-source-implementation-2026-10-13).
Host enrollment/acquisition and explicitly selected focused guest delivery are implemented. The isolated candidate excludes the active settings fixture; the original fixture and concurrent guest-runner work are preserved. The user confirmed no VmTest enrollment exists and requested leaving live PAT acceptance pending. Existing installed controllers, VM pins and package pauses are unchanged by this work. All five legacy ranges and the rounded total remain unchanged.

Previous settings implementation: [Windows recovery readiness implementation](#windows-recovery-readiness-implementation-2026-10-13).
Implemented the accepted Windows recovery readiness/native entry guide, with
independent media, backup retrieval, credentials and encrypted-volume access
kept separate from Windows RE registration changes. Native inspection and
Restart now are explicit manual actions. All five ranges remain unchanged;
boot/GUI and Server acceptance stay pending. No VM, package or GitHub request.

Previous settings implementation: [Windows Audio service implementation](#windows-audio-service-implementation-2026-10-13).
Implemented advanced Automatic/running and legacy Manual/stopped Audiosrv choices
with bounded dependency inspection/refusal, second runtime preflight and drift
reporting. Exact saved recovery owns only the primary service; playback-device
mute remains separate and deferred. Supported targets stay empty for apply;
actual audio, dependency/trigger, GUI and Server acceptance remain open. Local
mocked evidence is recorded below. No service, audio device, package or VM is
changed. Packages stay paused; manual VM confirmation remains required. All five
ranges and rounded total remain unchanged because the outcome stays partial.

Latest infrastructure context: [Bridge/controller RC resumption retained](#bridgecontroller-rc-resumption-retained-2026-10-13).
The user will return near v3 RC. The active controller ledger retains accepted
bridge, newer-controller and hosted-source baselines separately, plus remaining
RC validation/delivery/portability work and safety constraints. No new run is
scheduled; bridge heartbeat confirmed PAUSED. Master publication stays held
until v3 release-candidate readiness and an agreed decision. Optional PAT support
remains approved/pending; reusable extraction stays deferred. Raw local evidence
needs preservation outside Git; ArtCraft Launcher must not be restarted. This
handoff closes no legacy outcome; all five ranges and rounded estimates remain
unchanged. Other migration activity and unfinished fixture edits are preserved.

### Earlier migration and acceptance context

Previous settings increment: [Shutdown Event Tracker policy implementation](#shutdown-event-tracker-policy-implementation-2026-10-13).
Implemented one paired machine policy for Disabled, Always, Server Only,
Workstation Only and override removal, with complete typed capture and partial
failure reporting. Disabled preserves the prior display choice through a validated
KeepCurrent marker; generated documentation also now lists firewall and owned-plan
managed targets. Server 2025 stays pending with no supported apply targets. Prompt/
precedence/Core and exact target recovery remain open. Local checks are recorded
below; no shutdown, live policy, package or VM occurs. All five estimates and the
rounded total stay unchanged; manual VM confirmation remains required.

Previous settings increment: [Server Manager startup policy implementation](#server-manager-startup-policy-implementation-2026-10-13).
Implemented the accepted advanced machine startup policy, separate from the
console preference and live console launch. Suppression, explicit policy-disabled
startup and override removal preserve distinct reverse semantics and typed saved
recovery. Server 2025 remains a candidate with no supported apply targets; desktop/
Core, logon and effective precedence evidence stay open. Local evidence is recorded
below. Packages remain paused and VM execution still requires manual confirmation.
All five estimate ranges and the rounded total remain unchanged.

Previous settings increment: [conditional media policy implementation](#conditional-media-policy-implementation-2026-10-13).
Implemented separate pending current-user radio-preset and machine Windows Media
DRM policies with exact local ADMX mappings, explicit policy-disabled/removal
states and typed saved recovery. Corrected blanket retirement wording in the
existing music metadata control. Current component effects, effective managed
precedence and target acceptance remain open. Local checks are recorded below;
no player, license, package or VM is changed. Packages stay paused and VM testing
still requires manual user confirmation. All five ranges and the rounded total
remain unchanged because the media bundle has no complete feature acceptance.

Previous settings increment: [owned power-plan copy implementation](#owned-power-plan-copy-implementation-2026-10-13).
Implemented explicit machine/admin creation candidates for Balanced, High
Performance and conditional Ultimate templates, separate from selection. Capture
records destination/ownership before duplication; compensating recovery refuses
active, changed, orphaned and incomplete copies. Local mocked checks are recorded
below. Supported targets remain empty; native export reproducibility, GUI,
hardware/edition and Server acceptance remain open. Packages stay paused and
VM tests still require manual user confirmation. All five ranges and the rounded
total remain unchanged because no legacy outcome gains complete acceptance.

Previous settings increment: [registry failure and capture repair](#registry-failure-and-capture-repair-2026-10-13).
Repaired shared registry inspection/removal/write failures while implementing
pending policies. Missing keys are distinct from denied/unavailable inspection;
readers capture key existence once and mutations/cleanup report errors rather than
claim success. Existing snapshot fields and recovery paths remain compatible.
Local evidence is recorded below. No live setting or VM test is changed; packages
stay paused and manual VM confirmation remains required. All five estimates stay
unchanged because this repair closes no legacy feature outcome.

Previous settings increment: [Windows Security icon guide implementation](#windows-security-icon-guide-implementation-2026-10-13).
Delivered the accepted guided startup/appearance workflow with machine policy,
intended-user startup, overflow and user-controlled refresh kept distinct. Catalog
presentation preserves published states and policy-only recovery; manual GUI
steps are reported as user work, not captured apply success. Actual multi-user/
appearance and Server evidence remain open. Packages stay paused, VM testing
still requires manual confirmation, and all five estimates remain unchanged.

Previous settings increment: [Windows CEIP policy implementation](#windows-ceip-policy-implementation-2026-10-13).
Implemented the pending Windows participation policy with correct inverted Group
Policy wording and separate opt-out, opt-in and override-removal semantics. Local
mapping evidence and typed recovery are retained; current collection, effective
policy and target acceptance remain open. App-V and telemetry mirrors remain
deferred. No privacy change, package acquisition or VM test is run. All five
ranges and rounded total stay unchanged; manual confirmation remains required
before disposable VM testing.

Previous settings increment: [update notification policy implementation](#update-notification-policy-implementation-2026-10-13).
Implemented a pending coordinated update-notification policy with distinct local
default/disabled/removal states, a minimum-build guard and separate read-only
legacy interception observation. Effective-policy/source and notification/reboot
acceptance remain open; apply targets remain empty. No update, live policy or VM
test occurs. Packages stay paused and manual confirmation is still required for
VM testing. All five estimate ranges and the rounded total remain unchanged.

Previous settings increment: [modern firewall profile implementation](#modern-firewall-profile-implementation-2026-10-13).
Implemented pending Domain/Private/Public local controls and enable-all with
complete capture, effective-policy/active-network inspection, drift checks and
partial-failure recovery. Supported targets remain empty pending VM acceptance;
no machine firewall state is changed. Local results are recorded below. Packages
stay paused and disposable VM tests remain held for manual confirmation. All five
ranges and the rounded total stay unchanged because feature acceptance remains open.

Latest infrastructure context: [recurring bridge Full Windows 11 attempt](#recurring-bridge-full-windows-11-attempt-2026-10-13).
The frozen CI source again passed validation, 1,280 guest tests and all 217
source hashes. Integration deferred at the first 7-Zip lookup on quota zero,
and the installed 0.4.0 failure collector timed out at 60 seconds after writing
an empty omissions list. Checkpoint cleanup and UAC checks passed. Collector
0.4.1 and controller 0.4.3 now allow bounded teardown timing diagnosis and
disable AutomatedLab's optional version check in each process. Full package
acceptance is still open; earliest retry is 06:43:23 UTC, with the recurring
bridge attempt set for 08:55 Europe/Copenhagen. The new settings' manual VM
hold is separate. All five estimate ranges remain unchanged.

Previous run: [keyboard range and service recovery follow-up](#keyboard-range-and-service-recovery-follow-up-2026-10-13).
Added stored keyboard repeat-delay positions 2/3 while retaining the published
registry backend, aliases and typed recovery. A native backend remains deferred
until effective-session, persistence and exact recovery evidence is proven.
Corrected service key-existence capture and retained older raw-only recovery
records that lack key-state history. Local validation is recorded in the dated
entry below: **51 focused mocked tests passed per PowerShell edition**, with
parser/catalog/profile/reference validation also passing. Disposable VM tests
remain held for explicit manual confirmation;
no VM test or package migration is launched or scheduled by this continuation.
All five ranges and the rounded total remain unchanged: both areas retain
feature/target acceptance and the visual-effects bundle remains partial.

Previous settings increment: [WAP Push/Search service implementation with VM acceptance held](#wap-pushsearch-service-implementation-and-acceptance-hold-2026-10-13).
Implemented explicit delayed-start and startup-only choices on both existing
service IDs, SCM/literal delay inspection and versioned compatible recovery.
Local mocked validation is recorded in the dated entry below; GUI/SCM/boot/workload
acceptance remains open. All disposable VM tests for this work are held until the
user manually confirms testing may resume after the GitHub cache/backoff
investigation. No VM tests are launched or scheduled by this increment, and no
package acquisition or package migration is performed. All five ranges and the
rounded total were reviewed and remain unchanged because the service outcomes
are still partial.

Previous infrastructure context: [focused installed collector failure acceptance](#focused-installed-collector-failure-acceptance-2026-10-13).
Installed collector 0.4.0 passed a controlled Windows 11 failure fixture in
36.113 seconds through the existing 60-second failure-evidence launcher.
All 800 byte-identical exported files retained hashes/timestamps; changed and
missing files were copied, while a locked transcript remained preserved with
one recorded omission. Checkpoint cleanup succeeded with unchanged UAC; both
VMs are Off, controllers Ready, queues empty and locks available. The scheduled
Full follow-up has now completed as recorded above; package acceptance remains open.
Commit `a156475` is published. Hosted validation passed 1,280 tests per edition;
its Full Server CI request passed all 1,280 guest tests and integration, with
successful collection and checkpoint cleanup. Both protected controllers now
use collector 0.4.0, with all five installed file hashes matching reviewed source.
Both VMs are Off and controllers Ready. A refresh attempted during the Server
request stopped before changing either controller, then succeeded after cleanup.
The focused failure-path check is now accepted on Windows 11; consecutive
two-target Full acceptance remains open. An AutomatedLab import during the
preceding refresh encountered quota exhaustion.
The [Windows 11 failure and repair](#windows-11-full-quota-failure-and-collector-repair-2026-10-12)
records the preceding implementation and acceptance evidence.
All 1,277 guest tests and the preceding setting round trips passed, but package
integration deferred on quota zero after a fresh 58-request preflight. Partial
collection timed out; checkpoint cleanup succeeded. Collector 0.4.0 now avoids
recopying byte-identical exported evidence; 71 mocked controller tests passed
per edition. Controller refresh and focused Windows 11 failure-path acceptance
are now complete; Full acceptance remains pending.
Consecutive two-target Full acceptance and overall certification remain open.
The [Java and AD-analysis preparation review](#application-java-and-ad-analysis-preparation-review-2026-10-12)
retains its separate partial requirements below.
All 79 unresolved application-ledger outcomes are assigned once to 13 discussion
groups. The user selected ImageMagick's x64 Q16 HDRI DLL installer with machine
scope/PATH and listed Q16 portable build, current-user GnuPG command line/Kleopatra
without Explorer/Outlook integration, and Wireshark live capture with a separate
interactive, administrator-only Npcap step without assumed OEM rights.
These are partial requirements decisions, not
completed migrations. No new outcome was resolved, retired or excluded; no
installer, VM or handler ran. All five group ranges and the rounded total below
were reviewed and remain unchanged, with scope, terms and acceptance retained.
R02 confirms both Python models, with install manager as default and machine
scope for the traditional installer. Manager-managed runtimes remain per-user.
Volatility 3 will use a pinned release, isolated environment and broader plugin
dependencies; Volatility 2 remains in retirement review. Exact runtime/dependency
compatibility, environment behavior and unanswered R01 choices remain open.
Latest follow-up confirms unchanged machine PATH and preserved associations for
the traditional Python installer, and bundled/validated pip without an automatic
installation-time upgrade. Exact controls and preservation/recovery still need
acceptance; manager integration and runtime/update policy remain open.
R03 confirms current BloodHound CE with container deployment reviewed separately,
both compatible optional collectors and ImproHound retirement review. Corrected
the Neo4j legacy contract: separate database/APOC artifacts plus configuration
and service changes. Standalone Java/Neo4j and remaining AD tools stay unresolved.

Approximately **145-200 distinct legacy work items**
remain; use **about 175** for planning after the two explicit retirements recorded
on 2026-10-17. Earlier numerical reviews below retain their original dates. These are candidates for migration,
retirement, combination or replacement, not a commitment to implement all of them.


### Recent implementation and acceptance context

Latest release-discovery implementation, **2026-10-12**: package module 0.10.0
adds five-minute bounded metadata reuse, shared release backoff and explicit
freshness/quota provenance without forwarding credentials or using expired data.
Focused mocked regression passed 124 selected tests per edition and complete
native regression passed 1,276 per edition. The one live-registry test stayed
excluded on the workstation. Hosted CI passed all 1,277 tests per edition and the
first Full Server CI run passed. The second Server request passed all 1,277 guest
tests but failed integration when publisher quota reached zero before 7-Zip
acquisition. Cleanup succeeded; consecutive two-target acceptance remains pending.
Follow-up Windows PowerShell regression passed all 1,276 selected tests with
HTTP cmdlet proxy defaults confined to a closed loopback endpoint; no test
failure required public API access. The shared quota traffic source remains
unestablished; see the [isolation follow-up](#release-discovery-network-isolation-follow-up-2026-10-12).
See the [quota failure](#rate-aware-release-discovery-repetition-quota-failure-2026-10-12)
and [first acceptance run](#rate-aware-release-discovery-first-ci-acceptance-2026-10-12).
All five group ranges and the rounded total below were reviewed and remain
unchanged; see the [dated implementation](#rate-aware-release-discovery-implementation-2026-10-12).

Numerical reconciliation reviewed **2026-10-12**, reconciling the last numerical estimate revision
with six subsequently accepted application distributions, Opera's exclusion and
two accepted setting retirements. Settings decrease by two outcomes and
packages/artifacts by seven; the other three groups remain unchanged. The
[dated reconciliation](#estimate-reconciliation-2026-10-12) records the arithmetic
and evidence. Partial bundles, deferred work and pending acceptance remain
counted. The new PowerShell appearance setting closes no legacy outcome;
user-bin startup PATH, directory provisioning and WindowsApps repair remain pending.

Latest controller follow-up, **2026-10-12**: after publisher quota recovered,
the complete-state migration-branch CI pilot passed all 1,248 Server guest tests
and applicable Full integration scenarios. Hosted and local regression passed
1,248 tests per edition. Evidence upload and checkpoint cleanup succeeded,
with host UAC unchanged. Overall controller certification and default-branch
cutover remain deferred. No legacy outcome was
resolved, retired or excluded. All five group ranges below were reviewed and
remain unchanged, with partial/deferred scope retained. See the
[successful Full pilot](#full-controller-ci-acceptance-2026-10-12),
[preceding retry](#full-controller-retry-2026-10-12),
[unit repair](#controller-unit-regression-repair-2026-10-12) and
[preceding failed pilot](#full-github-controller-pilot-review-2026-10-12).

Latest documentation review, **2026-10-12**: the PowerShell profile archive
handoff records reproduction without private chat helpers, retained evidence
boundaries and remaining cloud/network/alternate-launch and legacy PATH work.
No new implementation, acceptance run or resolved legacy outcome is claimed.
All five group ranges and the rounded total below were reviewed and remain
unchanged; see the [dated handoff review](#powershell-profile-archive-handoff-review-2026-10-12).

After **every migration run**, including follow-up implementation, review and
acceptance runs, update this overview before closing the run. Refresh the review
date, latest-run summary, all five group ranges, row examples/progress and rounded
total against the updated family and disposition records. Record completed,
retired, excluded, deferred and partial outcomes in a dated entry in the
[estimate review history](#migration-estimate-review-history) or the linked
migration ledger, together with the estimate adjustment and remaining acceptance.
Remove only resolved scope; retain omitted or deferred scope and update the
separate evaluation backlog. If a run resolves no legacy outcome, fails acceptance
or leaves rounded ranges unchanged, still record the review and explain why the
estimates remain unchanged.

## Documentation and licensing release requirements

Keep the final README linked to
[Important to review licensing](package-licensing.md#important-to-review-licensing).
Maintain a product-specific list of free-use restrictions requiring corporate,
professional, technician or paid-engagement review, including Npcap and KAPE.
Verify current publisher terms and the selected version/edition; do not assume
that all individual use is free or all internal company use requires payment.
Company-specific findings stay in the local exportable review store.

Use the [documentation model](models/documentation-model.md) for lowercase
topic filenames, reserved entry points and explicit existing path exceptions.
Keep current operation guidance in the [documentation index](README.md),
priorities in [TODO](../TODO.md), unresolved outcomes in active ledgers, and
dated reports in the [archive](archive/README.md). Before release, reconcile
remaining acceptance and remove session/migration narratives from durable
guides. Preserve real schema/recovery migration procedures and evidence links.

## Optional GitHub authentication: v3 scope

**Approved 2026-10-13; source implementation complete, live acceptance pending.
High priority for development and acquisition reliability.** Optional use by end users is part
of the feature; implementing it is now approved v3 scope. Track execution in
the [active backlog](../TODO.md#development-reliability---high-priority), ahead
of lower-priority feature expansion.

The objective is to reduce development's dependence on shared-IP anonymous
quota. GitHub normally allows 60 anonymous REST requests/hour per originating
IP and 5,000 PAT-authenticated requests/hour per user. The user allowance is
shared across that user's tokens and applications; secondary limits still
apply. Use response headers and existing cache/backoff, not an assumed fixed
available budget. GitHub Actions' built-in token has different limits and is
not interchangeable with a personal token.
[GitHub quota guidance](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

Approved design and implementation sequence:

1. Add explicitly selected authentication for public GitHub release metadata,
   initially using an expiring, minimally privileged user-supplied PAT. Anonymous
   remains the default. Do not silently discover environment/CLI/runner tokens,
   switch identities, or fall back to anonymous after credential rejection.
2. Use protected credential storage with a nonsecret reference in configuration
   and CLI usage. Resolve under the actual executing account, including an
   elevated or scheduled-task identity. Keep plaintext tokens out of command
   arguments, profiles, repository files, snapshots, exported state and logs.
   Authenticate only to the explicitly trusted HTTPS API host; do not forward
   credentials to redirects, asset hosts or installer processes. No credential
   is configured by this scope approval.
3. Separate anonymous/authenticated cache contexts and authorization-sensitive
   metadata. Account for shared user quota rather than treating each PAT as a
   separate allowance. Preserve bounds, freshness, provenance, digest checks
   and rate-limit deferral. Give failures and authentication-mode observations
   useful nonsecret reporting. Add read-only completion/help for introduced
   finite modes and discoverable credential references without retrieving secrets.
4. Keep host authentication and guest provisioning explicit. Initial host support
   does not automatically authenticate a guest or increase its anonymous budget.
   Guest support requires a separate selected mode, dedicated minimally privileged
   test credentials, a controlled delivery channel and verified evidence redaction
   and cleanup. Never bake a token into the clean checkpoint or automatically
   copy host/CI credentials. A host acquisition service is a separate possible
   design; label that evidence as host acquisition rather than guest discovery.

Acceptance requires mocked Windows PowerShell 5.1/7 coverage for explicit opt-in,
anonymous compatibility, credential lookup failure/expiry/rejection, account
context separation, destination/redirect restrictions, cache/backoff and secret
redaction. Use disposable authorized target/credential fixtures for applicable
authenticated acquisition and any separately enabled guest mode. Checkpoint reset
does not revoke leaked credentials. Authentication does not replace source,
publisher or payload verification and does not itself close controller acceptance.
[GitHub credential handling](https://docs.github.com/en/rest/authentication/keeping-your-api-credentials-secure).

This adds acquisition infrastructure, not a migrated legacy product/feature
outcome. Track its pending work separately from the five legacy estimate ranges.
The reusable release-discovery module remains [optional downstream work](../TODO.md#optional-reusable-github-release-discovery-module),
deferred and outside current v3 scope. The [source implementation entry](#github-pat-source-implementation-2026-10-13)
and [operating guide](github-release-discovery.md#explicit-pat-enrollment-and-selection)
record delivery and remaining acceptance. No real credential enrollment, package
acquisition, controller refresh or VM run is performed by this implementation
turn; existing package pauses and acceptance gates remain in force.

## Purpose and inventory

This is the batch inventory for migrating the selectable commands in `legacy/v2/default.preset` to the v3 catalog and profiles. It includes active and commented selectors. The original inventory contained **732 distinct legacy function names** across **30 family groups**; **731** remain in the preset after the user-requested Opera exclusion on 2026-10-11. The excluded outcome remains accounted for in the application ledger. Active selectors are marked **default**. Paired legacy commands should become states of one v3 operation only when inspection confirms that they control the same setting or package.

The catalog supports `ScheduledTask`, `AdapterBinding`, `DefenderPreference`, `SmbProtocol`, `PowerScheme`, `NetBios`, `RemoteDesktopFirewall`, `SoundScheme`, `RegistryValue`, `RegistryValueSet`, `RegistryKeySet`, `Package`, `DefenderExclusion`, `WindowsService`, `BackgroundAppOverrides`, `BootConfiguration`, `NetworkProfile`, `PowerSetting`, `ShellFolder`, and `ProfileSetting`. Migration of the other groups requires the minimum additional operation kinds and focused handlers for Windows components, account/configuration changes, files/assets, and system tasks. Each handler must participate in planning, `ShouldProcess`, state capture or declared compensating behavior, status/reporting, and partial-failure reporting.

The optional [God Mode desktop folder](god-mode.md) uses the focused `ShellFolder`
handler. It is a separately requested option, not a migrated legacy selector;
it does not change the upstream preset inventory or implement general file deployment.

## Custom-library interface: v3 release requirement

**Decision accepted, 2026-10-10:** A documented and implemented custom-library
interface is a v3 release requirement. Other maintainers must be able to adopt
the RIDE model and maintain their own operations and profiles in a separate
repository without modifying or forking the core engine. Migration of the
built-in catalog alone does not satisfy this release requirement.

The initial implementation now accepts explicit local library manifests,
external catalogs and declared profiles using built-in handlers. Custom-handler
registration remains pending release work; general profile inheritance is
deferred until demonstrated needs justify it.
The earlier [custom library review](#custom-library-review-2026-10-09) remains a
disposition of that library's content; it does not replace this interface work.

### Sequence during migration

1. **Define the contract now.** Document a small, versioned library manifest,
   explicit local library selection, engine compatibility, library ownership and
   operation/group ID rules. Define how external catalogs and profiles resolve
   references, reuse built-in handlers and participate in saved-run recovery.
   Keep profiles and manifests declarative. Preserve published IDs; reject
   duplicate IDs rather than silently overriding built-in or external entries.
2. **Build a metadata-only pilot during migration.** Add explicit library loading
   and shared catalog resolution, then prove a separate sample library with one
   registry operation, one package using an existing handler and a profile.
   Execution, discovery, validation, generated references and read-only completion
   must use the same resolved metadata. Discovery and completion must not import
   custom operational modules or invoke handlers. Establish this path before
   substantial additional handler work, so later migrations can reuse it.
3. **Prove custom handlers as a real need arises, before v3 release.** Introduce
   a small handler registration/dispatch contract covering inspection, desired
   state checks, apply/remove as applicable, snapshots, recovery and partial
   failures. Pilot one independently useful external handler and move existing
   handler wiring behind the contract incrementally. Use experience from the
   remaining component, package and file/asset migrations to settle the contract;
   do not wait until all migration work is finished to start integration.

Build the foundation and pilots alongside migration. Defer automatic library
installation/update, remote registries, elaborate dependency resolution and
general profile inheritance until demonstrated needs justify them. Retain the
settings/package lifecycle distinction, supported-target checks, elevation,
engine-controlled ShouldProcess and recovery reporting. Custom PowerShell code
is explicitly selected trusted code; declarative loading is not a sandbox for
custom handlers. This work does not reconnect the legacy runner or import
`lib-custom.psm1`.

### Acceptance before v3 release

- A maintainer can follow the authoring guide and starter library to add both
  metadata using built-in handlers and a new custom handler, outside the RIDE
  checkout, without editing core files. Document the manifest and handler API,
  compatibility, loading, validation, upgrade and recovery workflows.
- External entries work through the normal list/search/show, plan/status,
  apply/remove and restore paths as applicable. Enumerable library selection
  and external IDs, states and profiles receive read-only completion from the
  same selected library sources.
- Validation rejects invalid schemas, incompatible library versions, duplicate
  IDs and unresolved references before mutations. Library selection and profile
  loading do not silently discover or execute arbitrary modules.
- Saved runs identify the library, library version, operation and handler/snapshot
  contract needed for recovery. Define a tested compatibility or migration path
  for upgrades; missing or incompatible libraries produce actionable recovery
  errors before applying changes, without discarding captured state or fetching
  replacement code automatically.
- Windows-native mocked tests cover loading, dispatch, completion, preview,
  repeat apply, recovery and partial failures on PowerShell 5.1 and 7. Disposable
  Windows VM checks prove the external setting/package/handler lifecycles on
  their declared targets; Windows 11 results do not establish Server support.

This is separate engine/release work, not additional legacy feature or product
outcomes. The remaining migration estimates above are unchanged by this decision.

### Foundation implementation, 2026-10-10

Library API 1 provides explicit `-Library` selection, bounded declarative manifest
loading, merged metadata, shared catalog/profile validation, namespace and duplicate
ownership checks, external discovery/completion and separate reference export.
External `RegistryValue` and EXE/MSI `Package` operations use existing handlers.
Saved state identifies the library/version/catalog fingerprint, and restore
preflights every record before the first writer. Original library bytes remain
the recovery path; cross-version migration is not yet implemented.

The [authoring guide](custom-libraries.md) documents the contract and the copyable
`examples/contoso/` starter. Its package group references the existing 7-Zip ID
rather than introducing duplicate product ownership; mocked fixtures separately
exercise a newly declared external package. The foundation does not reconnect
legacy functions or establish a custom-handler API. Custom dispatch, upgrade
migration and disposable-VM acceptance remain open release requirements.
Validation on Windows PowerShell 5.1.26100.9549 and PowerShell 7.6.5:

- Shared validation and generated-reference checks pass with the starter selected:
  271 operations, 3 groups, 5 profiles and 86 PowerShell files.
- All 26 custom-library tests pass on each runtime, including external paths,
  metadata-only discovery/completion, validation/export, mocked setting/package
  preview, repeat apply, partial failure and restore identity checks.
- The 144 existing search, catalog, license review, observation import,
  managed-setting and package-evidence tests pass on each runtime. Their temporary
  files were placed inside the workspace to avoid sandbox rename restrictions;
  PowerShell 7 used inert Defender command declarations solely for Pester mocks.
- Broader unit runs did not pass in this sandbox: temporary-file access failures
  affected cache/review/automation tests, and PowerShell 7 lacked Defender commands
  for one mock. A clean full-suite CI run and disposable-VM library acceptance
  remain required. No real registry writer, installer or VM scenario ran here.

This is no legacy migration batch; the dated group ranges and rounded total
remain unchanged because no additional legacy outcomes were implemented.

### Guided authoring, 2026-10-10

`tools/New-RideLibrary.ps1` now guides maintainers through the supported API 1
choices and creates a validated new manifest/catalog/profile project. Shared
choices cover Package/RegistryValue, EXE/MSI, scopes, registry types, architectures
and source providers; target names come from the catalog. Repeatable declarative
definitions, preview and cancellation are supported; existing directories are
never replaced. The helper runs no handlers or installers.

Custom product/documentation links are optional; supplied links are validated.
Package download and license sources remain required. DirectHttps adds explicit
versioned publisher installers alongside GitHub releases, with an optional
expected SHA-256. RecoveryUri is an optional retained manual-recovery aid, not an
automatic version-recovery mechanism. A KeePassXC MSI authoring example replaces
the need to guess catalog fields; publisher prerequisites and VM acceptance are
still required. Custom handlers and cross-version recovery remain open.

Validation: 164 affected tests pass on each of Windows PowerShell 5.1.26100.9549
and PowerShell 7.6.5 (authoring, libraries, search, package evidence and catalog;
one WindowsIntegration test excluded). Static validation passes with the starter
selected, checking 271 operations, 3 groups, 5 profiles and 90 PowerShell files.
The KeePassXC definition was generated, resolved through search and exported with
a successful reference check. Tests use isolated workspace temporary files and
mocked network/installer calls; PowerShell 7's existing Defender test uses inert
command declarations for mocks. No package was downloaded or installed, and no
registry writer or VM integration ran.

This adds authoring/engine work, not migrated legacy outcomes; the dated group
estimates and rounded remaining total are unchanged.

### Early sample inspection and ZIP installers, 2026-10-10

The guided helper now offers an optional sample URL or local file immediately
after selecting Package, before scope, targets and architecture questions.
Bounded HTTPS downloads and content/resource inspection suggest editable installer
type, packaging/member path, product name/version and download filename without
executing payloads. Launcher architecture and separate archive/member hashes are
reported as evidence; payload support, detection, scope, arguments and licensing
remain author decisions. Download failure permits manual authoring and WhatIf
performs no download, extraction or project writes. Independent inspection is
available through `tools/Inspect-RideInstaller.ps1`.

API 1 adds optional `ArchiveType = 'Zip'`, exact `InstallerEntry` and optional
`ExpectedInstallerSha256` for DirectHttps EXE/MSI packages. Existing direct entries
remain valid. Extraction selects one bounded self-contained installer, checks type
and member digest, and cleans staging after the process exits. The complete source
ZIP and notices remain cached; acquisition evidence separates member and archive
hashes. Portable apps, adjacent payloads and detached installer workers are outside
this path. Existing compensating removal/recovery semantics remain in effect.

The supplied Windows 7 Games ZIP was downloaded and inspected without execution:
one EXE, resource version 4.3 and an x86 launcher; its inner EXE hash matches the
[publisher's checksum](https://win7games.com/). The authoring guide records exact
member/hash evidence and outstanding VM checks. A publisher-origin referrer was
needed to download it. Installation, detection, uninstall and recovery acceptance
still require disposable Windows VMs; inspection establishes no Server support.

Validation on Windows PowerShell 5.1.26100.9549 and PowerShell 7.6.5: the 164
existing affected regression tests and all 15 new inspection/ZIP tests pass on
each runtime; one WindowsIntegration test remains excluded. Tests cover early
prompts/defaults, explicit architecture, member completion/selection, cancellation,
unsafe paths/duplicates, bounded entry counts, content rejection, preview,
archive/member evidence, digest rejection and mocked EXE/MSI dispatch. Static
validation passes with the starter library: 271 operations, 3 groups, 5 profiles,
93 PowerShell files and current generated documentation. Network and installer
calls are mocked in unit tests. Separate live sample downloads/inspection pass
on both runtimes. No installer, registry writer or VM integration ran.

This adds authoring/handler infrastructure, not migrated legacy outcomes. The
dated group estimates and rounded remaining migration total are unchanged.

### Incremental library authoring and license references, 2026-10-10

The same wizard now supports `-Add` for existing generated libraries, also exposed
as `Add-RideLibraryOperation`. It reuses the namespace, requires a higher version,
preserves existing operation IDs/groups/profile choices, appends new selections,
and validates staged metadata before publication. Prior manifest/catalog/profile
bytes are retained in a sibling history directory for saved-run recovery.
Duplicate operation/product ownership is rejected. Publication locks block readers
from mixed metadata; failed writes restore the previous files. Unrelated library
files remain untouched; alternate profiles are copied into recovery metadata.

Custom LicenseUri and TermsUri are optional HTTP/HTTPS information references,
including internal hosts and localhost. A descriptive License remains required;
the wizard defaults to Unknown and can describe licenses shipped in local files
or payloads. Missing links export as Not provided, without an empty Markdown link.
The built-in catalog retains required official HTTPS licensing references, and
custom installer sources still require HTTPS. No license review decision is
inferred from an informational link.

Validation: **212 Pester tests passed** in each of Windows PowerShell 5.1 and
PowerShell 7.6.5; one Windows integration case was excluded. Coverage includes
optional/HTTP/localhost references, reference export, guided addition, duplicate
rejection, preserved selections/groups/profiles, exact prior metadata, WhatIf,
write rollback and retained recovery after rollback failure. Native validation
with the operator's existing games library passed in both editions: 271
operations, 2 groups, 5 profiles and 93 PowerShell files; built-in generated
documentation is current. No installer or state-changing VM scenario ran.

This is authoring/recovery infrastructure, not a legacy migration batch; the dated
group estimates and rounded remaining total remain unchanged. Custom handlers,
cross-version state migration and disposable-VM lifecycle acceptance remain open.

### HKCR context-menu authoring, 2026-10-10

The helper accepts HKCR and long .reg root names, mapping HKCR to
HKCU\Software\Classes for User scope or HKLM\Software\Classes for Machine scope.
The displayed destination and published metadata use that explicit root; raw
merged-view paths remain invalid in catalogs. Scope-conflicting paths are refused.
This follows Microsoft's documented Classes-root distinction and preserves a
stable inspection/recovery location without installing an HKCR drive.

API 1 now accepts RegistryValueSet with 2-10 coordinated String/DWord components
using the existing engine lifecycle. The wizard supports unnamed default values
and distinguishes empty String data from an absent value. Typed default-value
writes/deletion use the native registry API; recovery retains the original kind,
including serialized arrays. Built-in reference requirements remain in place;
custom documentation is optional. Existing IDs, manifests and saved-run identity
remain unchanged; new operations still require their matching library version.

The Certutil context-menu authoring example preserves the operator's exact two
values as one user-scoped setting, including the unusually named empty value.
No icon interpretation was substituted in that initial version. The
2026-10-11 correction in example version 0.1.1 writes
`Icon = 'shell32.dll,-152'`, as requested. Version 0.1.2 adopts the requested
`SHA-256 with Certutil` verb key and label, retaining the `SHA256` command
argument. Preserve generated 0.1.0/0.1.1 libraries and manifests for old-run
recovery against the original registry destinations. Restore earlier runs
before applying the new version to avoid duplicate verb entries; see the
[current example guidance](custom-libraries.md#hkcr-and-coordinated-registry-entries)
and [requested hashing additions](candidate-tools.md#requested-v3-additions-2026-10-11).
Windows 11 icon rendering, menu visibility, hashing,
repeat apply, unset and saved-run restore require disposable-VM acceptance.

Validation: **32 custom-registry tests passed** in each of Windows PowerShell 5.1
and PowerShell 7.6.5, covering scope mapping, literal/default values, guided and
incremental authoring, malformed metadata, completion, preview, repeat apply,
saved-run recovery, typed serialized data and preservation of unrelated values.
Affected authoring/library/catalog/search/sixty-setting regressions also passed
in both editions; one Windows integration case was excluded. Native validation
with the operator's games library and generated context-menu example passed in
both editions: 272 operations, 2 groups, 6 profiles and 94 PowerShell files;
built-in generated documentation is current. Registry access was mocked in
lifecycle tests; no registry writes or Certutil execution occurred.

This extends authoring infrastructure, not a legacy migration batch; dated group
estimates and rounded remaining migration totals remain unchanged.

### Custom-library examples reconciliation, 2026-10-12

The operator chose to relocate the former root `games-library/` into
`examples/games-library/`. The maintained example preserves `custom.games` and
`custom.games.classic-msgames`, the profile selection, installer/detection choices
and pinned archive/member digests. Version 0.1.1 removes the placeholder license
URL while retaining License=Unknown. The exact original 0.1.0 metadata remains
under `examples/games-library.history/0.1.0/` for matching saved-run recovery.
The recovery snapshot was compared byte-for-byte with the original Git blobs.

The new Windows 7 Games authoring definition reproduces the maintained manifest,
catalog and profile. The examples index links this ZIP/EXE case, KeePassXC MSI,
the Contoso starter and the current 0.1.2 Certutil icon/HKCR example. Unverified
games detection, architecture, silent arguments and licensing are called out in
its README; no replacement metadata or VM acceptance is inferred.

Windows-native checks passed in PowerShell 5.1 and 7.6.5: all three authoring
definitions generated, the maintained games files matched regenerated metadata,
the original recovery manifest resolved, and the four current libraries validated
together (305 operations, 4 groups, 8 profiles, 97 PowerShell files). Built-in
generated documentation is current. No payload was downloaded or executed and no
Windows state changed. This reconciles examples rather than migrating a legacy
outcome; dated estimates and rounded remaining migration totals are unchanged.

### One main custom-library example, 2026-10-12

The approved consolidation replaces the two current starter libraries with
`examples/library/`, one readable catalog under `example.library`. It combines
the inert marker, corrected Certutil setting, Windows 7 Games ZIP/EXE metadata
and a group referencing built-in 7-Zip. Starter custom.psd1 selects only the
marker; settings.psd1 selects the marker/Certutil, and packages.psd1 selects the
7-Zip group/Games. The generated-layout custom profile keeps `-Add` usable on a
copy without changing the two optional profiles.

This introduces new example IDs, documented in `examples/recovery/README.md`;
it does not rename old saved records or infer a state migration. Exact Contoso
0.1.0 and Games 0.1.0/0.1.1 catalogs, manifests and profiles are retained under
`examples/recovery/` for original-identity restore. Their metadata hashes were
checked before/after relocation. The earlier reconciliation paths above are
superseded by these recovery paths. Small authoring definitions remain separate
helper-input examples with their original namespaces. The historical Contoso
snapshot remains a focused published-ID lifecycle/recovery test fixture.

Validation: **37 focused Pester tests passed** in each of Windows PowerShell 5.1
and PowerShell 7.6.5, covering the shared catalog, separated profiles, completion,
copied-library Add, historical identities and existing lifecycle/recovery checks.
Native validation passed in both editions with the main library: 304 operations,
4 groups, 7 profiles and 98 PowerShell files; built-in generated documentation is
current. Original Contoso and Games 0.1.0 metadata also matches the original Git
blobs. No installers or live registry writers ran.

Games installer/detection choices and pinned digests remain unchanged except
for the new operation/PackageId namespace. Current examples still require
disposable-VM acceptance; no download or Windows mutation is part of this merge.
This consolidates documentation and metadata, not a legacy migration batch;
dated group estimates and rounded remaining totals remain unchanged.

### CLI preview forwarding and Games detection, 2026-10-12

An operator's install command without WhatIf entered preview, while removal
reported an installed Games package absent. The CLI forwarded unbound WhatIf and
Confirm variables rather than common-parameter values; native PowerShell treats
WhatIf:null as enabled. Runner 0.9.2 now forwards the effective WhatIfPreference
and only explicitly bound Confirm, including explicit false values. This covers
apply/install/set/unset/remove, download and restore; inherited preview remains
effective and the preview plan uses the same flag.

Read-only HKLM uninstall inspection found Windows 7 Games for Windows 11, 10 and 8,
version 4.3. The original ^Solitaire$ pattern did not match that registered product.
The main example advances to 0.1.1 with the exact observed product-name pattern;
the small games definition advances to 0.1.2. Main library 0.1.0 metadata, including
all profiles, is retained unchanged at examples/recovery/library/0.1.0 for matching
old-run recovery. The corrected show command reports Installed=True and 4.3.

Validation: **71 focused tests passed** in each of Windows PowerShell 5.1 and
PowerShell 7.6.5. CLI regression tests run the real runner against an isolated fake
engine, covering all seven state-changing command paths, explicit/inherited/false
WhatIf and bound/omitted Confirm without installers or registry writes. Example
and original-library lifecycle/recovery checks passed alongside them. Native
validation passed in both editions; no install, remove or download was executed
against the workstation. Package/menu VM acceptance remains pending. These are
CLI/detection repairs, not a migration batch; dated estimates remain unchanged.

### Custom-library authoring and resolver reload, 2026-10-12

The guided package prompt now identifies `DisplayNamePattern` as the exact
registered product name and explains how to verify it in Windows Installed apps
or a disposable VM. This addresses the Games bundle being entered as
`Solitaire`, an included game rather than the installed suite.

A long-lived elevated PowerShell session can retain the older API 1 resolver.
Its rejection text mentions only RegistryValue and Package even though the
current library accepts RegistryValueSet. Runner 0.9.3 refreshes the resolver
for commands and completion, and engine import refreshes it for direct callers.
An isolated regression probe preloads an obsolete resolver and verifies that
the current example resolves. No library schema or published ID changes were
needed. This is a CLI/authoring repair, so migration estimates stay unchanged.

### Deferred package detection in guided authoring, 2026-10-12

The registered uninstall DisplayName cannot reliably be inferred from an EXE
or ZIP before installation. The guided helper now accepts a blank detection
answer and saves the remaining choices as an unpublished declarative draft.
After a manual test installation in a disposable VM,
`-Definition <draft> -ResumeDraft` prompts for the observed full product name and generates the exact
regex before publishing. `-Add` follows the same path and preserves the original
library until the draft is complete. This avoids treating an unknown product
as absent in a loadable library. The published catalog schema and existing
library identities remain unchanged; migration estimates remain unchanged.

## Migration estimate review history

### Bridge/controller RC resumption retained, 2026-10-13

Before archiving this chat, reconciled its durable decisions and unresolved work
into the existing [controller ledger](migrations/controller-certification.md#resume-near-v3-release-candidate),
with links from the task list, documentation index and controller/release guides.
The accepted anonymous Full pair baseline (guest a156475/controller 55e97c0),
new host-controller scoped baseline (3107711 over guest a156475) and hosted
candidate validation (f5e3218 through identical-tree cc5481f) remain distinct.
Their committed dated reports retain the actual revisions, run IDs and hashes.
No future RC revision, newer guest source or unfinished settings is claimed
accepted by those results.

The user will resume remaining work near v3 RC; master publication is held until
RC readiness and an agreed publication/activation decision. Remaining work is
RC-source comparison/revalidation, affected live scenario acceptance, actual
workflow_dispatch/trusted master-push delivery and record reconciliation. The
runbook's cross-host reproduction requirement remains unclaimed. Optional PAT
support is approved high-priority v3 scope with implementation/acceptance pending;
reusable extraction remains deferred. The completed bridge heartbeat is confirmed
PAUSED with no next run. Backoff, process-cache boundaries, no token forwarding,
busy-resource avoidance, frozen-checkout preservation and the prohibition on
restarting ArtCraft Launcher are retained. TCP samples did not establish quota
request counts or complete causal attribution. Preserve ignored/protected raw
diagnostics when moving hosts; only the summarized evidence is version controlled.
No VM, publisher preflight, master, controller or activation-variable change.
Other migration work and unfinished fixture edits remain untouched.

Resolved, retired and newly excluded legacy outcomes: **zero**; partial/deferred
scope retained. All five reviewed ranges remain settings **38-58**, packages/
artifacts **58-73**, components **20-25**, accounts/assets **25-35**, maintenance
**8-12**; sum **149-203**, rounded **150-205**, about **180**. Handoff documentation
closes no legacy feature/product outcome, so estimates remain unchanged.

### Hosted final-source validation passed, 2026-10-13

Published candidate f5e32180faf96508c35534ba46677bc78d0fe889 passed full hosted
Validate through trigger cc5481f2bdff02015f939d1b9d631fca135737e7 on review branch
codex/ride-v3-hosted-validation-20261013. Both reference the exact same tree
29999e7a2f4e7e2dab74c35e3993782ca0cd025c, so the trigger changed no candidate
content. [Run 38413683226](https://github.com/tjuuljensen/ride-windows/actions/runs/38413683226)
finished both windows-latest jobs successfully: Windows PowerShell 5.1 passed
1,455 tests with no skips; PowerShell 7 passed 1,453 with the two intentional
Windows PowerShell-only host-preflight skips. Both had zero failures,
inconclusive or unrun tests, and passed validation of 318 operations, three
groups, five profiles and 120 PowerShell files. Decoded logs and completed job
steps were audited at 14:42:11 UTC. The
[dated evidence](archive/evidence/hosted-final-source-validation-2026-10-13.md)
records actual revisions, job IDs, totals and retained log hashes.

This closes hosted validation for the recorded candidate. The review branch
is excluded from the VM workflow push filter; no Hyper-V request, self-hosted
run, master/activation-variable change or frozen CI checkout advance occurred.
Existing branch/index and unrelated unfinished service/settings fixture edits
were preserved. Those unpublished edits are outside this result. Hosted mocked
regression does not close their native/GUI/target acceptance. Controller 0.4.6
scoped acceptance and historical anonymous bridge pairs remain accepted; its
heartbeat stays disabled. The user requires v3 release-candidate readiness
before master publication, so manual dispatch/trusted master-push gates remain
deferred. Future implementation and eventual RC source need applicable fresh
validation. ArtCraft Launcher must not be restarted.

Resolved, retired and newly excluded legacy outcomes: **zero**; partial/deferred
scope retained. All five reviewed ranges remain settings **38-58**, packages/
artifacts **58-73**, components **20-25**, accounts/assets **25-35**, maintenance
**8-12**; sum **149-203**, rounded **150-205**, about **180**. Hosted infrastructure
validation closes no legacy feature/product outcome, so estimates are unchanged.

### Controller acceptance records completed, 2026-10-13

Windows elevation allowed the reviewed acceptance.md records to be saved beside
both protected controller evidence.json files at 14:16:41 UTC. Verification at
14:17:34 UTC matched both reviewed record hashes and confirmed unchanged
configuration hashes and ValidationStatus NotValidated. Record hashes and
accepted/deferred scope are retained in the
[dated evidence](archive/evidence/controller-046-scoped-acceptance-2026-10-13.md)
and [active matrix](migrations/controller-certification.md). This closes the
candidate record step, not the broader stable-controller certificate.

Post-save readiness at 14:17:38 UTC found both VMs Off/tasks Ready/queues empty/
locks available/no recovery blocks, unchanged checkpoint/account/source pins
and five installed hashes, clean frozen CI a156475 and launcher absent. No
further VM run was submitted and no unrelated migration activity was changed.
Existing anonymous bridge 2/2 pairs remain accepted; its heartbeat stays disabled.
Final published-source hosted validation, manual dispatch/trusted master-push
and default-branch publication remain deferred. ArtCraft Launcher must not be
restarted. Master, activation variables and the CI checkout remain unchanged.

Resolved, retired and newly excluded legacy outcomes: **zero**. Partial/deferred
scope retained. Reviewed ranges remain settings **38-58**, packages/artifacts
**58-73**, components **20-25**, accounts/assets **25-35**, maintenance **8-12**;
sum **149-203**, rounded **150-205**, about **180**. Saving infrastructure
acceptance records closes no legacy feature/product outcome, so estimates are
unchanged.

### Controller 0.4.6 scoped acceptance, 2026-10-13

Candidate source 3107711/controller 0.4.6/registration 0.1.3/collector 0.4.1
completed fresh installed normal, intentional timeout and refusal acceptance on
both pinned configurations. Normal Server/Windows 11 runs each passed validation,
all 1,280 Pester tests and all 217 frozen CI source hashes. The guest baseline
stays a156475; newer migration settings are not accepted by these UnitOnly runs.

Windows 11 timeout c61528bb07394d02aec9430ac17dfa9c returned expected TimedOut
13:41:55-13:47:43 UTC, with expected client exit 1, process-tree termination,
collector completion within 90 seconds, explicit locked-transcript omission and
clean checkpoint recovery. Server timeout e9dbd5a238914edea6915bb6de7eeea7 had
the same accepted fault outcome. Neither interrupted run claims Pester completion.
Four missing-checkpoint/expired-request probes at 13:50:14-13:50:53 UTC failed
for their intended reasons before VM use, preserving configuration hashes and
full snapshot-ID sets. New registration and all result types omit host-UAC fields;
no host-UAC value or policy was read or changed. Final readiness at 13:52:48 UTC
found both VMs Off/tasks Ready/queues empty/locks available/no recovery blocks,
unchanged pins/installed hashes, clean CI and launcher absent.

The [dated report](archive/evidence/controller-046-scoped-acceptance-2026-10-13.md)
retains actual run IDs and reviewed reuse of historical operating-mode,
serialization and interrupted-worker evidence. The
[active matrix](migrations/controller-certification.md) records scoped acceptance
and remaining certification. Protected acceptance.md records belong beside each
controller's evidence.json; registration remains NotValidated. Default master
currently lacks the VM workflow; manual dispatch/trusted master-push acceptance
and final hosted validation remain deferred. No master, activation variable,
CI checkout, unrelated settings or competing migration activity was changed.
Historical anonymous bridge pairs remain accepted; its heartbeat stays disabled.
ArtCraft Launcher remains closed and must not be restarted.

Resolved, retired and newly excluded legacy outcomes: **zero**. Partial and
deferred legacy scope is retained. All five reviewed ranges remain settings
**38-58**, packages/artifacts **58-73**, components **20-25**, accounts/assets
**25-35**, maintenance **8-12**; sum **149-203**, rounded **150-205**, about
**180**. Controller infrastructure acceptance closes no legacy feature/product
outcome, so ranges and rounded estimate remain unchanged.

### Registry failure and capture repair, 2026-10-13

Follow-up implementation review found shared registry reads used silent errors,
which could report denied inspection as missing state, and removal/write/empty-key
cleanup could conceal nonterminating provider failures. Settings module 0.3.0
now uses terminating reads except recognized actual missing-key errors, reports
unavailable drives/access failures, and captures KeyExisted with the value data.
Removal checks genuine absence first; mutations and empty-key cleanup use Stop.
Value-set reader 0.2.1 and engine 0.17.1 reuse authoritative key capture while
retaining compatible fallback for earlier three-field reader objects. Saved
snapshot formats and legacy restore paths are retained.

Final local selection passed **79 mocked checks per edition** on Windows PowerShell
5.1 and PowerShell 7.6.5, including missing/denied/unavailable registry access,
terminating mutations, typed keyboard/service/policy recovery and existing
coordinated settings. Parser/catalog/profile/reference checks passed on both
editions (309 operations, three groups, five profiles, 114 PowerShell files).
Initial keyboard recovery fixtures
assumed removal did not inspect current presence; they now supply the real
post-apply present-value state for the corrected idempotent/error-reporting path.
No actual registry, startup, service, package, VM or controller schedule is changed.
The user's manual VM-testing hold remains active.

Resolved/retired/excluded legacy outcomes: **none**. This improves shared lifecycle
reporting, not target/feature acceptance. Existing partial/deferred settings and
all other group scope remain. Reviewed ranges: settings **38-58**, packages/artifacts
**58-73**, components **20-25**, accounts/configuration/files **25-35**, maintenance
**8-12**; rounded total **150-205**, about **180**. Provider/runtime acceptance in
disposable targets remains separate; estimates do not decrease for a handler repair.

### Windows Security icon guide implementation, 2026-10-13

Delivered the accepted [startup guide](security-icon-startup.md) and catalog-backed
scope/requirements presentation for the existing stable policy. Hidden, Shown and
override-removal meanings remain unchanged; Shown permits display subject to
startup/component readiness rather than repairing a launcher. The guide separates
machine/admin policy, intended-user startup, overflow, missing/managed components
and user-controlled refresh. GUI steps do not become captured/automatically
reversible RIDE actions. No historical Run reconstruction, process/service repair,
protection change or automatic refresh is introduced. Official references were
verified and generated documentation now qualifies effective inspection by handler
after the preceding firewall implementation.

Local parser/catalog/profile/generated-reference checks passed on both Windows
PowerShell 5.1 and PowerShell 7.6.5 (309 operations, three groups, five profiles,
113 PowerShell files). No additional fixture or live test was needed for this
metadata/guide-only increment. No live
startup, policy, protection, VM test or package acquisition occurs. Actual
appearance, multi-user startup scope, managed precedence and independent Server
evidence remain pending; the manual VM-confirmation hold remains in force.

Resolved/retired/excluded legacy outcomes: **none**. The accepted guided replacement
is delivered but feature/target acceptance is still partial. Other partial/deferred
scope is retained. Reviewed ranges: settings **38-58**, packages/artifacts **58-73**,
components **20-25**, accounts/configuration/files **25-35**, maintenance **8-12**.
Rounded total stays **150-205**, about **180**; documentation delivery is not
observed startup/appearance acceptance.

### Windows CEIP policy implementation, 2026-10-13

Implemented an advanced experimental Windows CEIP participation policy candidate
with OptedOut=0, OptedIn=1 and removal as separate local states. The negatively
named Group Policy has Enabled=0/Disabled=1, confirmed by exact Microsoft reference
and read-only local ICM.admx inspection; source hash is in the
[CEIP guide](ceip-policies.md). Existing scalar registry snapshots/typed recovery
are retained. SupportedTargets remains empty with Windows 11 as a candidate;
the catalog validates explicitly pending scalar policies without assigning support.

Local verification passed **22 selected mocked checks per edition** on Windows
PowerShell 5.1 and PowerShell 7.6.5: four CEIP cases, 17 notification cases and
the candidate-metadata check. Parser/catalog/profile/reference validation passed
on both editions (309 operations, three groups, five profiles, 113 PowerShell
files). No host privacy preference,
collection probe, package acquisition, client activation or VM test is performed.
Effective managed-policy/source, current CEIP consumers, editions/GUI and Server
acceptance remain open. App-V's separate installed/enabled-client consumption
mapping and native/Wow6432Node telemetry mirrors remain deferred. The user's
manual-confirmation hold remains in force; no VM schedule/controller request is made.

Resolved/retired/excluded legacy outcomes: **none**. The telemetry bundle remains
partial and all other partial/deferred scope is preserved. Reviewed ranges:
settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/configuration/files **25-35**, maintenance **8-12**. Rounded total remains
**150-205**, about **180**; a pending local policy is not a closed telemetry outcome.

### Update notification policy implementation, 2026-10-13

Implemented the accepted three-value Windows Update display-policy candidate
using the existing RegistryValueSet handler. Local ADMX/ADML read-only inspection
confirmed Machine key, gate 1/0, enum 0/1/2 and active-hours checkbox identity;
Microsoft's CSP reference supplies checkbox 0/1 and Windows 11 22H2 applicability.
Declared states distinguish explicit default, restart-warning preservation,
advanced suppression, active-hours variants, disabled gate/subordinate removal
and complete override removal. MinimumBuild 22621 is enforced independently of
target acceptance. New targets remain empty, with Windows 11 as a candidate.

Added bounded read-only registry observations to value sets; the old MusNotification
Debugger value is reported separately and excluded from writes, snapshots and
restore. Existing typed recovery and unrelated values are preserved. Policy source,
GUI normalization/notifications/reboots and independent Server applicability remain
open. The [notification guide](update-notifications.md) records local source hash,
precise boundaries and native interruption-management steps.

Final local Pester selection passed **43 checks per edition** on Windows
PowerShell 5.1 and PowerShell 7.6.5: 17 notification cases, 20 firewall cases,
five existing coordinated-registry cases and the candidate metadata check.
Parser/catalog/profile/reference validation passed on both editions (308
operations, three groups, five profiles, 112 PowerShell files). Test fixtures
exclude WindowsIntegration and automatic Pester registry writes. No live update/policy/IFEO, package
acquisition, VM test or controller schedule is performed. Manual VM confirmation
remains required. Initial new test assertions used the component argument where
the full desired state was needed; corrected fixture scope retains intended gate,
level and checkbox assertions without a product fix.

Resolved/retired/excluded legacy outcomes: **none**. The interruption-management
outcome remains partial; accepted IFEO-technique retirement was already recorded.
All other partial/deferred scope is retained. Reviewed ranges: settings **38-58**,
packages/artifacts **58-73**, components **20-25**, accounts/configuration/files
**25-35**, maintenance **8-12**; rounded total **150-205**, about **180**. A new
candidate ID and source review do not close the legacy outcome.

### Modern firewall profile implementation, 2026-10-13

Implemented four pending modern operations: independent Domain/Private/Public
On and advanced Off, plus On-only enable-all as one operation capturing all local
flags before the first write. The focused handler distinguishes PersistentStore
configuration, ActiveStore policy/source availability, active networks and legacy
key presence. Only declared local Enabled fields are written; complete preflight,
per-write drift/readback and staged errors retain bounded mixed-state recovery.
The legacy StandardProfile ID/recovery remains unchanged. No generic local reset,
NotConfigured mutation, rule/service repair, automatic cleanup or disable-all
action is added. See [modern firewall profiles](firewall-profiles.md).

All new records have empty supported targets and explicit candidate Windows
11/Server 2025 targets until VM acceptance. Normal apply is blocked. Local mocked
checks passed **44 selected tests per edition** on Windows PowerShell 5.1 and
PowerShell 7.6.5, including 20 firewall cases and relevant dispatch/presentation
and candidate metadata. An initial broader selection passed 45 checks but could
not start one existing Defender fixture because Get-MpPreference is absent; the
final supported selection excludes that unrelated fixture. Parser/catalog/profile/
generated-reference checks passed on both editions (307 operations, three groups,
five profiles, 111 PowerShell files). No VM test, controller request, package
acquisition or live firewall change occurs here. The separate infrastructure
failure-collection entry is retained as evidence from its prior scheduled request;
it does not release this chat's manual-confirmation gate.

Resolved/retired/excluded legacy outcomes: **none**. GUI/connection/lifecycle,
managed precedence and separate Server applicability remain pending. All other
partial/deferred scope is retained. Reviewed ranges: settings **38-58**,
packages/artifacts **58-73**, components **20-25**, accounts/configuration/files
**25-35**, maintenance **8-12**. Rounded total remains **150-205**, about **180**;
four new catalog IDs are not four closed legacy outcomes.

### Scheduled Windows 11 Full attempt and real failure collection, 2026-10-13

The user-authorized single follow-up ran after the reported quota reset.
At 04:44:21 UTC, one anonymous 7-Zip release lookup returned HTTP 200, version
26.04, quota **45** remaining and reset **05:43:13 UTC**. Both VMs were Off,
controllers Ready, queues empty, worker locks available and no recovery blocks.
All five installed files matched reviewed source; CI checkout was clean at
`a15647590a1324681bbe4a69cbb55e498a623522`. Newer unfinished settings changes
in the working checkout were preserved and excluded from this CI-source test.

Full Windows 11 request `45682bfb744849beb7b5b2bd1733cc15` ran
04:44:46-05:17:34 UTC with installed collector **0.4.0**, SHA-256
`57DFFD7B437B180C9136DBC3F4AE6C244915706F05095F56384EB15A476215C2`.
All **217 source hashes** matched the snapshot and frozen CI checkout. Windows
11 Enterprise Evaluation build **26300**, Windows PowerShell **5.1.26100.9444**,
passed validation and all **1,280 Pester tests**; XML reports zero failures,
errors, skips or unrun tests. Pre-package setting round trips completed; AC/DC
lid-close scenarios explicitly skipped because the VM exposes no lid setting.
Full integration failed before 7-Zip payload acquisition: quota **0**, reset
05:43:13 UTC, retry no earlier than **05:43:14 UTC**, without expired metadata
or automatic retry. No successful release observation belongs to this request.

The updated installed failure collector completed within the worker's unchanged
60-second bound, with **CollectionError null**, empty collection-errors.log and
an empty omission list. Guest-state export and checkpoint cleanup also reported
no error; UAC stayed **1/5/1**. Summary, XML, transcript and **791 retained state
JSON files**, including **395 manifests**, were preserved. Those counts include
available saved state, not a claim that every file was created by this request.
Postflight found both VMs Off, controllers Ready, queues empty, locks available,
no blocks and pinned checkpoint IDs unchanged. This was a local CI-source
request, not a GitHub workflow dispatch; no new upload artifact is claimed.
It establishes real failure-path collection of the previously problematic large
export, alongside the focused 800-file fixture, but not Full package acceptance.

Only the preflight publisher check was made by this follow-up before submission;
local evidence was monitored while the guest ran. This still does not identify
the source of shared-IP quota consumption. No host credential forwarding,
dependency configuration, repository switches, master or new target support
changed. The single scheduled follow-up is complete; no duplicate request or
additional automation was created. New settings' manual VM-acceptance hold and
their incomplete implementation remain separate from this frozen-source attempt.

Resolved, retired and excluded legacy outcomes: **zero**. All five overview
ranges and row progress were reviewed: settings **38-58**, packages/artifacts
**58-73**, components **20-25**, accounts/assets **25-35**, maintenance **8-12**;
sum **149-203**, rounded **150-205**, about **180**, unchanged because controller
recovery acceptance closes no legacy feature/product outcome. Full Windows 11
package integration, repeated two-target acceptance, overall certification,
partial settings/application scope and default-branch cutover remain open.

### Recurring bridge Full Windows 11 attempt, 2026-10-13

One anonymous publisher preflight at 05:46:13 UTC returned HTTP 200 and 45
requests remaining, resetting at 06:43:22 UTC. Both pinned VM controllers were
idle, their five installed hashes matched source, and the published CI checkout
was clean at `a15647590a1324681bbe4a69cbb55e498a623522`. Newer settings
edits in the shared working tree were excluded. Full CI-source request
`ef33b0ad1cf04029959590b02178d7d9` ran 05:46:41-06:23:44 UTC. All 217
source hashes matched, guest validation and 1,280 Pester tests passed with zero
XML failures/errors/skips/not-run. Integration failed before 7-Zip acquisition
on quota zero; reset was 06:43:22 UTC, earliest retry 06:43:23 UTC. There was no
expired metadata, automatic retry or successful release observation. Full
acceptance failed and the consecutive-pass sequence resets.

Collector 0.4.0 retained summary, XML, transcript and 791 state JSON files,
including 395 manifests. Its empty omissions list was written before the
60-second process bound, but the collector was terminated with a timeout; this
run cannot accept bounded failure collection. Guest state export and checkpoint
cleanup had no error. UAC stayed 1/5/1; both VMs ended Off, tasks Ready, queues
empty, locks available, no recovery blocks and pinned checkpoints unchanged.
Collector 0.4.1 adds timing markers and controller 0.4.3 extends the still-bounded
process limit to 90 seconds. Windows PowerShell 5.1 passed 71 focused controller
tests; the three affected PowerShell 7 launcher tests passed, while one separate
queue-order test in its full file failed. Live acceptance of the revised bound
remains required.

The first protected refresh let AutomatedLab attempt an optional version lookup
inside the recorded backoff; it received a rate-limit error. A process-only
`AutomatedLab.DisableVersionCheck` setting is now in the revised controller
source, with no token forwarding or persisted host setting. This accidental
request is a backoff defect to track. The recurring heartbeat is scheduled for
08:55 Europe/Copenhagen after the reported retry time. Its next run must check
quota and controller readiness before one serialized request. No new settings
VM acceptance is implied by this separate infrastructure request.

Resolved, retired and excluded legacy outcomes: **zero**. Reviewed ranges are
settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/assets **25-35**, maintenance **8-12**; sum **149-203**, rounded
**150-205**, about **180**, unchanged because this infrastructure run closes no
legacy feature/product outcome. Full Windows 11 package acquisition,
consecutive Windows 11/Server 2025 acceptance, controller certification,
settings acceptance and default-branch cutover remain open.

### Controller 0.4.6 Server timeout acceptance, 2026-10-13

Deliberate five-minute UnitOnly/CI request e9dbd5a238914edea6915bb6de7eeea7
returned expected TimedOut, 13:33:15-13:39:10 UTC; client exit 1 was expected.
The process tree terminated and collector 0.4.1 completed within its unchanged
90-second bound. Readable artifact/partial guest evidence was retained; the
locked transcript was explicitly omitted. Copy ran 13:39:05.998-08.163 UTC,
session closed 08.207, stderr empty, collection/cleanup errors null. No complete
transcript or Pester pass is claimed. Host-UAC fields were absent. All 217 source
hashes, five installed hashes and pins matched; target VM Off/task Ready/queues
empty/lock available/no block, clean CI a156475 and launcher absent.

Both normal configurations had passed. Readiness at 13:40:37 UTC preceded
Windows 11 timeout c61528bb07394d02aec9430ac17dfa9c. Its result and final refusal
probes were pending at this checkpoint; their completion is recorded above.
See the [dated report](archive/evidence/controller-046-scoped-acceptance-2026-10-13.md)
and .local/controller-046-server-timeout-audit.json. An intentional timeout is
accepted fault handling, not a passing Full integration run. Existing bridge
pairs remain accepted; heartbeat disabled; broader certification/master
publication deferred. No variable, CI checkout or other migration changed.
ArtCraft Launcher must not be restarted.

Resolved, retired and newly excluded legacy outcomes: zero; partial/deferred
scope retained. Reviewed ranges: settings 38-58, packages/artifacts 58-73,
components 20-25, accounts/assets 25-35, maintenance 8-12; sum 149-203, rounded
150-205/about 180, unchanged because this infrastructure run closes no legacy
feature/product outcome.

### Controller 0.4.6 Windows 11 normal acceptance, 2026-10-13

Registered UnitOnly/CI request 3c0a98c38c5b42b5991f9a5f8f150e0d passed
13:07:39-13:32:02 UTC under installed 0.4.6/collector 0.4.1 from source 3107711.
Validation, all 1,280 guest Pester tests and 217 snapshot/clean CI hashes passed;
XML has zero failures/errors/skips/unrun tests. IntegrationPassed=false is
expected for UnitOnly. The new result omits UacBefore/UacAfter. Export and
checkpoint cleanup had no errors, retaining zero state JSON/manifests. Target
VM Off/task Ready/queues empty/lock available/no block, pins/checkpoint/five
installed hashes unchanged, CI a156475 clean and launcher absent.

Both normal configurations are accepted over frozen guest source; newer guest
settings are outside this result. Both controllers were idle at 13:33:01 UTC
before Server timeout e9dbd5a238914edea6915bb6de7eeea7 started. Its expected
fault outcome was pending at this checkpoint; completion is recorded above.
See the [dated report](archive/evidence/controller-046-scoped-acceptance-2026-10-13.md)
and .local/controller-046-win11-normal-audit.json. Broader certification/manual
dispatch/master publication remain deferred, with no master, activation-variable
or CI checkout change. Bridge heartbeat remains disabled; launcher must not
be restarted.

Resolved, retired and newly excluded legacy outcomes: zero; partial/deferred
scope retained. Reviewed ranges: settings 38-58, packages/artifacts 58-73,
components 20-25, accounts/assets 25-35, maintenance 8-12; sum 149-203, rounded
150-205/about 180, unchanged because this infrastructure run closes no legacy
feature/product outcome.

### Controller 0.4.6 Server normal acceptance, 2026-10-13

Registered UnitOnly/CI request20186578684e4716a1f633a99393fe9d passed
12:43:08-13:03:10UTC under installed candidate0.4.6/collector0.4.1 and reviewed
host source3107711. Guest validation and all1280 Pester tests passed, with zero
XML failures/errors/skips/unrun. IntegrationPassedfalse is expectedUnitOnly;
this is normal controller acceptance, not a Full bridge/package run. All217
snapshot/CI source hashes match clean frozen a156475. The new final result
omits UacBefore/UacAfter; no host-UAC inspection was performed. Export and
checkpoint cleanup had no error, with zero stateJSON/manifests expected from
this unit-only run. TargetVMOff/taskReady/queuesempty/lockavailable/noblocks,
pins/checkpoint/fiveinstalledhashes unchanged; CI stayedclean and launcherabsent.
Audit.local/controller-046-server-normal-audit.json retains the actual result,
guest identity/XML/hash and recovery evidence. Both controllers were idle at
13:06:54UTC before Windows11 request3c0a98c38c5b42b5991f9a5f8f150e0d started;
that candidate normal request is active.

The [controller matrix](migrations/controller-certification.md) records Server
normal acceptance and remaining Windows11/timeout/refusal gates. Candidate
host execution is distinguished from frozen guest source and from historical
anonymous bridge2/2 acceptance. Manual GitHub dispatch/master push remain
deferred behind default-branch publication; no master, variable or CI checkout
change was made. Competing migration work remains untouched; ArtCraft Launcher
must not be restarted. Existing bridge heartbeat staysdisabled.

Resolved/retired/newly excluded legacy outcomes: zero; partial/deferred scope
retained. All five reviewed ranges remain settings38-58, packages/artifacts
58-73, components20-25, accounts/assets25-35 andmaintenance8-12; sum149-203,
rounded 150-205, about 180. No legacy feature/product outcome was closed, so
estimates stayunchanged; broader certification remains open.

### Controller 0.4.6 guarded refresh, 2026-10-13

Administrator-approved registration refreshed both protected controllers
12:37:53-12:40:02UTC from isolated reviewed source published in3107711. Both
worker locks were held, with guards refusing busy VMs/tasks/queues/recovery
blocks. All five installed hashes matched source; the module hash is
2920E1BCF41EB61564F74315FC1D004872DC0BD2DF1697CC65420A30293F2507.
VM/checkpoint/account/ISO/repository pins remained unchanged. Registration
0.1.3 omitted Host.Uac and retained NotValidated; collector stays0.4.1. Readiness
at12:42:30UTC verified both VMs Off/tasksReady/queuesempty/locksavailable/noblocks,
CIa156 clean and launcher absent. No VM or publisher request was part of refresh;
no host-UAC inspection or global policy change was performed.

The first installed candidate request20186578684e4716a1f633a99393fe9d is a
registered Server UnitOnly/CI request with90minute timeout; its later acceptance is recorded separately.
This tests the new host controller over frozen guest source, excluding other
new migration settings. The [acceptance matrix](migrations/controller-certification.md)
retains before/after evidence and open normal/fault/runtime gates. GitHub's
default master README is readable, but its VM workflow file returns404; manual
workflow_dispatch remains deferred behind default-branch publication. No master,
repository variable, CI checkout or unrelated migration activity was changed.
Current anonymous bridge2/2 pairs remain accepted and its heartbeat disabled;
ArtCraft Launcher must not be restarted.

Resolved/retired/newly excluded legacy outcomes: zero; partial/deferred scope
retained. All five reviewed ranges stay settings38-58, packages/artifacts58-73,
components20-25, accounts/assets25-35 andmaintenance8-12; sum149-203, rounded
150-205/about180. This controller refresh closes no legacy feature/product
outcome, so estimates remain unchanged; broader certification remains pending.

### Controller 0.4.6 regression validation, 2026-10-13

The newer controller0.4.5 was committed in5fdde5d. Native Windows PowerShell
5.1 passed108 focused tests; PowerShell7 reproduced the prior queue-claim
failure. JSON deserialization produced a DateTime submission value, whose
string coercion was incompatible with the Danish parser. Valid requests were
quarantined, so that PowerShell7 run failed acceptance. Controller0.4.6
normalizes parsed DateTime values to UTC round-trip strings before existing
validation. The new October13/Danish-culture regression preserves the exact
submission instant; ordered claims and malformed-request quarantine remain.

The repaired source passed109 controller/profile-boundary/release-discovery
checks on Windows PowerShell5.1 and107 on PowerShell7, with only two intentional
Windows PowerShell-only host-preflight skips. Neither had failures or unrun
tests. Parser and whitespace checks passed. Tests used isolated temporary
files and mocked system/network calls, with no VM, publisher, installer,
host-registry or global-policy actions. Source hashes, XML and pre-fix failures
are retained under.local/controller-045-ps51 and.local/controller-045-ps7.
Current recovery guidance was corrected to remove obsolete host-UAC drift
inspection. The [controller acceptance matrix](migrations/controller-certification.md)
separates this source validation from installed runtime evidence and records
historical evidence that may be reused after delta review.

Installed controllers remain0.4.3 until an idle guarded refresh. Registration
0.1.3 and candidate0.4.6 normal/failure/timeout result contracts still require
live acceptance. Existing anonymous bridge pairs Windows11 2/2 andServer2025
2/2 remain accepted on their recorded CI/controller baseline; its heartbeat
stays disabled. Competing migration work must finish before shared resources
are touched. ArtCraft Launcher must not be restarted. Broader certification,
optional authentication, settings acceptance and default-branch cutover remain
separate; no master/support-declaration change is implied.

Resolved, retired and newly excluded legacy outcomes: zero; partial/deferred
migration outcomes retained. All five reviewed ranges stay settings38-58,
packages/artifacts58-73, components20-25, accounts/assets25-35 andmaintenance
8-12; sum149-203, rounded 150-205, about 180. The infrastructure correction closes
no legacy feature/product outcome, so estimates remain unchanged.

### GitHub quota bridge two-target pair complete, 2026-10-13

Second Server Full CI-source request `420c567aea0b44118862ecfcf1de35a5`
passed 11:48:54-12:07:42 UTC. One anonymous preflight after the recorded
deadline returned HTTP 200/58 remaining/reset12:44:35 UTC. Clean published
CI `a156475` and installed reviewed controller `55e97c0` remained unchanged
(collector 0.4.1/module 0.4.3); newer controller 0.4.5, unfinished settings
and staged documentation/ledger work were preserved and excluded. Validation,
all 1,280 guest tests, applicable integration, all 217 source hashes and two
publisher SHA-256 digests passed. 7-Zip26.04/Notepad++8.9.8.1 network metadata
retained freshness; no Server ProcessCache reuse was observed. Windows 11's
pair retains real cache reuse. Last saved quota51 was not exhausted; unsupported
Windows 11 integration scenarios were explicitly skipped without expanding
Server support or skipping Pester tests.

Normal export/checkpoint cleanup had no errors, retaining 10 state JSON files
including three manifests. UAC stayed 1/5/1. Postflight12:08:10UTC verified
both VMs Off, tasks Ready, queues empty, locks available, no recovery blocks,
unchanged pins/checkpoints and all five installed hashes, CI clean and launcher
absent. Failure collection was not invoked; earlier real bounded-failure
acceptance remains separate. [Archived gate completion](archive/evidence/github-quota-bridge-pair-gate-complete-2026-10-13.md)
retains all four accepted IDs, exact baselines, applicability and provenance.

**Windows 11 2/2 and Server 2025 2/2** complete the current anonymous bridge
pair gate. The same heartbeat was disabled (PAUSED), with no next bridge run
scheduled. Shared resources are yielded for other authorized work, subject to
fresh readiness checks. Retained observed reset+1s is12:44:36UTC/14:44:36
Europe/Copenhagen for separate future publisher work, not quota exhaustion.
ArtCraft Launcher must not be restarted. Broader controller certification,
controller0.4.5 publication/acceptance, optional authentication, default-branch
cutover and unrelated settings testing remain open; no registration status,
master branch or support declaration changed.

Resolved, retired and newly excluded legacy outcomes: **zero**; partial and
deferred migration outcomes remain unchanged. All five reviewed ranges remain
settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/assets **25-35**, maintenance **8-12**; sum **149-203**, rounded
**150-205**, about **180**, unchanged because this infrastructure gate closes
no legacy feature/product outcome.

### Server 2025 first consecutive Full pass, 2026-10-13

Full CI-source request `9f3c92ba97da41d4b88de8c86e380ab4` passed
10:51:45-11:06:52 UTC. One anonymous preflight after the deadline returned
HTTP 200/57 remaining/reset11:44:21 UTC. Clean CI `a156475` and installed
reviewed controller `55e97c0` (collector 0.4.1/module 0.4.3) remained unchanged;
newer controller 0.4.5, unfinished settings and staged documentation renames
were excluded and preserved. Validation, all 1,280 guest tests, applicable
Server Full integration and all 217 snapshot/CI source hashes passed.
7-Zip 26.04 and Notepad++ 8.9.8.1 supplied two network metadata observations
with matching publisher digests and freshness provenance. No ProcessCache
reuse was observed on Server; Windows 11's pair retains real cache evidence.
The last saved publisher lookup had 51 remaining; quota was not exhausted.
Catalog-unsupported Windows 11 scenarios were explicitly skipped, without
expanding Server support or skipping Pester tests.

Normal export/checkpoint cleanup had no errors, retaining 10 state JSON files
including three manifests. UAC stayed 1/5/1; both VMs ended Off, tasks Ready,
queues empty, locks available, no recovery blocks, pins and five installed
hashes unchanged, CI clean and launcher absent. Failure collection was not
invoked; earlier bounded-failure evidence remains separate.
[Archived Server acceptance](archive/evidence/github-quota-bridge-server-first-pass-2026-10-13.md)
retains correlated identities, applicability and publisher provenance.

Progress is **Windows 11 2/2, Server 2025 1/2**. The same active heartbeat's
next attempt is **13:47 Europe/Copenhagen**, after observed reset plus one
second, for the second Server Full with fresh quota/resource checks. Disable
the bridge heartbeat after both pairs complete. ArtCraft Launcher must not
be restarted. Broader controller certification, newer controller acceptance,
default-branch cutover and unrelated settings acceptance remain separate.
Resolved, retired and newly excluded legacy outcomes: **zero**; partial and
deferred migration outcomes remain unchanged. Reviewed ranges: settings
**38-58**, packages/artifacts **58-73**, components **20-25**, accounts/assets
**25-35**, maintenance **8-12**; sum **149-203**, rounded **150-205**, about
**180**, unchanged because this infrastructure pass closes no legacy outcome.

### Windows 11 consecutive Full pair acceptance, 2026-10-13

Second Full CI-source request `dbfd74b1bfca4e0a91c4f6b088f2ee23` passed
09:49:44-10:23:06 UTC with ArtCraft Launcher still closed. One anonymous
preflight returned HTTP 200/57 remaining/reset10:44:06 UTC. Clean published
CI `a156475` and reviewed installed controller `55e97c0` remained unchanged
(collector 0.4.1/module 0.4.3); unfinished settings and staged documentation
renames were preserved and excluded. Validation, all 1,280 guest tests, Full
integration and all 217 snapshot/CI source hashes passed. Eight network plus
three real ProcessCache/payload Cache observations had matching publisher
digests; reuse preserved original timestamps and occurred before expiry.
The last saved lookup had 40 remaining; quota was not exhausted.

Normal export/checkpoint cleanup had no errors; retained state has 838 JSON
files including 413 manifests. UAC stayed 1/5/1; both VMs ended Off, tasks
Ready, queues empty, locks available, no recovery blocks, and pins and five
installed hashes unchanged. CI remained clean and the launcher absent.
Failure collection was not invoked; earlier bounded failure evidence remains
separate. [Archived pair acceptance](archive/evidence/github-quota-bridge-windows-11-pair-2026-10-13.md)
retains correlated identities, package versions and provenance.

Consecutive progress is **Windows 11 2/2, Server 2025 0/2**. The same active
heartbeat's next attempt is **12:47 Europe/Copenhagen**, after observed reset
plus one second, for the first Server Full with a fresh quota/resource check.
Two consecutive Server passes remain; disable the bridge heartbeat when both
pairs complete. Do not restart ArtCraft Launcher. Controller certification,
default-branch cutover and unrelated settings acceptance remain separate.
Resolved, retired and newly excluded legacy outcomes: **zero**; partial and
deferred settings outcomes remain unchanged. Reviewed ranges: settings
**38-58**, packages/artifacts **58-73**, components **20-25**, accounts/assets
**25-35**, maintenance **8-12**; sum **149-203**, rounded **150-205**, about
**180**, unchanged because this infrastructure gate closes no legacy outcome.

### Launcher-closed Windows 11 Full acceptance, 2026-10-13

Full CI-source request `2ceab6f49e6d408d86f713fc5ba4b28b` passed
08:49:47-09:29:57 UTC with the user-approved ArtCraft Launcher closure in
effect. The anonymous preflight returned 58 remaining, compared with 31 on
recent failed runs. Approved CI source `a156475` stayed clean; installed
collector 0.4.1/controller 0.4.3 matched the reviewed published `55e97c0`
baseline while unrelated working-copy documentation-link changes remained
excluded. Validation, all 1,280 guest tests, Full integration and all 217
source hashes passed. Eight publisher network observations and three real
ProcessCache/payload Cache observations retained matching digests. Cache
reuse occurred before each five-minute expiry; the last metadata lookup had
41 requests remaining. No expired metadata or token forwarding was used.

Guest export and checkpoint cleanup had no errors, preserving 838 retained
state JSON files including 413 manifests. UAC stayed 1/5/1; both VMs ended
Off, controllers Ready, queues empty, locks available, no recovery blocks and
pinned checkpoints/reviewed installed hashes unchanged. The launcher remained
closed. A passive sample observed 29 repeated TCP samples from VS Code;
these are not HTTP request counts or proof of exclusive quota ownership.
Detailed [archived acceptance](archive/evidence/github-quota-bridge-launcher-closed-acceptance-2026-10-13.md)
retains source/controller identities, package versions and provenance.

Consecutive Full progress is **Windows 11 1/2, Server 2025 0/2**. The same
heartbeat is set for **11:47 Europe/Copenhagen**, after the observed reset,
for the second Windows 11 run, then two Server runs if each passes. Controller
certification, default-branch cutover and unrelated settings acceptance remain
separate. Resolved, retired and excluded legacy outcomes: **zero**. Reviewed
ranges: settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/assets **25-35**, maintenance **8-12**; sum **149-203**, rounded
**150-205**, about **180**, unchanged because this infrastructure acceptance
closes no legacy feature/product outcome.

### Quota failure and observed launcher client, 2026-10-13

The 07:50:22 UTC anonymous 7-Zip preflight returned HTTP 200, version 26.04,
31 requests remaining and reset 08:43:43 UTC. Both controllers were idle;
installed hashes and VM/checkpoint/account/ISO/repository pins matched. CI
checkout was clean at `a15647590a1324681bbe4a69cbb55e498a623522`; newer
settings remained excluded. Full Windows 11 request
`21b380695758461ebe090c34f537a595` ran 07:51:53-08:20:39 UTC. Validation,
all 1,280 guest tests and all 217 source hashes passed with zero XML failures/
errors/skips/not-run. Integration failed before 7-Zip acquisition on quota zero,
reset 08:43:43 UTC, retry no earlier than 08:43:44 UTC. No expired metadata,
automatic retry or successful release observation was used. Consecutive Full
passes remain zero.

Collector 0.4.1 completed inside the 90-second bound with no errors/omissions:
copy 08:20:24.067-08:20:36.983 UTC, teardown finished 08:20:37.014 UTC.
Guest state export and checkpoint cleanup passed. Summary/XML/transcript and
791 retained state JSON files, including 395 manifests, were preserved. UAC
stayed 1/5/1; both VMs ended Off, tasks Ready, queues empty, locks available,
no recovery blocks and pinned checkpoints/installed hashes unchanged.

A passive ten-minute host sample found 465 repeated TCP observations of
ArtCraft Launcher PID 27136 against api.github.com's once-resolved address,
08:00:07.848-08:04:36.451 UTC. These are connection observations, not 465 API
requests or proof of total shared quota ownership. No obvious host proxy or
Tailscale exit node was found; the three additional CI unit tests exercise
mocked collector paths. The user approved temporarily closing the launcher
during bridge testing. Its exact verified process was stopped after a graceful
close left it running; no launcher process remains and no startup/network
configuration changed. The next heartbeat is 10:50 Europe/Copenhagen after
the 10:43:44 retry deadline, with launcher closure retained as a diagnostic
condition for that test.

Resolved, retired and excluded legacy outcomes: **zero**. Reviewed ranges:
settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/assets **25-35**, maintenance **8-12**; sum **149-203**, rounded
**150-205**, about **180**, unchanged because this infrastructure run closes
no legacy feature/product outcome. Full package acquisition, consecutive
Windows 11/Server 2025 acceptance, controller certification and default-branch
cutover remain open. Other migration work and its separate VM-test gate remain
preserved.
The [archived diagnostic](archive/evidence/github-quota-bridge-launcher-diagnostic-2026-10-13.md)
retains the completed run and passive connection evidence.

### Revised collector real failure acceptance, 2026-10-13

At 06:52:05 UTC one anonymous publisher preflight returned HTTP 200, version
26.04, 31 requests remaining and reset 07:43:34 UTC. Both controllers were
idle with matching installed hashes and unchanged pinned configuration. The
approved CI checkout was clean at `a15647590a1324681bbe4a69cbb55e498a623522`;
newer settings work stayed excluded. Full Windows 11 CI-source request
`c08c77f026034547b4ceba4cfedc93af` finished 07:21:50 UTC. Validation,
all 1,280 Pester tests and all 217 source hashes passed, with zero XML
failures/errors/skips/not-run. Integration again failed before 7-Zip payload
acquisition on quota zero. Reset is 07:43:34 UTC, retry no earlier than
07:43:35 UTC. No expired metadata, automatic retry or successful release
observation was used. This fails Full acceptance and resets consecutive passes.

Installed collector 0.4.1 completed a real quota-failure collection: its copy
ran 07:21:38.488-07:21:48.134 UTC and guest-session teardown ended
07:21:48.169 UTC, inside the worker's 90-second bound. Collection, guest state
export and checkpoint cleanup had no errors; omissions were empty. Summary,
XML, transcript and 791 retained state JSON files, including 395 manifests,
were preserved. UAC stayed 1/5/1, both VMs ended Off, tasks Ready, queues empty,
locks available, no recovery blocks and pinned checkpoint IDs unchanged. This
accepts the revised failure collector on Windows 11, without accepting package
acquisition or overall controller certification.

Resolved, retired and excluded legacy outcomes: **zero**. Reviewed ranges:
settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/assets **25-35**, maintenance **8-12**; sum **149-203**, rounded
**150-205**, about **180**, unchanged because the infrastructure run closes no
legacy feature/product outcome. The recurring bridge check is set for
09:50 Europe/Copenhagen after the 09:43:35 retry time. Full Windows 11 package
acquisition, consecutive Windows 11/Server 2025 acceptance, controller
certification and default-branch cutover remain open. The separate manual VM
hold on new settings remains in force.

### Keyboard range and service recovery follow-up, 2026-10-13

Added `Position2='2'` and `Longest='3'` to the stable keyboard repeat-delay ID,
retaining `Shortest='0'`, `LegacyAppearance='1'`, override removal, the RegistryValue
handler and its typed snapshot contract. Description and
[guide](keyboard-repeat-delay.md) explicitly distinguish stored preferences from
effective interactive-session state. Microsoft documents the native 0-3 feature
range rather than this registry mapping. Native setter/notification integration
is deferred until GUI, persistence, intended-user/session and versioned recovery
acceptance; the backend is not silently changed during the VM hold.

Review also found a defect in the preceding service increment: its typed restore
validation expected `KeyExisted`, while the real generic registry reader omits it.
Service module 0.3.1 explicitly captures key existence, refuses unavailable service
keys, and preserves unversioned raw-only records without that field by retaining
the service key. Regression fixtures now reproduce the actual reader contract
instead of assuming the field is present.

Local Pester validation passed **51 selected tests per edition** on Windows
PowerShell 5.1 and PowerShell 7.6.5. The selection covers keyboard range/completion,
serialized typed and absent literal recovery, preservation of unrelated values,
preview and saved-state failure records, plus the service regression suite and
its actual-reader/missing-key-field compatibility fixtures. WindowsIntegration
tests and Pester's automatic registry fixture are excluded. Parser/catalog/profile
and generated-reference validation passed on both editions for **303 operations,
three groups, five profiles and 109 PowerShell files**. No publisher API was used.
No live registry,
input preference, service, installer, package download or disposable VM is changed.
The user's manual-confirmation requirement remains in force for VM tests; no
controller request or future VM schedule is created by this continuation.

Resolved/retired/excluded legacy outcomes: **none**. Keyboard's visual-effects
bundle and service outcomes remain partial. Packed masks, native effective-state
recovery, GUI/boot/workload behavior and independent Server applicability remain
deferred. All other groups retain their existing scope and progress. Reviewed
ranges: settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/configuration/files **25-35**, maintenance **8-12**. Rounded total remains
**150-205**, about **180** for planning; additional states and a recovery repair
are not acceptance of a legacy feature outcome.

### WAP Push/Search service implementation and acceptance hold, 2026-10-13

Resumed Windows/application settings while package migration is paused for the
GitHub interface/cache/backoff work. Implemented the already accepted service
design on `windows.wap-push-service` and `windows.search-indexing-service`:
`AutomaticDelayedRunning` and four GUI-aligned startup-only choices. Retained
published preset meanings, IDs, baselines, profiles and target declarations.
The coordinated handler uses SCM delayed-start APIs, captures literal and SCM
state, verifies staged changes and restores version-2 or compatible unversioned
snapshots. Discovery, matching, planning/status and metadata-only completion
describe explicit versus preserved delay/runtime. See the
[service guide](service-settings.md) and
[implementation ledger](migrations/remaining-settings-decisions.md#service-implementation-increment-2026-10-13).

Final focused native Pester checks passed **38 tests per edition** on Windows
PowerShell 5.1 and PowerShell 7. The preceding broader mocked settings run passed
**235 tests**; subsequent presentation/compile/recovery assertions are covered by
the final focused suite. A new presentation test initially used the wrong
`MatchesDesired` property; correcting it to the existing `InDesiredState` property
produced the final pass without a product fix. Parser/catalog/profile/generated
reference validation passed on both editions for **303 operations, three groups,
five profiles and 108 PowerShell files**. Native API declarations compile without
opening SCM handles; service/CIM/SCM/registry effects are mocked and run records
use temporary fixture storage. WindowsIntegration tests and Pester's automatic
registry fixture remain excluded; no publisher API is requested by these checks.
No disposable VM, installer, package download or live service change runs here.
The user's explicit restriction requires **manual confirmation before any
disposable VM tests start**, after the GitHub cache/backoff investigation;
elapsed time, quota recovery or cache freshness does not release that hold.
This increment creates no VM test schedule or controller request.

Resolved/retired/excluded outcomes: **none**. WAP Push and Search remain partial
pending GUI/SCM normalization, next-boot behavior, triggers/dependencies, actual
workloads and exact real-system recovery. Server applicability remains separate
and no support is added. Deferred mapping/resource and all other group scope are
retained. Reviewed all five ranges: settings **38-58**, packages/artifacts
**58-73**, components **20-25**, accounts/configuration/files **25-35**, maintenance
**8-12**. Rounded total stays **150-205**, about **180** for planning. Implementation
and additional states do not close a legacy outcome without feature acceptance.

### Focused installed collector failure acceptance, 2026-10-13

User authorized focused failure-path testing immediately and one Full integration
follow-up after the reported quota reset. Other migration chats were inactive;
both VMs were Off, controllers Ready, queues empty, worker locks available and
no recovery blocks. Elevated fixture helper acquired the Windows 11 controller's
exclusive lock and used its installed pinned configuration and clean checkpoint.
Run `13eb2e6239c444e6b3eefa8a79d19a3f` completed at
04:11:25-04:16:40 UTC. Installed collector **0.4.0**, SHA-256
`57DFFD7B437B180C9136DBC3F4AE6C244915706F05095F56384EB15A476215C2`,
completed through `Save-RideAutomationFailureEvidence` in **36.1126535 seconds**,
inside the unchanged 60-second deadline. The fixture deliberately failed after
pre-exporting 800 small JSON files, changing a same-length file, adding one new
file and locking the guest transcript. All 800 identical files retained both
SHA-256 and last-write timestamps; changed/missing bytes arrived, and the existing
host transcript was preserved with exactly one independent omission. The 806
exported files are controlled fixture evidence, not migrated-operation outcomes.

This exercises the installed bounded failure launcher and collector against a
real guest; it is not a queued Full worker acceptance or publisher acquisition.
No package installer or RIDE operation handler ran. The helper disabled only its
own in-memory AutomatedLab version check; no persisted dependency settings changed.
Pinned checkpoint cleanup succeeded with no error, UAC stayed 1/5/1, and both
VMs returned Off, tasks Ready, queues empty, locks available and no blocks.
Local correlated logs/results are retained under `.local/collector-failure-live/`.
The fixture helper SHA-256 is
`8EF90C84999340234D71EDB4A7C25A08FF97DA6DCD4231314ABAF5CAD6EF7430`.

Created a single follow-up in this task for **06:43 Europe/Copenhagen on
2026-10-13**, after the last reported reset at 04:42:59 UTC. It checks publisher
availability once and both controllers' activity before requesting Full Windows
11 CI-source acceptance; unavailable quota or competing VM work defers submission.
No repeated polling, host-token forwarding or duplicate Full request is scheduled.

This focused acceptance resolves, retires and excludes **zero legacy outcomes**.
All five overview ranges and row examples were reviewed: settings **38-58**,
packages/artifacts **58-73**, components **20-25**, accounts/assets **25-35**,
maintenance **8-12**; sum **149-203**, rounded **150-205**, about **180**.
Ranges stay unchanged because controller recovery acceptance closes no legacy
feature/product outcome. Partial application choices, Full Windows 11 and repeated
two-target acceptance, overall certification and default-branch cutover remain open.

### Published Server acceptance and controller refresh, 2026-10-13

Commits `c415aba` and `a156475` are published on `codex/ride-v3-migration`.
[Hosted validation 38342901538](https://github.com/tjuuljensen/ride-windows/actions/runs/38342901538)
passed all **1,280 tests per edition**, with no failures, skips or unrun tests.
[Full Server CI 38342901443](https://github.com/tjuuljensen/ride-windows/actions/runs/38342901443),
request `bade4fd6631e4283a326a05c47fcc7e0`, passed at
03:42:02-03:58:58 UTC on Server 2025 build 26100. Validation, all **1,280 guest
tests** and Full integration passed. All 217 snapshot/CI source hashes matched;
collection, guest-state export and checkpoint cleanup reported no errors, with
UAC unchanged. Ten retained state JSON files include three manifests. Fresh
network metadata selected 7-Zip 26.04 and Notepad++ 8.9.8.1, with matching
publisher digests and quota 14/13 remaining at 03:58:23/26 UTC. Reset was
04:42:59 UTC. Artifact `11788600887` is 131,331 bytes, SHA-256
`2226dae3aae4c56957aba48be99960a2beffa2e725004ca41db5c8105cadc40f`.

The first elevated registration helper stopped at 03:44:42 UTC because the
Server VM was Running, before changing either controller. After the request's
cleanup and upload completed, registration refresh succeeded at
03:59:50-04:02:23 UTC under the existing controller account. Both installed
collectors are now **0.4.0**, SHA-256
`57DFFD7B437B180C9136DBC3F4AE6C244915706F05095F56384EB15A476215C2`;
all five controller files match reviewed source. VM/checkpoint/account/ISO hashes
and repository paths are unchanged. Both VMs are Off, tasks Ready, queues empty,
locks available and no recovery blocks. Registration retains **NotValidated**.
The successful Full run used the preceding Server collector 0.3.0; it does not
establish live failure-path acceptance of the newly installed collector.

Refresh logged a caught GitHub quota error during AutomatedLab initialization.
Installed AutomatedLabCore 5.61.0 makes an optional release-version request on
module import unless `AutomatedLab.DisableVersionCheck` is true. This identifies
one additional request path, not the source of all observed quota consumption.
No global dependency configuration or host credential forwarding was changed.
No additional Full request was submitted after that exhaustion observation.

This acceptance and deployment resolve, retire and exclude **zero legacy
outcomes**. All five overview ranges and row examples were reviewed: settings
**38-58**, packages/artifacts **58-73**, components **20-25**, accounts/assets
**25-35**, maintenance **8-12**; sum **149-203**, rounded **150-205**, about
**180**, unchanged because infrastructure acceptance closes no legacy outcome.
Partial application choices, live collector failure-path verification, consecutive
two-target Full acceptance, certification and default-branch cutover remain open.

### Collector continuation readiness, 2026-10-13

Read-only inspection at 02:01:43 UTC found both VMs Off, tasks Ready, empty
pending/running queues and no recovery blocks. Installed Server/Windows 11
collectors remain 0.3.0/0.2.0; tested source 0.4.0 is ready for administrator
registration refresh. The current process has a non-elevated OS token. Other
migration chats were idle. One publisher lookup again deferred on quota zero,
with reset 02:42:38 UTC and earliest retry 02:42:39 UTC. No payload, automatic
retry or VM submission followed. Remaining Full acceptance needs reliable
publisher availability; explicit authenticated discovery remains a separate
opt-in design, with no host credential forwarding introduced here.

This continuation review resolves, retires and excludes **zero legacy outcomes**.
All five overview ranges and their pending work were reviewed: settings **38-58**,
packages/artifacts **58-73**, components **20-25**, accounts/assets **25-35**,
maintenance **8-12**; sum **149-203**, rounded **150-205**, about **180**.
Existing partial application choices, collector deployment/live verification,
two-target Full acceptance, certification and default-branch cutover remain open.

### Windows 11 Full quota failure and collector repair, 2026-10-12

Post-reset host preflight at 16:37:35 UTC succeeded with 58 requests remaining;
other migration activity was documentation review, and both VMs/controllers
were idle with empty queues, available locks and unchanged pinned checkpoints.
CI-source Full request `554bf0cb1598406f852d53ea1d5ca26b` ran
16:38:15-17:07:47 UTC against `18d5f5b`. All 216 source hashes matched.
Windows 11 Enterprise Evaluation build 26300, Windows PowerShell 5.1.26100.9444,
passed validation and all 1,277 Pester tests. The preceding setting round trips
completed, but integration stopped before 7-Zip acquisition: quota zero, reset
17:37:26 UTC, earliest retry 17:37:27 UTC. There was no real successful release
observation, expired-data fallback or automatic retry. No new Windows target
or whole-build support declaration follows from this failed acceptance.

Partial collection exceeded the worker's 60-second bound. The main runner had
already retained summary, XML, transcript and 791 state JSON files, including
395 manifests; these are retained evidence counts, not a claim that every file
originated in this request. Guest state collection and checkpoint cleanup had
no error, with UAC unchanged. Postflight at 17:08:59 UTC found both VMs Off,
tasks Ready, empty queues, available locks, no blocks and pinned IDs unchanged.

Collector 0.4.0 compares guest and existing export SHA-256 values in one remote
enumeration, reuses identical files and independently copies changed/missing
files while reporting unavailable files. The 60-second recovery bound stays
unchanged. Three regressions cover 400 retained files, changed same-length bytes
and unavailable evidence; all 71 controller tests passed per PowerShell edition.
Both editions passed repository parser/catalog/profile/generated-doc validation.
Installed collectors remain Server 0.3.0 and Windows 11 0.2.0. This process is
not an OS administrator, so protected registration refresh and live verification
remain pending. Closing this task's monitoring tab and limiting API checks did
not establish a completed repeated-run sequence or identify the quota source.

This failed acceptance and repair resolve, retire and exclude **zero legacy
outcomes**. Settings **38-58**, packages/artifacts **58-73**, Windows components
**20-25**, accounts/configuration/assets **25-35**, maintenance **8-12** were
reviewed and remain unchanged: sum **149-203**, rounded **150-205**, about **180**.
Partial/deferred scope, repeated Full acceptance, protected collector verification,
overall certification and master/default-branch cutover remain open.

### Application Java and AD-analysis preparation review, 2026-10-12

Reviewed R03's nine unresolved outcomes. User confirmed current BloodHound CE
with container deployment reviewed separately, both SharpHound/AzureHound
matched to the chosen backend, and ImproHound retirement review. These four
partial legacy-outcome decisions do not install databases or collect domain/cloud
data. Host applicability, stable artifacts, licenses, compatibility and saved
state/recovery remain open; standalone Java/Neo4j, RSAT, ADReplStatus and
PingCastle remain individual choices.

Corrected the ledger's Neo4j source interpretation: the selector downloads a
Neo4j ZIP separately from APOC, modifies unrestricted procedures and installs/
starts a service; it does not use an APOC asset as the database installer.
This clarifies a blocker without accepting the outcome or its side effects.
Publisher checks distinguish current CE container deployment, backend-compatible
collectors, ImproHound's historical test matrix and Docker Desktop's exclusion
of Windows Server. JDK 11's roadmap alone does not justify retirement.

Resolved, retired or excluded this run: **zero**. Ledger totals remain 29 accepted,
79 unresolved and one Opera exclusion. No installer, database, collector, VM
test, profile or support declaration changed. Reviewed all five ranges and
row progress: settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/assets **25-35**, maintenance **8-12**; sum **149-203**, rounded
**150-205**, about **180**. Package/component examples now reflect AD preparation
and its deployment boundary; setting, asset and maintenance acceptance/ownership
work remains unchanged. Partial/deferred scope remains counted, so estimates do
not decrease for preference decisions or this source correction.

### Application Python PATH, association and pip choices, 2026-10-12

Recorded the integration-round reply **1A, 2A, 3A**: traditional Python machine
installation leaves machine PATH unchanged and preserves existing file
associations; installation uses bundled/validated pip without an automatic
upgrade. These explicitly replace three legacy side effects while retaining the
confirmed traditional machine scope and install-manager default. Exact installer
controls, command coexistence, preserved state and recovery await verification.
Manager registration/aliases, automatic missing-runtime acquisition and manager
update delivery remain separate unresolved choices; existing installations and
recommended profiles were not changed.

Resolved, retired or excluded this run: **zero**. These are partial requirements
for the existing Python outcome, not a new accepted migration. Ledger totals
remain 29 accepted, 79 unresolved and one Opera exclusion. No installer, VM test
or support declaration changed. Reviewed all five overview ranges and row
progress: settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/assets **25-35**, maintenance **8-12**; sum **149-203**, rounded
**150-205**, about **180**. Association and pip examples now reflect the explicit
choices; other groups retain their open acceptance/ownership work. No estimate
change is justified before implementation/acceptance or final retirement.

### Application Python defaults and Volatility plugin choices, 2026-10-12

Recorded user reply **1A, 2A, 3A**: Python install manager is the default variant,
the traditional installer serves all users in machine scope, and Volatility 3's
isolated environment includes core plus broader plugin dependencies. Both Python
models remain selectable under one stable product ID. Manager-managed runtimes
remain per-user; the selected traditional scope does not change that contract.
Exact releases, interpreter/wheel compatibility, manager deployment, PATH/aliases,
associations, updates, symbols/caches and recovery remain unresolved. Volatility 2
is still in retirement review; cloud/development extras and driver execution are
separate. These are preparation decisions, not implementation acceptance.

Resolved, retired or excluded this run: **zero**. The 109 application-ledger
outcomes retain their dispositions: 29 accepted, 79 unresolved and the existing
Opera exclusion. No installer, VM test or support declaration changed. Reviewed
all five overview ranges and row progress: settings **38-58**, packages/artifacts
**58-73**, components **20-25**, accounts/assets **25-35**, maintenance **8-12**;
sum **149-203**, rounded **150-205**, about **180**. The packages row now records
the confirmed default/scope/plugin choices; other examples still describe their
open behavior/ownership/update work. The subsequent integration-preparation
review presented machine-PATH, association and pip-upgrade questions, with no
answers inferred; manager automatic runtime acquisition/update delivery remains
separate. All five ranges and row examples were rechecked and remain unchanged.
Ranges remain unchanged because preference
decisions close no technical acceptance, retirement or deferred legacy outcome.

### Application Python and memory-tools preparation review, 2026-10-12

Reviewed the R02 group's five unresolved outcomes: Python, Volatility 2/3, YARA
and Loki. The [preparation record](migrations/application-review-rounds-2026-10-12.md#r02-preparation-review-2026-10-12)
captures legacy all-user Python/PATH/association/pip behavior, the install
manager's per-user runtime ownership and separate uninstall/update semantics,
archived Volatility 2 source versus standalone distribution, and Volatility 3's
checkout/symbol/dependency lifecycle. User confirmed both Python deployment models
as selectable variants under one stable product ID; its default, scope, release
and environment behavior remain undecided. User also selected Volatility 2
retirement review and a managed pinned Volatility 3 release with an isolated
Python environment; final V2 disposition and V3 runtime/dependency/symbol details
remain open. Earlier confirmed R01 choices
remain recorded; its unanswered choices remain open.

Resolved, retired or excluded this run: **zero**. No new migration implementation,
installation, VM run or support declaration. All 109 ledger selectors and their
dispositions remain: 29 accepted outcomes, 79 unresolved reviews and the existing
Opera exclusion. YARA/Loki source and update blockers remain separate. Reviewed
all five ranges and refreshed examples: settings **38-58**, packages/artifacts
**58-73**, components **20-25**, accounts/assets **25-35**, maintenance **8-12**;
sum **149-203**, rounded **150-205**, about **180**. No range adjustment is justified
because this run prepares choices and closes no implementation/acceptance work.
Existing partial/deferred outcomes and settings evaluation remain counted.

### Application ledger decision review, 2026-10-12

Reviewed all 109 application-ledger outcomes: ten earlier migrations, nineteen
newly accepted distributions, 79 unresolved review outcomes and one existing
Opera exclusion. The [discussion map](migrations/application-review-rounds-2026-10-12.md)
assigns every unresolved outcome once to 13 primary groups and records shared
runtime, collection, policy and hardware boundaries. Requirements were confirmed
for four legacy outcomes: ImageMagick's x64 Q16 HDRI DLL installer with machine
scope/PATH and listed Q16 portable build, current-user Gpg4win command line/Kleopatra
without Explorer/Outlook integration, and Wireshark live capture with an interactive,
administrator-only Npcap step without assumed OEM rights. Other editions/scopes,
integrations, applicable driver terms,
shared ownership and lifecycle acceptance remain partial/deferred. Npcap adds
new requested capability beyond the legacy silent install; it is not a newly
resolved legacy outcome. Other 75 unresolved outcomes retain individual review.

Resolved/retired/excluded this run: **zero**. No application implementation,
installation, VM test, license approval or support declaration changed. Current
publisher guidance was checked for the first decision rounds; older release
observations remain dated. This review refreshed all five ranges and their row
examples: settings **38-58**, packages/artifacts **58-73**, components **20-25**,
accounts/assets **25-35**, maintenance **8-12**, rounded **150-205**, about **180**.
The ranges remain unchanged because confirmed preferences do not close the
technical or acceptance work. Existing partial/deferred scope and settings
evaluation are retained separately. The overview table stays immediately below
the title and review summary; previous implementation/acceptance context is
preserved below it.

### Rate-aware release discovery implementation, 2026-10-12

Package module 0.10.0 implements the [release discovery contract](github-release-discovery.md):
five-minute reuse per endpoint, 64 entries/two MiB per response, shared release
quota and secondary backoff, no expired-data fallback or automatic retry, and
freshness provenance in resolved/saved artifacts and observations. Public requests
carry no authentication; scoped authentication remains a separate opt-in design.
The existing selected-asset publisher and digest/checksum checks are retained.
Focused mocked native regression passed 124 selected tests per edition, including
29 new discovery cases. Complete native regression passed 1,276 per edition with
zero failures or skips; the one workstation live-registry test was excluded.
Early Pester discovery and HTTP fixture construction failures were corrected
before these passing runs. Consecutive Full VM runs on both supported targets
remain pending. Parser/catalog/generated documentation checks passed on both
editions. The profile archive handoff edits
are retained; no additional profile implementation or acceptance is claimed.

This increment resolves, retires and excludes **zero legacy outcomes**. Settings
**38-58**, packages/artifacts **58-73**, Windows components **20-25**,
accounts/configuration/assets **25-35**, and maintenance **8-12** were reviewed
and remain unchanged: sum **149-203**, rounded **150-205**, about **180**.
Partial bundles and deferred scope remain counted. Release acceptance, remaining
controller certification and default-branch cutover remain open; master and its
VM switch are unchanged.

### Rate-aware release discovery first CI acceptance, 2026-10-12

Commit `18d5f5b` passed all 1,277 hosted tests per edition. Full CI request
`f5ae11428a5248009f891c8e5fee9ac3` passed validation, all 1,277 guest tests
and applicable Server integration. All 216 source hashes matched. Retained
7-Zip/Notepad++ acquisition records include API source, fetch/expiry times,
observed quota and matching provider digests. Collection and checkpoint cleanup
succeeded with UAC unchanged; both VMs were Off, tasks Ready and queues empty
afterward. GitHub uploaded correlated artifact `11754039820`.

A single live host lookup through the new resolver at 14:59:33 UTC correctly
deferred acquisition on quota zero, reported reset 15:37:05 UTC and earliest
retry 15:37:06 UTC, and performed no payload download or automatic retry.
Consecutive Server and Windows 11 Full acceptance remains pending; this is
one successful Server run, not a completed two-target series.

This acceptance and exhausted preflight resolve, retire and exclude **zero legacy
outcomes**. Settings **38-58**, packages/artifacts **58-73**, Windows components
**20-25**, accounts/configuration/assets **25-35**, maintenance **8-12** were
reviewed and remain unchanged: sum **149-203**, rounded **150-205**, about **180**.
Partial/deferred legacy work remains counted. Overall controller certification,
scoped authentication design and master/default-branch cutover remain deferred.

### Rate-aware release discovery repetition quota failure, 2026-10-12

After the reported reset, one host lookup at 15:43:54 UTC succeeded with 44
requests remaining. Other migration chats were idle, VMs Off, tasks Ready,
queues empty and both worker locks available before submission. Ordinary-shell
CI-source request `a51320cf5d1e47a0ad13c5c13ebfc41c` ran 15:44:37-16:00:25 UTC
against unchanged commit `18d5f5b`; all 216 retained source hashes matched.
Validation and all 1,277 guest tests passed, but Full Server integration failed
before 7-Zip acquisition: quota zero, reset 16:37:16 UTC, earliest retry
16:37:17 UTC. The resolver did not use expired data or automatically retry.
No real release-acquisition success was recorded for this request. Partial
state collection and checkpoint cleanup succeeded; both VMs were Off, tasks
Ready, queues empty, locks available, pinned IDs unchanged and UAC 1/5/1.
This local submission is CI-source evidence, not a new GitHub dispatch/upload.

The successful Server sequence was interrupted; two consecutive Full runs per
target remain pending. The source of the shared-IP quota drain is not established.
A native unit investigation with HTTP confined to a closed loopback proxy later
passed; it excluded the workstation live-registry test. No credentials or
controller configuration were changed to bypass publisher exhaustion.

This failed acceptance resolves, retires and excludes **zero legacy outcomes**.
Settings **38-58**, packages/artifacts **58-73**, Windows components **20-25**,
accounts/configuration/assets **25-35**, maintenance **8-12** were reviewed
and remain unchanged: sum **149-203**, rounded **150-205**, about **180**.
Partial/deferred scope, two-target acceptance, overall controller certification
and master/default-branch cutover remain open.

### Release-discovery network-isolation follow-up, 2026-10-12

An additional Windows PowerShell 5.1 full unit run passed 1,276 selected tests
in 18 minutes 12.84 seconds with zero failures/skips and one intentionally
excluded WindowsIntegration test. Invoke-WebRequest and Invoke-RestMethod
proxy defaults pointed to a closed loopback endpoint in the test process.
The explicit child-process tests inspect local resolver/evidence behavior.
No production code or machine integration ran in this follow-up. This supports
test isolation without identifying the shared-IP quota source. A 50-second
read-only host connection sample while both VMs were Off found a VS Code
connection to the API address; that alone cannot attribute requests or quota.
No unrelated client was stopped or changed.

This investigation resolves, retires and excludes **zero legacy outcomes**.
Settings **38-58**, packages/artifacts **58-73**, Windows components **20-25**,
accounts/configuration/assets **25-35**, maintenance **8-12** were reviewed
and remain unchanged: sum **149-203**, rounded **150-205**, about **180**.
Partial/deferred scope, repeated two-target Full acceptance, overall controller
certification and master/default-branch cutover remain open.

### PowerShell profile archive handoff review, 2026-10-12

The [profile continuation record](archive/migrations/powershell-profile-acceptance.md#continuation-after-the-chat-is-archived)
preserves the accepted implementation, maintained reproduction entry point,
exact prerequisite evidence and remaining work. Original implementation and
acceptance are committed in `3ffe294`; raw `.local` evidence remains outside Git.
Cloud hydration, network-backed Documents, interactive alternate-credential
launches, additional rendering modes and external-library support need separate
increments. Legacy startup PATH, directory provisioning and WindowsApps repair
remain deferred; profile colors are outside the legacy inventory.

This documentation review resolves, retires and excludes **zero legacy outcomes**
and performs no new Windows acceptance. Settings **38-58**, packages/artifacts
**58-73**, Windows components **20-25**, accounts/configuration/assets **25-35**
and maintenance **8-12** were reviewed and remain unchanged: sum **149-203**,
rounded **150-205**, about **180**. Existing partial bundles and independent
controller/release acceptance remain open.

### Estimate reconciliation, 2026-10-12

The last numerical revision, after remaining-applications batch 1, set settings
to **40-60** and packages/artifacts to **65-80**. Later reviews retained those
ranges because individual changes fitted their coarse uncertainty. This refresh
now applies the cumulative resolved outcomes to both endpoints, preserving the
range widths rather than treating the unchanged historical figures as current.

- Settings: **40-60 minus 2 = 38-58**, for the accepted Task Manager
  expanded/compact and Computer Browser visibility retirements recorded below
  and in the [settings decision ledger](migrations/remaining-settings-decisions.md).
- Packages/artifacts: **65-80 minus 7 = 58-73**, for Caffeine, NetworkMiner,
  Chrome, Signal, WinSCP and Thunderbird acceptance, plus Opera's user-policy
  exclusion. The [application ledger](migrations/application-migration-review.md#accounting-and-acceptance)
  reconciles **109 outcomes/components = 10 earlier migrations + 19 newly
  accepted outcomes + 79 individual review items + 1 exclusion**. Its 79 review
  items include adjacent settings, components and configuration assigned to
  their respective groups; they are not all additional package items.
- Windows components **20-25**, accounts/configuration/assets **25-35** and
  maintenance **8-12** remain unchanged: the reviewed records establish no
  additional resolved legacy outcome in these groups.

The five ranges sum to **149-203**; rounding the endpoints to the nearest five
gives **150-205**, with **about 180** as the planning figure. These remain rough
estimates, not an exact census of atomic tasks. No new implementation or target
acceptance is claimed by this documentation reconciliation. Partial legacy
bundles and separate evaluation work remain open. The PowerShell appearance
addition is outside the legacy inventory and closes no PATH or provisioning
outcome. Earlier dated estimates below are retained as historical records.

### Full GitHub controller pilot review, 2026-10-12

The [AutomatedLab follow-up](../tests/integration/automatedlab-tasks.md#full-pilot-follow-up-2026-10-12)
records CI request `575ec412969844438bfa5a3aa1812e51` from `25a3a31`.
Catalog validation passed, but eight of 1,241 unit tests failed before Full
integration began. The failures match hosted PowerShell 7 validation. Collection,
upload and Server checkpoint recovery succeeded, with host UAC unchanged.
Further pilot requests are deferred while separate profile acceptance uses the VMs.

This infrastructure acceptance run resolves, retires and excludes **zero legacy
outcomes**. Settings **38-58**, packages/artifacts **58-73**, Windows components
**20-25**, accounts/configuration/assets **25-35**, and maintenance **8-12** were
reviewed and remain unchanged. Their sum remains **149-203**, rounded to
**150-205**, about **180** for planning. Existing partial bundles, deferred work,
profile acceptance and controller acceptance remain open; no Windows target or
operation acceptance is added by this failed pilot.

### Controller unit regression repair, 2026-10-12

The [controller unit repair](../tests/integration/automatedlab-tasks.md#unit-regression-repair-2026-10-12)
addresses missing metadata assets in copied checkouts and the registry-authoring
fixture's public-command import order. Both PowerShell editions passed all 101
focused checks and all 1,241 repository checks, with zero failures or skips.
Hosted validation and Full CI acceptance are pending. No VM integration
was started, and unrelated profile migration changes are excluded from this
isolated committed-source validation. The previous competing VM work finished.

This repair resolves, retires and excludes **zero legacy outcomes**. Settings
**38-58**, packages/artifacts **58-73**, Windows components **20-25**,
accounts/configuration/assets **25-35**, and maintenance **8-12** were reviewed
and remain unchanged. The sum is still **149-203**, rounded to **150-205**,
about **180**. Partial bundles and deferred scope remain counted. Full GitHub
integration and the remaining controller acceptance are still open; these
fixture tests add no operation or Windows-target acceptance.

### Full controller retry, 2026-10-12

Full CI request `05f1359469af482390932470e007dc10` from `570a144`
passed catalog validation and all 1,241 Server guest tests. Hosted validation
also passed 1,241 tests per PowerShell edition. Integration then failed during
7-Zip acquisition with HTTP 403; a subsequent single publisher check confirmed
rate-limit exhaustion. Evidence upload, collection and checkpoint recovery
succeeded with host UAC unchanged. Both VMs and controllers were idle afterward.
See the [correlated pilot evidence](../tests/integration/automatedlab-tasks.md#unit-regression-repair-2026-10-12).

This retry resolves, retires and excludes **zero legacy outcomes**. Settings
**38-58**, packages/artifacts **58-73**, Windows components **20-25**,
accounts/configuration/assets **25-35**, and maintenance **8-12** were reviewed
and remain unchanged: sum **149-203**, rounded **150-205**, about **180**.
Partial bundles and deferred work remain counted. Separate two-target acceptance
of the requested PowerShell appearance settings closes no legacy PATH or
provisioning outcome. Full controller acceptance and rate-aware release discovery
remain open; the failed pilot adds no operation or Windows-target acceptance.

The operator subsequently authorized publication of all current changes.
Complete-state review retained the independently accepted profile handler and
its identity/visual harness, documentation and progress-tracking rules. Native
PowerShell 7 and Windows PowerShell 5.1 each passed all **1,248** repository
tests with zero failures or skips; both editions validated 303 operations, three
groups, five profiles, 106 PowerShell files and current generated documentation.
This follow-up also resolves, retires and excludes zero legacy outcomes. All
five ranges and the rounded total above remain unchanged for the same reason;
partial/deferred legacy scope and controller acceptance remain open.

### Full controller CI acceptance, 2026-10-12

After quota reset, publisher preflight returned HTTP 200 with 58 requests
remaining. Complete-state commit `3ffe294` passed all 1,248 hosted tests on
both editions. Full CI request `9706aaca6bab48cea35e7ebeb6a0eb14` then passed
catalog validation, all 1,248 Server guest tests and the applicable Full
integration scenarios. All 214 source hashes matched; GitHub uploaded the
correlated evidence, and collection/checkpoint cleanup succeeded with UAC
unchanged. Both VMs were Off, tasks Ready, queues empty and no blocks remained.
See the [dated acceptance evidence](../tests/integration/automatedlab-tasks.md#full-migration-branch-ci-acceptance-2026-10-12).

This acceptance resolves, retires and excludes **zero legacy outcomes**: it
validates migration infrastructure and previously implemented operations.
Settings **38-58**, packages/artifacts **58-73**, Windows components **20-25**,
accounts/configuration/assets **25-35**, and maintenance **8-12** were reviewed
and remain unchanged. Sum **149-203**, rounded **150-205**, about **180**.
Partial bundles and deferred scope remain counted. Separate profile appearance
acceptance adds no legacy PATH/provisioning outcome. Overall controller
certification, Windows 11 Full controller scenarios and default-branch cutover
remain deferred; publisher rate-aware discovery is still open. Server success
does not accept skipped Windows 11-only or undeclared Server package scenarios.
Final evidence notes change documentation only and use a push-skip marker to
avoid another VM request; the tested implementation remains `3ffe294`.

### Earlier estimate reviews, 2026-10-11

The 2026-10-11 [hashing additions](candidate-tools.md#requested-v3-additions-2026-10-11)
queue three new outcomes outside the legacy selector inventory. Correcting the
Certutil authoring example accepts no legacy outcome; all five group estimates
and the rounded **160-215**, about **190**, total remain unchanged.
The same-day [application continuation](archive/migrations/application-follow-up-2026-10-11.md)
accepts Caffeine and NetworkMiner on both targets, bringing these batches to
fifteen accepted distributions. All five ranges in the overview were reviewed;
the two resolved outcomes fit within their coarse uncertainty, so rounded ranges
remain unchanged. Deferred bundle components and runtime decisions remain counted.

The subsequent [installed continuation](archive/migrations/application-installed-follow-up-2026-10-11.md)
accepts machine Chrome and current-user Signal on both targets, bringing the
accepted distributions to seventeen (six installed, eleven portable). All five
groups were reviewed again: the two additional resolved product outcomes fit
within the rounded packages/artifacts **65-80** range. Settings **40-60**,
components **20-25**, accounts/assets **25-35** and maintenance **8-12** remain
unchanged; the rounded total remains **160-215**, about **190**. The application
ledger now retains 80 individual review outcomes/components and one user-policy
exclusion, including adjacent
settings and prerequisites counted in their respective estimate groups.

The same-day settings review accepts retirement of the paired legacy Task Manager
expanded/compact selector, resolving one feature outcome without adding a new
operation. Historical source is preserved; new Task Manager preferences would
need separate GUI/mapping evidence. All group ranges were reviewed and remain
unchanged, including settings **40-60**: this one disposition is within the coarse
uncertainty. The rounded total remains **160-215**, about **190**. Other accepted
setting designs still awaiting implementation and feature acceptance remain
counted in the [settings decision ledger](migrations/remaining-settings-decisions.md).

The same-day settings review also accepts retirement of the paired legacy
Computer Browser visibility selectors, resolving one further legacy outcome.
Preserve historical source and existing Hidden values; modern network-discovery
guidance is separate follow-up, not an equivalent migrated registry control.
All five group ranges were reviewed again and remain unchanged: settings
**40-60**, packages/artifacts **65-80**, components **20-25**, accounts/assets
**25-35** and maintenance **8-12**. This one additional disposition is within the
rounded uncertainty; the total remains **160-215**, about **190**. Accepted
designs still awaiting implementation/feature evidence remain counted.

The same-day user decision excludes Opera from migration and removes its legacy
installer and preset entry. All five estimate groups were reviewed again; this
one excluded product is within their rounded uncertainty. Settings **40-60**,
packages/artifacts **65-80**, components **20-25**, accounts/assets **25-35** and
maintenance **8-12** remain unchanged, totaling **160-215**, about **190**.
The subsequent [WinSCP acceptance](archive/migrations/application-winscp-follow-up-2026-10-11.md#final-correlated-acceptance)
resolves one portable product, bringing accepted distributions to eighteen
(six installed, twelve portable). Twelve portable lifecycles and 230 guest checks
passed per target. All five ranges were reviewed again and remain unchanged:
this product and the excluded Opera outcome fit within the coarse uncertainty.
The application ledger contains ten earlier migrations, eighteen newly accepted
outcomes, eighty individual review items and one user-policy exclusion.

The [Thunderbird continuation](archive/migrations/application-thunderbird-follow-up-2026-10-11.md)
records the user's Release x64/en-GB/current-user choice and implements its
destination, execution-context, edition-conflict and profile-preservation
contracts. Target acceptance is pending; the ledger now separates one
implementation awaiting acceptance from 79 individual review items. All five
estimate groups were refreshed on 2026-10-11: settings **40-60**,
packages/artifacts **65-80**, components **20-25**, accounts/assets **25-35** and
maintenance **8-12**, totaling **160-215**, about **190**. Resolving this one
product's choices does not materially change the rounded uncertainty, and
unfinished target acceptance remains accounted for.

After the user requested continuation, Thunderbird's deployment and recovery
acceptance passed on both targets: 242 guest checks and seven installed
lifecycles each. The ledger now records nineteen newly accepted outcomes
(seven installed, twelve portable), ten earlier migrations, 79 individual review
items and one user-policy exclusion. All five estimate groups were refreshed
again on 2026-10-11: settings **40-60**, packages/artifacts **65-80**, components
**20-25**, accounts/assets **25-35**, maintenance **8-12**, totaling **160-215**,
about **190**. Completing this one product does not change the rounded ranges;
the remaining edition, component, licensing and infrastructure review work is
retained. Elevated controller refresh is deferred as requested.

Settings implementation started on 2026-10-11 with the shared scope, enforcement,
GUI and prerequisite presentation contract and four reviewed existing settings.
This increment closes no additional legacy feature outcome; the remaining
metadata audits, handler work and feature acceptance stay counted. All five
rounded ranges above remain unchanged, including settings **40-60** and the
total **160-215**, about **190**. Tests were held until the concurrent application
migration and its tests finished, as requested; native PowerShell 5.1/7 then
covered 149 passing checks per edition, with two fixture checks passing on
targeted retry. Parser, catalog/profile and generated-reference checks passed
on both editions. Feature and GUI acceptance remain separate. Progress is recorded
in the [settings decision ledger](migrations/remaining-settings-decisions.md).

The estimate reconciles the family lists in the [migration inventory](#migration-inventory)
with implemented equivalents and the
[software disposition ledger](migrations/install-programs-dispositions.md).
Count an enable/disable pair as one feature and install/remove as one product
lifecycle. Count independently useful variants separately. A split into several
catalog operations does not by itself resolve several legacy work items; omitted
parts of a legacy bundle remain pending. Assign each item to one group to avoid
counting a product's installer and deployed files twice. The group ranges are
rough estimates, and their sum is rounded for the headline total.

Do not subtract the catalog operation count from the 732 legacy selector names:
paired states, one-to-many splits and separately requested additions such as God
Mode make those units different. This estimate excludes the separate
[custom library backlog](migrations/custom-ride-dispositions.md) and the 23 helper
functions outside the upstream preset.

Already implemented settings have a separate **evaluation and acceptance backlog**
in the [settings post-migration review](migrations/settings-post-migration-review.md),
including the nine numbered suggestion channels and Cortana-derived preferences.
They are not additional migration items in this table. Implementation counts do
not establish understood user-visible behavior or complete acceptance.

The earlier twelve-setting evidence rerun added no newly migrated feature or product
outcomes. It kept the then-current five group ranges and rounded **200-250** total
unchanged while closing twelve pending lifecycle checks in the separate acceptance
backlog. The two batches below subsequently adjusted the estimate. Feature/UI/restart
checks and partial legacy bundles remain pending.

## Remaining-applications batch 1, 2026-10-11

The [consolidated application ledger](migrations/application-migration-review.md)
assigns all package-family selectors to two batches and records omitted bundle
components separately. Batch 1 implements optional VS Code User Setup, Firefox
x64 MSI, DB Browser for SQLite x64 MSI and Autopsy x64 MSI. The VS Code edition
and Firefox language/architecture retain the legacy intent. Publisher adapters
resolve exact versions and declared artifact hosts; saved selection/acquisition
records retain scope, provider, variant and recovery limits.

Windows-native parser/catalog/profile and mocked checks passed on PowerShell
5.1 and 7. Both actual guests passed all four installed lifecycles and 211
focused Pester checks after correcting Firefox's MSI-wrapper EXE removal.
Windows 11 Enterprise Evaluation build 26300 and Server 2025 Standard Evaluation
build 26100 with Desktop Experience passed original-absence restore. Evidence
export, pinned checkpoint recovery and shutdown succeeded on both targets.
Production metadata now declares those two targets. Application/UI behavior,
Server Core and exact recovery of a previously installed EXE/MSI version remain
separate limits; see the dated acceptance record.

All five estimate groups were reviewed after acceptance. With nine portable
outcomes already resolved by batch 2, these four further product outcomes lower
packages/artifacts from 70-80 to **65-80** and the rounded total from 165-215 to
**160-215 / about 190**. The central planning figure remains unchanged because
of rounding. Settings 40-60, components 20-25, accounts/assets 25-35 and
maintenance 8-12 are unchanged. Licensed, interactive, driver/reboot,
Office/Teams and guest-hardware outcomes retain individual review dispositions.

### Installed continuation, 2026-10-11

Optional `package.chrome` retains the legacy enterprise stable x64 MSI and
machine scope. Its mutable publisher source is pinned to inspected version
155.0.8059.40 and SHA-256; changed bytes require review. Optional `package.signal`
retains the official stable x64 current-user distribution, binding versioned
bytes to the publisher feed's SHA-512. Removal temporarily preserves Signal's
Roaming data, refusing active processes, unsafe roots and interrupted/colliding
recovery instead of deleting or overwriting user data.

Both actual guests passed all six installed scenarios and 224 mocked guest
checks: Windows 11 request `0a58abbfedac42ab87e60c6a682b4968` and Server 2025
request `a68b43e9367148caba8f3fd173b5bdb6`. Chrome/Signal passed profile fixtures,
preview, repeat installation/removal and compensating removal recovery. Evidence
collection, pinned checkpoint reset and shutdown passed with unchanged UAC.
All 78 earlier artifact observations were preserved while 16 correlated records
were appended. Exact previous-version recovery, application UI/account behavior
and Server Core remain outside this acceptance. Profiles and published defaults
did not gain new applications.

The historical INI-to-process-variable path and application language literals
are reconciled in the [language audit](migrations/application-batch-decisions-2026-10-11.md).
The agreed Danish formats and full Office/proofing bundle remain explicit
requirements. Current ODT excludes UK English for Visio; that conflict remains
for individual decision rather than silent US-English substitution. Gpg4win's
nested GnuPG ownership, Wireshark's global content/runtime effects, FTK's
CodeMeter prerequisite and other unclear outcomes remain review items.
Estimate effects are recorded in the dated estimate section above; neither
review preparation nor a downloaded sample is counted as another migration.

## Remaining-applications batch 2, 2026-10-11

Managed portable lifecycle now uses configurable machine ToolsDirectory,
bounded extraction, hashes and an ownership journal. It refuses collisions,
preserves modified/application/user files and restores captured owned bytes
only when retained recovery files are available. Schema-3 package records and
a local selection index retain the edition/destination after preference changes;
older saved schemas remain readable. ShareX keeps its published ID and installed
default; portable is an explicit variant. No recommended profile gained apps.

Portable candidates cover Chainsaw, Hindsight GUI, CyberChef, standalone PuTTY,
ShareX portable, SRUM Dump, SrumMonkey, CyLR x86 and dejsonlz4 x86. Nested archive layouts and supplied
notices are retained. Collector, scanner and forensic parsing execution is
separate from deployment acceptance; no Defender exclusions are implicit.
Dynamic repositories/collections, unknown editions, unsupported extraction
formats and missing release evidence remain in the application ledger.

All nine portable distributions passed deployment lifecycle and recovery on
Windows 11 Enterprise Evaluation build 26300 and Server 2025 Standard Evaluation
build 26100 with Desktop Experience. Both guests passed 207 focused Pester
checks. Collected state and acquisition evidence precede successful checkpoint
reset and shutdown. Production metadata now declares those two targets.

After acceptance, all five estimate ranges were reviewed. Packages/artifacts
decreased from 80-90 to 70-80 for nine resolved distribution outcomes; settings
40-60, components 20-25, accounts/assets 25-35 and maintenance 8-12 are unchanged.
The rounded total decreased to **165-215 / about 190**. Four installed outcomes
awaited the subsequent corrected batch 1 acceptance described above. The ledger
retains omitted components of CCleaner, Arsenal/MEGAcmd and
Office/Teams. Evaluation of adjacent application settings remains in its own
review backlog. See [application packages](application-packages.md) for schema,
configuration, removal and recovery contracts.

## Remaining-settings batch 1, 2026-10-10

The user authorized the remaining Windows/application settings in two batches.
Batch 1 adds **17 optional operations**: 13 existing scheduled-task flags and
four registry policies. Each task has its own exact identity, enablement flag,
missing-resource result, preview, saved snapshot and recovery. No task is
created, launched, deleted or silently substituted. Task references document
the API; they do not establish that every historical task is present or that
disabling it achieves a complete privacy outcome.

The four policies cover application-impact telemetry, compatibility inventory,
the Start most-used list and the Ctrl+Alt+Delete sign-in requirement. The Start
policy has a current exact Microsoft reference; the earlier description of it
as obsolete is superseded by this review. Reverse privacy selectors remove
overrides through WindowsDefault; explicit Enabled/Allowed are separate states.
The secure-attention reverse selector writes an explicit value, as in legacy.

The Office Click-to-Run monitoring task is maintenance, not a telemetry promise.
Office 2016 task names remain version-dependent and unavailable when absent.
All entries stay outside recommended profiles. Telemetry and feedback bundles
remain partial because activation overrides, obsolete preview controls,
feedback-frequency data and product-specific CEIP behavior are not included.

**Estimate adjustment after batch 1:** Approximately four legacy outcomes are
resolved (scheduled drive optimization, the Start list, secure-attention sign-in
and the error-report queue completing its existing reporting preference).
The rounded settings range decreases from 65-85 to **60-80**. Packages 80-90,
components 20-25, accounts/configuration/assets 25-35 and maintenance 8-12 were
reviewed and are unchanged. The rounded total is **195-245**, about **220**.
The 17 catalog IDs are not subtracted as 17 legacy outcomes. Implementation
does not close user-visible acceptance or remove partially implemented bundles.

**Validation:** Disposable Windows 11 Enterprise Evaluation build 26300, guest
PowerShell 5.1.26100.9444 and Pester 5.7.1 passed all **851 guest tests**, followed
by **12/17 available setting lifecycles across 28 named states** in run
`60bfde39fdaf433fb12d03c0d69fae8e` (`SettingsRemainingBatch1`). Preview, repeat
apply and exact saved-run restore passed. Compatibility Appraiser, ProgramDataUpdater
and the three Office task identities were absent, so those five remain unavailable
and unvalidated. The controller collected evidence, restored the pinned clean
checkpoint, stopped the VM and reported no cleanup/collection errors. Host UAC
values were unchanged (EnableLUA=1, ConsentPromptBehaviorAdmin=5,
PromptOnSecureDesktop=1). Design decisions and pending acceptance remain in the
[post-migration review](migrations/settings-post-migration-review.md).

## Remaining-settings batch 2, 2026-10-10

Batch 2 adds **19 optional operations**, bringing these two batches to **36**.
Seven adapter binding operations capture stable adapter GUIDs and all reported
coupled flags; LLTD keeps mapper/responder together. Focused handlers cover SMB1,
SMB2/3, Controlled Folder Access, the per-interface NetBIOS registry preference,
local Remote Desktop firewall flags,
existing power-scheme selection and a coherent current-user sound scheme.
Registry settings cover Remote Desktop connection permission, NCSI policy and
three documented current Microsoft Edge policies. The old EdgeHTML preloading
area is replaced by distinct startup-boost and background-app controls; shortcut
creation is explicitly an Edge installation policy, not deletion of existing
shortcuts or a promise about every update action.

**Estimate adjustment after batch 2:** Approximately fifteen current legacy
outcomes are implemented or replaced: six protocol/discovery/client binding
outcomes, SMB1, the SMB server bundle, NetBIOS, NCSI, Remote Desktop, Controlled
Folder Access, sound scheme, current Edge startup/background behavior and Edge
installation shortcut creation. The power-scheme creation/menu bundle remains
partial. Five obsolete setting outcomes are retired from current Windows 11
scope: Wi-Fi Sense, HomeGroup, integrated Flash, IE desktop first-run and the
deprecated Maps-app update tweak. Historical source is preserved.

The rounded settings range decreases from 60-80 to **40-60**. Packages 80-90,
components 20-25, accounts/configuration/assets 25-35 and maintenance 8-12 were
reviewed and remain unchanged. Application Guard's optional-feature disposition
is retained in components rather than counted twice here. The rounded total
decreases to **175-225**, about **200**. These are approximate feature outcomes;
the 19 new IDs are not the estimate subtraction unit.

**The last-setting milestone is not reached.** Server coverage is blocked by
missing Server 2025 media/VM acceptance. Other retained work needs recovery or
current-behavior design: BitLocker enrollment/secrets, System Restore, Windows
RE, Shell registration trees, packed preferences, partial bundles and legacy
undocumented controls. The new [decision and blocker ledger](migrations/remaining-settings-decisions.md)
records all of these separately from implemented settings' behavioral acceptance.
The requested final walkthrough will use that ledger and the post-migration
review after retained implementation scope is resolved.

Native and VM validation results are recorded below. A missing
resource or failed scenario is never converted into a passed feature test.

The first two batch 2 VM attempts passed their full guest suites (857 and 859
tests) but failed integration acceptance: missing SMB1 and list-based power
recovery in the first, then CIM DHCP/default NetBIOS recovery in the second.
Both were recovered through the pinned checkpoint, with evidence collection and
host UAC unchanged. The [decision ledger](migrations/remaining-settings-decisions.md#lifecycle-evidence)
retains both failed runs and their corrections. NetBIOS now follows the legacy
registry preference with typed/absence snapshots rather than an unrecoverable
CIM-mode conversion. The third attempt passed 860 guest tests and 17 complete
setting lifecycles, including exact NetBIOS restore. It exercised 43 named states,
including two in the later failed power scenario. Power-scheme
native stderr terminated the Windows PowerShell wrapper before exit-code
inspection; saved-run recovery passed, but integration acceptance failed. The
wrapper now captures native diagnostics and validates the resulting active GUID.
Eleven focused checks pass on both native PowerShell versions. All three failed
attempts retain collected evidence, clean-checkpoint recovery and unchanged host
UAC. The successful final rerun is recorded below; this adds no migration outcomes and
leaves the reviewed estimate unchanged.

The fourth attempt passed 862 guest tests and the same 17 complete lifecycles.
Its native exit-code check confirmed a real Ultimate Performance activation
failure, while Balanced/High Performance and exact saved-run recovery worked.
The operation now exposes only those two states; Ultimate Performance selection,
creation and resource ownership remain deferred in the decision ledger. The
power bundle was already partial, so the estimate remains unchanged. Evidence
collection, pinned-checkpoint recovery and host UAC checks passed. Final
acceptance of the corrected two-state scope is recorded below.

**Final batch 2 validation:** Run `5b66779b3628494a814b061bc1ce07a9`
(`SettingsRemainingBatch2`) passed all **862 guest tests**, **18/19 available
operation lifecycles** and **43 named states** on the same Windows 11 build and
guest PowerShell/Pester versions as batch 1. Preview, repeat apply and exact
saved-run restoration passed, including NetBIOS, sound, Remote Desktop and
Balanced/High Performance selection. SMB1 was unavailable because its driver
was absent, so that lifecycle remains unvalidated. Evidence collection,
pinned-checkpoint restore and VM shutdown passed without errors; host UAC was
unchanged. The collected run directory is recorded in the decision ledger.

These two batches therefore have **30/36 operation lifecycles across 71 named
states** accepted in the disposable VM. Five task identities and SMB1 retain
resource-specific gaps. Native PowerShell 7 and 5.1 validation and generated
documentation checks pass for 270 operations, two groups and four profiles;
completion passes for all 36 settings. Feature/UI/restart acceptance and the
40-60 deferred setting outcomes remain separate. Final acceptance changes no
migration estimate, and the requested last-setting walkthrough remains pending.

## Custom library review, 2026-10-09

The separate `custom-ride` library is reconciled in the
[custom library disposition ledger](migrations/custom-ride-dispositions.md).
Its 21 module functions include two ISL functions excluded immediately at the
user's request; the remaining 19 functions, supporting scripts, bootstrap
artifacts, README candidates and desktop content have explicit dispositions.
`custom-config.ini` was not opened. This supplemental inventory does not change
the 732-selector/30-family count for the upstream legacy preset.

These are planned migrations, not new supported operations. Retain the existing
catalog IDs and the package variant/source decisions below. Do not import
`lib-custom.psm1`, restore the legacy `-include` runner, or copy bundled vendor
binaries and analyst desktop content into RIDE.

| Work item | Migration boundary and acceptance |
| --- | --- |
| FTK Imager | Prioritize one optional package with an official release-page resolver and installed lifecycle. Exterro's public [8.3 release page](https://www.exterro.com/ftk-downloads/ftk-imager-8-3) exposes the 8.3.0.27 ZIP without registration; unauthenticated HEAD returned 200. Add safe ZIP/member selection, artifact/signature evidence, actual installer arguments, detection, repeat/upgrade/removal and recovery tests. Do not carry forward the 4.7.1 EXE or copied system-DLL workaround. |
| Managed portable pilot | After the shared managed-file lifecycle exists, use Microsoft's `etl2pcapng` as a small pilot. Current v1.11.0 is a standalone EXE. Select the exact asset, record version and owned files, and validate WhatIf, modified-file preservation, removal and recovery. Acquisition tooling never runs packet collection implicitly. |
| Memory acquisition | Evaluate current Magnet DumpIt first; Process Capture 1.3 and RAM Capture 1.20 remain conditional alternatives. Implement supplied-artifact acquisition for form-gated downloads. Require modern Windows driver/VBS compatibility evidence; deployment never starts a capture. EDD 3.10 and USB Detective remain held for current-source, version, edition and distribution review. |
| RawCopy | Keep as a conditional specialist candidate. The legacy latest-release lookup selects a Windows 2000/NTFS 3.0 build. Choose the modern upstream binary at an immutable revision, review evidence and compatibility, then use the shared portable handler. |
| Analyst analysis tools | Reuse the existing YARA, capa, FLOSS, KAPE, Zimmerman, Sysinternals and Volatility work items. Add optional Detect It Easy, x64dbg, HxD, ExifTool, Thumbcache Viewer and separately evaluated Volatility Workbench; review peStudio licensing/source and named NirSoft tools individually. No default broad tool suite or replacement package IDs. |
| Active power scheme | Reconcile both `Set-PowerPlan` scripts with the Power Scheme Settings family. Add a dedicated active-scheme lifecycle or explicit extension to the power handler; capture prior GUID, distinguish scheme creation from selection, own only created schemes, and offer completion from discovered schemes. Current lid-close operations do not implement scheme selection. |
| Wi-Fi and BitLocker | Reconcile Wi-Fi import with `AddWiFi`; add secret-safe profile capture/import and exact recovery. Separate BitLocker policy from OS-volume TPM+PIN enrollment and verified recovery escrow. Reuse the BitLocker family, never treat the existing encryption-method policy as protector enrollment. Test on disposable, representative Windows targets. |
| Fonts/backgrounds | Reuse the Customization family for generic handlers if needed. SOC/organization storage owns font/branding assets; retain font licensing. The custom wallpaper/lock-screen wrappers call the wrong function and are discarded. |
| Analyst desktop material and helpers | External ownership: private SOC manifests/runbooks and controlled content storage. No SANS PDFs, incident tracker, identity/audit helpers, broad Atomic execution scripts, mailbox writers, or organization signature templates enter RIDE as custom operations. See the ledger for alternatives and individual exclusions. |

Start with FTK acquisition/lifecycle review and the shared portable pilot; follow
with distinct opt-in acquisition and analysis profiles. Keep memory capture,
forensic imaging and adversary simulation in SOC runbooks, outside setup apply.
Future profile composition may reference RIDE IDs, but must not create a second
Windows settings writer or assume an external catalog extension is already
supported. Each implementation batch requires the existing mocked/VM acceptance
rules; no new Windows support is established by this documentation review.

## PowerShell model and script follow-ups

Repository-specific models belong in `docs/models/`; `docs/repository-portfolio/`
is reserved for network-devices governance. Maintained PowerShell scripts and
exported commands follow the [native help and version contract](models/script-repository-model.md).

The [8 October 2026 PowerShell walkthrough](migrations/powershell-script-walkthrough.md)
records every script's disposition, preserved upstream/legacy exceptions, and
validation evidence. Its **Remaining operational work and exceptions** section
is the follow-up inventory for bootstrap argument handling and safety, disk
helpers, AutomatedLab guest-path staging, decoder provenance, profile/image/OpenSSH
helpers, and VM-only validation. Those repairs remain open; completion of the
help rewrite does not complete them or establish additional Windows support.

That walkthrough passed 102 isolated tests and excluded one live-registry test
for disposable-VM execution. These results supplement the batch-specific
evidence below; no new state-changing integration run occurred in the walkthrough.

## Batch rules

- Migrate active default selectors first, in the order shown, then commented selectors within each family. A single migration request may cover several consecutive batches or complete low-risk family groups; preserve each type/family boundary and review batch results before moving to a new handler type.
- Keep each batch within one operation type and family. Use **up to 10 new v3 operations** for the pilot batch. After an established handler and its mocked tests pass, allow up to **25 operations** in homogeneous, low-risk settings batches. Keep packages, Windows components, account/configuration changes, files/assets, system tasks, and any batch using a new handler at 10 or fewer until their behavior is proven. Keep related state pairs and multi-state settings together.
- Add stable catalog IDs, per-operation supported Windows targets, scope, privilege, actions, rollback behavior, and target defaults as each operation is migrated. Do not infer support from the legacy preset header.
- Mark existing v3 equivalents complete instead of re-adding them: `ShowKnownExtensions` → `windows.show-known-extensions`; `DisableAutoplay` → `windows.autoplay-policy`; `DisableAutorun` → `windows.autorun-policy`; `Install7Zip` → `package.7zip`; and the commented `InstallNotepadPlusPlus` → `package.notepadpp`.
- Keep detailed type metadata in the operation catalog and generate `docs/OPERATIONS.md` through its exporter. This plan is the migration inventory, not a second catalog.
- Before closing each batch, refresh the [remaining-work estimate](#estimated-remaining-migration-work), record the batch's effect on legacy outcomes and estimates, and update the separate post-migration evaluation backlog.

## Migration inventory

### Sixty-setting session, 2026-10-10

This explicitly requested session adds **60 optional settings**, covering **86
legacy selectors** and **43 legacy feature bundles**. It uses 34 scalar registry
operations, 11 coordinated registry value sets, four This PC namespace key sets,
four service operations, six power indexes and one BCD policy. The settings stay
outside profiles and declare Windows 11 only. Existing UWP privacy operations
were reconciled and excluded from this count.

The homogeneous family groups are Privacy (2), Security (7), Network (3),
Services (6), UI (11), Explorer (12), BitLocker (2), Applications (11) and Power
(6). The new coordinated handler is reviewed as a ten-operation pilot (seven
architecture-mirrored folder preferences, Control Panel, mouse precision and
fullscreen preferences), followed by the one-operation UAC group after its
mocked lifecycle/failure checks. This session does not raise the limit for
future new handlers.

**Migration estimate adjustment:** The 60 IDs resolve approximately **35 whole
legacy feature outcomes**, with **eight broader bundles retained as partial**:
SmartScreen, web search, security-tray startup behavior, the visual-effects
bundle, Xbox app management, media online access, WAP Push delayed startup and
Search delayed startup. The estimate counts feature outcomes, not the 60 new
IDs. Settings decrease from 100-120 to **65-85**; the other four group ranges
were reviewed and remain unchanged because this batch adds no package,
component, account/asset or maintenance lifecycle. Rounded total decreases
from 230-280 to **200-250**, or **about 225** for planning. Already implemented
but unverified effects remain in the separate evaluation backlog.

**Semantic and recovery decisions:**

- Keep native/32-bit folder mirrors, the three mouse acceleration values,
  Control Panel view, fullscreen preferences and the two UAC consent values
  inside their respective coordinated operations. Each state lists every
  component; a failure after the first write retains all original values.
  Preserve IDs and keep prior handlers available for saved-run recovery.
- UAC NoPrompt means administrators elevate without consent. SecureConsent
  uses secure-desktop consent for non-Windows binaries. These are optional
  guest-test choices; migration does not elevate a host process or change
  EnableLUA. They are not selected in a profile.
- App permission policies were already implemented. Do not create duplicates.
  SmartScreen covers the Windows Shell policy, not retired EdgeHTML. Web-search
  enforcement is edition dependent; old Cortana/Bing preferences remain excluded.
- Defender cloud membership and sample submission have different user outcomes.
  Tamper protection can reject or override policy writes; registry lifecycle
  checks do not prove effective protection. Security icon policy leaves the
  startup entry and antivirus protection alone. Memory integrity is an
  enablement request with VBS/hardware/driver/restart dependencies, not a complete
  provisioning operation.
- Visual-effects controls identify their individual effect. Do not overwrite
  UserPreferencesMask or pretend these preferences reproduce the complete
  legacy performance/appearance bundle. KeyboardDelay uses the Windows string
  preference rather than the legacy DWORD. Shortcut suffix writes four zero
  bytes; Enabled removes the override as in the legacy reverse selector.
- Folder namespace registration is separate from architecture-mirrored
  ThisPCPolicy preferences. Neither changes folder contents. Unknown current
  shell/registry mappings remain experimental and outside recommended profiles.
  Control Panel Categories writes explicit zeroes; WindowsDefault reproduces
  the legacy category selector's removal of both values.
- Service changes capture and preserve the original DelayedAutoStart value.
  AutomaticRunning does not copy the legacy WAP/Search override to 1.
  Sleep-button AC/DC actions, Sleep menu visibility, display timeout and sleep
  timeout are distinguishable settings. Timed indexes are seconds; legacy
  durations are named choices, not Windows defaults. Unavailable power settings
  are reported separately. Automatic boot recovery does not implement reagentc
  or disable/reset Windows RE.
- Developer Mode and trusted-app sideloading are independently useful local
  preferences. Media policies identify Windows Media Player Legacy and the
  individual metadata source; old radio/WMDRM controls remain excluded pending
  retirement review. Game preferences do not remove/reinstall Xbox apps.
  Microsoft's AllowGameDVR reference currently limits enforcement to Windows 10
  desktop, so the retained Windows 11 policy is explicitly experimental.
- RegistryValueSet is an additive catalog kind. Older engines cannot execute it:
  distribute catalog, engine, focused handler, validator and generator together.
  Snapshot records retain named component data/type/existence and key existence;
  no existing operation or saved-run contract is reassigned.

| Operation | Handler | Legacy selectors | States |
| --- | --- | --- | --- |
| `windows.smartscreen-shell-policy` | RegistryValue | `DisableSmartScreen`, `EnableSmartScreen` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.search-web-policy` | RegistryValue | `DisableWebSearch`, `EnableWebSearch` | `Blocked`, `Allowed`, `WindowsDefault` |
| `windows.firewall-standard-profile-policy` | RegistryValue | `DisableFirewall`, `EnableFirewall` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.security-notification-icon` | RegistryValue | `HideDefenderTrayIcon`, `ShowDefenderTrayIcon` | `Hidden`, `Shown`, `WindowsDefault` |
| `windows.memory-integrity-request` | RegistryValue | `EnableCIMemoryIntegrity`, `DisableCIMemoryIntegrity` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.defender-cloud-membership` | RegistryValue | `DisableDefenderCloud`, `EnableDefenderCloud` | `Disabled`, `Advanced`, `WindowsDefault` |
| `windows.defender-sample-submission` | RegistryValue | `DisableDefenderCloud`, `EnableDefenderCloud` | `Prompt`, `SafeSamples`, `Never`, `AllSamples`, `WindowsDefault` |
| `windows.unidentified-network-category` | RegistryValue | `SetUnknownNetworksPrivate`, `SetUnknownNetworksPublic` | `Private`, `Public`, `WindowsDefault` |
| `windows.network-device-auto-setup` | RegistryValue | `DisableNetDevicesAutoInst`, `EnableNetDevicesAutoInst` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.connection-sharing-ui` | RegistryValue | `DisableConnectionSharing`, `EnableConnectionSharing` | `Hidden`, `Available`, `WindowsDefault` |
| `windows.hardware-clock-time-basis` | RegistryValue | `SetBIOSTimeUTC`, `SetBIOSTimeLocal` | `Local`, `UTC`, `WindowsDefault` |
| `windows.sleep-menu-option` | RegistryValue | `DisableSleepButton`, `EnableSleepButton` | `Hidden`, `Shown`, `WindowsDefault` |
| `windows.window-drag-content` | RegistryValue | `SetVisualFXPerformance`, `SetVisualFXAppearance` | `Outline`, `Contents`, `WindowsDefault` |
| `windows.menu-open-delay` | RegistryValue | `SetVisualFXPerformance`, `SetVisualFXAppearance` | `Immediate`, `Delay400ms`, `WindowsDefault` |
| `windows.window-minimize-animation` | RegistryValue | `SetVisualFXPerformance`, `SetVisualFXAppearance` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.keyboard-repeat-delay` | RegistryValue | `SetVisualFXPerformance`, `SetVisualFXAppearance` | `Shortest`, `LegacyAppearance`, `WindowsDefault` |
| `windows.selection-rectangle-transparency` | RegistryValue | `SetVisualFXPerformance`, `SetVisualFXAppearance` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.desktop-label-shadows` | RegistryValue | `SetVisualFXPerformance`, `SetVisualFXAppearance` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.desktop-peek` | RegistryValue | `SetVisualFXPerformance`, `SetVisualFXAppearance` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.explorer-network-icon` | RegistryValue | `HideNetworkFromExplorer`, `ShowNetworkInExplorer` | `Hidden`, `Visible`, `WindowsDefault` |
| `windows.bitlocker-enhanced-pin` | RegistryValue | `EnableEnhancedPIN`, `DisableEnhancedPIN` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.bitlocker-additional-startup-auth` | RegistryValue | `EnableAdditionalAuthAtStart` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.onedrive-file-sync-policy` | RegistryValue | `DisableOneDrive`, `EnableOneDrive` | `Blocked`, `Allowed`, `WindowsDefault` |
| `windows.first-logon-animation` | RegistryValue | `DisableFirstLogonAnimation`, `EnableFirstLogonAnimation` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.media-player-library-sharing` | RegistryValue | `DisableMediaSharing`, `EnableMediaSharing` | `Blocked`, `UserChoice`, `WindowsDefault` |
| `windows.media-player-disc-metadata` | RegistryValue | `DisableMediaOnlineAccess`, `EnableMediaOnlineAccess` | `Blocked`, `UserChoice`, `WindowsDefault` |
| `windows.media-player-music-metadata` | RegistryValue | `DisableMediaOnlineAccess`, `EnableMediaOnlineAccess` | `Blocked`, `UserChoice`, `WindowsDefault` |
| `windows.developer-mode-preference` | RegistryValue | `EnableDeveloperMode`, `DisableDeveloperMode` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.trusted-app-sideload-preference` | RegistryValue | `EnableDeveloperMode`, `DisableDeveloperMode` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.game-mode-preference` | RegistryValue | `DisableXboxFeatures`, `EnableXboxFeatures` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.game-recording-user-preference` | RegistryValue | `DisableXboxFeatures`, `EnableXboxFeatures` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.game-recording-policy` | RegistryValue | `DisableXboxFeatures`, `EnableXboxFeatures` | `Disabled`, `Allowed`, `WindowsDefault` |
| `windows.taskbar-animation-preference` | RegistryValue | `SetVisualFXPerformance`, `SetVisualFXAppearance` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.shortcut-name-suffix` | RegistryValue | `DisableShortcutInName`, `EnableShortcutInName` | `Disabled`, `Enabled` |
| `windows.desktop-folder-this-pc` | RegistryKeySet | `HideDesktopFromThisPC`, `ShowDesktopInThisPC` | `Hidden`, `Visible` |
| `windows.documents-folder-this-pc` | RegistryKeySet | `HideDocumentsFromThisPC`, `ShowDocumentsInThisPC` | `Hidden`, `Visible` |
| `windows.downloads-folder-this-pc` | RegistryKeySet | `HideDownloadsFromThisPC`, `ShowDownloadsInThisPC` | `Hidden`, `Visible` |
| `windows.pictures-folder-this-pc` | RegistryKeySet | `HidePicturesFromThisPC`, `ShowPicturesInThisPC` | `Hidden`, `Visible` |
| `windows.telemetry-service` | WindowsService | `DisableDiagTrack`, `EnableDiagTrack` | `Disabled`, `AutomaticRunning` |
| `windows.wap-push-service` | WindowsService | `DisableWAPPush`, `EnableWAPPush` | `Disabled`, `AutomaticRunning` |
| `windows.sysmain-service` | WindowsService | `DisableSuperfetch`, `EnableSuperfetch` | `Disabled`, `AutomaticRunning` |
| `windows.search-indexing-service` | WindowsService | `DisableIndexing`, `EnableIndexing` | `Disabled`, `AutomaticRunning` |
| `windows.sleep-button-action-ac` | PowerSetting | `DisableSleepButton`, `EnableSleepButton` | `DoNothing`, `Sleep` |
| `windows.sleep-button-action-dc` | PowerSetting | `DisableSleepButton`, `EnableSleepButton` | `DoNothing`, `Sleep` |
| `windows.display-idle-timeout-ac` | PowerSetting | `DisableSleepTimeout`, `EnableSleepTimeout` | `Never`, `TenMinutes` |
| `windows.display-idle-timeout-dc` | PowerSetting | `DisableSleepTimeout`, `EnableSleepTimeout` | `Never`, `FiveMinutes` |
| `windows.sleep-idle-timeout-ac` | PowerSetting | `DisableSleepTimeout`, `EnableSleepTimeout` | `Never`, `ThirtyMinutes` |
| `windows.sleep-idle-timeout-dc` | PowerSetting | `DisableSleepTimeout`, `EnableSleepTimeout` | `Never`, `FifteenMinutes` |
| `windows.boot-failure-recovery-policy` | BootConfiguration | `DisableBootRecovery`, `EnableBootRecovery` | `IgnoreAllFailures`, `WindowsDefault` |
| `windows.desktop-folder-shell-policy` | RegistryValueSet | `HideDesktopFromExplorer`, `ShowDesktopInExplorer` | `Hidden`, `Visible`, `WindowsDefault` |
| `windows.documents-folder-shell-policy` | RegistryValueSet | `HideDocumentsFromExplorer`, `ShowDocumentsInExplorer` | `Hidden`, `Visible`, `WindowsDefault` |
| `windows.downloads-folder-shell-policy` | RegistryValueSet | `HideDownloadsFromExplorer`, `ShowDownloadsInExplorer` | `Hidden`, `Visible`, `WindowsDefault` |
| `windows.music-folder-shell-policy` | RegistryValueSet | `HideMusicFromExplorer`, `ShowMusicInExplorer` | `Hidden`, `Visible`, `WindowsDefault` |
| `windows.pictures-folder-shell-policy` | RegistryValueSet | `HidePicturesFromExplorer`, `ShowPicturesInExplorer` | `Hidden`, `Visible`, `WindowsDefault` |
| `windows.videos-folder-shell-policy` | RegistryValueSet | `HideVideosFromExplorer`, `ShowVideosInExplorer` | `Hidden`, `Visible`, `WindowsDefault` |
| `windows.3d-objects-folder-shell-policy` | RegistryValueSet | `Hide3DObjectsFromExplorer`, `Show3DObjectsInExplorer` | `Hidden`, `Visible`, `WindowsDefault` |
| `windows.control-panel-view` | RegistryValueSet | `SetControlPanelSmallIcons`, `SetControlPanelLargeIcons`, `SetControlPanelCategories` | `SmallIcons`, `LargeIcons`, `Categories`, `WindowsDefault` |
| `windows.mouse-pointer-precision` | RegistryValueSet | `DisableEnhPointerPrecision`, `EnableEnhPointerPrecision` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.fullscreen-optimizations` | RegistryValueSet | `DisableFullscreenOptims`, `EnableFullscreenOptims` | `Disabled`, `Enabled`, `WindowsDefault` |
| `windows.uac-admin-consent` | RegistryValueSet | `SetUACLow`, `SetUACHigh` | `NoPrompt`, `SecureConsent`, `WindowsDefault` |

**Validation:** Catalog/parser/generated-document validation passes on native
Windows PowerShell 5.1 and PowerShell 7 for 234 operations, two groups, four
profiles and 57 PowerShell files. Before the focused-suite enhancement, each
full native Pester run passed **712 tests**
with zero failures, including all **130 batch tests**; the one live-registry
integration test is excluded on the developer host. Disposable-VM lifecycle
acceptance is recorded below. Three additional BCD absence/recovery regression tests pass on both
native PowerShell versions after the VM exposed repeated deletion of an absent
override; the handler now skips that deletion and preserves inspection errors.

VM run `23ebc3bbe7914002935974bac75e9ce2` passed all 710 guest Pester tests and
46 new setting lifecycles. Two sleep-button indexes were unavailable in the
VM's exposed power scheme, and BCD restoration stopped the suite before the
eleven coordinated settings. Evidence collection and clean-checkpoint recovery
succeeded; captured host UAC values were unchanged.

The corrected run `1739e90855de4b0eac58726eb27b995e` reached the 25-minute
controller timeout. Partial-evidence collection also timed out after 60 seconds;
it retained some machine-state records but no terminal guest summary, Pester XML
or transcript. A UAC record at 05:35 UTC and a later Git package record at 05:37
UTC suggest execution advanced beyond the sixty-setting suite into the full
suite's package scenarios. This is partial evidence, not a completed acceptance
pass. Clean-checkpoint recovery succeeded, no cleanup block remains, and host
UAC values were unchanged. That run did not extend the earlier 46 confirmed
lifecycles. The two sleep-button controls require applicable hardware/scheme
checks; the repaired BCD policy and eleven coordinated settings were awaiting
the focused evidence rerun below.

**Focused acceptance rerun, 2026-10-10:** Run
`78b3734bfb0e4c179f0dfd7119a7aff1` passed `SettingsBatch60Recovery` on Windows 11
Enterprise Evaluation build **26300**, using guest Windows PowerShell
**5.1.26100.9444** and Pester **5.7.1**. Validation and all **718 guest Pester
tests** passed with zero failures. All **12 lifecycle scenarios** passed across
their **36 named states**: the BCD recovery policy, seven architecture-mirrored
folder preferences, Control Panel view, mouse precision, fullscreen optimization
preferences and UAC administrator consent. Each scenario checks apply/restore
preview, repeat apply and exact captured-state recovery.

Transcript, Pester XML, guest summary and saved state were collected under
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results\78b3734bfb0e4c179f0dfd7119a7aff1`.
Both summaries report Passed and the requested suite; the transcript lists all
twelve distinct IDs. Evidence collection and clean-checkpoint recovery
succeeded, the VM is off, no cleanup block remains, and host UAC values remained
`EnableLUA=1`, `ConsentPromptBehaviorAdmin=5`, `PromptOnSecureDesktop=1`.
Combined with the earlier run, **58 of 60** settings have confirmed lifecycle
acceptance; **two sleep-button indexes** remain unavailable on this VM.

Both direct and registered-task runners now accept the validated suite
selection. The installed protected controller was refreshed through the
registration workflow with administrator approval; routine requests use the
registered task without another elevation prompt. The focused-suite
orchestration checks pass **49 tests** on each native PowerShell version.
`SettingsBatch60Recovery` avoids package scenarios while retaining validation,
guest Pester, evidence correlation and checkpoint cleanup. Feature/UI/restart
acceptance remains separate; no Windows Server support is added.

### Post-migration usability review, 2026-10-10

The [settings post-migration review](migrations/settings-post-migration-review.md)
evaluates the existing one-to-many splits, including all fifteen app-suggestion
preferences and three personalization preferences retained from Cortana.
Implementation and registry lifecycle acceptance do not mean their user-visible
behavior is understood. The nine numbered content channels remain unresolved;
the catalog now names their app-suggestions area and experimental status, gives
individual literal/state descriptions, and replaces the stale Spotlight fragment.
No unknown channel is recommended for a profile or combined app-suggestions
control. IDs and saved-run recovery remain stable. Other combined settings have
explicit retain, partial, or further-review dispositions in the review.

### Forty-setting follow-up, 2026-10-09

This request adds **40 optional registry operations** with **81 explicit states**
and references **44 distinct legacy selectors**. The family boundaries are
Privacy Tweaks (22), Network Tweaks (1), Service Tweaks (7), UI Tweaks (2),
Security Tweaks (2), and Explorer UI Tweaks (6). This is the user's explicit
forty-setting session; it uses the proven scalar handler and does not increase
the pilot limit for new handlers. All entries declare Windows 11 only and remain
outside profiles. No Windows Server target is added.

| Family | Legacy selectors | Catalog operation | Explicit states |
| --- | --- | --- | --- |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.content-delivery` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.oem-preinstalled-app-suggestions` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.preinstalled-app-suggestions` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.silent-app-installation` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-310093` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-314559` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-338387` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-338388` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-338389` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-338393` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-353694` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-353696` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-353698` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.settings-pane-suggestions` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.post-setup-suggestions` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableCortana`, `EnableCortana` | `windows.implicit-text-personalization` | `Restricted=1`, `Allowed=0` |
| privacy-tweaks | `DisableCortana`, `EnableCortana` | `windows.implicit-ink-personalization` | `Restricted=1`, `Allowed=0` |
| privacy-tweaks | `DisableCortana`, `EnableCortana` | `windows.input-personalization-contact-harvesting` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableTelemetry`, `EnableTelemetry` | `windows.diagnostic-data-policy` | `Off=0`, `Required=1`, `Optional=3` |
| privacy-tweaks | `DisableTelemetry`, `EnableTelemetry` | `windows.linguistic-data-collection-policy` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableFeedback`, `EnableFeedback` | `windows.feedback-notifications-policy` | `Disabled=1`, `Allowed=0` |
| privacy-tweaks | `DisableErrorReporting`, `EnableErrorReporting` | `windows.error-reporting` | `Disabled=1`, `Enabled=0` |
| network-tweaks | `DisableNCSIProbe`, `EnableNCSIProbe` | `windows.ncsi-active-probing` | `Disabled=0`, `Enabled=1` |
| service-tweaks | `DisableUpdateMSRT`, `EnableUpdateMSRT` | `windows.msrt-update-offering` | `Disabled=1`, `Allowed=0` |
| service-tweaks | `DisableUpdateDriver`, `EnableUpdateDriver` | `windows.update-driver-policy` | `Excluded=1`, `Included=0` |
| service-tweaks | `DisableUpdateDriver`, `EnableUpdateDriver` | `windows.device-metadata-downloads` | `Prevented=1`, `UserChoice=0` |
| service-tweaks | `DisableUpdateAutoDownload`, `EnableUpdateAutoDownload` | `windows.update-download-mode` | `NotifyDownload=2`, `AutoDownload=3` |
| service-tweaks | `DisableAutoRestartSignOn`, `EnableAutoRestartSignOn` | `windows.automatic-restart-sign-on` | `Disabled=1`, `Enabled=0` |
| service-tweaks | `EnableStorageSense`, `DisableStorageSense` | `windows.storage-sense` | `Enabled=1`, `Disabled=0` |
| service-tweaks | `DisableRecycleBin`, `EnableRecycleBin` | `windows.recycle-bin-policy` | `Bypass=1`, `UseRecycleBin=0` |
| ui-tweaks | `DisableLockScreen`, `EnableLockScreen` | `windows.lock-screen-policy` | `Disabled=1`, `Enabled=0` |
| ui-tweaks | `EnableVerboseStatus`, `DisableVerboseStatus` | `windows.verbose-logon-status` | `Enabled=1`, `Disabled=0` |
| security-tweaks | `EnableSharingMappedDrives`, `DisableSharingMappedDrives` | `windows.linked-mapped-drives` | `Enabled=1`, `Disabled=0` |
| security-tweaks | `DisableDownloadBlocking`, `EnableDownloadBlocking` | `windows.attachment-zone-information` | `Discard=1`, `Preserve=2` |
| explorer-ui-tweaks | `ShowRecycleBinOnDesktop`, `HideRecycleBinFromDesktop` | `windows.desktop-recycle-bin-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowThisPCOnDesktop`, `HideThisPCFromDesktop` | `windows.desktop-this-pc-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowUserFolderOnDesktop`, `HideUserFolderFromDesktop` | `windows.desktop-user-files-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowControlPanelOnDesktop`, `HideControlPanelFromDesktop` | `windows.desktop-control-panel-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowNetworkOnDesktop`, `HideNetworkFromDesktop` | `windows.desktop-network-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowBuildNumberOnDesktop`, `HideBuildNumberFromDesktop` | `windows.desktop-build-number` | `Shown=1`, `Hidden=0` |

These are independently selectable settings, not a compatibility runner for
the legacy functions. Every entry has a Microsoft reference, a scope/elevation
requirement, `WindowsDefault` baseline, and exact captured-value restore.
`unset` removes only the declared override; it does not mean the opposite
explicit state and does not restore a prior value. Image-dependent literal
defaults remain `<platform-defined>`.

**Partial replacements and deferred behavior:**

- App suggestions: migrate the fourteen independent ContentDeliveryManager
  values and post-setup preference. Internal subscription numbers are identified
  literally rather than assigned guessed feature names. Their Microsoft links
  describe feature behavior, not those values. Current-build effects require
  review. Do not migrate `PreInstalledAppsEverEnabled` (historical bookkeeping),
  the obsolete Ink Workspace suggestion flag, CloudStore binary truncation or
  ShellExperienceHost termination. The legacy function is only partly covered.
- Cortana: expose text/ink personalization and contact harvesting as their own
  preferences. Their mappings remain subject to behavior review. Cortana app
  installation/removal, retired taskbar controls, privacy-consent bookkeeping
  and PolicyManager default-store mutations remain excluded. These settings do
  not resurrect Cortana.
- Telemetry: migrate diagnostic-data policy and linguistic-data collection.
  Diagnostic Off is edition-dependent and is not a guarantee of zero network
  traffic. Do not copy redundant non-policy/Wow6432Node mirrors, retired
  preview-build controls, licensing overrides, old AppCompat/App-V controls or
  Office/Windows scheduled-task changes. The broader function remains partial.
- Feedback and error reporting: migrate their scalar settings; SIUF frequency
  and scheduled tasks remain deferred. The [Windows Maps retirement](https://learn.microsoft.com/en-us/windows/uwp/maps-and-location)
  excludes its old automatic-update preference from this batch.
- Driver updates: keep quality-update drivers separate from device metadata
  application downloads. The legacy driver-search ordering value is deferred.
  Automatic Updates retains two supported download modes; no IFEO debugger
  workaround, implicit update installation, or reboot behavior is copied.
- Storage Sense: change only its enablement value; preserve other cleanup
  preferences and notification bookkeeping. No recursive subtree removal.
  RIDE does not run cleanup. Restoring a preference cannot recover content
  later deleted by Windows; the same limit applies to Recycle Bin bypass.
- Desktop namespace icons: migrate the Windows 11 NewStartPanel values only.
  Legacy ClassicStartMenu writes are excluded on this target. Each icon has
  explicit Shown/Hidden states, while the all-icons preference remains separate.
  No icon files are deleted and no shell restart occurs. Visible icon and
  desktop-version-label behavior still requires review.
- Mapped-drive links do not alter UAC consent settings. Attachment zone
  information is modeled accurately as Preserve/Discard, not as a universal
  download blocker; existing file metadata is not changed.

**Validation:** Catalog generation and parser validation pass for 174 operations,
2 groups, 4 profiles and 52 maintained PowerShell files. All 570 isolated tests
pass on both Windows PowerShell 5.1 and PowerShell 7; the live-registry test is
reserved for the disposable VM. Settings-only run
`2ab1773b3c5944819fcff8dab44342d0` passed all 571 Pester tests and all 40
registry lifecycle scenarios on Windows 11 Enterprise Evaluation, build 26300.
The suite exercised all 81 explicit states, preview, repeat apply, baseline
removal, and prior value/type/existence restore. Evidence collection and clean
checkpoint recovery succeeded, leaving the VM off. This batch did not request
host UAC elevation; the host's UAC consent values remained unchanged.
Feature effects, UI refresh, restart,
actual update acquisition, network probing and deferred multi-component
behavior remain separate acceptance work.

### Optional Windows settings session, 2026-10-09

This migration adds **20 optional registry operations** covering **41 legacy
selectors** in consecutive family batches: UI Tweaks (9), Privacy Tweaks (7),
Service Tweaks (3), and Explorer UI Tweaks (1). All use the established
`RegistryValue` lifecycle, preserve state pairs, declare Windows 11 only, and
stay outside the workstation default profile.

| Family | Legacy selectors | Catalog operation | Explicit states |
| --- | --- | --- | --- |
| ui-tweaks | `HideNetworkFromLockScreen`, `ShowNetworkOnLockScreen` | `windows.lock-screen-network-selection` | `Hidden=1`, `Shown=0` |
| ui-tweaks | `HideShutdownFromLockScreen`, `ShowShutdownOnLockScreen` | `windows.shutdown-without-logon` | `Disabled=0`, `Enabled=1` |
| ui-tweaks | `DisableAeroShake`, `EnableAeroShake` | `windows.title-bar-shake` | `Disabled=1`, `Enabled=0` |
| ui-tweaks | `HideRecentlyAddedApps`, `ShowRecentlyAddedApps` | `windows.start-recently-added-apps` | `Hidden=1`, `UserChoice=0` |
| ui-tweaks | `EnableTitleBarColor`, `DisableTitleBarColor` | `windows.title-bar-accent-color` | `Enabled=1`, `Disabled=0` |
| ui-tweaks | `SetAppsDarkMode`, `SetAppsLightMode` | `windows.app-color-mode` | `Dark=0`, `Light=1` |
| ui-tweaks | `SetSystemDarkMode`, `SetSystemLightMode` | `windows.system-color-mode` | `Dark=0`, `Light=1` |
| ui-tweaks | `DisableChangingSoundScheme`, `EnableChangingSoundScheme` | `windows.sound-scheme-change-policy` | `Blocked=1`, `Allowed=0` |
| ui-tweaks | `SetTaskbarAlignmentLeft`, `SetTaskbarAlignmentMiddle` | `windows.taskbar-alignment` | `Left=0`, `Centered=1` |
| privacy-tweaks | `DisableSensors`, `EnableSensors` | `windows.sensors-policy` | `Disabled=1`, `Allowed=0` |
| privacy-tweaks | `DisableBiometrics`, `EnableBiometrics` | `windows.biometrics-policy` | `Disabled=0`, `Allowed=1` |
| privacy-tweaks | `DisableCamera`, `EnableCamera` | `windows.app-camera-policy` | `ForceDeny=2`, `ForceAllow=1`, `UserControl=0` |
| privacy-tweaks | `DisableMicrophone`, `EnableMicrophone` | `windows.app-microphone-policy` | `ForceDeny=2`, `ForceAllow=1`, `UserControl=0` |
| privacy-tweaks | `SetP2PUpdateLocal`, `SetP2PUpdateInternet`, `SetP2PUpdateDisable` | `windows.delivery-optimization-download-mode` | `HttpOnly=0`, `LocalNetwork=1`, `Internet=3` |
| privacy-tweaks | `EnableClearRecentFiles`, `DisableClearRecentFiles` | `windows.clear-recent-documents-on-exit` | `Enabled=1`, `Disabled=0` |
| privacy-tweaks | `DisableRecentFiles`, `EnableRecentFiles` | `windows.recent-document-history-policy` | `Disabled=1`, `Allowed=0` |
| service-tweaks | `DisableFastStartup`, `EnableFastStartup` | `windows.fast-startup` | `Disabled=0`, `Enabled=1` |
| service-tweaks | `DisableAutoRebootOnCrash`, `EnableAutoRebootOnCrash` | `windows.auto-reboot-on-crash` | `Disabled=0`, `Enabled=1` |
| service-tweaks | `EnableClipboardHistory`, `DisableClipboardHistory` | `windows.clipboard-history` | `Enabled=1`, `Disabled=0` |
| explorer-ui-tweaks | `ShowNavPaneLibraries`, `HideNavPaneLibraries` | `windows.navigation-pane-libraries` | `Shown=1`, `Hidden=0` |

Every operation also provides `WindowsDefault` and uses it as its baseline:
remove the override without assuming that removal is the opposite explicit
state. `unset` removes the override; saved-run restore recovers the original
value, type and absence. In particular, the legacy reverse selectors for network
selection, shake, recently added apps, sound changes, sensors, biometrics,
camera/microphone, recent history, clipboard history, taskbar alignment and
Libraries often removed values. Their new explicit reverse states write a
declared value; use `WindowsDefault` to reproduce override removal.

The sound-scheme restriction and clear-recent-documents policy use Microsoft's
documented **HKCU user scope**, correcting legacy HKLM writes. The recent-history
restriction retains the machine scope permitted by `StartMenu.admx`. The
biometric framework mapping is confirmed by `Biometrics.admx`; its reference
documents policy-controlled framework enablement rather than the exact registry
value. Camera and microphone policies control supported Windows apps, with
per-app exceptions; they are not universal hardware switches. No enrollment,
credential changes, sign-out, crash, shutdown, hibernation enablement or Explorer
restart is performed by the migration or handler.

Delivery Optimization `LocalNetwork=1` now selects LAN peering explicitly.
`HttpOnly=0` replaces the legacy `SetP2PUpdateDisable` branch's retired
`Bypass=100` mode on Windows 11; it disables peering while retaining update
downloads. `Internet=3` remains available only through explicit selection.
See the [Microsoft reference](https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-reference).
Restoring policy cannot recover history later deleted by Windows or recreate
clipboard content; recovery is exact for the captured registry setting.

**Literal defaults:** Schema 1 now permits `DefaultValueExists = $null`,
`DefaultValue = $null` when images/themes/user profiles do not have one
universal literal default. Status and generated documentation render
`<platform-defined>`; `MatchesDefault` remains null, including when the live
value is absent. Boolean true/false still mean a known present/absent literal
default, and zero remains an explicit value. Effective defaults explain
dependencies independently of the baseline. Use the updated engine, generator
and validator with this catalog; older readers render null existence as absent.
Tagged releases retain their own catalog/tools, and saved-run schemas are
unchanged. Keep the current catalog and handlers available when restoring runs
containing the newly added IDs.

**Validation:** Catalog/parser/generated-document checks pass for 134 operations,
2 groups, 4 profiles and 51 PowerShell files. All 327 isolated tests pass on
Windows PowerShell 5.1 and PowerShell 7 (324 full-suite checks plus 3 new guest
runner checks), including 123 tests for this batch. Tab completion resolves the
new IDs and multi-state selections from the catalog. The tests found and fixed
an elevation check that did not recognize a singleton machine plan on Windows
PowerShell 5.1. An existing God Mode fixture now adds a separate Delete grant
without reconstructing Windows generic ACL rights, and compares permissions
when Windows recalculates the DACL auto-inherited bookkeeping flag.

The VM runner now launches tests in a fresh guest PowerShell process after
Pester hit the remoting thread's call-depth limit. The disposable-VM scenarios
cover all explicit states, preview, repeat apply, baseline and exact restore.
Run `959e8b4c2a374041a792497f42dd2588` on Windows 11 Enterprise Evaluation,
build 26300, passes all 328 guest Pester tests and all 20 registry lifecycle
scenarios, including the 43 explicit states. The broader package suite was
interrupted after a prolonged Joplin acquisition; Joplin completed shortly before
interruption, and the run is not a full-suite pass. The completed transcript and
Pester XML are retained with the run's interruption record. The controller
restored the clean checkpoint without cleanup errors; host UAC values were
unchanged. Registry round trips do not prove visible
shell refresh, sensor/biometric hardware behavior, app access, peer transfer,
hibernation or crash recovery. Those scenarios remain separately required;
Windows Server support is not added.

The obsolete Most used list policy, Win+X shell replacement, small taskbar icons,
NumLock SendKeys, packed visual effects, shortcut icon resource overrides and
multi-value Control Panel/pointer settings remain deferred. Taskbar desktop
selectors are existing `windows.task-view-button` equivalents; do not add
duplicate operations.

The 2026-10-11 [post-migration review](migrations/settings-post-migration-review.md)
proposes current GUI sizing and Terminal default-profile outcomes for the small
taskbar/Win+X entries above. The old mappings remain deferred; newer Windows 11
taskbar controls and Terminal profiles require their own capability, mapping,
scope and recovery evidence. Neither outcome is retired or subtracted merely
because the legacy implementation no longer establishes current behavior.

### Unattended migration session, 2026-10-08

Git for Windows now passed installation, repeat installation, local repository
init/add/commit/HEAD verification and uninstall in the Windows 11 VM (run
`20cb460af8be447dafcfc62662f99d35`, 103 guest tests passed). Latest patch releases
with four-part installer filenames are supported. The Git publisher's exact
release-note SHA-256 is checked separately from GitHub's asset digest.

The accepted batch adds standalone Git LFS, Joplin, ShareX, WinDirStat and PowerShell
7. New MSI support handles quiet install/removal and the declared restart-needed
exit code without rebooting implicitly. User packages query HKCU instead of
mistaking a machine installation for current-user presence. Git LFS requires
Git; the ordered `solution.git-development` group expresses install/removal
order. Full Windows 11 request `9744844940fd4ca498ef6486092ac831` passed 128
guest tests and integration, including all five install/repeat/remove scenarios
and the installed PowerShell executable/version check. Both new user policies
passed apply/repeat/exact-restore/WindowsDefault checks. Collection and checkpoint
recovery succeeded; the VM is off at the pinned clean baseline and host UAC is
unchanged. Native host checks passed 127 isolated tests on PowerShell 5.1 and 7.
See [the session results](archive/migrations/2026-10-08-unattended-results.md) for run IDs,
corrected failures, coverage limits and remaining work.

All **53 Install programs selectors** are individually reconciled in
[the disposition ledger](migrations/install-programs-dispositions.md), including
specific deferred work. Reconciliation does not mean every selector is
implemented. No portable tool tree, Defender exclusion, license acceptance or
replacement community Sysmon policy is applied implicitly.

The Windows Configuration family gains `windows.edge-friendly-url-format`
and `windows.start-run-as-different-user`, selected in `profiles/default.psd1`.
They cover `DisableFriendlyURLFormat`/`UnconfigureFriendlyURLFormat` and
`EnableRunAsInStartMenu`/`DisableRunAsInStartMenu`. The Start policy uses the
documented **HKCU user scope**, correcting the legacy HKLM write. Its Disabled
state is explicit zero; WindowsDefault removes the override. Both operations
capture exact prior values; VM tests cover repeat, baseline and restore.
Other selectors in that family remain pending.

Follow-up Windows 11 run `64be8db70ffc45d79d9a1ae02ba4c64c` passed validation,
132 Pester tests, and the full integration suite. It verified both Defender
exclusions through apply, repeat-apply, and exact restoration. The two lid-close
operations also passed handler tests; integration correctly reported them as
unavailable because the disposable Windows 11 VM exposes no lid-close setting.
The VM returned to its clean checkpoint and off state, and host UAC was
unchanged. The registered VM runbook remains usable from an unelevated prompt.
The final unit-only run `b03644c4e24e4d9091e0275586370f00` then passed all
134 guest Pester tests after adding engine plan/state assertions.

Follow-up Windows 11 run `48ce9b4de1d64daa9d9812273035b01a` passed catalog
validation, all 136 Pester tests, and the full integration suite. It verified
the optional taskbar clock seconds, Recycle Bin delete-confirmation, and desktop
icon visibility settings through apply, repeat-apply, declared baseline, and
exact restoration. Git LFS, Joplin, ShareX, WinDirStat, and PowerShell package
lifecycle checks also passed. The two lid-close integration checks were skipped
because the disposable VM does not expose lid settings. The runner restored the
VM to its pinned clean checkpoint with no cleanup or collection errors; host UAC
was unchanged.

The larger catalog exceeds PowerShell 5.1's whole-file safe-data complexity
limit. A bounded metadata reader evaluates each literal operation/group with
SafeGetValue, rejects executable entries and preserves schema 1. Execution,
validation, generation and read-only completion use that same reader.

Provisioning now accepts a local PSD1 and generates a per-VM controller seed;
the runbook explains every field and downstream inheritance. Server 2025 media
is unavailable, so its creation and runtime acceptance remain pending.
Concurrent multi-lab networking also requires a reviewed shared-NAT design:
the script now blocks creating a second host NAT instead of risking the
working Windows 11 network. Unique VM/controller names do not solve WinNAT's
one-network limitation.

Publisher/signature investigations and the evidence workflow are maintained in
[package-verification-matrix.md](package-verification-matrix.md). The shared
library contains observations, not an approval policy or automatic signer gate.

Each group lists exact legacy function names found in the preset. Test demand is required for every batch; complex Windows integration checks are deferred to the later VM phase.

**Batch 1 implemented:** Settings / Privacy configurations migrates `DisableInkingAndTypingData` to `windows.inking-typing-data` and adds it to the workstation default profile. Catalog validation and the Pester 5.7 unit suite pass; the Windows 11 disposable-VM check remains deferred. The reverse `EnableInkingAndTypingData` selector has no legacy implementation and remains unresolved below.

**Batch 2 implemented:** Settings / Defender configuration migrates the two active default selectors `ExcludeToolsDirDefender` and `ExcludeBootstrapDirDefender` to `windows.defender-tools-exclusion` and `windows.defender-bootstrap-exclusion`. Both are in the workstation default profile. Catalog validation and the Pester 5.7 mocked unit suite pass; disposable Windows 11 VM verification remains deferred.

**Low-risk family 1/5 complete:** Network Functions maps the scalar registry selectors `DisableAutoconfigURL` and `DisableMulticastDNS` to `windows.proxy-autoconfig-url` and `windows.llmnr-policy`, both selected in the workstation default profile. The legacy `DisableIEProxyAutoconfig` selector mutates a packed binary value and remains deferred. The `DisableMulticastDNS` name is misleading: the implementation changes the LLMNR policy value.

**Low-risk family 2/5 complete:** Privacy Tweaks maps eight scalar registry values from `DisableTailoredExperiences`, `DisableActivityHistory`, `DisableLocation`, `DisableAdvertisingID`, and `DisableWebLangList` to eight reversible operations in the default profile. Telemetry's task changes, service changes, app removal/cache mutation, feedback/error-reporting tasks, and legacy Wi-Fi Sense/Maps settings remain deferred for complexity or current-Windows applicability review.

**Low-risk family 3/5 complete:** Service Tweaks maps four scalar registry values from `DisableMaintenanceWakeUp`, `DisableSharedExperiences`, and `EnableNTFSLongPaths` to reversible operations. The existing Autoplay and Autorun selectors remain complete; COM-based update enrollment and the Windows Update debugger override are deferred.

**Low-risk family 4/5 complete:** UI Tweaks maps 19 scalar registry operations to the default workstation profile in three reviewable batches (9, 9, and 1 operation). A follow-up optional batch adds the taskbar clock seconds and Recycle Bin delete-confirmation selectors as exact-rollback Windows 11 user settings; neither is added to the default profile. This includes Action Center/toast behavior, accessibility prompts, taskbar controls, startup sound, and the Alt+Tab Edge-tab filter. The binary shortcut-name value, Task Manager process/polling behavior, packed visual-effects value, dynamic sound-scheme changes, and OS-branching or special-key settings remain deferred. Catalog/profile validation and mocked Pester checks pass (31 tests total); disposable-VM checks remain required before broadening declared Windows support.

**Low-risk family 5/5 complete:** Explorer UI Tweaks adds eight scalar registry operations in one batch for hidden files, navigation-pane expansion, sync notifications, recent/frequent shortcuts, Explorer start location, and thumbnail cache behavior. A follow-up optional batch adds the desktop icon visibility selector as an exact-rollback Windows 11 user setting, outside the default profile. The already-migrated Show Known Extensions operation remains the existing equivalent. The initial scalar batch deferred the three This PC folder visibility selectors; those were later migrated under Family 12 using a reversible registry key-set handler.

**Family 11/30 active defaults migrated:** UI Tweaks maps the active scalar registry defaults into the workstation profile. The binary shortcut-name value, Task Manager process/polling behavior, packed visual-effects value, dynamic sound-scheme changes, and OS-branching or special-key settings remain deferred. Catalog/profile validation and mocked Pester checks pass; full disposable-VM coverage remains outstanding.

**Family 12/30 migrated and validated:** Explorer UI Tweaks includes eight reversible scalar registry settings, the optional `windows.desktop-icons-visibility` setting, and `windows.music-folder-this-pc`, `windows.videos-folder-this-pc`, and `windows.3d-objects-folder-this-pc`. The desktop icon selector remains outside the default profile. The new allowlisted `RegistryKeySet` handler captures recursive key values, registry types, and security descriptors before changing registration keys, so restore can reconstruct the prior tree. Windows may recalculate the DACL auto-inherited control flag when a key is recreated; validation confirms the restored owner, group, ACL entries, registry values, and value kinds. All active default selectors are represented in the default profile. Catalog validation, all 55 Pester tests, and Windows 11 disposable-VM round trips pass.

**Family 6/30 migrated:** Hardening Windows maps the active defaults `DisableSSDPdiscovery`, `DisableUniversalPlugAndPlay`, and `DisableWinHttpAutoProxySvc`. The first two use a reversible Windows service handler that captures and restores startup mode and running state; both are disabled and stopped by the default workstation profile. Enabled means Manual and Running for both services. The WPAD selector maps to the documented `DisableWpad` WinHTTP registry value; despite its legacy name, it does not disable the WinHTTP Auto-Proxy service. Catalog validation passes. Pester could not run in the restricted execution session because its framework's temporary registry keys are denied; mocked checks and disposable Windows 11 and Server 2025 VM checks remain outstanding.

**Family 7/30 migrated:** UWP Privacy Tweaks adds 19 reversible registry settings for the active background policy, app privacy policies, four file-system capabilities, and the UWP swap-file setting. `EnableUWPBackgroundApps` also maps to a separate user-scoped reset operation that captures and restores existing per-app `Disabled` and `DisabledByUser` values. The swap-file registry mapping is not documented by Microsoft; its operation links to the closest UWP lifecycle behavior reference and flags the mapping for review. Catalog validation passes. Pester could not run in the restricted execution session because its framework's temporary registry keys are denied; mocked checks and disposable Windows 11 VM checks remain outstanding.

**Family 8/30 active defaults migrated:** Security Tweaks adds the AutoShareServer and AutoShareWks settings, the current user's Windows Security account-protection warning, both 64-bit and 32-bit .NET strong-crypto values, and reversible BCDEdit operations for the F8 boot menu and DEP policy. The existing Windows Script Host operation covers `DisableScriptHost`. BCDEdit changes are recorded exactly and take effect after restart. AutoShareServer is supported on Windows Server 2025 and is not selected in the workstation profile; AutoShareWks is selected there. Catalog validation passes. Pester and disposable Windows VM checks remain outstanding; Pester is blocked in this session by denied temporary registry keys.

**Family 9/30 migrated:** Network Tweaks adds `windows.current-network-category`, which applies Private or Public to all reported non-domain profiles and captures the individual prior categories for exact restore. `windows.remote-assistance-policy` reversibly controls `fAllowToGetHelp`; Quick Assist removal remains a separate deferred operation because Windows 11 delivers it as a Store app and its lifecycle needs its own reliable reinstall behavior. Both defaults are selected in the workstation profile. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trips pass.

**Family 10/30 active defaults migrated with one deferral:** Service Tweaks adds `windows.microsoft-product-updates`, using the documented `AllowMUUpdateService` preference to opt in to Microsoft product updates; it is selected in the workstation default profile. `DisableUpdateRestart` remains deferred because the legacy implementation installs an experimental Image File Execution Options debugger for `MusNotification.exe`, and its exact effect and safe restoration need review before reproducing it. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trip passes.

**Family 14/30 active default migrated:** BitLocker adds `windows.bitlocker-encryption-method`, mapping the legacy AES-256 selector to the exact reversible `EncryptionMethod=4` policy value. The operation is Windows 11-only pending target-specific integration coverage and describes that it affects future encryption, not existing encrypted drives. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trip passes. Windows Server support remains undeclared.

**Family 15/30 reconciled, implementation incomplete:** The active Git default has passed install, repeat, local init/add/commit/HEAD and removal in Windows 11. 7-Zip, Notepad++, Sysmon and standalone Git LFS, Joplin, ShareX, WinDirStat and PowerShell 7 use the package lifecycle. The XML artifact remains download-only at an immutable commit; Sysmon installation uses its default configuration. All 53 selectors have an explicit disposition in [the ledger](migrations/install-programs-dispositions.md). Deferred selectors require the stated handler/source/licensing work before implementation; the current batch's acceptance is recorded in the session section above.

### Settings

#### Power Scheme Settings (power-scheme-settings)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetPowerSchemeBalanced`, `SetPowerSchemeHighPerf`, `SetPowerSchemeUltimate`, `SetPwrSchemeDesktopMenu`,
`RemovePwrSchemeDesktopMenu`, `SetLidCloseActionBattSleep`, `SetLidCloseActionBattDoNothing`,
`SetLidCloseActionPwrDoNothing`, `SetLidCloseActionPwrSleep`

**Partially migrated:** `SetLidCloseActionBattSleep` / `SetLidCloseActionBattDoNothing`
map to `windows.lid-close-action-dc`; the corresponding `Pwr` pair maps to
`windows.lid-close-action-ac`. The `PowerSetting` handler captures the active
scheme and literal AC/DC index for exact restore, and treats the initial value
as platform-defined rather than claiming a Windows default. Device/scheme
combinations that do not expose the setting report `Unavailable`; no power
setting is selected in the workstation profile. Catalog validation, mocked
handler lifecycle tests, and the Windows 11 VM integration suite pass, but the
VM had no lid-close control, so actual apply/restore on lid-capable hardware is
still required. The three named power-plan selectors and two desktop-context
menu selectors remain deferred because scheme creation/removal and dynamic
registry-tree rollback need separate designs.

#### Privacy configurations (privacy-configurations)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableInkingAndTypingData` **default**

#### Defender configuration (defender-configuration)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`ExcludeToolsDirDefender` **default**, `ExcludeBootstrapDirDefender` **default**, `RemoveToolsDirDefender`,
`RemoveBootstrapDirDefender`

#### Hardening Windows (hardening-windows)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableSSDPdiscovery` **default**, `DisableUniversalPlugAndPlay` **default**,
`DisableWinHttpAutoProxySvc` **default**, `EnableSSDPdiscovery`, `EnableUniversalPlugAndPlay`,
`EnableWinHttpAutoProxySvc`

#### Network Functions (network-functions)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableIEProxyAutoconfig` **default**, `DisableAutoconfigURL` **default**, `DisableMulticastDNS` **default**,
`EnableIEProxyAutoconfig`, `EnableAutoconfigURL`, `EnableMulticastDNS`, `GetNoTelemetryHostsFile`,
`SetDefaultHostsfile`

#### Privacy Tweaks (privacy-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableTelemetry` **default**, `DisableCortana` **default**, `DisableWiFiSense` **default**,
`DisableAppSuggestions` **default**, `DisableActivityHistory` **default**, `DisableLocation` **default**,
`DisableMapUpdates` **default**, `DisableFeedback` **default**, `DisableTailoredExperiences` **default**,
`DisableAdvertisingID` **default**, `DisableWebLangList` **default**, `DisableErrorReporting` **default**,
`DisableDiagTrack` **default**, `DisableWAPPush` **default**, `EnableTelemetry`, `EnableCortana`,
`EnableWiFiSense`, `DisableSmartScreen`, `EnableSmartScreen`, `DisableWebSearch`, `EnableWebSearch`,
`EnableAppSuggestions`, `EnableActivityHistory`, `DisableSensors`, `EnableSensors`, `EnableLocation`,
`EnableMapUpdates`, `EnableFeedback`, `EnableTailoredExperiences`, `EnableAdvertisingID`, `EnableWebLangList`,
`DisableBiometrics`, `EnableBiometrics`, `DisableCamera`, `EnableCamera`, `DisableMicrophone`,
`EnableMicrophone`, `EnableErrorReporting`, `SetP2PUpdateLocal`, `SetP2PUpdateInternet`, `SetP2PUpdateDisable`,
`EnableDiagTrack`, `EnableWAPPush`, `EnableClearRecentFiles`, `DisableClearRecentFiles`, `DisableRecentFiles`,
`EnableRecentFiles`

#### UWP Privacy Tweaks (uwp-privacy-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableUWPBackgroundApps` **default**, `EnableUWPBackgroundApps`, `DisableUWPVoiceActivation`,
`EnableUWPVoiceActivation`, `DisableUWPNotifications`, `EnableUWPNotifications`, `DisableUWPAccountInfo`,
`EnableUWPAccountInfo`, `DisableUWPContacts`, `EnableUWPContacts`, `DisableUWPCalendar`, `EnableUWPCalendar`,
`DisableUWPPhoneCalls`, `EnableUWPPhoneCalls`, `DisableUWPCallHistory`, `EnableUWPCallHistory`,
`DisableUWPEmail`, `EnableUWPEmail`, `DisableUWPTasks`, `EnableUWPTasks`, `DisableUWPMessaging`,
`EnableUWPMessaging`, `DisableUWPRadios`, `EnableUWPRadios`, `DisableUWPOtherDevices`, `EnableUWPOtherDevices`,
`DisableUWPDiagInfo`, `EnableUWPDiagInfo`, `DisableUWPFileSystem`, `EnableUWPFileSystem`, `DisableUWPSwapFile`,
`EnableUWPSwapFile`

#### Security Tweaks (security-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableAdminShares` **default**, `HideAccountProtectionWarn` **default**, `DisableScriptHost` **default**,
`EnableDotNetStrongCrypto` **default**, `EnableF8BootMenu` **default**, `SetDEPOptOut` **default**,
`SetUACLow`, `SetUACHigh`, `EnableSharingMappedDrives`, `DisableSharingMappedDrives`, `EnableAdminShares`,
`EnableBrowserServiceView`, `DisableFirewall`, `EnableFirewall`, `HideDefenderTrayIcon`,
`ShowDefenderTrayIcon`, `DisableDefender`, `EnableDefender`, `DisableDefenderCloud`, `EnableDefenderCloud`,
`EnableCtrldFolderAccess`, `DisableCtrldFolderAccess`, `EnableCIMemoryIntegrity`, `DisableCIMemoryIntegrity`,
`EnableDefenderAppGuard`, `DisableDefenderAppGuard`, `ShowAccountProtectionWarn`, `DisableDownloadBlocking`,
`EnableDownloadBlocking`, `EnableScriptHost`, `DisableDotNetStrongCrypto`, `EnableMeltdownCompatFlag`,
`DisableMeltdownCompatFlag`, `DisableF8BootMenu`, `DisableBootRecovery`, `EnableBootRecovery`,
`DisableRecoveryAndReset`, `EnableRecoveryAndReset`, `SetDEPOptIn`

#### Network Tweaks (network-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetCurrentNetworkPrivate` **default**, `DisableRemoteAssistance` **default**, `SetCurrentNetworkPublic`,
`SetUnknownNetworksPrivate`, `SetUnknownNetworksPublic`, `DisableNetDevicesAutoInst`,
`EnableNetDevicesAutoInst`, `DisableHomeGroups`, `EnableHomeGroups`, `DisableSMB1`, `EnableSMB1`,
`DisableSMBServer`, `EnableSMBServer`, `DisableNetBIOS`, `EnableNetBIOS`, `DisableLLMNR`, `EnableLLMNR`,
`DisableLLDP`, `EnableLLDP`, `DisableLLTD`, `EnableLLTD`, `DisableMSNetClient`, `EnableMSNetClient`,
`DisableQoS`, `EnableQoS`, `DisableIPv4`, `EnableIPv4`, `DisableIPv6`, `EnableIPv6`, `DisableNCSIProbe`,
`EnableNCSIProbe`, `DisableConnectionSharing`, `EnableConnectionSharing`, `EnableRemoteAssistance`,
`EnableRemoteDesktop`, `DisableRemoteDesktop`

#### Service Tweaks (service-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`EnableUpdateMSProducts` **default**, `DisableUpdateRestart` **default**,
`DisableMaintenanceWakeUp` **default**, `DisableSharedExperiences` **default**, `DisableAutoplay` **default**,
`DisableAutorun` **default**, `EnableNTFSLongPaths` **default**, `DisableUpdateMSRT`, `EnableUpdateMSRT`,
`DisableUpdateDriver`, `EnableUpdateDriver`, `DisableUpdateMSProducts`, `DisableUpdateAutoDownload`,
`EnableUpdateAutoDownload`, `EnableUpdateRestart`, `EnableMaintenanceWakeUp`, `DisableAutoRestartSignOn`,
`EnableAutoRestartSignOn`, `EnableSharedExperiences`, `EnableClipboardHistory`, `DisableClipboardHistory`,
`EnableAutoplay`, `EnableAutorun`, `DisableRestorePoints`, `EnableRestorePoints`, `EnableStorageSense`,
`DisableStorageSense`, `DisableDefragmentation`, `EnableDefragmentation`, `DisableSuperfetch`,
`EnableSuperfetch`, `DisableIndexing`, `EnableIndexing`, `DisableRecycleBin`, `EnableRecycleBin`,
`DisableNTFSLongPaths`, `DisableNTFSLastAccess`, `EnableNTFSLastAccess`, `SetBIOSTimeUTC`, `SetBIOSTimeLocal`,
`EnableHibernation`, `DisableHibernation`, `DisableSleepButton`, `EnableSleepButton`, `DisableSleepTimeout`,
`EnableSleepTimeout`, `DisableFastStartup`, `EnableFastStartup`, `DisableAutoRebootOnCrash`,
`EnableAutoRebootOnCrash`

#### UI Tweaks (ui-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableActionCenter` **default**, `DisableLockScreenBlur` **default**, `DisableAccessibilityKeys` **default**,
`ShowTaskManagerDetails` **default**, `ShowFileOperationsDetails` **default**, `HideTaskbarSearch` **default**,
`HideTaskView` **default**, `SetTaskbarCombineWhenFull` **default**, `HideTaskbarPeopleIcon` **default**,
`ShowTrayIcons` **default**, `DisableSearchAppInStore` **default**, `DisableNewAppPrompt` **default**,
`DisableShortcutInName` **default**, `SetVisualFXPerformance` **default**, `SetSoundSchemeNone` **default**,
`DisableStartupSound` **default**, `EnableVerboseStatus` **default**, `DisableF1HelpKey` **default**,
`DisableTaskbarWidgets` **default**, `DisableTaskbarChat` **default**, `RemoveEdgeTabsFromAltTab` **default**,
`EnableActionCenter`, `DisableLockScreen`, `EnableLockScreen`, `DisableLockScreenRS1`, `EnableLockScreenRS1`,
`HideNetworkFromLockScreen`, `ShowNetworkOnLockScreen`, `HideShutdownFromLockScreen`,
`ShowShutdownOnLockScreen`, `EnableLockScreenBlur`, `DisableAeroShake`, `EnableAeroShake`,
`EnableAccessibilityKeys`, `HideTaskManagerDetails`, `HideFileOperationsDetails`, `EnableFileDeleteConfirm`,
`DisableFileDeleteConfirm`, `ShowTaskbarSearchIcon`, `ShowTaskbarSearchBox`, `ShowTaskView`,
`ShowSmallTaskbarIcons`, `ShowLargeTaskbarIcons`, `SetTaskbarCombineNever`, `SetTaskbarCombineAlways`,
`ShowTaskbarPeopleIcon`, `HideTrayIcons`, `ShowSecondsInTaskbar`, `HideSecondsFromTaskbar`,
`EnableSearchAppInStore`, `EnableNewAppPrompt`, `HideRecentlyAddedApps`, `ShowRecentlyAddedApps`,
`HideMostUsedApps`, `ShowMostUsedApps`, `SetWinXMenuPowerShell`, `SetWinXMenuCmd`, `SetControlPanelSmallIcons`,
`SetControlPanelLargeIcons`, `SetControlPanelCategories`, `EnableShortcutInName`, `HideShortcutArrow`,
`ShowShortcutArrow`, `SetVisualFXAppearance`, `EnableTitleBarColor`, `DisableTitleBarColor`, `SetAppsDarkMode`,
`SetAppsLightMode`, `SetSystemDarkMode`, `SetSystemLightMode`, `AddENKeyboard`, `RemoveENKeyboard`,
`EnableNumlock`, `DisableNumlock`, `DisableEnhPointerPrecision`, `EnableEnhPointerPrecision`,
`SetSoundSchemeDefault`, `EnableStartupSound`, `DisableChangingSoundScheme`, `EnableChangingSoundScheme`,
`DisableVerboseStatus`, `EnableF1HelpKey`, `DisableTaskbarDesktops`, `EnableTaskbarDesktops`,
`EnableTaskbarWidgets`, `EnableTaskbarChat`, `SetTaskbarAlignmentLeft`, `SetTaskbarAlignmentMiddle`,
`SetEdgeTabsWindowsAnd5tabs`, `SetEdgeTabsWindowsAnd3tabs`, `SetEdgeTabsWindowsAndAll`

#### Explorer UI Tweaks (explorer-ui-tweaks)

**Optional registry batch, 2026-10-09:** Seven further current-user folder
options map 14 legacy selectors to the existing `RegistryValue` lifecycle.
They remain outside the workstation default profile. Explicit on/off states
write a DWORD; `WindowsDefault` removes the override and is the declared
baseline. Removing an override is distinct from restoring the captured prior
value and registry type.

| Legacy selectors | Catalog operation |
| --- | --- |
| `ShowExplorerTitleFullPath`, `HideExplorerTitleFullPath` | `windows.explorer-title-full-path` |
| `ShowSuperHiddenFiles`, `HideSuperHiddenFiles` | `windows.protected-files-visibility` |
| `EnableFldrSeparateProcess`, `DisableFldrSeparateProcess` | `windows.explorer-separate-process` |
| `EnableRestoreFldrWindows`, `DisableRestoreFldrWindows` | `windows.restore-folder-windows` |
| `DisableSharingWizard`, `EnableSharingWizard` | `windows.sharing-wizard` |
| `HideSelectCheckboxes`, `ShowSelectCheckboxes` | `windows.item-selection-checkboxes` |
| `DisableThumbnails`, `EnableThumbnails` | `windows.thumbnail-display` |

The legacy reverse selectors for title paths, folder-window restoration and
Sharing Wizard removed a value. Their v3 explicit reverse states use zero or
one; use `WindowsDefault` to reproduce legacy override removal. Protected-file
visibility also depends on hidden-file visibility. Thumbnail display remains
separate from cache creation and network thumbnail database settings.

Microsoft's [folder option registry reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f)
and [additional folder option reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/a6ca3a17-1971-4b22-bf3b-e1a5d5c50fca)
document six mappings. The checkbox operation links to
[Microsoft's user-visible option](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows);
its legacy `AutoCheckSelect` value is retained for review rather than claiming
that the folder-option specification documents that value (it names
`UseCheckBoxes`). No Explorer restart, logoff, share creation or cache deletion
is performed by these operations.

Native catalog/parser/generated-document validation and all 170 isolated tests
pass on Windows PowerShell 5.1 and PowerShell 7, including 35 new batch tests.
The existing live-registry test is excluded from workstation validation.
The VM suite includes apply, repeat, baseline and exact restore scenarios for
all seven operations. Their clean-profile literal defaults and visible Explorer
behavior still require disposable Windows 11 verification, including sign-in
and touch-related behavior; no Windows Server support is added by this batch.
Other optional Explorer selectors remain pending.

**Optional registry follow-up, 2026-10-09:** Three further current-user folder
options map six legacy selectors to the same exact-restore handler. They stay
outside the default profile and declare Windows 11 as their only target.

| Legacy selectors | Catalog operation | Explicit states |
| --- | --- | --- |
| `ShowEmptyDrives`, `HideEmptyDrives` | `windows.empty-drives-visibility` | `Visible=0`, `Hidden=1` |
| `ShowFolderMergeConflicts`, `HideFolderMergeConflicts` | `windows.folder-merge-conflicts` | `Shown=0`, `Hidden=1` |
| `ShowNavPaneAllFolders`, `HideNavPaneAllFolders` | `windows.navigation-pane-all-folders` | `Enabled=1`, `Disabled=0` |

All three legacy reverse selectors remove the value; use `WindowsDefault` or
`unset` for that behavior. The explicit reverse states now write a DWORD.
Folder merge prompts remain distinct from duplicate-file prompts, and the
navigation-pane option remains distinct from auto-expansion. The
[Microsoft settings reference](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic)
documents these options rather than their precise registry mappings; the
catalog marks the retained legacy mappings for review. Clean-profile literal
defaults and visible behavior still need disposable Windows 11 verification.
The VM suite now includes registry round trips for all three.

Catalog/parser/generated-document validation, discovery and ID completion
checks pass. All 185 isolated tests pass on Windows PowerShell 5.1 and
PowerShell 7, including 50 Explorer tests; the existing live-registry test is
excluded from workstation validation. No state-changing VM run occurred for
this follow-up.

Other same-family candidates remain pending: per-icon desktop visibility,
desktop build-number display, and encrypted/compressed
file colors. The legacy file-color value is named
`ShowEncryptCompressedColor`, whereas Microsoft's older folder-option
specification names `ShowCompColor`; resolve that difference on the target
before choosing a mapping. Desktop icon selectors write two values and need
a coordinated restore contract. Namespace-key removals and context-menu
mutations remain separate from this scalar batch.

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`ShowKnownExtensions` **default**, `ShowHiddenFiles` **default**, `EnableNavPaneExpand` **default**,
`HideSyncNotifications` **default**, `HideRecentShortcuts` **default**, `SetExplorerThisPC` **default**,
`HideMusicFromThisPC` **default**, `HideVideosFromThisPC` **default**, `Hide3DObjectsFromThisPC` **default**,
`DisableThumbnailCache` **default**, `DisableThumbsDBOnNetwork` **default**, `ShowExplorerTitleFullPath`,
`HideExplorerTitleFullPath`, `HideKnownExtensions`, `HideHiddenFiles`, `ShowSuperHiddenFiles`,
`HideSuperHiddenFiles`, `ShowEmptyDrives`, `HideEmptyDrives`, `ShowFolderMergeConflicts`,
`HideFolderMergeConflicts`, `DisableNavPaneExpand`, `ShowNavPaneAllFolders`, `HideNavPaneAllFolders`,
`ShowNavPaneLibraries`, `HideNavPaneLibraries`, `EnableFldrSeparateProcess`, `DisableFldrSeparateProcess`,
`EnableRestoreFldrWindows`, `DisableRestoreFldrWindows`, `ShowEncCompFilesColor`, `HideEncCompFilesColor`,
`DisableSharingWizard`, `EnableSharingWizard`, `HideSelectCheckboxes`, `ShowSelectCheckboxes`,
`ShowSyncNotifications`, `ShowRecentShortcuts`, `SetExplorerQuickAccess`, `HideQuickAccess`, `ShowQuickAccess`,
`HideRecycleBinFromDesktop`, `ShowRecycleBinOnDesktop`, `ShowThisPCOnDesktop`, `HideThisPCFromDesktop`,
`ShowUserFolderOnDesktop`, `HideUserFolderFromDesktop`, `ShowControlPanelOnDesktop`,
`HideControlPanelFromDesktop`, `ShowNetworkOnDesktop`, `HideNetworkFromDesktop`, `HideDesktopIcons`,
`ShowDesktopIcons`, `ShowBuildNumberOnDesktop`, `HideBuildNumberFromDesktop`, `HideDesktopFromThisPC`,
`ShowDesktopInThisPC`, `HideDesktopFromExplorer`, `ShowDesktopInExplorer`, `HideDocumentsFromThisPC`,
`ShowDocumentsInThisPC`, `HideDocumentsFromExplorer`, `ShowDocumentsInExplorer`, `HideDownloadsFromThisPC`,
`ShowDownloadsInThisPC`, `HideDownloadsFromExplorer`, `ShowDownloadsInExplorer`, `ShowMusicInThisPC`,
`HideMusicFromExplorer`, `ShowMusicInExplorer`, `HidePicturesFromThisPC`, `ShowPicturesInThisPC`,
`HidePicturesFromExplorer`, `ShowPicturesInExplorer`, `ShowVideosInThisPC`, `HideVideosFromExplorer`,
`ShowVideosInExplorer`, `Show3DObjectsInThisPC`, `Hide3DObjectsFromExplorer`, `Show3DObjectsInExplorer`,
`HideNetworkFromExplorer`, `ShowNetworkInExplorer`, `HideIncludeInLibraryMenu`, `ShowIncludeInLibraryMenu`,
`HideGiveAccessToMenu`, `ShowGiveAccessToMenu`, `HideShareMenu`, `ShowShareMenu`, `DisableThumbnails`,
`EnableThumbnails`, `EnableThumbnailCache`, `EnableThumbsDBOnNetwork`

#### Server Specific Tweaks (server-specific-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`HideServerManagerOnLogin`, `ShowServerManagerOnLogin`, `DisableShutdownTracker`, `EnableShutdownTracker`,
`DisablePasswordPolicy`, `EnablePasswordPolicy`, `DisableCtrlAltDelLogin`, `EnableCtrlAltDelLogin`,
`DisableIEEnhancedSecurity`, `EnableIEEnhancedSecurity`, `EnableAudio`, `DisableAudio`, `AudioMute`,
`AudioUnmute`

#### Bitlocker (bitlocker)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetDefaultBitLockerAES256` **default**, `SetDefaultBitLockerAES128`, `PutBitlockerShortCutOnDesktop`,
`EnableLockOutThreshold`, `DisableLockOutThreshold`, `EnableEnhancedPIN`, `DisableEnhancedPIN`,
`EnableAdditionalAuthAtStart`, `EnableBitlockerTPMandPIN`, `EnableBitlocker`, `DisableBitlocker`,
`AddBitlockerRecoveryPswd`, `DisplayBitlockerRecoveryPwd`


### Packages

#### Install programs (install-programs)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`Install7Zip` **default**, `InstallGit4Win` **default**, `GetSysmonSwiftXML` **default**,
`InstallSysmon64` **default**, `Remove7Zip`, `InstallGitLFS`, `RemoveGitLFS`, `RemoveGit4Win`,
`InstallPSScriptTools`, `RemovePSScriptTools`, `InstallVSCode`, `RemoveVSCode`, `InstallGPGwin`,
`InstallNotepadPlusPlus`, `RemoveNotepadPlusPlus`, `GetSysmonOlafXML`, `RemoveSysmon64`,
`InstallVMwareWorkstation`, `RemoveVMwareWorkstation`, `SetVMDirUserhome`, `SetVMDirDocuments`,
`InstallThunderbird`, `InstallJoplin`, `InstallImageMagick`, `InstallImageMagickPortable`,
`RemoveImageMagickPortable`, `InstallSignal`, `InstallPython`, `InstallYara`, `RemoveYara`, `GetCyberChef`,
`RemoveCyberChef`, `InstallCaffeine`, `RemoveCaffeine`, `InstallPutty`, `RemovePutty`, `InstallWinSCP`,
`InstallKAPE`, `RemoveKAPE`, `InstallVeraCrypt`, `InstallVeraCryptPortable`, `InstallADReplStatus`,
`RemoveADReplStatus`, `InstallFirewallNotifier`, `RemoveFirewallNotifier`, `InstallWinDirStat`,
`RemoveWinDirStat`, `InstallShareX`, `RemoveShareX`, `InstallShareXportable`, `RemoveShareXportable`,
`InstallPowerShell`, `InstallAutomatedLab`

#### Office Apps (office-apps)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`DisableOneDrive` **default**, `UninstallOneDrive` **default**, `InstallOffice365` **default**,
`DisableTeamsAutoStart` **default**, `RemoveTeamsStoreApp` **default**, `EnableOneDrive`, `InstallOneDrive`,
`ResetTeamsAutoStart`, `RemoveTeamsWideInstaller`, `InstallVisioPro`

#### System Tools (system-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`GetSysinternalsSuite`, `RemoveSysinternalsSuite`, `InstallJoeWare`, `RemoveJoeWare`, `InstallCCleaner`,
`RemoveCCleaner`, `InstallMitec`, `RemoveMitec`, `InstallNtcore`, `RemoveNTCore`, `InstallTMOG`, `RemoveTMOG`,
`InstallWireshark`, `RemoveWireshark`, `InstallZimmermanTools`, `RemoveZimmermanTools`,
`InstallNirsoftLauncher`, `RemoveNirsoftLauncher`, `InstallNirsoftToolsX64`, `RemoveNirsoftToolsX64`,
`InstallNirsoftPkgFiles`, `RemoveNirsoftPkgFiles`, `InstallArsenalRecon`, `InstallWinget`,
`InstallWingetAutoUpdate`

All 25 selectors have a current reconciliation in the [System Tools disposition ledger](migrations/system-tools-dispositions.md). None is yet represented by a v3 catalog operation.

**Defender and antivirus research (2026-10-09; investigation only):**

- **NirSoft:** Elevated alert risk is confirmed. NirSoft itself says alerts are
  common for some password-recovery utilities; its historical report includes
  password, credential, and key-recovery tools, though that report is no longer
  maintained. This supports a package-specific compatibility review, not a
  blanket exclusion or a claim that each current binary is safe. The selectors
  fetch a changing collection, so identify exact files and versions before
  considering any exception. [NirSoft antivirus report](https://www.nirsoft.net/false_positive_report.html)
- **JoeWare:** A Defender-related issue is confirmed for **AdFind**, not for
  every JoeWare utility. The publisher reports Defender blocking AdFind and
  attributes its reputation to legitimate Active Directory reconnaissance
  also being used by attackers. The legacy selector downloads the entire linked
  JoeWare tools collection, so inventory its contents before treating it as a
  single package or scoping an exception. [JoeWare report](https://blog.joeware.net/2023/02/22/6166/)
- **NTCore:** No source-confirmed Defender alert was found for the artifacts
  selected by the legacy function. That is unknown status, not evidence of a
  clean scan: the script crawls linked pages and collects multiple EXE/ZIP
  artifacts. Enumerate and pin the intended subset before migration.
- **Eric Zimmerman tools:** The publisher says all tools are digitally signed
  and characterizes antivirus hits as false positives after verifying the
  signature. Treat this as a publisher assertion that must be checked per
  artifact; the legacy function downloads and executes a mutable `master`
  PowerShell script before copying the resulting collection. Pin and verify
  that bootstrap script and record each resulting binary before any execution
  or exclusion decision. [Official tools and publisher guidance](https://ericzimmerman.github.io/)
- **Arsenal Recon:** The publisher documents antivirus compatibility steps for
  Arsenal Image Mounter (AIM), including possible exclusions for its folder or
  executables, and says AIM may need to allow a `utilman.exe` alert during VM
  boot. It also documents antivirus-evasion behavior in AIM's guest-VM tools.
  This establishes known AV interaction, not a confirmed Defender detection
  for every current artifact. The legacy selector downloads every MEGA link on
  the publisher page plus MEGAcmd, so resolve exact products, versions,
  licensing, drivers, and rollback before migration. [AIM walkthrough](https://arsenalrecon.com/arsenal-image-mounter-aim-walkthrough)

No tools were downloaded, executed, or scanned for this review, and no VM or
integration tests were run. Any Defender exclusion remains a separate,
package-scoped decision requiring exact artifact evidence and the verification
described in [Package-specific Defender exclusions](#package-specific-defender-exclusions).

#### Active Directory Tools (active-directory-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallRSAT`, `RemoveRSAT`, `InstallOpenJDK`, `InstallNeo4j`, `GetBloodhound`, `RemoveBloodhound`,
`GetSharphound`, `RemoveSharphound`, `GetAzurehound`, `RemoveAzurehound`, `GetImproHound`, `RemoveImprohound`,
`GetPingCastle`, `RemovePingCastle`

#### For Linux VMs (for-linux-vms)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallVirtIOGuestTool`, `InstallSpiceGuestTool`, `InstallSpiceWebDAV`

#### Browsers and Internet (browsers-and-internet)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`DisableEdgePagePrediction` **default**, `InstallFirefox` **default**,
`CreateFirefoxPreferenceFiles` **default**, `InstallChrome` **default**,
`CreateChromePreferenceFile` **default**, `RemoveFirefox`, `RemoveFirefoxPreferenceFiles`, `RemoveChrome`,
`RemoveChromePreferenceFile`

Opera was excluded by user trust-policy decision on 2026-10-11. Its legacy
installer and preset entry were removed; it has no v3 package. The historical
732-selector inventory retains this exclusion for accounting; the preset now
contains 731 of those selectors. See the [application ledger](migrations/application-migration-review.md).

#### Forensic Tools (forensic-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallAutopsy`, `InstallNetworkMiner`, `RemoveNetworkMiner`, `InstallAutorunner`, `RemoveAutorunner`,
`InstallChainsaw`, `RemoveChainsaw`, `GetChromeParser`, `RemoveChromeParser`, `InstallCyLR`, `RemoveCyLR`,
`InstallDejsonlz4`, `RemoveDejsonlz4`, `GetHex2text`, `RemoveHex2text`, `InstallHindsight`, `RemoveHindsight`,
`InstallSqlitebrowser`, `GetShimCacheParser`, `RemoveShimCacheParser`, `GetPSTViewer`, `GetOSTViewer`,
`InstallLoki`, `RemoveLoki`, `InstallSSView`, `RemoveSSView`, `InstallSrumMonkey`, `RemoveSrumMonkey`,
`InstallSrumDump`, `RemoveSrumDump`, `InstallThumbcacheviewer`, `RemoveThumbcacheviewer`,
`InstallSuperFetchTools2`, `RemoveSuperFetchTools2`, `InstallUserAssist`, `RemoveUserAssist`,
`InstallThumbsviewer`, `RemoveThumbsviewer`, `InstallRegRipper`, `RemoveRegRipper`, `InstallWinhex`,
`RemoveWinhex`, `InstallWinPmem`, `RemoveWinPmem`, `InstallVolatility2`, `RemoveVolatility2`,
`InstallVolatility3`, `InstallPartDiagParser`, `RemovePartDiagParser`, `InstallGglCookieCruncher`,
`RemoveGglCookieCruncher`, `InstallSigma`, `RemoveSigma`

#### Offensive Tools (offensive-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallHashcat`, `RemoveHashcat`, `InstallHashcatLauncher`, `RemoveHashcatLauncher`


### Windows components

#### Windows Subsystem for Linux (windows-subsystem-for-linux)

**Test demand:** Required per batch: mocked Pester tests for feature/app state, apply/remove calls, ShouldProcess, and failures. Defer OS-image, reboot, and broad component integration to disposable VMs.

**Legacy selectors:**

`EnableWSL`, `DisableWSL`, `InstallWSLubuntu`, `RemoveWSLubuntu`, `InstallWSLdebian`, `RemoveWSLdebian`,
`InstallWSLkali`, `RemoveWSLkali`, `InstallWSLFedora`

#### Application Tweaks (application-tweaks)

**Test demand:** Required per batch: mocked Pester tests for feature/app state, apply/remove calls, ShouldProcess, and failures. Defer OS-image, reboot, and broad component integration to disposable VMs.

**Legacy selectors:**

`UninstallMsftBloat` **default**, `UninstallThirdPartyBloat` **default**, `DisableXboxFeatures` **default**,
`DisableAdobeFlash` **default**, `DisableEdgePreload` **default**, `DisableEdgeShortcutCreation` **default**,
`DisableIEFirstRun` **default**, `DisableFirstLogonAnimation` **default**, `DisableMediaSharing` **default**,
`UninstallInternetExplorer` **default**, `SetPhotoViewerAssociation` **default**,
`AddPhotoViewerOpenWith` **default**, `UninstallXPSPrinter` **default**, `RemoveFaxPrinter` **default**,
`InstallMsftBloat`, `InstallThirdPartyBloat`, `UninstallWindowsStore`, `InstallWindowsStore`,
`EnableXboxFeatures`, `DisableFullscreenOptims`, `EnableFullscreenOptims`, `EnableAdobeFlash`,
`EnableEdgePreload`, `EnableEdgeShortcutCreation`, `EnableIEFirstRun`, `EnableFirstLogonAnimation`,
`EnableMediaSharing`, `DisableMediaOnlineAccess`, `EnableMediaOnlineAccess`, `EnableDeveloperMode`,
`DisableDeveloperMode`, `UninstallMediaPlayer`, `InstallMediaPlayer`, `InstallInternetExplorer`,
`UninstallWorkFolders`, `InstallWorkFolders`, `UninstallHelloFace`, `InstallHelloFace`,
`UninstallMathRecognizer`, `InstallMathRecognizer`, `UninstallPowerShellV2`, `InstallPowerShellV2`,
`UninstallPowerShellISE`, `InstallPowerShellISE`, `InstallLinuxSubsystem`, `UninstallLinuxSubsystem`,
`InstallHyperV`, `UninstallHyperV`, `UninstallSSHClient`, `InstallSSHClient`, `InstallSSHServer`,
`UninstallSSHServer`, `InstallTelnetClient`, `UninstallTelnetClient`, `InstallNET23`, `UninstallNET23`,
`UnsetPhotoViewerAssociation`, `RemovePhotoViewerOpenWith`, `UninstallPDFPrinter`, `InstallPDFPrinter`,
`InstallXPSPrinter`, `AddFaxPrinter`, `UninstallFaxAndScan`, `InstallFaxAndScan`, `InstallSandbox`,
`RemoveSandbox`


### Accounts and configuration

#### Windows configuration (windows-configuration)

**Current disposition:** The two registry-policy defaults for Edge URL copying
and Start's Run as different user command are migrated. Account creation,
administrator membership, built-in-account changes, language packs and copying
regional settings require account/locale handlers and multi-user recovery
coverage. `AddUserBinToPath` remains pending as a per-user PowerShell startup PATH
outcome with separate directory provisioning. Persistent user-environment PATH
would be a distinct setting with exact capture/restore; this selector does not
implement it. See [profile migration analysis](powershell-profiles.md).
The remaining optional selectors need their own component, credential/network,
activation or security-policy workflows before migration.

**Test demand:** Required per batch: mocked Pester tests for user/locale/configuration discovery, apply, restore or compensating behavior, and failures. Defer multi-user, locale, and machine-wide scenarios to disposable VMs.

**Legacy selectors:**

`CreateNewLocalAdmin` **default**, `DisableBuiltinAdministrator` **default**,
`DisableFriendlyURLFormat` **default**, `EnableRunAsInStartMenu` **default**,
`InstallLanguagePackGB` **default**, `SetRegionalSettings` **default**, `CopyRegionSettingsToAll` **default**,
`AddUserBinToPath` **default**, `ActivateWindows`, `ActivateWindowsOEM`, `MakeLoggedOnUserAdmin`,
`MakeLoggedOnUserNoAdmin`, `AddWiFi`, `DisableWindowsStoreApp`, `EnableWindowsStoreApp`,
`UnconfigureFriendlyURLFormat`, `DisableRunAsInStartMenu`, `EnableInternetPrinting`, `DisableInternetPrinting`,
`EnableMemoryIntegrity`, `DisableMemoryIntegrity`, `InstallLanguagePackDK`, `InstallLanguagePackCustom`,
`CopyRegionSettingsWelcome`, `CopyRegionSettingsNewUser`


### Files and assets

#### Customization (customization)

**Test demand:** Required per batch: isolated Pester tests using temporary paths or mocked file/registry calls for content, idempotence, WhatIf, and restore. Defer real shell/profile integration to disposable VMs.

**Legacy selectors:**

`InstallFonts` **default**, `ReplaceDefaultWallpapers` **default**, `SetLockScreen`, `SetDefaultLockScreen`,
`InstallLenovoVantage`, `RemoveLenovoVantage`

#### PowerShell profile settings (requested v3 addition, 2026-10-12)

Add an optional current-user setting that gives elevated Windows Terminal
PowerShell sessions a blue background, based on the shell's actual token.
Cover Windows PowerShell 5.1 and installed PowerShell 7, including a normal
Terminal profile opened as a new tab inside an elevated window. This is shell
startup configuration, distinct from RIDE's declarative selection profiles and
the already accepted Terminal default-profile setting.

The implemented Recommended state uses Campbell for normal 5.1 sessions, One Half
Dark for normal 7 sessions and Campbell PowerShell blue for elevated sessions in
both. AdminBlue changes only elevated sessions; Default/unset remove the chosen
block and Baseline resolves to Default. Tab-title customization stays deferred.
See the [handler and migration analysis](powershell-profiles.md) and the
[profile appearance decision and acceptance requirements](migrations/settings-post-migration-review.md#powershell-profile-appearance-request-2026-10-12).

The focused reversible profile-file handler discovers each
runtime's intended-user ConsoleHost profile, manages only an identifiable RIDE
block, preserves unrelated bytes and concurrent edits, supports preview, and
captures prior block/file presence for saved-run recovery. Do not invoke the
legacy writer as a v3 handler. Add read-only inspection, planning and completion
from the same declared/discovered choices, mocked lifecycle tests and disposable
Windows VM appearance checks before publishing supported-target metadata.

Two catalog IDs and an optional powershell-colors selection profile are implemented,
with shared file mechanics, preview, read-only inspection/completion and versioned
saved-run recovery. Disposable Windows 11 and Server 2025 Desktop Experience
acceptance passed, including 22 Terminal cases per target and exact recovery;
both targets are now declared with explicit defaults. See the
[dated acceptance record](archive/migrations/powershell-profile-acceptance.md).
Unit fixtures do not modify workstation
startup profiles. This resolves no legacy outcome and is outside the
[legacy estimates in the overview](#estimated-remaining-migration-work);
the separately requested appearance addition does not reduce those ranges.


### System tasks

#### Unpinning (unpinning)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`CleanPublicDesktop` **default**, `UnpinStartMenuTiles`, `UnpinTaskbarIcons`

#### Operational Tasks (operational-tasks)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`GetWindowsUpdatesWithPwsh`, `CleanLocalWindowsUpdateCache`, `RunDiskCleanup`, `GetWindowsProductKey`,
`RunSysprepGeneralizeOOBE`

**PSWindowsUpdate evaluation (2026-10-11; pending):** Before migrating
`GetWindowsUpdatesWithPwsh`, test a pinned PSWindowsUpdate version in disposable
Windows 11 VMs on each intended supported build, including 24H2 and 25H2, and
Windows Server 2025 VMs. Validate Server Core and Desktop Experience separately
if both are offered; add older Server releases only after their own acceptance
checks pass. Verify scan, update selection, download, installation, per-update
results, pending-reboot reporting, explicit reboot handling, and rescan after
reboot. Check interaction
with the modern Windows Update Orchestrator and differences from Settings update
history. Start with Windows PowerShell 5.1; validate PowerShell 7 separately if
offered. Record the tested module version, OS builds, failures, and adoption
decision before declaring support. For server scenarios, verify configured WSUS
and public update sources without silently switching sources or overriding
managed policy, and require explicit reboot opt-in compatible with maintenance
windows. Keep server OS upgrades separate from routine update installation.
This evaluation does not complete a migration outcome; remaining-work estimates
are unchanged.

#### Other Functions (other-functions)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`SetHostname` **default**

#### Auxiliary Functions (auxiliary-functions)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`WaitForKey` **default**, `Restart` **default**, `StopComputer`

## Preset references to reconcile

These selectors do not exactly match a function name in the legacy modules. Resolve or explicitly mark them unsupported before their family batch is migrated. Do not silently create catalog entries for misspelled or missing functions.

| Preset selector | Reconciliation |
| --- | --- |
| `DisableAdditionalAuthAtStart` | The library defines `DisableAdditionaAuthAtStart` (missing “l”); verify and correct the intended legacy behavior. |
| `DisableBrowserServiceView` | The library defines `DisableBrowserSvcView`; verify whether the shortened function is the intended implementation. |
| `EnableInkingAndTypingData` | No matching function is defined; preserve as unresolved until implementation or removal is decided. |
| `InstallNucleusKernelFATNFTS` | The library defines `InstallNucleusKernelFATNTFS`; reconcile the transposed letters. |
| `RemoveWinCSP` | The library defines `RemoveWinSCP`; reconcile the preset typo and keep the removal selector with the WinSCP package batch. |
| `RemoveWSLFedora` | No matching function is defined; the Fedora install selector has no matching removal implementation. |
| `RequireAdmin` | This is a preset prerequisite directive, not a function. Represent the privilege requirement in operation metadata and profile/run guidance rather than as an operation. |

## Library functions outside the preset inventory

The following 23 function names are defined in the legacy modules but are not selected by name in `default.preset`; keep them out of these batches and record them as a separate future-review backlog:

`DisableAdditionaAuthAtStart`, `DisableBrowserSvcView`, `DisableFirewallDomain`, `DisableFirewallPrivate`, `DisableFirewallPublic`, `DisableWSUS`, `EnableFirewallDomain`, `EnableFirewallPrivate`, `EnableFirewallPublic`, `EnableWSUS`, `Export-FunctionFromFile`, `Get-PackageInfo`, `Get-RideBootstrapFolder`, `Get-RideSoftwareFolder`, `Get-RIDEvars`, `Install-RideDownloadedExe`, `Install-RideDownloadedMsi`, `InstallEntraConnect`, `InstallNucleusKernelFATNTFS`, `RemoveWinSCP`, `Save-RideDownload`, `Test-FunctionName`, and `Test-RideDownloadOnly`.

Several items overlap with misspelled preset selectors listed above. Those functions remain outside the inventory until the selector mismatch is reconciled.

## Package download and artifact records

The current minimum is a working **download latest** path. Package operations must be able to resolve the current release, select the declared Windows artifact, download it without installing it, and report the version and file location. Installing the latest release uses the same resolver and acquisition path. A missing publisher checksum or signature must not prevent acquisition or ordinary package installation; report the available evidence and the locally observed hash accurately so users can make an informed choice. The first provider adapters are 7-Zip, Notepad++, and Git for Windows.

Each provider adapter returns structured release metadata: package ID, resolved version, architecture, filename, artifact URI, release/source URI, any provider-reported digest, and available checksum/signature sidecar URIs. Reject malformed URLs, ambiguous asset matches, and a provider digest mismatch. Do not discard a downloaded installer after a successful install; retain it in the configured artifact repository for reuse and record its observed SHA-256.

The shared, version-controlled `catalog/artifact-observations.json` is an append-only metadata library, not a binary repository or trust store. Each observation binds package ID, resolved version, filename, source URI, acquisition time, route/transport label, and observed SHA-256 to one exact file. It may also record a provider digest, signature/checksum evidence and result, Authenticode signer details, and file size. A hash computed only after download is an observation, not publisher authentication. Multiple observations for the same exact artifact are retained so later work can compare downloads made through independent internet paths. Do not claim independence solely because observations have different timestamps or users.

Maintain `docs/package-verification-matrix.md` from per-package source investigations. Record whether the official source resolves latest, provides exact versioned URLs, publishes checksums, offers detached signatures and a key identity, or supplies an Authenticode signature. Distinguish publisher-provided evidence from hosting-provider metadata and from hashes RIDE observes itself. The matrix informs a later policy decision; it does not block latest acquisition. The CLI `download` command acquires without installing; artifacts are retained by package and version, and observations are appended to `catalog/artifact-observations.json`.

Package presence remains separate from acquisition: downloading an installer does not make its operation `Present`. A later install-from-repository mode should install an already acquired artifact without network fallback. Download-only `Artifact` catalog entries are separate from packages and desired Windows state; the first is the user-selected SwiftOnSecurity Sysmon XML, resolved to an immutable Git commit URL and retained without applying it.

### Verification vocabulary and future policy decision

The earlier policy names `Bypass`, `Verified`, and `Strict` are provisional. `Verified` was intended to mean validation using provider/publisher evidence (for example a published checksum, detached signature, or Authenticode identity); a RIDE-computed SHA-256 alone is only an observed hash. Do not make `Verified` the default or require pinned exact versions until the package matrix shows which evidence is actually available. Keep download/install latest usable while collecting that evidence.

Any provider-reported digest that RIDE chooses to check must match the downloaded bytes; a mismatch is a hard failure. Record unavailable, invalid, or untrusted signature/checksum evidence without mislabeling the file. After the matrix is populated, decide which policies should gate installation, whether a trust exception is needed for checksum-only sources, and how machine-enforced minimums interact with user choices. Strict could later require exact version pinning, trusted publisher signatures, a signed repository manifest, and approved providers; those are decisions for the evidence review rather than prerequisites for this phase.

### Package-specific Defender exclusions

Before migrating additional packages that are known to trigger Microsoft Defender alerts, add package-level compatibility metadata and use it as the source for narrowly scoped directory exclusions. Dual-use forensic and security tools can exhibit behavior that overlaps with malicious activity; an observed alert is a reason to record and review the exception, not a blanket verdict that the package is safe.

- Record the package ID, affected exact version and artifact digest where known, Defender detection name or ID, affected file, observation date, evidence/source, rationale, and review status. Keep the record tied to the reviewed package artifact; require renewed review when the artifact changes.
- Install each package that needs an exception into an isolated, deterministic package directory under the configured `ToolsDirectory`. Metadata must identify the exclusion scope as that package directory. Do not derive a package exception by excluding the shared `ToolsDirectory` parent or a general Downloads directory.
- Generate exclusions only for packages selected for installation by the applicable analyst/tooling profile and whose metadata contains a reviewed exception. Show each package, exact resolved path, and recorded reason in the plan and run report; provide a readable grouped summary when several packages share a path.
- Preserve the existing repository-tools and bootstrap exclusions as separately documented compatibility decisions while this step is implemented. Do not silently remove or broaden them as a side effect of package metadata work. Review whether each remains needed against the repository functions and bootstrap workflow that prompted it.
- Capture pre-change exclusion state and restore only the state changed by the run. Deduplicate identical exact paths without broadening the resulting set.

**Verification required:** Add mocked Pester coverage proving that reviewed packages selected by the profile produce only their declared package-directory exclusions; unreviewed or unselected packages produce none; configured `ToolsDirectory` changes resolve correctly; duplicate paths are deduplicated without promoting them to a parent directory; `WhatIf` makes no change; existing exclusions are preserved; and restore removes only exclusions introduced by the run. In a disposable Windows 11 and Windows Server 2025 VM, inspect effective Defender exclusions and verify that a reviewed package's intended functions work while a neighboring, unexcluded directory remains scanned. Do not use live malware as a test fixture. The plan/report must make the longer exception list reviewable by package, path, version, evidence, and reason.

Expose the `download` command explicitly through the CLI and keep it separate from `RIDEVAR-Download-Only` and other legacy environment flags. Mock HTTP requests, digest comparison, and installer processes in Pester; verify that download-only never starts an installer and that installation uses the same acquisition path. Provider digests, when offered and checked, must match the downloaded bytes. Add installer failure, idempotence, and `WhatIf` cases. Future local-repository and signature-enforcement modes remain follow-up work informed by the source matrix.

7-Zip, Notepad++, and Git for Windows now resolve the latest GitHub release to a versioned asset. The release API endpoint remains mutable by design to satisfy the latest-download baseline; each resolved artifact URI and version are recorded in the observation library. Publisher signature verification and reproducible installation from the local artifact repository remain future work.

### Rate-aware GitHub release discovery before unattended VM CI cutover

**Scheduled migration infrastructure work:** The Server 2025 full CI pilot
failed at 7-Zip release discovery when the shared, unauthenticated GitHub REST
API budget reached zero; see the [pilot evidence](../tests/integration/automatedlab-tasks.md).
The limit applies to the originating IP across GitHub-release packages, so
substituting another GitHub-hosted test package does not solve it. Complete a
shared, rate-aware `GitHubReleaseApi` resolver before enabling unattended VM
testing on the default branch.

Implementation is now available in package module 0.10.0, with
[documented process-local bounds, freshness and quota behavior](github-release-discovery.md).
Native complete regression passed 1,276 selected tests per edition; consecutive
two-target Full acceptance remains pending. This does not enable default-branch VM testing or complete overall
controller certification.

Design bounded reuse of release metadata with explicit freshness and source
provenance, while preserving the declared latest-release behavior and artifact
digest checks. On 403/429 exhaustion, report the remaining budget and reset time
and defer the run without hammering the endpoint or claiming a pass. Evaluate
scoped authentication through the [approved v3 scope](#optional-github-authentication-v3-scope); never commit a token, log it, or automatically
forward a runner credential into a disposable guest or collected evidence.
Acceptance requires mocked PowerShell 5.1/7 cases for shared quota, cache
freshness, expiry, exhaustion and recovery, followed by consecutive full CI VM
runs on supported targets with source hashes, package verification and cleanup
evidence. This work adds reliability to acquisition, not a legacy product
outcome; it does not change the migration estimates.

## Package variants and portable lifecycle

**Approved decision, 2026-10-09; implementation pending:** Support both installed
and portable distributions, with a recommended default per product and explicit
overrides. Offer only catalog-declared variants that have been implemented and
tested; supporting both does not require every product/provider combination.
Distinguish distribution (installed or portable), artifact format (MSI, EXE, ZIP
or standalone file), and provider (direct publisher download or a future WinGet
adapter). Scope remains a separate constraint declared by each supported variant.
The [application guide](application-packages.md) owns the implemented selection,
configuration and recovery workflow; WinGet remains future work.

**Approved amendment, 2026-10-14; implementation pending:** Workstation
installation, separate portable copies and acquisition USB/toolkit assembly are
independent workflows that may coexist under one product ID. Each deployment
needs separate ownership, distribution, scope, destination, version and recovery
records. Product-specific conflict and acquisition-suitability acceptance are
required. The [deployment decision ledger](migrations/package-deployment-decisions.md)
records the approved scope and unresolved schema, lifecycle and kit work.
Current runtime behavior remains single-selection; packages remain paused.

### Catalog and selection contract

- Keep one stable product ID, such as `package.sharex`, with variants in its
  catalog record or referenced manifest. Each variant declares acquisition,
  detection, supported Windows targets, scope, privileges, dependencies,
  install/removal behavior, and recovery limits. Provider adapters share the
  package lifecycle rather than duplicating it.
- Use installed editions by default for ordinary desktop applications where
  their integration is useful, and portable editions for portable-only products
  and suitable managed tools. Prefer MSI when features are equivalent and its
  lifecycle is tested; do not impose one artifact format on every product.
- Allow optional global distribution/provider preferences in the agreed local
  configuration. Explicit profile or command selections override preferences;
  unsupported explicit selections fail clearly. A preference may fall back to
  the product default when unavailable, with the reason shown in the plan.
- Resolve the selected variant, provider, scope, and destination during planning
  and record them with the artifact/version evidence in the saved run. Removal
  and restoration use that recorded selection rather than re-evaluating current
  preferences. Installation failures must not trigger a switch of variant or
  provider; the separate acquisition fallback rules below remain bounded to
  approved equivalent sources.
- Allow explicitly selected installed and portable deployments to coexist after
  product-specific conflict validation, with separate destinations, ownership
  and lifecycle records. Never silently replace or adopt another deployment.
  Replacing installed with portable, or the reverse, requires an explicit
  migration accounting for configuration and integration. The current runtime
  edition-conflict guard stays in place until deployment selection, state
  compatibility and applicable acceptance are implemented.
- Preserve existing IDs and profiles: entries without a variant retain their
  current catalog default. Version any required catalog/profile/state schema
  change and document its migration and recovery path. Final field/CLI names
  remain implementation work; new enumerable parameters require read-only
  completion and synchronized help.

### Managed portable lifecycle

- Install machine portable packages into isolated, deterministic product
  directories under the configurable `ToolsDirectory`. Any supported user
  variant must declare its user-scoped destination and state ownership.
- Record managed files, version, artifact evidence, shortcuts, and PATH changes.
  Detect presence from both the ownership manifest and actual files, reporting
  missing or modified files. Do not adopt arbitrary existing files implicitly.
- Preserve application settings and user-created files during upgrades and
  removal. Remove only owned package content and integration; never delete the
  shared tools root or overwrite modified/user files without an explicit policy.
- Participate in planning, `ShouldProcess`, pre-change capture, idempotence,
  status, and partial-failure reporting. Exact binary recovery requires retained
  verified artifacts and captured prior file state; application-data recovery
  must be declared separately. Otherwise report compensating recovery limits.
- Declare services, drivers, reboot requirements, and other system changes even
  for publisher-labelled portable products. Managed-file removal alone cannot
  recover those side effects. Defender exceptions remain governed by the
  separate package-specific exclusion decision above.

### Implementation order and acceptance

Implement direct managed-portable support alongside the existing EXE/MSI
handlers first, then add WinGet as an optional provider. Keep the standalone
bootstrap usable without requiring WinGet. Resume deferred portable selectors
from the [Install programs ledger](migrations/install-programs-dispositions.md)
and [System Tools ledger](migrations/system-tools-dispositions.md) only after
their package-specific source, ownership, dependencies, and recovery work is
complete.

Require mocked tests for variant/preference resolution, strict explicit choices,
existing-edition conflicts, safe extraction and ownership, modified/user-file
preservation, repeat installation, removal, recovery, `WhatIf`, and partial
failures. Exercise each offered variant/provider lifecycle in disposable Windows
VMs on its declared targets before claiming support, including upgrades with
preserved user data and cleanup of owned shortcuts/PATH changes. This decision
does not mark any deferred selector implemented or extend Windows support.

## Multiple package sources

Current adapters support GitHub releases/files, direct HTTPS and selected
publisher APIs/pages. Alternative-provider selection and fallback below remain
planned; WinGet has no implemented adapter, and PSGallery has no implemented
adapter or specific recorded design. The 2026-10-14 coexistence approval does
not authorize either provider's implementation. See the
[source-provider review](migrations/package-deployment-decisions.md#source-provider-knowledge-retained).

Represent all approved acquisition/install providers for a package in its single package record or referenced manifest. For example, a package can describe both a direct GitHub release artifact and a WinGet source, with each provider's package identifier, exact version mapping, architecture, artifact metadata, and verification requirements. Provider adapters implement the mechanics; package-specific PSM1 files must not duplicate the package lifecycle or make implicit source choices.

Source selection should be deterministic and policy-driven: allow an explicit source choice and a configured preference among approved providers. An explicit provider choice must not fall back to another provider. Auto-selection may move to another provider only when it is approved for the same package/version, distribution, and scope and satisfies that provider's pinned artifact and trust metadata. An acquisition transport or availability failure may permit trying the next approved provider, with the resolved provider reported; an installation failure, version mismatch, hash mismatch, invalid signature, or unexpected publisher must stop the operation. Do not silently retry an integrity failure through a different source.

When providers supply different installers or materially different package builds, model them as distinct artifacts with provider-specific metadata and verification, even when they install the same logical package. Record the selected provider and artifact digest in the download manifest and run report so an installation can be reproduced and audited. Tests should cover provider preference, explicit source selection, approved transport fallback, and fail-closed verification errors.

**Agreed storage choices:** customizable values live in data-only, schema-versioned local configuration, split by scope: machine configuration under `%ProgramData%\RIDE\configuration.psd1` and user configuration under `%LocalAppData%\RIDE\configuration.psd1`. `ToolsDirectory` is machine-scoped and defaults to the system-drive `Tools` directory; it is not a catalog default or process environment variable. Package profiles currently resolve latest; exact-version selection and repository-backed reproducibility are later options, not prerequisites for acquisition.

## Package deployment coexistence design recorded, 2026-10-14

Recorded the user's approved [deployment model](migrations/package-deployment-decisions.md)
and remaining decisions. This amends the earlier mutually exclusive edition
design while preserving the current runtime guard. Separate workstation,
portable and acquisition-kit ownership/lifecycle, schema compatibility,
product-specific conflicts, offline kit behavior and redistribution review
remain unimplemented or deferred. Source-provider review confirms existing
publisher/GitHub acquisition; WinGet remains planned and PSGallery unspecified.
No package acquisition, VM submission, Windows state change, support widening or
legacy outcome resolution/retirement/exclusion occurred. Existing accepted
distributions and partial/deferred outcomes retain their evidence. Reviewed all
five overview ranges: 38-58 / 58-73 / 20-25 / 25-35 / 8-12; rounded
150-205/about 180, unchanged because a design decision closes no legacy outcome.
Kit workflow adds future development scope; effort estimates need review once
its schema/workflow is specified. Packages remain paused. Documentation links,
LF line endings and focused changes reviewed; no runtime tests needed.

## Acceptance and later integration

- For every batch, run catalog/profile validation and Pester coverage for planning, handler behavior through mocks, idempotence, `WhatIf`, and applicable restore or compensating behavior before accepting the batch.
- Keep package tests offline and deterministic by mocking download resolution and installer processes.
- Before accepting package migrations that use Defender exceptions, complete the package-specific exclusion metadata step and its mocked and disposable-VM verification above; ensure plans and reports identify every package-scoped exception.
- Defer complex disposable-VM scenarios—including reboot/Sysprep, broad Windows component changes, multi-user or machine-wide configuration, destructive cleanup, and live installer recovery—to a later integration phase.
- Add or retain Windows support declarations only after the affected operations pass their applicable disposable-VM checks on Windows 11 and Windows Server 2025.

## Owned power-plan copy implementation, 2026-10-13

Implemented the accepted creation/selection separation as three pending
machine/admin creation candidates. Explicit destination GUID and owner token
are saved before changes, intent precedes duplication, finalized ownership uses
a bounded native export fingerprint, and inspection stays read-only. Recovery
retains active/changed/unfinalized/orphaned copies and never selects a plan to
force deletion. Existing Balanced/HighPerformance selection and captured-GUID
recovery remain intact. Ultimate duplication is conditional, not an activation
fix. Desktop menu deployment and intended-user scope remain deferred.

Local validation: 30 focused mocked checks passed on each native PowerShell
edition (5.1 and 7.6.5), including existing selection and pending metadata. Parser,
catalog/profile and generated documentation checks passed with 312 operations,
3 groups, 5 profiles and 116 PowerShell files. Expanded checks cover ownership-write failure, concurrent locks, reparse/oversized
records and repeat-create idempotence. A temporary ACL fixture mistake was repaired;
the repeat-create check exposed and corrected a new entry-array comparison error. No live plan, package or VM is changed.

Outcome ledger: **partial** power-plan bundle; **resolved implementation** for
explicit owned creation and bounded compensating recovery; **excluded** implicit
activation/fallback/adoption/global resets; **deferred** hardware/edition, export
reproducibility, GUI, intended-user menu and Server acceptance. No legacy outcome
is retired or fully closed by this run. All five group ranges were reviewed:
settings 38-58; packages 58-73; components 20-25; accounts/config/files 25-35;
maintenance 8-12; rounded total 150-205 (about 180). They remain unchanged because
mocked lifecycle evidence cannot close feature/target acceptance. Disposable VM
execution is held for manual user confirmation; packages remain paused.

## Conditional media policy implementation, 2026-10-13

Implemented two independent omitted media-online components as pending scalar
policies: Prevent Radio Station Preset Retrieval in intended-user HKCU without
admin, and Prevent Windows Media DRM Internet Access in machine HKLM with admin.
Both distinguish Blocked=1, PolicyDisabled=0, WindowsDefault override removal
and exact prior typed recovery. Local templates confirm classes and values;
pre-Vista radio applicability and historical WMDRM support labels are retained
as gaps rather than current effect evidence. Corrected blanket retirement text
in the existing music metadata description. No automatic DRM composition or
player/license acquisition is introduced.

Local evidence: 24 focused mocked checks passed on each native PowerShell edition
(5.1 and 7.6.5), including 6 media cases plus notification and catalog regressions.
Parser, catalog/profile and generated documentation validation passed with 314
operations, 3 groups, 5 profiles and 117 PowerShell files.
Outcome ledger: **partial** media-online bundle; **resolved implementation** for
two independently scoped conditional policies; **excluded** generic all-traffic,
PlayReady, license-store and automatic metadata-bundle changes; **deferred**
current consuming component, managed precedence, GUI/content and target evidence.
No legacy outcome is retired or fully closed. All five ranges were reviewed:
settings 38-58, packages 58-73, components 20-25, accounts/config/files 25-35,
maintenance 8-12, rounded total 150-205 (about 180). They remain unchanged because
policy mapping and mocked lifecycle do not close feature acceptance. Packages
remain paused; no VM tests start without manual user confirmation.

## Server Manager startup policy implementation, 2026-10-13

Implemented the accepted advanced machine/admin policy with Suppressed=1,
AutomaticStartup=0 and WindowsDefault override removal. Local ServerManager.admx
and exact CSP references confirm mapping and inverted policy wording; Server
Manager Properties preference, logon availability and effective managed source
are kept separate. The legacy reverse removes the override. Typed prior-state
recovery reuses the focused registry handler; no task, component or console
start/stop is introduced. Windows Server 2025 is a candidate only.

Local evidence: 21 focused mocked checks passed on each native PowerShell edition
(5.1 and 7.6.5), including 3 Server Manager cases and notification/catalog regressions.
Parser, catalog/profile and generated documentation validation passed with 315
operations, 3 groups, 5 profiles and 118 PowerShell files.
Outcome ledger: **resolved implementation** of the focused policy; **partial**
Server Manager legacy outcome pending desktop/Core/logon/precedence evidence;
**excluded** console-preference reconstruction and live console actions;
**deferred** target acceptance. No retirement or new legacy closure is counted.
All five ranges reviewed: settings 38-58; packages 58-73; components 20-25;
accounts/config/files 25-35; maintenance 8-12; total rounded 150-205 (about 180).
Ranges remain unchanged because local mapping and mocked gates are not Server
feature acceptance. Packages stay paused; manual VM confirmation is required.

## Shutdown Event Tracker policy implementation, 2026-10-13

Implemented the accepted coherent machine/admin display policy with Disabled,
Always, ServerOnly, WorkstationOnly and WindowsDefault. Local Reliability.admx
confirms gate 1/0 and display 1/2/3, matching focused Microsoft documentation.
Disabled preserves the display value/type/absence rather than deleting a saved
choice. Enabled choices write display before gate. WindowsDefault removes both
policy overrides explicitly; the legacy reverse removed only enablement and is
not silently claimed identical. Exact saved restore captures/replays the prior
pair in reverse order; partial errors retain the whole capture. No shutdown,
logging/clear, timestamp, reporting or policy refresh action is introduced.

The additive KeepCurrent marker is schema-validated and handler-preflighted;
existing null/removal and snapshots retain their meaning. Plan/status and generated
component text distinguish preservation. Generated managed-target rows now also
show modern firewall profile identities and owned-copy source GUIDs. Local evidence:
34 focused Server Manager/tracker/notification/catalog checks and 79 existing
registry/service/keyboard recovery checks passed on each native PowerShell edition
(5.1 and 7.6.5). Parser, catalog/profile and generated documentation validation
passed with 316 operations, 3 groups, 5 profiles and 118 PowerShell files.

Outcome ledger: **resolved implementation** for the paired policy and subordinate
preservation; **partial** Shutdown Event Tracker outcome pending actual prompts/
policy precedence/desktop/Core and exact target recovery; **excluded** host
shutdowns and unrelated logging policy; **deferred** target/client/Server evidence.
No legacy outcome is retired or closed. All five ranges reviewed: settings 38-58,
packages 58-73, components 20-25, accounts/config/files 25-35, maintenance 8-12;
rounded total 150-205 (about 180). They remain unchanged because local mapping and
mocked lifecycle do not close feature acceptance. Packages stay paused; VM
execution requires manual user confirmation.

## Windows Audio service implementation, 2026-10-13

Implemented the accepted advanced machine/admin Audiosrv service control with
AutomaticRunning and legacy ManualStopped, preserving rather than substituting
Disabled. Dependency inspection is bounded and read-only; nonrunning prerequisites,
active dependents, unknown/transitional state and load-order groups fail before
configuration. Related state is rechecked before runtime and compared afterward;
triggers reaching the desired primary runtime avoid redundant calls. No Force,
AudioEndpointBuilder/dependent change or dependency replay is introduced. Exact
prior primary startup/runtime and SCM/literal delay recovery retains snapshot v2
and old service compatibility. Changed active dependents can block recovery and
remain unowned manual review. Playback-device mute is separate and deferred.

Local evidence: 92 focused mocked checks passed on each native PowerShell edition
(5.1 and 7.6.5), including 13 new audio cases and existing registry/service/keyboard
recovery regressions. Parser, catalog/profile and generated documentation checks
passed with 317 operations, 3 groups, 5 profiles and 119 PowerShell files.
Final review reconciled the active settings queue and restored the estimate table
immediately below the title, preserving concurrent infrastructure records. Remaining
native/GUI-dependent settings need current-build evidence before implementation; no
VM-dependent validation is inferred from these local checks.
Outcome ledger: **resolved implementation** for the guarded primary service;
**partial** audio legacy bundle/outcome; **excluded** forced dependent stops,
implicit dependency repair, device/volume/microphone/app/default-device changes;
**deferred** native endpoint mute, actual audio/session, GUI, trigger/dependency
and target/Server acceptance. No retired or fully closed legacy outcome is counted.
All five ranges reviewed: settings 38-58; packages 58-73; components 20-25;
accounts/config/files 25-35; maintenance 8-12; rounded total 150-205 (about 180).
They remain unchanged because mocked primary lifecycle does not prove audio or
target acceptance. Packages remain paused. No live service, audio, package or
VM test occurs; VM execution still needs manual user confirmation.

## Settings validation dependency review, 2026-10-13

First heartbeat check at 07:37 UTC (09:37 Europe/Copenhagen) for
`resume-ride-migration-validation-after-github-backoff` inspected the dependency
chat and local bridge records only. The user has conditionally authorized this
chat's disposable VM testing after both verified VM tests and explicit resource
backoff/yield; a new manual confirmation is not required after those conditions
are genuinely satisfied. Elapsed time or a quota-reset timestamp is not readiness.

Dependency request `c08c77f026034547b4ceba4cfedc93af` failed Full acceptance at the
first 7-Zip lookup on quota zero. Validation, 1,280 guest tests and 217 source
hashes passed; installed collector 0.4.1 passed its actual failure path within
90 seconds with no omissions/errors. Checkpoint/UAC recovery and final idle were
reported verified. These results concern frozen CI source `a156475`, not this
chat's unfinished settings changes. The dependency recorded next allowed lookup
07:43:35 UTC and its own next attempt at 09:50 Copenhagen. Its failed acceptance
keeps this chat's verification gate closed, even while the VMs are reported idle.
No controller inspection/submission, GitHub request, package acquisition or
Windows state change was made by this settings continuation. The existing
heartbeat stays active and will recheck quietly; the bridge automation is untouched.

Outcome ledger: **deferred** all settings VM acceptance at the dependency gate;
**partial** existing implemented settings remain pending target/GUI evidence;
**resolved/retired** no additional legacy outcome; **excluded** package migration
and treating partial bridge results as complete acceptance. All five ranges and
row progress reviewed: settings 38-58, packages 58-73, components 20-25,
accounts/config/files 25-35, maintenance 8-12; rounded total 150-205 (about 180).
They remain unchanged because this is a read-only readiness review, with no new
legacy or target acceptance. Existing infrastructure results and unrelated
working-tree changes remain preserved.

## Windows Update interruption guide implementation, 2026-10-13

Implemented the accepted Reduce Windows Update interruptions guide in
update-notifications.md, retaining machine policy and personal preference
boundaries, explicit managed deadline/grace behavior and user-controlled restart
scheduling. Microsoft Support/Learn references were checked without GitHub API
access. There is no new handler/profile, policy write, automatic restart, AUOptions
rewrite or IFEO cleanup. Manual GUI settings are not represented as saved RIDE
changes. The scheduled validation dependency gate remains unchanged.

Local verification: parser/catalog/profile/generated-reference validation passed
on native PowerShell 5.1 and 7.6.5 (317 operations, 3 groups, 5 profiles,
119 PowerShell files). Focused diff/whitespace review passed. No runtime tests
were added for this documentation-only implementation.
Outcome ledger: resolved guided implementation; partial legacy interruption
outcome; excluded interception/automatic restart and unrelated policy changes;
deferred actual GUI/notification/reboot and Server acceptance. No retirement or
new legacy closure. All five ranges reviewed: settings 38-58; packages 58-73;
components 20-25; accounts/config/files 25-35; maintenance 8-12; rounded total
150-205 (about 180). Ranges remain unchanged because documented manual steps
are not target feature acceptance. Packages remain paused and no VM tests run.

## Local maximum password age implementation, 2026-10-13

Implemented windows.local-password-maximum-age using documented local
NetUserModalsGet levels 0/2 and Set level 1002. Only maximum-age seconds are
written; no full security-template/modal replay or password/account enumeration.
A bounded additive StateRange supplies NoExpiry and all 1-999 explicit day choices
from the same data reader used by execution/completion. Minimum age is preserved;
new day choices must exceed it. Domain controllers, unknown roles, changed local
SAM SID, modal context or stale maximum-age recovery are refused. Snapshot v1
retains exact prior custom seconds and expected field value, without secrets.

Local evidence: 54 selected mocked checks passed on each native PowerShell
edition (5.1 and 7.6.5), including native-type compilation without API invocation,
minimum/DC/drift/partial recovery, range completion, engine capture, owned-plan
and catalog regression. One test initially lacked its explicit catalog-reader
import; the fixture was corrected and final runs passed. Parser/catalog/profile/
generated-reference checks passed with 318 operations, 3 groups, 5 profiles and
121 PowerShell files. Focused code/whitespace/EOL review passed. No native policy
read/write, package action, VM test or anonymous GitHub request was invoked.

Outcome ledger: resolved maximum-age implementation; partial legacy password
bundle with complexity separate; excluded password changes, per-account/domain
flags, full policy replay and automatic weakening; deferred native/local-policy
GUI/provenance, member/Server and actual expiry acceptance. No outcome retired
or fully closed. All five ranges reviewed: settings 38-58, packages 58-73,
components 20-25, accounts/config/files 25-35, maintenance 8-12; rounded total
150-205 (about 180). They remain unchanged because mocked field lifecycle is
not target/account feature acceptance. VM testing retains the dependency gate.

## BitLocker recovery handoff implementation, 2026-10-13

Implemented the guided Back up/Show selected recovery-key area through current
Microsoft native Windows/account/organization interfaces. The only optional
PowerShell example projects nonsecret RecoveryPassword IDs/types for one explicit
volume; it is not executed. Normal backup retains the selected existing protector;
zero/multiple/ambiguous-ID cases remain pending rather than adopt/rotate a key.
File/USB, personal account, Entra/work/school, AD DS and explicit print routes have
distinct permissions and independent-access requirements. Native creation can
emit secrets and therefore stays a separate advanced implementation; no secret
viewer, upload, printing, Graph grant, protection change or key cleanup is added.

Microsoft Support/Learn references were reviewed without GitHub API requests.
Local parser/catalog/profile/generated-reference validation passed on native
PowerShell 5.1 and 7.6.5 (318 operations, 3 groups, 5 profiles and 121 PowerShell
files). Focused documentation/whitespace review passed. No runtime test was added
for this manual handoff, and the optional identifier example was not executed.
Outcome ledger: resolved guided backup/retrieval implementation; partial legacy
recovery outcome; excluded implicit creation/rotation/deletion and secret logging;
deferred secure additional creation/custom display, exact-ID/backend permission,
retrieval/unlock and Server evidence. No retirement or complete legacy closure.
All five ranges reviewed: settings 38-58; packages 58-73; components 20-25;
accounts/config/files 25-35; maintenance 8-12; rounded total 150-205 (about 180).
Ranges remain unchanged because native handoff guidance does not establish actual
secret-safe backup or recovery acceptance. No keys, accounts or host encryption
were inspected/changed. Packages remain paused and VM execution retains its gate.

## Windows recovery readiness implementation, 2026-10-13

Implemented `docs/recovery-readiness.md` and linked it from README. The guide
requires an independently verified route before the future advanced Disable
action, distinguishes media creation from file backup and recovery entry from
enablement/reset, and connects selected-key retrieval without recording secrets.
Optional `reagentc /info` inspection is documented but was not executed; no
restart, download, USB creation, recovery tool or account operation was run.

Resolved implementation scope: the accepted readiness/entry handoff. No whole
legacy outcome is closed or retired. Windows RE association/partition capture,
localized inspection, conflict refusal and bounded recovery remain deferred;
boot, encrypted access, independent-media and Server/Core evidence stay pending.
SupportedTargets and profiles are unchanged. Documentation-only validation is
recorded below; no mirrored unit tests were added for prose.

All five ranges were reviewed: settings 38-58; packages/artifacts 58-73;
components 20-25; accounts/configuration/files 25-35; maintenance 8-12. Rounded
total stays 150-205/about 180 because readiness guidance does not prove the
remaining native lifecycle or close its legacy feature outcome. Packages remain
paused and disposable VM validation remains gated by verified Github cache
acceptance plus explicit resource backoff/idle controllers.

Recovery-readiness validation: Windows PowerShell 5.1 and PowerShell 7.6.5
repository parser/catalog/profile/generated-documentation checks passed:
318 operations, 3 groups, 5 profiles and 121 PowerShell files per edition.
Focused whitespace review passed. No optional native example was executed.

## Documentation cleanup and licensing review list, 2026-10-13

Reviewed the shared network-devices documentation model and applied lowercase
kebab-case to topic guides and directories. Conventional entry points remain
uppercase; MIGRATION-PLAN.md and generated OPERATIONS.md retain their explicit
instruction/generator path contracts. Updated repository links and help references.
README now links to focused settings guidance and the corporate/professional
licensing watchlist. The list records publisher-specific Npcap, KAPE and Docker
Desktop review triggers, rather than a blanket personal-versus-company rule.

Consolidated the former roadmap's future work into TODO and retained its dated
snapshot. Archived seven completed run/acceptance reports and separated detailed
screen-lock pilot history from the active procedure and acceptance table. Active
application/settings decisions, pending source reviews and script exceptions
remain live. Existing uncommitted implementation and documentation work is retained.

Resolved legacy outcomes: none. Newly retired or excluded legacy outcomes: none.
Existing retired/excluded outcomes are unchanged. Deferred products/components,
partial settings and all target/GUI/runtime acceptance remain open. The settings
overview now points to durable guides; package progress now includes the licensing
watchlist, with no package admission or entitlement approval. Component, account/
asset and maintenance progress retain their prior acceptance limits.

| Group reviewed | Remaining range | Effect of this run |
| --- | ---: | --- |
| Windows and application settings | 38-58 | Navigation and evidence cleanup only; feature acceptance unchanged; modern Network discovery handoff implemented; profile/peer/target acceptance remains open; Storage Sense native cleanup-choice guidance implemented; GUI/content acceptance remains open; System protection native guidance implemented; volume coupling/history acceptance remains open; Feedback frequency native guidance implemented; paired type/unit/GUI evidence remains open; Latest focused validation: Solitaire previews/uninstall/reinstall/repeats and registration recovery accepted; GUI/fault/full-launcher/other targets pending |
| Packages, portable tools and downloadable artifacts | 58-73 | Licensing review guidance added; product outcomes and deployment acceptance unchanged |
| Windows components and optional features | 20-25 | No component implemented or accepted |
| Accounts, configuration and deployed files/assets | 25-35 | No configuration or asset outcome closed |
| Maintenance and operational actions | 8-12 | No runtime or CI acceptance established; optional GitHub authentication approved as high-priority v3 infrastructure, with implementation/acceptance pending |
| Total, rounded | 150-205 | About 180; no adjustment because documentation work closes no legacy outcome |

Release follow-up: refresh the licensing list against selected releases and
publisher terms, retain its final README link, and archive further evidence only
when current open work remains explicitly tracked. Organization-specific license
reviews remain local. No Windows state change or disposable-VM run is part of this
cleanup. Windows-native parser/catalog/profile/generated-document validation passed
for 318 operations, 3 groups, 5 profiles and 121 PowerShell files. Local Markdown
paths and heading anchors passed review. No runtime behavior or VM acceptance
was tested by this documentation change.

## Network discovery handoff implementation, 2026-10-13

Implemented `docs/network-discovery.md` and linked the Windows settings index.
The guide selects the actual connection/profile, treats changes as machine
networking with administrator/managed requirements, and keeps discovery separate
from sharing permissions, password-protected sharing, firewall flags, services
and components. It makes no invisibility claim or legacy Hidden cleanup.

Resolved implementation scope: accepted modern discovery guidance. Previous
Computer Browser selector retirement remains the only retired legacy outcome;
no new resolution, exclusion or estimate subtraction. Automated bounded capture,
partial recovery and actual peer/multi-profile/multi-user behavior stay deferred;
GUI and Server/Core applicability remain pending. No target/profile metadata
changes, live network inspection or settings mutation were performed.

Preserved concurrent README/index/documentation work. The new recovery-readiness
guide was renamed to lowercase using an intermediate path, links updated, and
run history kept in this ledger per the newly recorded documentation model.
Focused link/line-ending/whitespace review passed; this batch changes prose only.
All five ranges reviewed unchanged: settings 38-58; packages/artifacts 58-73;
components 20-25; accounts/configuration/files 25-35; maintenance 8-12; rounded
total 150-205/about 180. The guide does not establish native feature acceptance.
Packages remain paused and VM validation retains the Github cache evidence gate.

## Storage Sense guidance implementation, 2026-10-13

Implemented `docs/storage-sense.md` and its Windows settings index link. The
native handoff separates enablement from schedule/retention/cloud choices and
immediate cleanup. It keeps default value removal distinct from a full preference
reset and exact captured setting recovery distinct from content recovery.
Recursive reverse deletion and the unverified notification marker stay excluded;
no catalog/schema/handler/target change was made in this batch.

Resolved implementation scope: accepted native cleanup-choice guidance. The
legacy Storage Sense bundle remains partial; current GUI/value mapping,
defaults/managed precedence and actual disposable-file/cloud/offline behavior
remain deferred. No legacy outcome closes or is newly retired/excluded. No
settings screen, file cleanup, native handler or provider account was accessed.

Focused local-link/line-ending/whitespace review passed. This prose-only batch
does not require mirrored tests. All five ranges reviewed unchanged: settings
38-58; packages/artifacts 58-73; components 20-25; accounts/configuration/files
25-35; maintenance 8-12; rounded total 150-205/about 180. Guidance alone does
not establish feature acceptance. Packages remain paused; VM validation retains
verified Github cache tests plus explicit backoff/idle-resource authorization.

## System protection guidance implementation, 2026-10-13

Implemented `docs/system-protection.md` and Windows settings index link.
Separate On/advanced Off, allowance, history deletion, point creation and point
application are visible. Documented system-drive coupling prevents treating the
ComputerRestore API as independent per-volume configuration. Native UI is the
interim manual route; no GUI or native command was invoked. Point-in-time restore
is a separately documented current feature, not a guessed replacement backend.

Resolved implementation scope: native System protection guidance. Automated
enabled-volume inspection, stable affected-volume capture, completion, bounded
recovery and history-loss handling remain deferred. GUI, defaults and actual
restore history evidence stay pending. No legacy outcome closed/retired/excluded,
no new targets, Server port, settings or profile. Configuration recovery cannot
recreate deleted history and is not labeled Exact for the whole feature.

Focused document link/line-ending/whitespace checks passed; this prose-only batch
requires no mirrored unit tests. All five ranges reviewed unchanged: settings
38-58; packages/artifacts 58-73; components 20-25; accounts/configuration/files
25-35; maintenance 8-12; total 150-205/about 180. Guidance does not complete the
retained legacy outcome. Packages stay paused; VM execution remains conditional
on verified Github cache tests plus explicit backoff and idle shared resources.

## Feedback frequency guidance implementation, 2026-10-13

Implemented `docs/feedback-frequency.md` and its Windows settings index link.
The guide records the actual prior GUI label, offers only visible build choices,
leaves missing/managed controls pending and distinguishes manual return from
exact captured mixed/custom registry recovery. Existing machine feedback request
policy ID, states, edition scope and typed recovery remain unchanged.

Resolved implementation scope: accepted interim native frequency guidance.
`NumberOfSIUFInPeriod`/`PeriodInNanoSeconds` encoding, literal types/units and
current dropdown mapping remain deferred. No guessed interval/QWord/truncation,
Rules reset, all-user writes, task/app/service mutation or profile was added.
Current GUI/managed/prompt and paired lifecycle evidence remain pending; no
legacy outcome closed, retired or excluded. No user settings or accounts accessed.

Focused local-link/line-ending/whitespace checks passed; documentation-only work
does not require mirrored tests. All five ranges reviewed unchanged: settings
38-58; packages/artifacts 58-73; components 20-25; accounts/configuration/files
25-35; maintenance 8-12; rounded total 150-205/about 180. The native handoff
does not prove the retained paired legacy feature. Packages remain paused and
disposable VM authorization retains verified Github cache acceptance plus
explicit backoff/idle controllers and no competing queued work.

## Non-VM settings continuation review, 2026-10-13

Continued settings work one outcome at a time without a VM submission, package
acquisition or anonymous GitHub request. Local maximum password age now has a
focused pending SAM backend, finite completion and bounded exact raw field
recovery (54 focused mocked/catalog checks per Windows PowerShell edition).
Independent accepted native handoffs were implemented for Windows Update
interruptions, BitLocker backup/retrieval, recovery readiness, Network discovery,
Storage Sense cleanup choices, System protection and Feedback frequency.
Each run above records its implementation, remaining evidence and estimates.

Power Options access review found its native handoff already present, so no new
legacy resolution was counted. Clarified the fully qualified Windows-native
Control Panel command and linked its official canonical-launch references.
No generic shortcut handler exists to reuse; desktop-menu deployment still needs
bounded physical registry/file scope, ownership/capture/recovery and intended-user
GUI evidence. Direct quick selection, existing plan selection and owned creation
remain separate. No Power Options panel or command was executed during review.

Reviewed the remaining settings decisions. Existing deferred boundaries remain:
App-V policy/preference consumer; feedback pair encoding; localized WinRE/native
association recovery; system-protection inspection/coupling/history; proxy flags
and refresh; current Explorer/taskbar/NumLock/menu/mirror mappings; complexity and
IE ESC; Core Audio endpoint/session scope; and secure BitLocker lifecycle/input/
output/protector ownership. Do not turn unverified mappings into executable
states or claim feature acceptance from mocked tests or the new native guides.
No new exclusions/retirements and no whole retained legacy outcome closes.

Compact dependency snapshot and local bridge records were cross-checked. Latest
request `21b380695758461ebe090c34f537a595` remains Full acceptance failed on quota
zero; Pester/hash/collector/checkpoint success alone is insufficient. The latest
dependency turn ended with model-capacity failure and no verified acceptance.
Local loop has CurrentRequest null, backoff through 2026-10-13T08:43:44Z and
scheduled next 10:50 Copenhagen; the status file still contains its earlier active
request line, so those local records are not independently verified controller
idle evidence. Readiness remains false; no VM/controller, publisher or GitHub
endpoint was queried. This chat's conditional heartbeat remains active; no other
chat was messaged, interrupted, rescheduled or taken over.

All five ranges reviewed unchanged: settings 38-58; packages/artifacts 58-73;
components 20-25; accounts/configuration/files 25-35; maintenance 8-12. Rounded
total stays 150-205/about 180 because these are partial implementation/guidance
and deferral reviews, not closed legacy feature outcomes. Concurrent code and
documentation changes were preserved; topic links follow the new documentation
model. Final focused validation is recorded below.

Final continuation validation: Windows PowerShell 5.1 and PowerShell 7.6.5
parser/catalog/profile/generated-documentation checks passed, each checking
318 operations, 3 groups, 5 profiles and 121 PowerShell files. Focused guide
local links, LF and own-change whitespace checks passed. No VM or package run.

## Settings validation gate deferral at 08:49 UTC, 2026-10-13

At 2026-10-13T08:49:48.864Z, compact dependency revision 3 shows active turn 01a13470-7991-7860-afee-87779d36afee preparing a Full Windows 11 request. Local release status/loop still describe prior request 21b380695758461ebe090c34f537a595 and quota-failed acceptance. The loop has CurrentRequest null, but active dependency work is competing work; preflight quota58 and pre-submission idle claims are not verified completed acceptance or explicit yield. No controller inspection, GitHub/publisher request, VM submission, package acquisition or Windows state change was made. Conditional heartbeat remains active; dependency schedule/chat untouched. No legacy outcomes resolved, retired or newly excluded; all implemented settings retain partial/deferred acceptance. All five ranges reviewed unchanged: settings 38-58; packages/artifacts 58-73; components 20-25; accounts/configuration/files 25-35; maintenance 8-12; rounded total 150-205/about 180. No acceptance evidence arrived to justify a count reduction. Focused documentation whitespace review passed; no tests were needed for this deferral record.

## Settings validation gate deferral at 09:04 UTC, 2026-10-13

Read-only dependency revision 4 at 2026-10-13T09:04:49.112Z reports guest still running. Both local bridge records identify active Full request 2ceab6f49e6d408d86f713fc5ba4b28b; prior quota-failed result remains insufficient acceptance. No VM submission, publisher/GitHub request, package acquisition, native change or dependency interference. Heartbeat remains active; shared controllers are not independently queried while competing work exists. No legacy outcome resolved/retired/excluded; all pending implementation and acceptance retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; rounded total 150-205/about 180. No new acceptance evidence justifies reduction. Focused documentation whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 09:19 UTC, 2026-10-13

Read-only wake at 2026-10-13T09:19:49.292Z: dependency guest remains active; local release status and quota loop agree on competing request 2ceab6f49e6d408d86f713fc5ba4b28b. No completed acceptance or explicit yield. No GitHub/publisher request, VM submission, package acquisition, native change or dependency interference; conditional heartbeat remains active. No legacy outcome resolved/retired/excluded; existing partial/deferred scope retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; rounded total 150-205/about 180. No new acceptance evidence supports reduction. Focused whitespace checks passed; no tests for this status-only deferral.

## Settings validation gate deferral at 09:34 UTC, 2026-10-13

At 2026-10-13T09:34:49.549Z, compact dependency revision 6 explicitly reports Full Windows 11 request 2ceab6f49e6d408d86f713fc5ba4b28b Passed: validation/Pester1280,217 source hashes, real publisher/cache/digest observations and cleanup/UAC/idle. Local loop agrees and clears CurrentRequest; release status tail still has the earlier active line. This satisfies an observed verified VM result, but dependency remains active and explicitly plans Windows11 second pass then two Server2025 passes (recorded counts1/2 and0/2). No explicit backoff/yield; reported idle alone is not authorization. No controller inspection, VM submission, GitHub/publisher request, package/native change or dependency interference. Heartbeat stays active. No legacy outcome resolved/retired/excluded; pending settings evidence retained. All five ranges reviewed unchanged: settings38-58, packages/artifacts58-73, components20-25, accounts/configuration/files25-35, maintenance8-12; total 150-205, about 180. Dependency acceptance excludes current uncommitted migration source and closes no settings outcome. Focused whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 09:49 UTC, 2026-10-13

Read-only dependency revision 7 at 2026-10-13T09:49:49.810Z announces second Full Windows 11 submission in active turn 01a134a9-b599-7e60-aab8-668e062b24fb. Local bridge records retain first accepted request 2ceab6f49e6d408d86f713fc5ba4b28b (Windows 11 1/2, Server 0/2) and cleared prior request; fresh preflight/idle checks are pre-submission, not yield. Deadline recorded as 09:43:53Z; elapsed deadline is not authorization. No controller query, settings VM submission, GitHub/publisher request, package/native change or dependency interference. Heartbeat remains active. No legacy resolution/retirement/exclusion; partial/deferred evidence retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Dependency result tests frozen source, so no migration closure. Focused whitespace checks passed; no tests for this status-only deferral.

## Settings validation gate deferral at 10:04 UTC, 2026-10-13

Read-only dependency revision 8 at 2026-10-13T10:04:49.981Z and both local records agree second Full Windows 11 request dbfd74b1bfca4e0a91c4f6b088f2ee23 remains active. Prior accepted result retained; current guest/controller completion and explicit yield absent. Loop next wake12:47 Copenhagen, preflight reset10:44:06Z; neither timing nor quota implies readiness. No controller query, VM submission, GitHub/publisher request, package acquisition, native change or dependency interference; heartbeat active. No legacy outcome resolved/retired/excluded, partial/deferred evidence retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. No settings acceptance or count reduction. Focused whitespace checks passed; no tests for this status-only deferral.

## Settings validation gate deferral at 10:19 UTC, 2026-10-13

Read-only wake at 2026-10-13T10:19:50.228Z: dependency revision 9 and both local bridge records agree second Full request dbfd74b1bfca4e0a91c4f6b088f2ee23 remains active. Final integration/cleanup and explicit yield absent; prior first accepted result retained. No VM/controller query, GitHub/publisher request, package/native change or dependency interference. Heartbeat active. No legacy resolution/retirement/exclusion; partial/deferred acceptance retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. No settings acceptance supports count reduction. Focused whitespace check passed; no tests for this status-only record.

## Settings validation gate deferral at 10:34 UTC, 2026-10-13

At 2026-10-13T10:34:50.401Z, dependency revision 10 is idle and explicitly reports second Full Windows 11 Passed with 1,280 tests, 217 hashes, cache/digest and cleanup evidence. Both local bridge records agree Windows 11 2/2, Server 0/2; postflight10:26 reports VMs Off, tasks Ready, queues empty, locks available and no blocks. Deadline10:44:07UTC remains future; same dependency automation schedules competing Server Full at12:47Copenhagen, with two Server passes pending. No current controller query or durable resource yield is established for this settings run. Preserve deadline and dependency planned work; settings VM not submitted. No GitHub/publisher request, package/native change or dependency interference; heartbeat remains active. No legacy outcome resolved/retired/excluded; all five ranges reviewed unchanged: settings38-58, packages/artifacts58-73, components20-25, accounts/configuration/files25-35, maintenance8-12; total 150-205, about 180. Verified frozen-source dependency tests do not cover current uncommitted settings changes or justify migration closure. Focused whitespace checks passed; no tests for this deferral record.

## Optional GitHub authentication scope review, 2026-10-13

Approved optional PAT-based GitHub authentication as high-priority v3 acquisition/development reliability work and raised it in the active TODO. Protected credential references, explicit opt-in, trusted destinations, context separation, cache/backoff, reporting and explicit guest credential handling are recorded above. Host authentication alone does not change a guest's anonymous quota. Reusable-module extraction stays deferred downstream. No credentials configured, implementation, package acquisition, VM submission or schedule/controller change occurred in this planning review. Existing pauses and validation gates are preserved.

No legacy outcome resolved, retired or excluded; partial/deferred migration acceptance retained. All five ranges reviewed unchanged: settings 38-58; packages/artifacts 58-73; components 20-25; accounts/configuration/files 25-35; maintenance 8-12; rounded total 150-205/about 180. The newly approved authentication work is separately tracked infrastructure rather than an extra legacy outcome, so it does not alter that burndown count. Focused document/link/whitespace checks passed; no runtime tests for this planning-only change.

## Settings validation gate deferral at 10:49 UTC, 2026-10-13

Wake2026-10-13T10:49:50.616Z: compact dependency revision11 initially returned an idle advisory turn; one relevant recent read then showed active heartbeat turn01a134e2-7c5a-7143-b132-da492add56cb preparing a Server2025 Full request. Both local records still retain Windows11 2/2, Server0/2 and prior cleared request. An elapsed deadline or prior postflight idle cannot establish current shared-resource yield while the dependency prepares competing work. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference; conditional heartbeat active. No legacy outcomes resolved/retired/excluded; partial/deferred evidence retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Frozen-source bridge results do not cover current settings changes or justify count reduction. Focused whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 11:04 UTC, 2026-10-13

Read-only wake2026-10-13T11:04:50.824Z: dependency revision12 and both local records agree first Server2025 Full request9f3c92ba97da41d4b88de8c86e380ab4 is active. Windows11 verified2/2 retained; current Server integration/controller/recovery outcome pending. Pre-submission idle is not current yield. Next recorded dependency wake13:47Copenhagen; no readiness inferred from timing/quota. No controller query, settings VM submission, GitHub/publisher request, package/native action or dependency interference; heartbeat active. No legacy resolution/retirement/exclusion; partial/deferred evidence retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. No current migration acceptance supports reduction. Focused whitespace checks passed; no tests for this status-only deferral.

## Settings validation gate deferral at 11:19 UTC, 2026-10-13

Read-only wake2026-10-13T11:19:51.057Z: dependency revision13 explicitly reports first Server Full request9f3c92ba97da41d4b88de8c86e380ab4 Passed with1,280tests,217hashes, applicable integration, publisher digests, evidence/recovery/UAC and reported idle. Both local records agree Windows11 2/2, Server1/2, CurrentRequestnull; postflight11:07 records queuesempty/locksavailable/noblocks. Backoffdeadline11:44:22UTC remains future and final competing Server Full is scheduled13:47Copenhagen; no current independent idle/no competing work or settings resource handoff. No settings VM/controller query, GitHub/publisher request, package/native change or dependency interference; heartbeat active. Staged concurrent ledger changes preserved without index modification. No legacy resolution/retirement/exclusion; all five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Frozen-source acceptance excludes current settings changes and closes no migration outcome. Focused whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 11:34 UTC, 2026-10-13

Read-only wake2026-10-13T11:34:51.241Z: compact dependency revision13 unchanged and both local bridge records retain prior verified Windows11 2/2, Server1/2, CurrentRequestnull and prior postflight idle. Backoff deadline11:44:22UTC and final scheduled ServerFull13:47Copenhagen remain; no new current resource handoff evidence. No VM/controller query, GitHub/publisher request, package/native change or dependency interference; heartbeat active and staged concurrent changes preserved without index modification. No legacy resolution/retirement/exclusion; partial/deferred acceptance retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. No new settings acceptance supports reduction. Focused whitespace checks passed; no tests for unchanged-status deferral.

## Settings validation gate deferral at 11:49 UTC, 2026-10-13

Read-only wake2026-10-13T11:49:51.456Z: dependency revision14 and both local records agree second ServerFull420c567aea0b44118862ecfcf1de35a5 is active. Prior accepted pairs/progress retained; no final current integration/recovery result or yield. Pre-submission idle/hashes/pins are not current idle evidence. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference; heartbeat active and staged concurrent work preserved without index change. No legacy resolution/retirement/exclusion; partial/deferred settings acceptance retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. No current migration evidence supports closure/count reduction. Focused whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 12:04 UTC, 2026-10-13

Read-only wake2026-10-13T12:04:51.682Z: dependency revision15 reports guest command in progress, no controller errors, final evidence export not begun. Both local bridge records retain active request420c567aea0b44118862ecfcf1de35a5 and prior Windows11 2/2, Server1/2 acceptance. No final current result/recovery or yield. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference; conditional heartbeat active and concurrent staging preserved. No legacy resolution/retirement/exclusion; partial/deferred settings scope retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. No new settings acceptance supports count reduction. Focused whitespace checks passed; no tests for status-only deferral.

## Settings validation gate deferral at 12:19 UTC, 2026-10-13

Wake2026-10-13T12:19:51.947Z: compact revision16 and both local bridge records confirm second Server420c567aea0b44118862ecfcf1de35a5 passed, complete pairs2/2 on each target, evidence/export/cleanup/UAC and reported postflight idle. Bridge Activefalse, CurrentRequestnull, NextScheduledLocalnull; local release record explicitly yields resources, retaining publisher deadline12:44:36UTC. A relevant recent read confirms new user-authorized dependency turn01a13534-63ae-7c52-8b09-0dfc5a9ef41a plans newer-controller unit validation, protected refresh and VM acceptance. This competing work prevents relying on the earlier resource yield as current unrestricted availability. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference. Re-read current repository/script instructions, migration ledger and settings runner structure locally; discovered focused selector routing needs preparation rather than a broad Full/default-profile run. No controller/fixture changes made while the other owner validates/refreshes it. Conditional settings heartbeat remains active; bridge schedule untouched. No legacy resolution/retirement/exclusion or support expansion; all five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Frozen-source bridge acceptance excludes current migration source; no legacy count reduction. Focused whitespace checks passed; no tests for this deferral review.

## Settings validation gate deferral at 12:34 UTC, 2026-10-13

Read-only wake2026-10-13T12:34:52.149Z: dependency revision17 remains active, reports controller unit checks passed (109 on5.1,107 on7 with two expected skips), and prepares reviewed0.4.6 refresh plus live acceptance. Local bridge records retain completed frozen-source pairs2/2 per target, inactive loop/prior resource yield and deadline12:44:36UTC. Pre-refresh reported VM idle does not establish no competing controller work or acceptance of the new installed version. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference; heartbeat active and concurrent work preserved. No legacy resolution/retirement/exclusion; pending settings feature/target evidence retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Controller unit progress closes no settings outcome. Focused whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 12:49 UTC, 2026-10-13

Read-only wake2026-10-13T12:49:52.370Z: dependency revision18 reports Server command active; release status records protected0.4.6 refresh completed then live request20186578684e4716a1f633a99393fe9d active, with normal/focusedfailure acceptance still pending. Quota loop retains completed inactive bridge pairs on its recorded earlier baseline and is not current controller-availability evidence. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference; no use of now-unverified current installed controller for migration acceptance. Conditional heartbeat active. No legacy resolution/retirement/exclusion; all five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Frozen-source controller checks exclude current migration changes and close no settings outcome. Focused whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 13:04 UTC, 2026-10-13

Read-only wake2026-10-13T13:04:52.593Z: dependency revision19 explicitly retains pending Server20186578684e4716a1f633a99393fe9d result/evidence/newformat/recovery. Release status agrees active controller acceptance; completed inactive quota loop is earlier bridge evidence, not current VM availability. No controller query, settings VM submission, GitHub/publisher request, package/native change or dependency interference; heartbeat active. No legacy resolution/retirement/exclusion, partial/deferred evidence retained. All five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Pending controller result supplies no current migration acceptance/count reduction. Focused whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 13:19 UTC, 2026-10-13

Read-only wake2026-10-13T13:19:52.825Z: dependency revision20 reports Server tests/export/recovery passed; release status records Server20186578684e4716a1f633a99393fe9d accepted with217hashes/1,280tests/newresultformat/idle, then Windows11normal3c0a98c38c5b42b5991f9a5f8f150e0d active on installed0.4.6. Current Windows11 result and further timeout/failure checks pending; prior bridge yield is not current no-competing-work evidence. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference; heartbeat active. No legacy resolution/retirement/exclusion; all five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Frozen-source controller acceptance covers no current setting migration/GUI outcome or count reduction. Focused whitespace checks passed; no tests for this deferral record.

## Settings validation gate deferral at 13:34 UTC, 2026-10-13

Read-only wake2026-10-13T13:34:53.083Z: dependency revision21 reports Windows11 normal result passed/auditing; release status records both normal0.4.6 runs accepted with hashes/export/cleanup and then active deliberate Server timeout e9dbd5a238914edea6915bb6de7eeea7. Its expectedTimedOut/clientexit1 is a separate controller fault scenario, not failure of the completed bridge gate. Final bounded collection, checkpoint recovery and idle must verify before resource use. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference; heartbeat active. No legacy resolution/retirement/exclusion; all five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Controller control-flow acceptance covers no migration feature or count reduction. Focused whitespace checks passed; no tests for deferral record.

## Settings validation gate deferral at 13:49 UTC, 2026-10-13

Read-only wake2026-10-13T13:49:53.332Z: dependency revision22 reports both timeout cases passed with process termination/bounded collection/declared omissions and recovery. Release status then records active refusal probes holding both worker locks, using in-memory configurations/isolated results with no real checkpoint/config/queue changes. VMs Off does not establish controller availability while locks are held. No settings controller query, VM submission, GitHub/publisher request, package/native change or dependency interference; heartbeat active. Completed bridge pair evidence remains distinct from controller fault acceptance and settings feature acceptance. No legacy resolution/retirement/exclusion; all five ranges reviewed unchanged: settings 38-58, packages/artifacts 58-73, components 20-25, accounts/configuration/files 25-35, maintenance 8-12; total 150-205/about 180. Controller progress closes no settings outcome/count. Focused whitespace checks passed; no tests for deferral record.

## Focused settings fixture preparation, 2026-10-13

The dependency bridge passed both consecutive target pairs and explicitly yielded resources; current0.4.6 normal/timeout/refusal checks completed. Independent read-only Hyper-V checks required sandbox escalation after ordinary CIM access failed; escalated checks14:11:56-14:11:59UTC confirmed both VMsOff/tasksReady/empty queues/no blocks/matching pinned checkpoints/available worker locks. All five installed files on each controller match registration and current reviewed source. No extra VM confirmation requested; conditional authorization is now applicable. No GitHub/publisher request or package acquisition.

Implemented modules/RIDE.SettingsFixtureData.psm1, tests/SettingsFixtureData.Tests.ps1, tests/integration/Invoke-RideSettingsFixture.ps1 and guest runner0.7.0. Explicit data binds one operation/states/target to one request ID and named settings-only suite; package/Full/application, wrong-ID, unapproved candidate and unknown-state selections are refused. Live native calls use a fresh process after Pester to avoid mock native-type leakage. Candidate support changes are restricted to a guest-private catalog copy and recorded original/fixture hashes; published targets unchanged. Engine capture/repeat/preview/baseline/restore stay primary; actual feature/GUI/boot and deliberate native failures remain pending.

Both native5.1/7.6.5 passed 162 focused checks, one WindowsIntegration excluded; validation passed318 operations/3 groups/5 profiles/124 scripts. Focused diff/whitespace reviewed. The first correlated Local-source fixture will select only windows.wap-push-service and include current uncommitted framework and migration source in the hashed snapshot, never the old frozen CI revision. No state-changing test ran on the developer workstation. No legacy outcome closed/retired/excluded; all five ranges reviewed unchanged: settings38-58, packages/artifacts58-73, components20-25, accounts/configuration/files25-35, maintenance8-12; total 150-205, about 180. Fixture preparation and mocked tests are not feature acceptance. Conditional heartbeat remains active through validation work; dependency untouched.

## WAP Push focused fixture baseline repair, 2026-10-13

Local-source request ee270da2819b48b78683aa09147a23be on disposable Windows11 build26300 used commitf5e32180faf96508c35534ba46677bc78d0fe889 plus uncommitted fixture implementation. All270 source snapshot hashes match the preflight copy. Guest validation and162 focused tests passed, one WindowsIntegration excluded. WAP allseven states/repeat apply and startup-only runtime preservation passed; captured recovery exactly returned Manual/stopped, DelayedAutoStart DWORD1/key-present and SCMtrue. Overall request Failed because fixture0.1.0 attempted unsupported Baseline alias for this service kind, before restore-preview coverage. No handler defect claimed. Fixture0.1.1 now uses explicit BaselineState; retry follows fresh readiness checks. Final collection/cleanup and guest state export errors null, omissions empty; checkpoint recovery succeeded. Dated evidence archived at docs/archive/evidence/settings-wap-first-fixture-2026-10-13.md with active ledger pointer. No GitHub/publisher request, package acquisition or developer-machine state-changing test. No legacy outcome closed/retired/excluded; GUI/boot/workload/default/managed and deliberate native partial-failure evidence pending. All five ranges reviewed unchanged: settings38-58, packages/artifacts58-73, components20-25, accounts/configuration/files25-35, maintenance8-12; total 150-205, about 180. Failed fixture completion does not justify count reduction. Focused parser/diff checks passed after the one-line fixture repair; conditional heartbeat active.

## WAP Push focused lifecycle validation, 2026-10-13

Corrected Local-source request807cb015f98047548c59941bc5da3460 Passed, using00e820f876f6c00f70750c732b3057f5e82f79bd plus uncommitted fixture code. All273 retained/preflight hashes matched. Windows11 build26300/WinPS5.1.26100.9444 validation and162 focused Pester checks passed, one WindowsIntegration excluded. Allseven WAP choices/repeat apply, startup-only runtime preservation, apply/restore preview and explicit declared baseline passed. Exact captured recovery returned Manual/stopped, DWORD1/key-present and effectiveSCMtrue. Controller Error/CleanupError/CollectionError and guest StateCollectionError null; normal export/checkpoint recovery clean. Independent postflight bothVMsOff/tasksReady/queuesempty/locksavailable/noblocks/pinnedcheckpoints unchanged. Archive docs/archive/evidence/settings-wap-lifecycle-2026-10-13.md retains scope/hashes and prior failure pointer. No GitHub/package/host-UAC change or developer-machine integration. No new support/Server declaration or legacy closure/retirement/exclusion: GUI/session, boot/workload, defaults/managed and deliberate native partial failures remain pending. All five ranges reviewed unchanged: settings38-58, packages/artifacts58-73, components20-25, accounts/configuration/files25-35, maintenance8-12; total 150-205, about 180 because literal lifecycle is not the complete legacy feature. Conditional heartbeat active; WindowsSearch validation next, one operation at a time.

## Windows Search focused lifecycle validation, 2026-10-13

Request `53357a9252764c0fa543cd594f297de4` passed at 15:14:58 UTC. [Retained evidence](archive/evidence/settings-search-lifecycle-2026-10-13.md) records the current Local source snapshot, 277 matching hashes, 162 focused Pester passes, all seven states, exact Automatic/running/delayed recovery and independent idle/checkpoint verification. The implemented legacy service selector remains partial pending feature, GUI/session, boot/workload, managed/default and deliberately induced native failure evidence. No resolved/retired/excluded whole outcome or target expansion; package pause and other deferred outcomes remain. All five rounded ranges and total remain unchanged because this adds lifecycle evidence without closing a legacy feature.

## Keyboard repeat delay Windows 11 lifecycle passed, 2026-10-13

Request `2771dbd781814f6db578520e5796dd51`: passed. [Evidence](archive/evidence/settings-keyboard-repeat-delay-win11-2771dbd7-2026-10-13.md) retains 280 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller: ; cleanup: ; collection: ; guest: ; fixture: ; recovery: . No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Update-notification policy Windows 11 lifecycle passed, 2026-10-13

Request `8ca9c85022ee40c8bda98b1850297c6e`: passed. [Evidence](archive/evidence/settings-update-notification-display-policy-win11-8ca9c850-2026-10-13.md) retains 282 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## CEIP policy controlled-failure attempt Windows 11 lifecycle failed or incomplete, 2026-10-13

Request `85e70971f142431bac40fc8d250caf4d`: failed or incomplete. [Evidence](archive/evidence/settings-ceip-participation-policy-win11-85e70971-2026-10-13.md) retains 283 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Controlled native-write interruption did not trigger.. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## GitHub PAT source implementation, 2026-10-13

Implemented the approved host and guest authentication stages: explicit secure enrollment with account-bound DPAPI and restricted ACLs; authenticated public-only discovery through a bounded, redirect-free HttpClient boundary; explicit CLI/engine propagation through download, install, apply and restore; revision/identity cache separation and shared-account backoff; additive AuthenticationMode provenance; versioned controller capability and dedicated run-bound guest delivery; focused acquisition/failure/timeout scenarios; cleanup/recovery verification and a scanned, hash-correlated evidence export gate. Controller refresh preserves existing resource, account, source and ISO pins. See the [operating guide](github-release-discovery.md#explicit-pat-enrollment-and-selection).

The final isolated source candidate is retained locally at `.local/github-authentication-candidate-20261013-2b6d9963/ride-windows`, with 283 matching hashes and all seven proposed installed-controller file hashes beside it in `source-files.json`, `candidate.json` and `verification.json`. The active `settings-validation.fixture.psd1` is omitted only from that copy. The original fixture, concurrent settings changes and guest-runner additions remain intact. The candidate has not replaced any approved source-path pin or installed controller.

Native Windows validation passed 318 operations, three groups, five profiles and 130 PowerShell files in both PowerShell editions. Independent parsing and hash verification also passed for the isolated candidate (130 scripts, zero parser errors). Its final focused Pester run passed 247 tests on Windows PowerShell 5.1.26100.9549; PowerShell 7.6.5 passed 245 with two expected Windows PowerShell-only host-preflight skips. The broader PowerShell 7 run passed 1,536 tests with two expected skips and one WindowsIntegration exclusion. The broader Windows PowerShell 5.1 run passed 1,538 tests with one WindowsIntegration exclusion and no failures. Final enrollment-quota and protected-host-runner corrections then passed all 75 authentication boundary tests in both editions; the candidate was refreshed with those exact tested files. Tests used synthetic credentials, mocked HTTP/controller/installer operations and isolated TestDrive state; no actual publisher traffic or workstation integration changes. Final focused tests cover changes added during the broader regression run, including null-DACL rejection, rejection-driven shared-cache invalidation, controller pin preservation and retained snapshot/sidecar scanning.

The user confirmed no dedicated enrollment exists and explicitly left live PAT acceptance pending. Remaining acceptance: enroll a short-lived VmTest credential under the registered account; review/refresh the protected controller while idle; stage the reviewed candidate at an already approved source path; run focused anonymous/PAT discovery, publisher-digest download, cross-account DPAPI refusal, deliberate post-delivery failure and timeout on Windows 11 and Server 2025; retain verified absence, bounded collection, checkpoint recovery, idle state and safe export evidence. Hosted final-source Windows CI is also pending publication of the reviewed changes. No real credential was enrolled or read, no installed controller refreshed, no VM request submitted and no branch published by this implementation turn. Broad PAT Full runs, controller/default-branch certification and reusable-module extraction remain separate gates.

No legacy outcome was resolved, retired or excluded by this infrastructure work; partial and deferred feature acceptance remains. All five ranges were reviewed unchanged: settings 38-58; packages/artifacts 58-73; components 20-25; accounts/configuration/files 25-35; maintenance 8-12; rounded total 150-205/about 180. Package pauses remain in force. Authentication adds acquisition infrastructure and does not reduce the legacy outcome count.

## CEIP policy Windows 11 lifecycle failed or incomplete, 2026-10-13

Request `aa2bcd713bc74c1f8bdad36d134c7e92`: failed or incomplete. [Evidence](archive/evidence/settings-ceip-participation-policy-win11-aa2bcd71-2026-10-13.md) retains 284 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## CEIP policy source-reconciled Windows 11 lifecycle passed, 2026-10-13

Request `aa2bcd713bc74c1f8bdad36d134c7e92`: passed. [Evidence](archive/evidence/settings-ceip-participation-policy-win11-aa2bcd71-2026-10-13.md) retains 284 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Firewall enable-all seed-recovery attempt Windows 11 lifecycle failed or incomplete, 2026-10-13

Request `ffca76b53da744bfbe200daaeaec271f`: failed or incomplete. [Evidence](archive/evidence/settings-firewall-all-profiles-win11-ffca76b5-2026-10-13.md) retains 285 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: The term 'Restore-RideFirewallProfileState' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Firewall enable-all Windows 11 lifecycle failed or incomplete, 2026-10-13

Request `fd277d27cf694ad7a764005e804e37fd`: failed or incomplete. [Evidence](archive/evidence/settings-firewall-all-profiles-win11-fd277d27-2026-10-13.md) retains 286 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Firewall enable-all source-reconciled Windows 11 lifecycle passed, 2026-10-13

Request `fd277d27cf694ad7a764005e804e37fd`: passed. [Evidence](archive/evidence/settings-firewall-all-profiles-win11-fd277d27-2026-10-13.md) retains 286 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Firewall enable-all Windows Server 2025 lifecycle passed, 2026-10-13

Request `a9529e92f9a04790b96ef69e3c33701b`: passed. [Evidence](archive/evidence/settings-firewall-all-profiles-winserver-2025-a9529e92-2026-10-13.md) retains 287 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Public firewall profile Windows 11 lifecycle passed, 2026-10-13

Request `75c16478a8d04d66ad1a4614b49b7698`: passed. [Evidence](archive/evidence/settings-firewall-public-profiles-win11-75c16478-2026-10-13.md) retains 288 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Public firewall profile Windows Server 2025 lifecycle passed, 2026-10-13

Request `c3ab9d4cb70a46059f946983919c70ce`: passed. [Evidence](archive/evidence/settings-firewall-public-profiles-winserver-2025-c3ab9d4c-2026-10-13.md) retains 289 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Domain firewall profile Windows 11 lifecycle passed, 2026-10-13

Request `087701dce1ba484795bf59765e980074`: passed. [Evidence](archive/evidence/settings-firewall-domain-profiles-win11-087701dc-2026-10-13.md) retains 290 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Domain firewall profile Windows Server 2025 lifecycle passed, 2026-10-13

Request `02e343a038694f88bb01294a24c18dcd`: passed. [Evidence](archive/evidence/settings-firewall-domain-profiles-winserver-2025-02e343a0-2026-10-13.md) retains 291 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Private firewall profile Windows 11 lifecycle passed, 2026-10-13

Request `e7e35109260b46aa886b6eb540a6ad35`: passed. [Evidence](archive/evidence/settings-firewall-private-profiles-win11-e7e35109-2026-10-13.md) retains 292 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Private firewall profile Windows Server 2025 lifecycle passed, 2026-10-13

Request `7e3dea5bf4df48c485077c4df9e274c8`: passed. [Evidence](archive/evidence/settings-firewall-private-profiles-winserver-2025-7e3dea5b-2026-10-13.md) retains 293 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned Balanced power plan Windows 11 lifecycle failed or incomplete, 2026-10-13

Request `7a00278ac82a41ef9d47cd2a59186df2`: failed or incomplete. [Evidence](archive/evidence/settings-owned-balanced-power-plan-win11-7a00278a-2026-10-13.md) retains 294 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Owned copy changed or native export is not reproducible; refusing deletion.. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned-plan export diagnostic implemented; VM submission deferred, 2026-10-13

The owned Balanced recovery failure remains unresolved. Fixture 0.6.3 is ready for a current Local snapshot and bounded diagnostic acceptance, but no native export evidence was produced in this run. Approval review rejected both submissions before execution. Both controllers were independently verified Off/Ready with empty queues, available locks, no blocks, matching pinned checkpoints and installed hashes. The dependency explicitly verified Full pairs and yielded; review nevertheless requires direct user authorization. A concrete approval question is pending. No resolved, retired or excluded whole legacy outcome; all prior partial/deferred acceptance remains. All five ranges and rounded total are unchanged because implementation and parser checks do not resolve native comparison or feature acceptance.

## Owned Balanced export diagnostic Windows 11 lifecycle failed or incomplete, 2026-10-13

Request `94297e8f3d5646308f11e786355584bf`: failed or incomplete. [Evidence](archive/evidence/settings-owned-balanced-power-plan-win11-94297e8f-2026-10-13.md) retains 296 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Owned copy changed or native export is not reproducible; refusing deletion.. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Conditional radio policy Windows 11 lifecycle passed, 2026-10-13

Request `9cbb0b2a72e94a9ea14900842e5faac3`: passed. [Evidence](archive/evidence/settings-media-radio-preset-retrieval-policy-win11-9cbb0b2a-2026-10-13.md) retains 297 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Conditional Windows Media DRM policy Windows 11 lifecycle passed, 2026-10-13

Request `aca17a85e3ab46a1bf4664b93cd40c3e`: passed. [Evidence](archive/evidence/settings-media-drm-online-access-policy-win11-aca17a85-2026-10-13.md) retains 298 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Server Manager startup policy Windows Server 2025 lifecycle passed, 2026-10-13

Request `cce2df896ad047a6b71d9df6aa4f8230`: passed. [Evidence](archive/evidence/settings-server-manager-startup-policy-winserver-2025-cce2df89-2026-10-13.md) retains 299 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Shutdown Event Tracker Windows Server 2025 lifecycle passed, 2026-10-13

Request `2479f56603b1464598f23d47ab7a5363`: passed. [Evidence](archive/evidence/settings-shutdown-event-tracker-policy-winserver-2025-2479f566-2026-10-13.md) retains 300 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Local SAM maximum password age Windows Server 2025 lifecycle failed or incomplete, 2026-10-13

Request `acf7c02d919c40208548d1cdf93fa9b7`: failed or incomplete. [Evidence](archive/evidence/settings-local-password-maximum-age-winserver-2025-acf7c02d-2026-10-13.md) retains 301 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Local maximum age or related policy context changed; refusing stale recovery.. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Maximum-age fixture reverse recovery repaired, 2026-10-13

Failed request acf7c02d919c40208548d1cdf93fa9b7 is retained as evidence. Apply/readback/repeat passed for three bounded states; RIDE recovery did not pass because the fixture restored the earliest run across later writes. The expected-post-write refusal is correct. Repaired the fixture to recover the last run first and retain each per-step preview/readback. Added a regression proving out-of-order refusal and exact reverse-chain recovery with mocked native calls; 20 tests passed on PowerShell 5.1 and 7. Published targets, policy setter and stale/context safeguards unchanged. No resolved/retired/excluded outcome, all partial/deferred feature/default/managed evidence retained. All five rounded ranges remain unchanged because runtime retry and actual policy behavior are still pending.

## Local SAM maximum password age Windows Server 2025 lifecycle failed or incomplete, 2026-10-13

Request `4486e991080b404f9cb60f5fb1b8ec10`: failed or incomplete. [Evidence](archive/evidence/settings-local-password-maximum-age-winserver-2025-4486e991-2026-10-13.md) retains 302 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: The term 'Set-RideLocalPasswordAgeState' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Maximum-age fault binding repaired after exact recovery, 2026-10-13

Retained request 4486e991080b404f9cb60f5fb1b8ec10 as incomplete acceptance. NoExpiry/Days90/Days999 and per-step restore preview passed; reverse recovery returned exact original 42-day policy/context. The later controlled-fault probe failed before injection because maximum-age calls route directly from the engine, unlike firewall managed dispatch. Fixture 0.6.5 matches that retained module route; read-only module-path/native-setter discovery and both parser checks passed. Product policy/context guards and support declarations unchanged. Source and checkpoint audits passed with no delta. No resolved/retired/excluded outcome, pending feature/default/managed and native fault acceptance retained, all five ranges unchanged.

## Local SAM maximum password age Windows Server 2025 lifecycle passed, 2026-10-13

Request `9dd8005663cc4a5894c97b6ec04bb047`: passed. [Evidence](archive/evidence/settings-local-password-maximum-age-winserver-2025-9dd80056-2026-10-13.md) retains 303 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Local SAM maximum password age Windows 11 lifecycle passed, 2026-10-13

Request `95845a6e61344116bc5684aae0ec18b7`: passed. [Evidence](archive/evidence/settings-local-password-maximum-age-win11-95845a6e-2026-10-13.md) retains 304 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## WAP Push controlled startup recovery Windows 11 lifecycle passed, 2026-10-13

Request `a7f221f3b078422690a7abd6b2623873`: passed. [Evidence](archive/evidence/settings-wap-push-service-win11-a7f221f3-2026-10-13.md) retains 305 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Search controlled startup recovery Windows 11 lifecycle passed, 2026-10-13

Request `826e79723cf8457d8b0279e5fd355fd9`: passed. [Evidence](archive/evidence/settings-search-indexing-service-win11-826e7972-2026-10-13.md) retains 306 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Keyboard delay controlled write recovery Windows 11 lifecycle passed, 2026-10-13

Request `5195b4e734dc4d9ea37ad8a1dcdb79e5`: passed. [Evidence](archive/evidence/settings-keyboard-repeat-delay-win11-5195b4e7-2026-10-13.md) retains 307 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Update notification controlled paired-write recovery Windows 11 lifecycle passed, 2026-10-13

Request `5803c01cb50543a29982e8d6d9a9dc86`: passed. [Evidence](archive/evidence/settings-update-notification-display-policy-win11-5803c01c-2026-10-13.md) retains 308 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Guarded Windows Audio service Windows Server 2025 lifecycle passed, 2026-10-13

Request `7fe176404e774e75bee47b169b5e7094`: passed. [Evidence](archive/evidence/settings-audio-service-winserver-2025-7fe17640-2026-10-13.md) retains 309 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned logical-export comparison implemented, 2026-10-13

Raw export instability is repaired through documented application-hive data access rather than byte masking. New records retain raw evidence plus a versioned logical configuration digest. Existing version-1 ownership is not silently upgraded or given a fallback. Parser bounds, key/value class/type/raw bytes, UTF-16 names, ordinal ordering, no-follow subkeys and owner/group/DACL are explicit; transport timestamps, SACL, inherited/hardware effects and policy provenance remain outside the comparison. Native read-only parsing of scratch copies preserved original VM artifacts and returned equal f9a7db2de9b914fe7b79d9848a4d4507f843bfef34a0863f5c0868ba19055e74 digests. Both native editions passed 29 mocked tests; validation passed 131 source files. Fixture 0.6.6 checks real owned-copy label drift and restores only its known seed before normal saved-run compensation. Applicable VM creation/repeat/drift/compensation remains pending; source targets unchanged, no legacy resolution/retirement/exclusion. All five ranges unchanged because implementation does not close native/GUI/availability acceptance.

## Guarded Windows Audio service Windows 11 lifecycle passed, 2026-10-13

Request `3134e804661844108b9ed894cde274a2`: passed. [Evidence](archive/evidence/settings-audio-service-win11-3134e804-2026-10-13.md) retains 311 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned Balanced logical-export recovery Windows Server 2025 lifecycle passed, 2026-10-13

Request `365e4b4da29e4fcbb4762463f276ea35`: passed. [Evidence](archive/evidence/settings-owned-balanced-power-plan-winserver-2025-365e4b4d-2026-10-13.md) retains 312 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned Balanced logical-export recovery Windows 11 lifecycle passed, 2026-10-13

Request `cbb7a29d7111435da5b83cb7203f24b8`: passed. [Evidence](archive/evidence/settings-owned-balanced-power-plan-win11-cbb7a29d-2026-10-13.md) retains 313 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned High Performance logical-export recovery Windows Server 2025 lifecycle passed, 2026-10-13

Request `6021fbd5f4254fc1932e6828ee35fdfc`: passed. [Evidence](archive/evidence/settings-owned-high-performance-power-plan-winserver-2025-6021fbd5-2026-10-13.md) retains 314 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned High Performance logical-export recovery Windows 11 lifecycle passed, 2026-10-13

Request `0e7add1b8e1c483fbab35f23a74f808c`: passed. [Evidence](archive/evidence/settings-owned-high-performance-power-plan-win11-0e7add1b-2026-10-13.md) retains 315 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Conditional owned Ultimate Performance Windows Server 2025 lifecycle passed, 2026-10-13

Request `2cd90b3981df499c8f4b499dc9a87117`: passed. [Evidence](archive/evidence/settings-owned-ultimate-performance-power-plan-winserver-2025-2cd90b39-2026-10-13.md) retains 316 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Conditional owned Ultimate Performance Windows 11 lifecycle passed, 2026-10-13

Request `38e4646949c7439ca9f74c1e45e0dc92`: passed. [Evidence](archive/evidence/settings-owned-ultimate-performance-power-plan-win11-38e46469-2026-10-13.md) retains 317 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Explicit owned-plan guard fixtures implemented, 2026-10-13

Schema 2 adds one required finite Scenario field; schema 1 remains the exact seven-key contract. The read-only data module rejects unknown/non-owned guard scenarios and supplies completion enumeration. ActiveRefusal temporarily selects only the newly owned GUID via a separate engine-saved selection run; Server selection support/default fields are guest-private only. SettingDrift changes and reads back one AC sleep setting on the inactive new copy, requiring fingerprint change and retained ownership after refusal. InterruptedCreation wraps the exact retained command, throws after successful native duplication and checks Intent plus no continuation/delete. CheckpointOnly scenarios keep RIDE recovery false; audit records accepted guard evidence independently from lifecycle. Eighteen tests passed per native edition; parser checks passed. No resolved, retired or excluded outcome; native/GUI/default/managed acceptance stays partial, all five ranges unchanged.

## Owned Balanced active-copy refusal Windows Server 2025 ActiveRefusal guard passed, 2026-10-13

Request `4c1579dfc525486a9812979ca8b05a20`: passed. [Evidence](archive/evidence/settings-owned-balanced-power-plan-winserver-2025-4c1579df-2026-10-13.md) retains 318 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned Balanced ActiveRefusal Windows 11 ActiveRefusal guard passed, 2026-10-13

Request `76fbb477b11142288f90531093e6f833`: passed. [Evidence](archive/evidence/settings-owned-balanced-power-plan-win11-76fbb477-2026-10-13.md) retains 319 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned Balanced SettingDrift Windows Server 2025 SettingDrift guard passed, 2026-10-13

Request `8889c7171a8f4a9ebac14a5e456c271b`: passed. [Evidence](archive/evidence/settings-owned-balanced-power-plan-winserver-2025-8889c717-2026-10-13.md) retains 320 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: SettingDrift guard; guard accepted=True; RIDE recovery=False. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned Balanced SettingDrift Windows 11 SettingDrift guard passed, 2026-10-13

Request `75c3d9e2ece44fb9ad98a2a385cade8a`: passed. [Evidence](archive/evidence/settings-owned-balanced-power-plan-win11-75c3d9e2-2026-10-13.md) retains 321 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: SettingDrift guard; guard accepted=True; RIDE recovery=False. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned Balanced InterruptedCreation Windows Server 2025 InterruptedCreation guard failed or incomplete, 2026-10-13

Request `77ef1aa1c89240ddbb7d70e9dc4045f7`: failed or incomplete. [Evidence](archive/evidence/settings-owned-balanced-power-plan-winserver-2025-77ef1aa1-2026-10-13.md) retains 322 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: InterruptedCreation guard; guard accepted=False; RIDE recovery=False. Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: Interrupted creation did not retain the exact captured inactive Intent copy.; recovery: . No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Interrupted ownership capture fixture repaired, 2026-10-13

Failed request 77ef1aa1c89240ddbb7d70e9dc4045f7 remains archived. Native parser checks passed on 5.1 and 7. The fixture identity correction resolves no legacy outcome; interruption acceptance awaits focused retries. Rounded ranges remain unchanged.

## Owned Balanced InterruptedCreation Windows Server 2025 InterruptedCreation guard passed, 2026-10-13

Request `bf89d6e09ab8448e8e5a2e3cf3312bc3`: passed. [Evidence](archive/evidence/settings-owned-balanced-power-plan-winserver-2025-bf89d6e0-2026-10-13.md) retains 323 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: InterruptedCreation guard; guard accepted=True; RIDE recovery=False. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Owned Balanced InterruptedCreation Windows 11 InterruptedCreation guard passed, 2026-10-13

Request `6573f64481da4770b783f33e6d7a04ad`: passed. [Evidence](archive/evidence/settings-owned-balanced-power-plan-win11-6573f644-2026-10-13.md) retains 324 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: InterruptedCreation guard; guard accepted=True; RIDE recovery=False. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Remaining settings analysis and decision plan complete, 2026-10-13

See [remaining settings plan](migrations/remaining-settings-plan.md) for complete 29-row triage, earlier accepted-control acceptance, six verified first-batch IDs, E01-E08 implementation order and D01-D10 questions. Current catalog has 277 setting/control declarations, including 22 explicit presentation records and 15 pending candidates; these are not remaining legacy counts. All estimates remain unchanged because this analysis closes no feature outcome. Interactive elevation and unavailable session/component/physical/security resources are deferred while the user is away; existing unattended disposable tests remain authorized.

## Store app removal policy and v2 evaluation, 2026-10-14

The [joint policy and v2 review](migrations/store-app-removal-review.md) records official references, source/template hashes, literal list crosswalk, scope and recovery limits. A policy candidate is additional implementation scope within already-counted built-in app management; it resolves, retires and excludes no legacy outcome. App-by-app identity, edition/servicing/schema, standalone policy, sign-in, per-user app/data effects and reinstall acceptance remain deferred. No acquisition, VM submission, host mutation or support widening occurred. All five ranges and rounded total remain unchanged; R30/D11 extend the follow-up plan without counting table rows as legacy outcomes.

## Six control presentation batch implemented, 2026-10-14

The [batch evidence](archive/evidence/settings-presentation-batch1-2026-10-14.md) records six additive metadata changes, 122 passing PowerShell 7 tests, one excluded WindowsIntegration test, an initial CIM report-export failure and successful no-export retry, plus deferred PowerShell 5.1 runtime checks. No resolved/retired/excluded legacy outcome; GUI/managed and intended-user acceptance remain open. All five estimates and rounded total unchanged because only presentation was completed. No VM, package acquisition, GitHub publisher request or workstation integration. D01 choice: process handoff for the current signed-in desktop session, with other/no desktop sessions refused.

## Explicit desktop-user handoff implemented with native acceptance deferred, 2026-10-14

D01 current-desktop user-only process handoff implemented in ride.ps1 0.12.0 and RIDE.UserHandoff 0.1.0. [Guide](intended-user-handoff.md) and [evidence](archive/evidence/intended-user-handoff-batch1-2026-10-14.md) retain refusal, user-owned recovery, test retries and native gaps. Windows PowerShell 5.1 first-batch runtime deferral is resolved: 122 presentation/catalog/search tests and validation now passed using README process-only launch. Handoff/CLI tests passed 65/65 on both editions, no skipped. Mocked results do not establish actual Explorer launch, alternate-administrator behavior or mixed-profile ordering/recovery. Current Get-VM readiness failed denied CIM access; elevation and native interactive acceptance deferred per user instruction. Packages, target support and recommended profiles unchanged. All five ranges reviewed unchanged: settings 38-58 / packages 58-73 / components 20-25 / accounts-config-files 25-35 / maintenance 8-12, rounded 150-205, about 180; no whole legacy outcome resolved, retired or excluded. The user selected both separate Store workflows and reconciliation of changed historical app lists as the next batch; concrete app selection remains reviewable.

## Store app inventory and list reconciliation implemented, 2026-10-14

User chose both distinct Store workflows and reconciliation as app populations change. [119-row matrix](migrations/store-app-list-reconciliation.md), [inventory guide](store-app-inventory.md) and [dated evidence](archive/evidence/store-app-inventory-batch-2026-10-14.md) retain exact historical membership, current template PFNs, dependency/protected/utility review and unfamiliar current app handling. RIDE.StoreAppReview0.1.0 and export/compare tools0.1.0 perform no uninstall, registration, provisioning or acquisition. The current Microsoft guide includes XboxGamingOverlay absent from the inspected template; schema/PFN capability remains pending. All rows Unselected/RemovalApproved=false. Sixteen tests passed on each native edition, no failed/skipped; validation passed318ops/3groups/5profiles/137files. No live Appx collection or VM submission. Elevated readiness/native interactive acceptance postponed after denied CIM access. No legacy app retired, excluded or resolved from row count; all5ranges reviewed unchanged at 38-58 / 58-73 / 20-25 / 25-35 / 8-12, total 150-205, about 180. Explicit apps, applicable serviced schema, both executable lifecycle handlers and native acceptance remain next work. Packages paused.

## Store inventory context implemented and native collection refused, 2026-10-14

Request 3dfba9fd4b6f4e61bf24de7e8613777e used current Local source and a retained342-file preflight snapshot, fixture FDC659B975B6106788A18BB9399751AD56020B2DF0778E7BC33111B7EB0F4F20. [Refusal evidence](archive/evidence/store-app-inventory-refusal-2026-10-14.md) retains the stopped-WinRM preflight rejection, no worker seal/guest run, unchanged idle postflight and no service/UAC change. [Inventory collection plan](migrations/store-app-inventory-plan.md) records edition/release/OEM/user provenance, Windows 10 preservation, official lifecycle versus installed/image/policy authority and pending Pro/Home/Education references. Collector/export0.1.1 preserves raw edition/build and incomplete context; old schema1 remains readable. Fixture/data0.8.0/0.5.0 schema3 is identity-bound read-only StoreInventory, no operation/state/app selection; guest runner0.8.2 selects focused checks. Both editions passed20 Store review checks and78 combined fixture/CLI checks; validation318ops/3groups/5profiles/137files. Initial sandbox CIM denial resolved using the existing token outside sandbox, no UAC/elevation; actual host prerequisite is stopped WinRM. No inventory or native acceptance; host elevated preparation postponed. No app retired/excluded or whole legacy outcome resolved; existing schemas, installed controller0.4.6 and support targets preserved. All5ranges reviewed unchanged38-58/58-73/20-25/25-35/8-12,total 150-205, about 180 because implementation/refusal evidence closes no actual app outcome. Packages paused.

## Modern Store app scope accepted and reference collection prepared, 2026-10-14

User approved option3: reset supported v3 scope, preserve historical lists, use representative live references and both explicit workflows. [Current plan](migrations/store-app-inventory-plan.md) removes exhaustive edition/history coverage as an implementation prerequisite. [V2 archive](archive/migrations/store-app-v2-historical-coverage-2026-10-14.md) retains106 removal/102 registration names, original source hash and four reverse gaps; original legacy source unchanged. The blanket bulk removal/re-registration behaviors are retired as v3 implementation requirements, with no individual app declared absent/retired and no whole legacy app outcome closed. Default data reduced to25 inspected template candidates; optional IncludeHistoricalCoverage preserves119-row comparison. Store review0.2.0, provisioning exporter0.1.0, data fixture0.6.0/schema 4, native fixture0.8.1 and guest runner0.8.3 prepare separate user/provisioning evidence. Both native editions pass85 focused checks, zero failed/skipped; validation passes318ops/3groups/5profiles/138files. Mocked checks do not establish native inventory/consumer acceptance. Existing WinRM blocker retained; no new VM request/host service/elevation/controller refresh/acquisition. Reviewed all five ranges unchanged38-58/58-73/20-25/25-35/8-12,rounded150-205/about180: the scope retires universal replay requirements but leaves selected-app implementations and acceptance pending. All apps kept until user inventory review; packages paused.

## Store reference collection awaiting approved host prerequisite, 2026-10-14

Proceed follow-up: native readonly preflight at2026-10-14T07:51:26.8568522Z confirmed both VMs Off, tasks Ready, queues empty, locks available, no recovery blocks and unchanged pins/installed hashes. Dependency thread remains completed and bridge paused/yielded. Actual combined readiness is false: WinRM Stopped/Manual and current Windows token unelevated. User earlier instructed postponing elevation while AFK; a service-only Start WinRM helper is concrete and parsed, SHA256 FADD0A971BF5156E26209715C68B88FAD99C35C9A8C2389E2CDA70F3D2863969, with no startup/listener/firewall changes. UAC authorization requested and remains pending; it was not launched. Both Windows11/Server2025 schema4 data selections validate against their known accepted guest identities without submission. Readiness and prepared selection bytes remain local; source/controller/CI unchanged. No new native inventory, test acceptance, service/elevation/VM action or acquisition. No legacy outcome resolved/retired/excluded; all five ranges reviewed unchanged38-58/58-73/20-25/25-35/8-12,total150-205/about180 because this is a readiness deferral only. All apps kept until review; packages paused.

## Windows 11 Store reference collection, 2026-10-14

Run cdfee696816b4ce480cfce9371832b98 accepted read-only collection, not app-removal or policy acceptance. Guest Windows PowerShell 5.1 passed 155 focused Pester tests, zero failed; one registry WindowsIntegration test intentionally excluded. The configured reference user and online image provisioning have separate JSON/provenance/hashes. Raw registry ProductName reports Windows 10 Enterprise Evaluation while guest CIM reports Windows 11; edition/build are retained without rewriting observations. No fresh baseline, interactive desktop handoff or other edition/user coverage is claimed. No legacy outcome resolved, retired or excluded in this run; selected-app implementation, policy applicability, intended-user session behavior, protection/dependencies and recovery remain deferred or partial. All five ranges and rounded total stay unchanged because inventory evidence closes no removal lifecycle. See [dated collection evidence](archive/evidence/store-app-reference-collection-2026-10-14.md).

## Server Store reference collection and grouped review, 2026-10-14

Server run c1a950c3c611407d845efdf31aea1fb8 passed read-only StoreReferenceInventory with 57 current-user and five online provisioning rows. All 348 current-source snapshot hashes match actual bytes and preflight; the extra file versus Windows 11 is its dated evidence report. Guest validation/Pester/native collection and checkpoint cleanup passed with no error; both controllers idle and unchanged. Separate user and image scopes, account/SID provenance and hashes verified. The [dated evidence](archive/evidence/store-app-reference-collection-2026-10-14.md) and [grouped review](migrations/store-app-inventory-review.md) retain both captures. The review has 110 names including 25 template candidates, all Keep/unapproved. IsPartOfSystem is unavailable on every captured registration and remains null. Actual app protection/dependencies, user choices, interactive desktop handoff, policy capability/sign-in effects and removal/data/reinstall recovery remain partial or deferred. No whole legacy feature resolved, retired or excluded; no support target expanded. All five ranges and total stay unchanged because native collection is not app lifecycle acceptance. Packages paused; no app change, acquisition or GitHub request. Earlier WinRM refusal retained as history; directly authorized host start completed with Manual startup unchanged.

## Store app groups and workflow decisions, 2026-10-14

The [accepted group contract](store-app-groups.md) records the user choices and follow-up adding Media Player/Sound Recorder to multimedia. User uninstall/reinstall compositions and device policy share reviewed identities, with links both ways; they retain distinct actions, scope and recovery. Gaming frameworks/protected/shared components require guard/consumer review, not automatic removal; XboxGamingOverlay policy capability stays pending. Actual install-state selection, intended-user handoff, protection/source proof, partial failure and reinstall/data limits remain implementation/acceptance work. Acquisition-dependent reinstall stays deferred while packages are paused. No whole legacy outcome resolved or retired; codecs/extensions/legacy media and unlisted apps remain excluded from these group compositions, without declaring them globally retired. All five estimate ranges remain unchanged because this is an accepted design, not executable lifecycle acceptance. No app, policy, package, VM or host service action occurred. See [dated decisions](archive/evidence/store-app-group-decisions-2026-10-14.md).

## Store consumer batch 1 candidate implementation, 2026-10-14

StoreApps 0.1.0 and Invoke-RideStoreApps 0.1.0 implement the first accepted group as pending candidates, with four stable app IDs, exact family metadata, an ordered group and user-owned schema-1 Store records. Uninstall reverses order; retained-manifest registration uses owned removal intent/failed/completed records, original source/identity/hash and existing dependencies. No exact app-data/version recovery or automatic downloads/policy changes. Store rows have their own discovery view; profiles and generic package commands refuse routing. Parser/catalog/profile/generated docs validation passed on both native editions: 322 operations, four groups, five profiles, 141 PowerShell files. Initial regression failures exposed a completion path lookup, test module scoping/isolation and catalog test assumptions; corrected and verified, with no Windows mutation. Fixture data 0.7.0/schema 5 and native fixture 0.9.0 prepare StoreAppPreflight; this cannot open target support or accept uninstall/reinstall. No legacy outcome resolved/retired; later groups, protection/full-payload proof, actual user desktop/handoff, app lifecycle/partial native failures, managed policy and acquisition-dependent recovery remain partial/deferred. All five ranges unchanged because implementation is not acceptance. See [batch evidence](archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

## Store batch 2A candidate implementation, 2026-10-14

Accepted group 2A is now declared in the authoritative catalog and exposed by read-only discovery/completion and the guarded tool. Exact families matched the saved current-user reference; per-app type/source/session/policy and consumer guards remain required. Dependency inspection never deletes shared frameworks or protected Xbox Game Callable UI. Game Bar has no invented static policy ID; its separate policy capability stays pending. No whole legacy outcome resolved, retired or excluded; actual app-specific native removal/reinstall and source/desktop/protection acceptance remain partial/deferred. Rounded ranges stay unchanged because these are pending candidates sharing the tested backend, not accepted lifecycle outcomes. See [group guide](store-app-groups.md).

## Store batch 2B candidate implementation, 2026-10-14

Accepted group 2B is now declared in the authoritative catalog and exposed by read-only discovery/completion and the guarded tool. Exact families matched the saved current-user reference; per-app type/source/session/policy and consumer guards remain required. Dependency inspection never deletes shared frameworks or protected Xbox Game Callable UI. Game Bar has no invented static policy ID; its separate policy capability stays pending. No whole legacy outcome resolved, retired or excluded; actual app-specific native removal/reinstall and source/desktop/protection acceptance remain partial/deferred. Rounded ranges stay unchanged because these are pending candidates sharing the tested backend, not accepted lifecycle outcomes. See [group guide](store-app-groups.md).

## Store batch 2C candidate implementation, 2026-10-14

Accepted group 2C is now declared in the authoritative catalog and exposed by read-only discovery/completion and the guarded tool. Exact families matched the saved current-user reference; per-app type/source/session/policy and consumer guards remain required. Dependency inspection never deletes shared frameworks or protected Xbox Game Callable UI. Game Bar has no invented static policy ID; its separate policy capability stays pending. No whole legacy outcome resolved, retired or excluded; actual app-specific native removal/reinstall and source/desktop/protection acceptance remain partial/deferred. Rounded ranges stay unchanged because these are pending candidates sharing the tested backend, not accepted lifecycle outcomes. See [group guide](store-app-groups.md).

## Store batch 3 candidate implementation, 2026-10-14

Accepted group 3 is now declared in the authoritative catalog and exposed by read-only discovery/completion and the guarded tool. Exact families matched the saved current-user reference; per-app type/source/session/policy and consumer guards remain required. Dependency inspection never deletes shared frameworks or protected Xbox Game Callable UI. Game Bar has no invented static policy ID; its separate policy capability stays pending. No whole legacy outcome resolved, retired or excluded; actual app-specific native removal/reinstall and source/desktop/protection acceptance remain partial/deferred. Rounded ranges stay unchanged because these are pending candidates sharing the tested backend, not accepted lifecycle outcomes. See [group guide](store-app-groups.md).

## Store guard acceptance and native evidence follow-up, 2026-10-14

The initial Windows 11 source manifest FA33C7269DEBB6794FD9F6251EBAF1D1248665E9776C927B28843318526FA087 and fixture 56525BF13808F033A09E113B82BB7871D6F0CC377C2AC3E980C97E00CC2DD7D8 are retained with guard-only acceptance. Native evidence shows no desktop, incomplete protection/type, generic enrollment uncertainty and unavailable retained source; no uninstall/reinstall or GUI/management acceptance. The follow-up enriches observation without relaxing unknown system guards. Store certificate category does not establish system protection. The documented MDM API is client-only; Server remains conservative. All 22 app/group declarations match accepted scope and exact captured families, with no shared framework/protected Xbox membership. Native getter changes justify a new current-source diagnostic rather than presenting the older source result as their acceptance. No legacy outcome resolved/retired; actual protection model, intended-user Store handoff, desktop and app/partial-failure/recovery acceptance remain partial or deferred. All five ranges unchanged because guards are not app lifecycle acceptance. See [batch evidence](archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

## Store SDK inspection accepted and desktop handoff implemented, 2026-10-14

Run b581ad67f44b4a87a5fb3a7307f96d6c used current Local source including uncommitted declarations, module 0.1.2, fixture 3315E13A06A116EE3ED017C265B1282F24735ADE1301A9B5FC3F43A5ED26DA4D and source manifest CB1E1CDD6EE00787C3238A0BBE012EB9064F7BCFAF7533F170B394658A9B146E. SDK identity/type observations and client management query worked; missing system-protection flags remain null, not inferred from Store certificates. All actions refused with no Store records. Current desktop unavailable in unattended WinRM; published support remains empty. The later source handoff is covered by mocked tests, not this earlier native snapshot; Server validation follows with current source. Native uninstall/reinstall, partial failure, GUI/session, effective management, source survival and later app-specific acceptance remain deferred/partial. No legacy outcome resolved or retired; all five ranges unchanged because guard/API inspection is not lifecycle acceptance. [Follow-up decisions](migrations/store-app-follow-up-decisions.md) records protection and stub/source choices; [batch evidence](archive/evidence/store-consumer-apps-batch1-2026-10-14.md) retains hashes and limits.

## Server Store guard and absence preflight accepted, 2026-10-14

Run 8de2401ea49c49cfb82b47a1073d1904 completed at 2026-10-14T11:01:04Z using current Local source with uncommitted changes, fixture DAAC889E55A866227F199117DE12B8DB0DC6B2F4782332357B6FEE5E9243BF83 and source manifest 8635BDED9CC26EDB31CC46232655FF339F78E04E8E6284976E84CF76E260AA67. Native absence, target refusal and no-record/no-mutation behavior passed. Unknown Server enrollment source and unavailable WinRM desktop remain explicit refusals. Both VMs Off/tasks Ready, empty queues, available locks, pins/installed hashes/clean CI verified unchanged at 11:03:19Z. This earlier snapshot excludes the newly approved ReviewedIdentityRemovabilityV1 rule. No legacy outcome resolved, retired or excluded; native lifecycle, partial failure, retained-payload, interactive user and policy consumer acceptance remain deferred/partial. All five ranges and rounded total unchanged because absence/refusal evidence closes no app lifecycle. See [Store follow-up tasks](migrations/store-app-follow-up-decisions.md) and [dated evidence](archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

## Reviewed Store protection and source decisions implemented, 2026-10-14

The user approved ReviewedIdentityRemovabilityV1 for the 22 reviewed catalog identities: known NonRemovable=false, complete runtime-verified type/stub evidence and exact identity/family/source/consumer checks, while IsPartOfSystem remains null/Unknown. Known system/protected flags still refuse. The user also chose to wait for usable local reinstall source; stub News/Weather remain blocked and acquisition stays paused. Run 0341ac971c5a4c8ba7a12b15bd51b68e finished 2026-10-14T11:18:23Z on Local source including uncommitted changes, StoreApps 0.3.0/fixture 0.9.1, fixture hash 07FDE2B4B692DEE5E18496D911E97DE5ABF998382509DA8DF60F992DEC4F663C and source manifest FE2399CC69E9D2F8B5843010E29ADF645580F13662FC3C6D64F3FD0CB176A2AF. All 11 registration rows have verified runtime types and explicit Unknown system observations. Clipchamp/Solitaire only retain desktop/target refusals; News/Weather also retain stub/source refusals. All four actions refused without records or mutations; source bytes, identity/XML/checkpoint and final idle/pins/installed hashes/CI verified at 11:20:20Z. The later 0.3.1 repair requires runtime verification even when native fields are populated; it is covered by 31 mocked checks on both editions and PS7 repository validation, not that earlier VM snapshot. Full 174-check host matrix and both-edition parser/catalog validation passed before this last repair; overlapping subsets are not summed. No legacy outcome resolved, retired or excluded; native interactive/partial/recovery/policy/Server evidence remains deferred or partial. All five ranges and rounded total unchanged because guard acceptance does not close an app lifecycle. [Active tasks and answered choices](migrations/store-app-follow-up-decisions.md), [dated evidence](archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

## Read-only Store desktop probe prepared, 2026-10-14

Schema 6 admits exactly seven identity/request/target/scenario keys and refuses action, app selection and target-widening controls. Existing schemas remain unchanged. Probe shell observations do not verify active connection, elevation, actual desktop or handoff completion. [Desktop actor preparation](migrations/store-app-follow-up-decisions.md#desktop-actor-preparation-proposal) records the next isolated resource and deferred sign-in/UAC/credentials. Native request 2f461c696aea46f18a36277740ab14af uses Local source with fixture hash 0344DB41A93958C2A237462F4444200490CF7BF10C44A345E699E90B9E3C4B82 and 356 preflight files; final source, identity, XML, checkpoint and idle/pin audits remain required. All five ranges unchanged because resource observation resolves no legacy app lifecycle. No outcome retired/excluded/resolved; desktop, app recovery/partial behavior and separate policy remain deferred or partial. Catalog/generated descriptions now explicitly distinguish required removability/type/source evidence from visibly unknown IsPartOfSystem.

## Store desktop resource probe accepted, 2026-10-14

Run 2f461c696aea46f18a36277740ab14af finished 2026-10-14T11:40:52Z with fixture 0344DB41A93958C2A237462F4444200490CF7BF10C44A345E699E90B9E3C4B82 and source manifest 7CD8422790EF30FF70072239E0BB9FB74B41ADCE94908F8CBB5A646CE4110235. The actor resource probe observed one expected-SID shell, PID 5768/session 1; actual desktop/token/connection and source-bound worker remain unverified. No session/process/task/app was started by the probe and no Windows configuration changed. Native guest validation and mocked regressions include StoreApps 0.3.1, data 0.8.0 and fixture 0.10.0. Source bytes/preflight/correlation/XML/checkpoint and final both-idle/pins/installed hashes/CI audited at 11:44:11Z. Continue with isolated Plan-only desktop actor before uninstall. No legacy outcome resolved/retired/excluded; desktop, actual app recovery/partial failure, later groups and policy remain partial/deferred. All five ranges stay unchanged because resource availability closes no app lifecycle. See [actor preparation](migrations/store-app-follow-up-decisions.md#desktop-actor-preparation-proposal).

## Isolated Store desktop Plan actor implemented, 2026-10-14

Schema 7 preserves the earlier schemas and admits only an identity-bound declared pending Store group, no action/command/target-widening switches. The test-only worker exercises read-only Plan and Invoke-RideStoreDesktopRequest, preserving source-bound current-session checks; it does not exercise the production shell launcher or alternate administrator and cannot uninstall/reinstall. Task definition ownership, bounded timeout, failure artifact copy and cleanup are explicit. Native request 99adcc9ee9df4f85953f37cf058ca9f7 uses Local source with uncommitted changes, 357 preflight files and fixture CF894B8320728A3F3ECC773264DB3E8B359E01CA2FBF983396FC47446203E5C5. Source is sealed; final actor, task/checkpoint, XML, identity and idle/pin/hash audits remain required. No legacy outcome resolved/retired/excluded; full handoff/alternate-admin, app lifecycle/source recovery/partial failure and policy acceptance remain partial/deferred. All five ranges stay unchanged because implementation is not native acceptance. The [follow-up document](migrations/store-app-follow-up-decisions.md#first-app-lifecycle-fixture-design) prepares Solitaire as the first applicable isolated lifecycle, gated on desktop evidence.

## Native Store desktop actor startup failure and diagnostics repair, 2026-10-14

Run 99adcc9ee9df4f85953f37cf058ca9f7 completed Failed at 2026-10-14T12:03:35Z, with fixture CF894B8320728A3F3ECC773264DB3E8B359E01CA2FBF983396FC47446203E5C5 and source manifest C3F740C9A4D20FD50106FFCF012A22A33234FA2B7AAF4722242D2D7AB53DBACA. Parser/catalog and 204 mocked guest tests passed; real task returned 1 without actor.json. The cause is not established by that exit code. No app changed. Owned task removed, controller collection/cleanup errors empty; source bytes/preflight, final checkpoint and idle/pin/hash/CI audit passed at 12:06:04Z. Failed selection removed only after matching its receipt hash. The diagnostic repair creates a RunId-owned user-local test directory and captures bounded console output including bootstrap/worker startup failures; it preserves partial bytes and validates copied hashes after owned task cleanup. Current 0.11.1/actor 0.1.1 source passes parser/catalog validation; normal policy and production handoff unchanged. Native Plan/full launcher/alternate-admin/removal/recovery remain pending. No legacy outcome resolved/retired/excluded, all five ranges unchanged because a failed native worker grants no acceptance. [Active tasks](migrations/store-app-follow-up-decisions.md) retain this failure and gated Solitaire design.

## Store desktop identity guard refusal isolated, 2026-10-14

Run b2615b9d390447dc906a3a50b490cf78 completed Failed at 2026-10-14T12:15:34Z. Fixture 379319C1F22BF7062E0483A6A29B9EF76041559441CDF839B28E24F9FB6EC908; source manifest 982217E678EB07C627AB0D60F9849FD93023508826761958951E296B91661EB6. Console A9747DA7B24176C41EF503A029589C46D66E3DA6FAED4508B5511F4D70383675 proves actor.ps1 ran and refused its initial owner/session/elevation predicate; this does not identify which term failed. No app queried/changed. Owned task removed, all source hashes verified and final checkpoint/idle/pins/installed hashes/CI audited at 12:19:12Z. Failure audit and console retained before removal of the matching temporary selection. Actor 0.1.2 adds exact observations and read-only EnableLUA/consent/secure-desktop prerequisites to the existing captured console without changing UAC, logon configuration or production guards. Parser/catalog validation passes. Another focused identity diagnostic is authorized; native desktop/full launcher/alternate-admin and app lifecycle remain pending. No legacy outcome resolved/retired/excluded; all five ranges unchanged because guarded refusal grants no acceptance. [Follow-up tasks](migrations/store-app-follow-up-decisions.md) keep the gated Solitaire design.

## Terminal default-profile native guidance implemented, 2026-10-14

[Terminal profile guide](windows-terminal-profile.md) implements the accepted native UI handoff documentation while the Store actor diagnostic runs. It distinguishes defaultProfile (existing profile GUID/name) from the OS default-terminal-host choice and restored window layouts; it selects neither a profile nor a host on the workstation. Prior manual selection and missing-profile recovery remain explicit. E06 file ownership, syntax/comment preservation, conflict recovery and GUI acceptance remain deferred. No supported target or catalog operation is added, and no legacy outcome resolved/retired/excluded by documentation. All five ranges unchanged because guidance is not captured/native feature acceptance; selected playback endpoint guidance and its native endpoint/session backend remain separate. Local links/reference headings reviewed, no VM/package/GitHub request for this independent documentation work.

## Unelevated desktop resource prerequisite identified and deferred, 2026-10-14

Run d62ee7a8b55c4c2aa0b2352147901e87 finished Failed at 2026-10-14T12:27:12Z, fixture C56726427B33E35C007873A9DF83CE1F46F91DD0B3DB686EEFA72B345CBD3614, source manifest 0ED8737500063870F9AF6B44E5972CB2FE0AB0C10A47C4C43CE6DBEC9B48291C and console 484FEA918F831FB53A2B5B4748EFD79F1C5293C95F0ED07B999889A7A5867679. The identity predicate correctly refused an administrative token on the UAC-disabled guest despite a Limited task and correct session. This failure accepts no desktop/worker/full launcher/alternate-admin or app lifecycle. All source bytes/preflight, failure/console correlation, task cleanup and final checkpoint/idle/pins/installed hashes/CI verified at 12:29:53Z; only matching selection removed. No app queried/changed, no UAC or pin change. [Postponed resource decision](migrations/store-app-follow-up-decisions.md#desktop-resource-decision---separate-resource-authorized) requires a genuine unelevated desktop on a separately reviewed fixture resource; honor the user instruction to postpone interactive elevation/credentials while AFK. No legacy outcome resolved/retired/excluded; all five ranges unchanged because this is failed resource acceptance. Preserve actual app source/recovery/GUI/managed and policy evidence as deferred/partial. Continue independent authorized machine-setting boundaries.

## Local maximum-age 1/2/998-day boundaries Windows 11 lifecycle passed, 2026-10-14

Request `d17b3ecf49084aac8fa0bf45ed8eaa0c`: passed. [Evidence](archive/evidence/settings-local-password-maximum-age-win11-d17b3ecf-2026-10-14.md) retains 358 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: lifecycle; guard accepted=False; RIDE recovery=True. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Local maximum-age 1/2/998-day boundaries Windows Server 2025 lifecycle passed, 2026-10-14

Request `8da4114c2f504c5d8adb4b7321482641`: passed. [Evidence](archive/evidence/settings-local-password-maximum-age-winserver-2025-8da4114c-2026-10-14.md) retains 359 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: lifecycle; guard accepted=False; RIDE recovery=True. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Maximum-age boundary follow-up and minimum-age guard implemented, 2026-10-14

The fixed schema-2 MinimumAgeConflict admits only windows.local-password-maximum-age/Days1 with explicit target approval. Test-only level 1003 sets captured-zero minimum to one day; production backend remains level-1002 maximum-only. SAM/unrelated context, preview and refusal state are checked, native maximum setter counted, failed intent restored without a maximum write, and the exact fixture minimum seed separately recovered. Drift refuses replay. LifecyclePassed/ExactRecovery remain false for this guard; ExactFixtureSeed is not successful primary apply. The existing local security/password scope is unchanged; no passwords, domain controllers, UAC, app/package or GitHub work. Current source includes uncommitted changes; request 660dac2bfa0d45f3ac8d6e1f46dcc7eb has 360 preflight files and fixture 9454FD88FDC370A36FCCC1691B124A1D42583F698D88BBC728CDC915C8C47CA6. Native and checkpoint acceptance pending. No legacy outcome resolved/retired/excluded; GUI, managed/default/complexity and unelevated desktop resources remain partial/deferred, all five ranges unchanged. [Fixture contract](../tests/integration/settings-fixtures.md) documents the focused scope; [desktop prerequisite](migrations/store-app-follow-up-decisions.md#desktop-resource-decision---separate-resource-authorized) remains held.

## Local maximum-age conflicting minimum Windows 11 MinimumAgeConflict guard passed, 2026-10-14

Request `660dac2bfa0d45f3ac8d6e1f46dcc7eb`: passed. [Evidence](archive/evidence/settings-local-password-maximum-age-win11-660dac2b-2026-10-14.md) retains 360 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: MinimumAgeConflict guard; guard accepted=True; RIDE recovery=False. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Local maximum-age conflicting minimum Windows Server 2025 MinimumAgeConflict guard passed, 2026-10-14

Request `9921cbfc65c44a718fb1f872213e82f0`: passed. [Evidence](archive/evidence/settings-local-password-maximum-age-winserver-2025-9921cbfc-2026-10-14.md) retains 361 source hashes, the explicit single-operation selection, completed states, capture/recovery and clean postflight. Scope: MinimumAgeConflict guard; guard accepted=True; RIDE recovery=False. Controller, cleanup, collection, guest, fixture and recovery errors were absent. No resolved, retired or excluded whole legacy outcome; partial/deferred scope and package pause remain. All five ranges and total remain unchanged because this run adds bounded lifecycle or refusal evidence without closing feature, GUI/component, defaults/managed or native-failure acceptance.

## Two-target password-age boundary and conflict follow-up accepted, 2026-10-14

Completed follow-up source snapshots include current uncommitted code. Boundary runs: d17b3ecf49084aac8fa0bf45ed8eaa0c (Win11, 358 files, manifest EFB957614927236F75FC3B9AB9C186F166EBB354EAA36E85EB1824CCC9AA3F81) and 8da4114c2f504c5d8adb4b7321482641 (Server, 359 files, CD8E07D1970415711BA38BA6EABA58F9C747BB5EE8A005707DD0DF7A4658B001). Refusal runs: 660dac2bfa0d45f3ac8d6e1f46dcc7eb (Win11, 360 files, BCA0DF413CDF2804F8C24A7DEBB43B7DBA4703E4F7559DCC753A1CC4113054EE) and 9921cbfc65c44a718fb1f872213e82f0 (Server, 361 files, 3C82509E36F2E0417CB6A2634E68AB6EF9A21B3428220EE30F9A610636470EA7). All hashes/preflight entries, correlated guest/XML evidence, native recovery and final both-idle/pins/installed hashes/CI validated. MinimumAgeConflict uses test-only local minimum level 1003, while production maximum setter remains 1002 only; no successful primary apply is inferred from zero-write refusal. Current fixture/data 0.12.0/0.10.0; 178 host mocked checks passed on each edition, one registry case excluded. [Validation handoff](migrations/settings-validation-resume.md#password-age-boundary-and-refusal-follow-up-2026-10-14) links exact scope; [desktop resource follow-up](migrations/store-app-follow-up-decisions.md#desktop-resource-decision---separate-resource-authorized) remains postponed under the AFK elevation instruction. Published support, UAC, pins, profiles and package pause unchanged; no whole legacy outcome resolved/retired/excluded. GUI/default/managed, complexity/file-editor and app lifecycle remain partial/deferred, so all five ranges and rounded total stay unchanged.

## Separate Store desktop and read-only Plan accepted, 2026-10-14

Direct user authorization resolved the AFK resource-preparation hold. Exported the existing Windows 11 clean checkpoint locally, imported a new VM identity with independent disks, removed only its copied disconnected adapter after a dynamic-MAC assignment failure, enabled UAC only in that guest and captured a separate clean pin. Read-only schema-7 Plan verified all 362 original source files plus its isolated selection, actual expected SID/session and unelevated worker/Explorer; owned task cleanup, bounded evidence hashes and separate checkpoint recovery passed. Both original controllers remained Off/Ready/empty with accepted pins and five installed file hashes unchanged. See [dated resource evidence](archive/evidence/store-test-desktop-2026-10-14.md). Resolved the desktop resource prerequisite and read-only worker proof; no legacy outcomes retired or excluded. All Store app lifecycles, full launcher, alternate administrator, policy applicability and additional desktop/edition coverage remain partial or deferred. News and Weather remain source-refused. All five estimate ranges and rounded total remain unchanged because preparation and refusal-safe Plan close no whole legacy feature/product outcome. Apps kept; packages paused.

## Isolated Solitaire lifecycle fixture implementation, 2026-10-14

Added a bounded Solitaire-only request, exact private target-array patch validation, actual unelevated desktop actor and owned transient coordinator task. The private catalog can open only app.solitaire for Windows 11; identity, removability, runtime, consumer, policy and local-source guards remain production code. Native steps cover preview/removal/repeat/source survival/reinstall preview/registration/repeat, extra-record refusal and unchanged unrelated registrations. Current-source manifests retain original and candidate bytes and schema-1 Store records; checkpoint recovery remains separate from best-effort registration. Focused mocked tests passed 36/36 on both native editions using repository-owned temp paths after the command-sandbox temp path was refused; no workstation handler ran. Read-only repository validation passed both editions. No legacy outcome resolved/retired/excluded. Native lifecycle, GUI/app-data, full launcher, alternate administrator, policy and other app/edition acceptance remain partial or deferred, so all five estimates and rounded total remain unchanged. See [fixture contract](../tests/integration/settings-fixtures.md#isolated-solitaire-lifecycle-fixture). Packages paused; no VM submission yet.

## Solitaire first native lifecycle failure and diagnostics, 2026-10-14

First isolated native Solitaire run dfd6c2c94edd4eb09bd6457194f3bb82 used current Local source at e977b814bc0646d2fce3bf305752eab3a6344eb2 including uncommitted fixture code. All 369 original files and 371 isolated guest files matched source hashes; the only catalog change was the Solitaire target array. Uninstall preview, native removal and repeat passed; removal schema-1 record 03da459cd8d24a49a4b503d0adab46c7 completed, and unrelated registrations matched immediately after removal. Immediate reinstall Plan found a local manifest and dependencies, but the next preview refused Source unavailable or changed; no native reinstall or reinstall record followed. Lifecycle/re-registration acceptance failed. Owned task cleanup and separate checkpoint recovery passed; original pins/controllers/CI stayed unchanged. Resolved only focused removal/repeat evidence; no whole legacy outcome resolved, retired or excluded. Source stability and exact cause, native reinstall/repeat, GUI, interruption and other apps remain partial or deferred. Store handler 0.3.2 adds SourceError diagnostics and actor 0.1.1 captures delayed source/partial-state details; guard semantics remain unchanged. All five rounded estimates unchanged because required reinstall acceptance is missing. No next app or acquisition is selected.

## Solitaire diagnostic failure and WhatIf projection repair, 2026-10-14

Diagnostic run 10a640b3ab10400ba06eb99f0aefa3e5 retained current source at 006f5ab8cdd09f32711f2ea55f9a2666aaf52acc including uncommitted 0.3.2 diagnostics and actor 0.1.1. Removal record 27f78e7617d342bc8b6c0127de861411 completed; preview/removal/repeat and immediate/delayed source Plans passed, but reinstall preview was again source-refused. At exit the manifest was present with the original matching SHA256, all five dependencies were registered, and unrelated registrations matched both after removal and at exit. Source loss was not established. Native reproduction on both PowerShell editions demonstrated ForEach-Object PackageFullName emits no dependency values under inherited WhatIf; read-only Select-Object projection replaces it in handler 0.3.3. Guards and schema-1 records unchanged. Child exit code now correctly captured as 1; owned task and separate checkpoint cleanup passed. No native registration attempted and no whole legacy outcome resolved/retired/excluded. Focused regression verification and another same-app native run are warranted by the repaired preview defect; no next app or acquisition is selected. All five ranges and rounded total stay unchanged while reinstall, GUI, faults, full launcher and other target evidence remain partial or deferred.

## Solitaire result and repaired rerun elevation deferral, 2026-10-14

The repaired Solitaire rerun reached Windows elevation but returned The operation was canceled by the user at 14:40:57 UTC; ProcessId is null and no third native run was submitted. The completed native runs remain dfd6c2c94edd4eb09bd6457194f3bb82 and 10a640b3ab10400ba06eb99f0aefa3e5. Both passed preview/removal/repeat, task cleanup and separate checkpoint recovery, with original controller pins and installed hashes unchanged. Diagnostic evidence established a retained matching manifest, five available dependencies and unchanged unrelated registrations; the failure was a suppressed ForEach-Object member projection under WhatIf. Handler 0.3.3 fixes only read-only projection, with 37 focused checks passing on both editions and actual missing dependencies still refused. Native registration/repeat, full lifecycle, interruption, GUI, full launcher, alternate administrator and further apps remain partial or deferred. No whole legacy outcome resolved, retired or excluded. All five estimates and rounded total remain unchanged because required reinstall acceptance is still missing. See [dated validation evidence](archive/evidence/store-solitaire-validation-2026-10-14.md) and [active same-app follow-up](migrations/store-app-follow-up-decisions.md#solitaire-native-validation-follow-up). Original resource postflight Ready; separate VM Off on the unchanged new clean pin with no network adapter. Packages paused; no next app started.

## Solitaire basic native registration lifecycle accepted, 2026-10-14

The resumed Solitaire-only run 3899597cd74e477195a35b280b201308 passed at 14:53:26 UTC using handler 0.3.3 and actor 0.1.1. Current Local snapshot at 006f5ab8cdd09f32711f2ea55f9a2666aaf52acc includes uncommitted repair and migration changes. Original source manifest 07D00667A69D6D32847C46154A00643E2FA5C547EDE7C402FB0EBB17C269F7B1 covers 371 files; private guest manifest E1A9CEDBED38B0222A7684FBF097A530C8A2F0350A42C71B99E82BF4232F94F2 covers 373. Only the private Solitaire target array changed. Preview/removal/repeat/source survival/reinstall preview/native registration/repeat and unchanged unrelated registrations passed. Schema-1 removal record 75a3c361b3de453188c6d7d5110caef1 and reinstall record a67d72606707454c8122b122fb6a0fae both Completed, ExactRecovery=false. Expected session 1 worker/Explorer unelevated; guest child exit 0, bounded evidence hashes and owned task cleanup verified. Separate clean pin recovered Off with no adapter; original VMs/pins/five installed hashes/queues/locks and clean CI unchanged. See [dated evidence](archive/evidence/store-solitaire-validation-2026-10-14.md). Resolved focused basic Solitaire registration lifecycle and the WhatIf projection defect, not app data, GUI, interrupted native operations, full launcher, alternate administrator, other apps or other targets. No whole legacy bundle/product outcome resolves, retires or excludes, so all five ranges and rounded total stay unchanged. Published support closed, packages paused; result is reported before another app.

## Full remaining migration analysis and AFK handoff, 2026-10-14

The [full remaining migration follow-up](migrations/remaining-migrations-follow-up.md) now covers packages/artifacts, concrete component/resource objects, settings, accounts/configuration/assets and maintenance. It retains approved choices, presents B01-B10 matching batches and Q01-Q31 grouped follow-up decisions, and separates user decisions from API/build/consumer research. The [source audit](archive/evidence/remaining-migrations-analysis-2026-10-14.json) records hashes, every unresolved application's individual next gate, 30 settings rows and complete inventory families, including separate requested additions and source-only reconciliation.

Fresh Microsoft documentation identifies build-specific .NET 3.5 feature/installer routing and static/dynamic Store policy schemas; these are new applicability research gates, not accepted support or a broadened removal selection. Stale current settings/Store pointers now acknowledge accepted Solitaire basic registration lifecycle, with GUI/data, interruption, group/policy and full handoff still open. Candidate guidance now acknowledges existing EXE/MSI/portable and guarded ZIP paths without claiming arbitrary format/coexistence support.

Resolved in this run: planning coverage, question consolidation and stale current pointers. Retired/excluded: no new dispositions; earlier Browser/MusNotification/Opera/ISL and external-owner decisions retained. Deferred: package acquisition/implementation, fresh elevation, Clipchamp VM submission, servicing/media and hardware/security/boot evidence. Partial: existing implementation/lifecycle acceptance remains distinct from GUI/consumer/default/managed and exact or compensating recovery. No new target metadata, packages or Windows state changed. No completed fixture rerun.

All five estimate ranges remain settings 38-58, packages/portable/artifacts 58-73, components 20-25, accounts/configuration/files/assets 25-35 and maintenance 8-12; rounded 150-205/about 180. The 79 application and 30 setting rows overlap groups and accepted controls. Selector references, questions, source-only helpers and supplemental additions are not new completed legacy outcomes. Analysis closes zero legacy outcomes, so no rounded adjustment is warranted.

## B01 input and audio presentation, 2026-10-16

The [B01 batch record](migrations/settings-post-migration-review.md#b01-input-and-audio-presentation-review-2026-10-16)
records source `f53ce6ab102a` plus the focused patch, legacy mappings, consumers,
acceptance, recovery and next instructions. Four existing settings now have
explicit presentation: keyboard delay, pointer precision, registered sound scheme
and startup sound. Added selected-device native mute guidance in the existing
audio guide. Coverage is 32/277, with 245 presentation reviews remaining; these
are metadata counts, not legacy outcomes.

Complete catalog comparison passed after excluding only the four new metadata
blocks. Both native PowerShell editions passed 122 mocked tests (zero failures,
one WindowsIntegration test excluded) and validation of 340 operations, eight
groups, five profiles and 146 maintained PowerShell files. Generated reference
is current. No setter, support declaration, saved-state schema or default changed.

Resolved: selected presentation gaps and manual mute guidance. No whole legacy
outcome resolved, retired or excluded. Partial: existing settings retain GUI,
boot/session, managed-policy and hardware acceptance. Deferred: automated endpoint
identity/session/recovery, package work, component/Store elevation and remaining
accounts/assets/maintenance work. No Windows or VM state changed. All five
ranges were reviewed and remain settings 38-58, packages/artifacts 58-73,
components 20-25, accounts/configuration/files 25-35 and maintenance 8-12; rounded
150-205/about 180. Source readiness is not complete feature acceptance, so no
estimate reduction is justified. Next: B02 read-only endpoint identity/capture
contracts and isolated fixtures; preserve D08/Q30 for the future setter decision.

## B02 playback endpoint inventory, 2026-10-16

The [B02 record](migrations/settings-post-migration-review.md#b02-read-only-playback-endpoint-contract-2026-10-16)
documents the new standalone inventory module, export tool and 21 isolated tests.
Opaque render IDs and exact selection replace friendly-name/default guesses;
missing, inactive and unreadable states stay explicit. Expected execution SID and
session are checked before and after capture. Desktop identity remains unverified,
observations are sequential, and no mutation/recovery readiness is claimed.

Both native PowerShell editions passed 21 tests and validation of 340 operations,
eight groups, five profiles and 149 PowerShell files. An initial collision fixture
used a mock-invisible variable; corrected fixture now proves exclusive creation
preserves concurrent output. Interop compiled without live Core Audio calls.

Resolved: source-level endpoint observation/selection/export contract. Retired or
excluded: none. Partial: R20 audio outcome and broader B02 resource coverage.
Deferred: desktop/device/driver acceptance, D08/Q30 setter choice, other resource
identities, interactive Store work and unresolved deployment choices. Packages are
resumed under the overnight authorization; no acquisition in this batch. No Windows
state, support metadata or existing saved recovery changed. All five ranges remain
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; no whole legacy
outcome closed, so no estimate reduction. Next: B06 read-only component inventory
and B08 individual portable review while acceptance-dependent work is postponed.

## B06 component inventory, 2026-10-16

The [B06 record](migrations/remaining-migrations-follow-up.md#b06-component-inventory-implementation-2026-10-16)
retains the target/provider contract, validation, postponed acceptance and recovery.
Three distinct namespaces preserve raw state; completed-empty, failed and unselected
providers are different. Explicit native machine/build/edition checks precede capture
and include update-revision drift afterward. Saved completion and lookup stay read-only.

Twenty isolated Pester tests and repository validation passed on both native
PowerShell editions: 340 operations, eight groups, five profiles, 152 PowerShell files.
An initial test used PowerShell's automatic args variable inside the assertion block;
a dedicated target-splat variable corrected the fixture. No live query or servicing.

Resolved: component observation/export/lookup source slice. Retired/excluded: none.
Partial: B06 and broader B02 resource contracts. Deferred: native Windows 11/Server
collection, Q05/Q06 selections/media, dependencies, policy/reboot/data and servicing
recovery. Package implementation continues under the overnight authorization; user
choices are not inferred. All five ranges reviewed and unchanged: 38-58 / 58-73 /
20-25 / 25-35 / 8-12, rounded 150-205/about 180. No whole legacy feature or product
completed acceptance. Next: B08 portable review without activating any candidate.

## B08 Rufus portable source candidate, 2026-10-16

See the [application batch record](migrations/application-migration-review.md#b08-rufus-portable-source-candidate-2026-10-16)
for official source/signature/hash, selected file ownership, validation and recovery.
Pending package.rufus uses existing File staging with preserved portable-mode filename,
no supported targets and Windows 11 candidate acceptance. The four product tests plus
existing package/catalog tests passed 153 per edition after correcting omitted
CandidateTargets metadata. Validation passed 341 operations/eight groups/five profiles/
153 PowerShell files on both editions; generated reference and preview are current.

Resolved: requested Rufus source preparation. Retired/excluded: none. Partial: package
candidate with native lifecycle/GUI acceptance deferred; no legacy outcome closed.
Settings/components/accounts/actions gain no acceptance; source discovery/acquisition
is separate from activation. No USB, app, VM or controller change. All five ranges
remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. The addition
does not reduce legacy estimates. Continue RegRipper and independent source batches;
postpone unresolved prerelease/runtime or user-selection gates until input is available.

## B08 RegRipper 3.0 distribution candidate, 2026-10-16

See the [application batch record](migrations/application-migration-review.md#b08-regripper-30-distribution-candidate-2026-10-16)
for exact source, unsigned binary/runtime evidence, all member hashes, validation,
acceptance and recovery. Complete pinned archive ownership replaces the incomplete
legacy executable-only boundary while preserving custom plugins/reports. Pending
Windows 11 candidate only; no supported targets or profile selection. RegRipper4.0
terms and WFN prerelease/runtime selection remain independent deferred decisions.

Resolved: source candidate and inert lifecycle/recovery tests. Retired/excluded:
none. Partial: one legacy outcome; no native/parser/runtime acceptance. Both
editions passed repository validation (342 operations/eight groups/five profiles/
154 PowerShell files). 5.1 passed 74 focused tests; 7 passed 70 catalog tests and
four product tests on sequential rerun after a fixture replacement IOException.
No handler change hid that failure. No workstation, VM, controller or data change.
All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180: source readiness leaves acceptance outstanding. Continue independent batches
and retain unresolved ownership/runtime/interactive decisions for the user's return.

## B03 existing user-bin startup candidate, 2026-10-16

See the [setting batch record](migrations/settings-post-migration-review.md#b03-existing-user-bin-startup-candidate-2026-10-16)
for both legacy writers, implementation, acceptance procedure and recovery.
Two pending runtime operations share the existing profile lifecycle and fixed
UserBinPath renderer; normalized equivalent entries are preserved and known
unmarked legacy writers block enablement. No immediate/persistent PATH mutation
or bin provisioning. Existing color renderer and snapshot version 1 are preserved;
color acceptance scripts remain explicitly scoped to their original renderer.

Both native editions passed 140 focused tests, zero failures/skips and one
integration exclusion, plus validation of 344 operations/eight groups/five
profiles/155 PowerShell files. Runtime discovery and directory presence were
mocked; generated blocks ran only in restored test-process environment fixtures.
No real profile, persistent environment, VM, controller or component changed.

Resolved: source renderer and isolated duplicate/ownership/recovery evidence.
Retired/excluded: none. Partial: one user-bin legacy outcome, not two features.
Deferred: native startup/identity acceptance, Q08 persistent PATH/provisioning,
WindowsApps and Terminal JSONC ownership. All five ranges remain 38-58 / 58-73 /
20-25 / 25-35 / 8-12, rounded 150-205/about 180; source-ready code does not close
legacy acceptance. Presentation is 34/279 with 245 unreviewed declarations.
Continue independent source batches without waiting for per-batch approval.

## B08 pinned Python source candidates, 2026-10-16

The [application batch record](migrations/application-migration-review.md#b08-pinned-python-source-candidates-2026-10-16)
retains exact sources, source/raw-file agreement, licenses, syntax checks, tests,
acceptance and recovery. Complete Hex2text/ChromeSyncParser archives are pending
Windows 11 candidates; no profiles or supported target. ShimCacheParser's Python 2
syntax/runtime gap remains deferred. Nothing downloaded was executed; no database,
profile, interpreter, VM or controller was changed.

Both native editions passed 78 focused tests (one integration excluded) and
validation of 346 operations/eight groups/five profiles/156 PowerShell files.
Initial scratch insertion syntax was repaired before checks; whole-catalog
comparison preserves all original fields/groups apart from B01 presentation.
Resolved: complete source packaging/inert ownership for two partial products.
Retired/excluded: none. Deferred: native/interpreter/functional acceptance and the
third product's runtime choice. All five ranges remain 38-58 / 58-73 / 20-25 /
25-35 / 8-12, rounded 150-205/about 180; no legacy outcome closed. Continue
independent source work without waiting for per-batch approval.

## B03 Terminal JSONC preparation, 2026-10-16

See the [setting batch record](migrations/settings-post-migration-review.md#b03-terminal-jsonc-preparation-2026-10-16)
and [API contract](terminal-jsonc-preparation.md) for bounded parsing, exact field
ownership, recovery, source limits and the next integration procedure. Three pure
commands operate on supplied UTF-8 bytes and do not read/write a live settings file.
No selected instance/profile, package, component or catalog operation. Both native
editions passed 41 tests after correcting an overbroad expected-string fixture;
validation passed 346 operations/eight groups/five profiles/158 PowerShell files.

Resolved: E06 in-memory preservation/recovery proof. Retired/excluded: none.
Partial: Terminal outcome; no native or live-file acceptance. Deferred: intended
instance/SID/path, actual profile availability, exclusive writer, Q09 and GUI.
All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180; source preparation does not close legacy behavior. Continue independent work.

## B02 network adapter identity inventory, 2026-10-16

See the [setting batch record](migrations/settings-post-migration-review.md#b02-network-adapter-identity-inventory-2026-10-16)
and [operator/API contract](network-adapter-inventory.md). Explicit target checks,
bounded visible/hidden GUID observations, saved-only lookup/completion and exclusive
JSON export are source-ready. Both editions passed 23 tests after correcting a
reused race-test filename, and validation of 346 operations/eight groups/five
profiles/161 PowerShell files. No live provider query or network state change.

Resolved: B02 adapter identity observation contract. Retired/excluded: none.
Partial: adapter settings; native provider and behavior acceptance remain open.
Deferred: Q30/D10 selection, dependency checks and narrowly owned mutation/recovery.
All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180; no legacy outcome closed. Continue independent implementation.

## B04 default/LAN proxy observation, 2026-10-16

See the [setting batch record](migrations/settings-post-migration-review.md#b04-defaultlan-proxy-observation-2026-10-16)
and [operator/API guide](user-proxy-inventory.md). Explicit machine/SID/session,
literal options, UI fallback, native memory ownership and exclusive output are
source-ready. Both editions passed 31 focused tests after two fixture corrections;
separate x86/x64 ABI probes passed. Validation covers 346 operations/eight groups/
five profiles/164 PowerShell files. No native WinINet query or proxy change.

Resolved: E07 default/LAN observation and memory proof. Retired/excluded: none.
Partial: user proxy outcome. Deferred: native/UI/policy, named RAS, owned mutation,
refresh/recovery and WinHTTP. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 /
8-12, rounded 150-205/about 180; no legacy behavior accepted. Continue independent work.

## B01 media and privacy presentation, 2026-10-16

See the [setting batch record](migrations/settings-post-migration-review.md#b01-media-and-privacy-presentation-2026-10-16)
and [operator comparison](setting-presentation.md#media-and-privacy-choices).
Six existing AutoPlay/AutoRun, clipboard, location/scripting and advertising-ID
controls now distinguish policy/preference, complete legacy bundles and reverse
semantics. Presentation is 40/279 with 239 reviews open. All behavioral catalog
fields and profiles remain unchanged; exact references and local template facts
do not establish current GUI/managed/consumer acceptance.

Both editions passed 122 focused tests, one integration case excluded; final
validation and actual classification checks passed after four schema-label fixes.
Validation covers 346 operations/eight groups/five profiles/164 PowerShell files.
The [intervening package review](migrations/application-migration-review.md#b08-deferred-tool-source-checks-2026-10-16)
records SuperFetch's official HTTP 404 and R06's remaining distribution/dependency
inspection. No package added, no runtime/state changes.

Resolved: six presentation reviews and narrower source gates. Retired/excluded:
none. Partial: media/privacy outcomes. Deferred: GUI/managed/consumer/recommendation
acceptance and the three product source/runtime outcomes. All five ranges remain
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. Independent work continues.

## B04 proxy edit and recovery preparation, 2026-10-16

See the [setting batch record](migrations/settings-post-migration-review.md#b04-proxy-edit-and-recovery-preparation-2026-10-16)
and [API procedure](user-proxy-inventory.md#prepare-an-edit-and-recovery-in-memory).
Changed-bit/URL ownership and conflict recovery are source-ready; supplied-data
snapshots are neither engine manifests nor authorization for live writes.
Both editions passed 39 tests and validation of 346 operations/eight groups/five
profiles/166 PowerShell files. No native query/setter or network request.
The [YARA recheck](migrations/application-migration-review.md#b08-yara-availability-recheck-2026-10-16)
confirms v4.5.8 source-only assets; no older binary or replacement selected.

Resolved: E07 in-memory ownership/recovery proof and current YARA source-only
availability. Retired/excluded: none. Partial: user proxy outcome. Deferred:
live policy/identity/state binding, setter/refresh/native acceptance, RAS/WinHTTP
and YARA binary/build. All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180; no accepted legacy closure. Independent work continues.

## B02 volume identity inventory, 2026-10-16

See the [setting record](migrations/settings-post-migration-review.md#b02-volume-identity-inventory-2026-10-16)
and [volume procedure](volume-inventory.md). GUID-path capture/lookup/completion
is source-ready, with machine/build/edition guards, 512-row bound, missing versus
failed observation and no label/letter fallback. Multiple paths may identify one
volume; no permanent hardware, boot-role or protection identity is inferred.
Both editions passed 25 volume and 23 adapter tests plus validation of 346
operations/eight groups/five profiles/169 PowerShell files. Adapter invalid-input
fixtures now pass prepared rows across module scope. No native volume query.

Resolved: volume observation contract and adapter test accuracy. Retired/excluded:
none. Partial: resource identity preparation. Deferred: native collection,
selection, boot/protection/recovery state and storage mutations. All five ranges
stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. No accepted
legacy closure; independent work continues under the existing overnight scope.

## B01 power-control presentation, 2026-10-16

See the [setting record](migrations/settings-post-migration-review.md#b01-power-control-presentation-2026-10-16).
Seven existing controls now distinguish dedicated button, menu, screen-off and
idle-sleep effects, AC/DC sources, exact recovery and explicit legacy reverse.
Both editions passed 122 focused tests, one integration exclusion, whole-catalog
comparison and validation of 346 operations/eight groups/five profiles/169
PowerShell files. No power query/state change. Presentation is 47/279, 232 open.

Resolved: seven presentation reviews. Retired/excluded: none. Partial: power
user-visible evaluation. Deferred: added choices, localized parser/index bounds,
GUI/policy/hardware transitions. All five ranges stay 38-58 / 58-73 / 20-25 /
25-35 / 8-12, rounded 150-205/about 180; no legacy outcome closes. Continue the
independent handler preparation and remaining batches without a new approval.

## Power index capture and recovery repair, 2026-10-17

See the [setting record](migrations/settings-post-migration-review.md#power-index-capture-and-recovery-repair-2026-10-17)
and [recovery compatibility](setting-presentation.md#power-index-record-compatibility).
PowerSettings 0.2.0/Engine 0.20.3 preserve UInt32 indexes and adapt unmarked older
signed captures without editing records. Versioned new snapshots validate source,
scheme and encoding. Both editions passed 44 tests and validation of 346 operations/
eight groups/five profiles/169 PowerShell files. No native power call or VM run.

Resolved: signed-narrowing defect and compatible recovery. Retired/excluded: none.
Partial: power lifecycle. Deferred: native unsigned recovery, localized reads,
expanded choices and physical/GUI behavior. Ranges stay 38-58 / 58-73 / 20-25 /
25-35 / 8-12, rounded 150-205/about 180; no legacy outcome closes. Retain the
corrected handler for high-value recovery and continue independent source work.

## Typed power read backend, 2026-10-17

See the [setting record](migrations/settings-post-migration-review.md#typed-power-read-backend-2026-10-17).
PowerSettings 0.3.0/RIDE.PowerRead 0.1.0 remove English query-label parsing,
preserve UInt32 identity/value reads and reject active-plan drift. Existing writes
and compatible saved recovery remain. Both editions passed 63 tests and validation
of 346 operations/eight groups/five profiles/171 PowerShell files; no native call.

Resolved: source reader localization defect and read-drift proof. Retired/excluded:
none. Partial: power inspection/recovery. Deferred: native API/locale, hardware/GUI,
write races and additional choices. All five ranges remain 38-58 / 58-73 / 20-25 /
25-35 / 8-12, rounded 150-205/about 180. No legacy closure; independent work continues.

## B08 PSScriptTools source candidate, 2026-10-17

See the [package record](migrations/application-migration-review.md#b08-psscripttools-source-candidate-2026-10-17).
Complete pinned source/notices are prepared as an inert candidate, with Q15,
native lifecycle and runtime/import acceptance open. PS5 passed 74 tests; PS7
passed 73/74, then four package cases passed sequentially. The initial manifest
File.Replace failure remains evidence for a focused writer review. Both editions
passed validation of 347 operations/eight groups/five profiles/172 PowerShell files.

Resolved: pinned source candidate. Retired/excluded: none. Partial: PSScriptTools.
Deferred: deployment choice, native/dependency/runtime acceptance and writer review.
Five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180;
no accepted legacy closure. No upstream code or Windows configuration was executed.

## Portable manifest failure recovery, 2026-10-17

See the [package recovery record](migrations/application-migration-review.md#portable-manifest-failure-recovery-2026-10-17).
The shared writer retains failed staged journals and narrowly retries unchanged
files; 100 focused tests passed per edition, with 347 operations/eight groups/
five profiles/173 PowerShell files validated. Original failure cause and native
acceptance remain open. Resolved: source recovery gap. Retired/excluded: none.
Partial: portable outcomes. Deferred: runtime acceptance and deployment choices.
All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180, because this repair closes no legacy outcome. No VM or workstation integration.

## B01 Explorer folder options presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-explorer-folder-options-presentation-2026-10-17).
Eight existing controls gained presentation; operational mappings remain unchanged.
Both editions passed 122 focused tests (one integration exclusion), complete
catalog comparison and validation of 347 operations/eight groups/five profiles/173
PowerShell files. Resolved: presentation/reverse semantics. Retired/excluded: none.
Partial: Explorer outcomes. Deferred: GUI/managed/touch/logon/process/provider
acceptance. Presentation 55/279, 224 open; no legacy closure. Five ranges unchanged
at 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. No Windows state,
VM, controller or package was changed.

## B02 local user identity inventory, 2026-10-17

See the [identity preparation record](migrations/remaining-migrations-follow-up.md#b02-local-user-identity-inventory-2026-10-17).
Bounded SID capture, saved lookup/completion and exclusive export are source-ready.
Both editions passed 26 tests and validation of 347 operations/eight groups/five
profiles/176 PowerShell files; the initial 25/26 numeric-boundary failure remains
recorded. Resolved: local identity contract. Retired/excluded: none. Partial: account
preparation. Deferred: native provider, ownership, credentials, membership and viable
access acceptance. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180; no legacy closure. No account, VM or controller changed.

## B08 AzureHound stable artifact preparation, 2026-10-17

See the [artifact record](migrations/application-migration-review.md#b08-azurehound-stable-artifact-preparation-2026-10-17).
Official v3.1.2 x64 ZIP matches publisher/GitHub digests; executable metadata and
separate tag notices are retained without execution. Resolved: artifact/integrity/
license observations. Retired/excluded: none. Partial: collector preparation.
Deferred: backend match, companion-notice ownership and native/functional acceptance.
Catalog unchanged; no tests repeated. Five ranges remain 38-58 / 58-73 / 20-25 /
25-35 / 8-12, rounded 150-205/about 180, because no legacy outcome closed. No VM,
credentials, collection, service or protected controller changes occurred.

## B09 user language list inventory, 2026-10-17

See the [regional preparation record](migrations/remaining-migrations-follow-up.md#b09-user-language-list-inventory-2026-10-17).
Ordered language/input capture, saved lookup/completion and exclusive JSON export
are source-ready with 28 tests per edition and validation of 347 operations/eight
groups/five profiles/179 PowerShell files. Resolved: observation and legacy bundle
boundary. Retired/excluded: none. Partial: regional configuration. Deferred: native
provider, GUI, capability and writer/recovery acceptance. All five ranges remain
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; no legacy closure.
No settings, language pack, welcome/default-user profile, VM or controller changed.

## B09 existing language priority preparation, 2026-10-17

See the [regional preparation record](migrations/remaining-migrations-follow-up.md#b09-existing-language-priority-preparation-2026-10-17).
Existing-tag order preparation and conflict-aware order recovery are source-ready;
53 tests passed per edition and 347 operations/eight groups/five profiles/181
PowerShell files validated. Resolved: order ownership/no-op recovery. Retired/
excluded: none. Partial: regional configuration. Deferred: native state store,
setter and GUI/side-effect acceptance. All ranges remain 38-58 / 58-73 / 20-25 /
25-35 / 8-12, rounded 150-205/about 180; no legacy closure or Windows state change.

## B01 App Privacy policy presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-app-privacy-policy-presentation-2026-10-17).
Seventeen presentation reviews distinguish default policy, per-app exceptions,
Enabled removal, voice dependency and omitted historical background-user cleanup.
Both editions passed 122 tests (one integration exclusion), whole-catalog comparison
and validation of 347 operations/eight groups/five profiles/181 PowerShell files.
Resolved: presentation/reference semantics. Retired/excluded: none. Partial: App
Privacy/background outcomes. Deferred: native app, GUI, managed and locked-session
acceptance. Presentation 72/279, 207 open. No legacy closure; ranges stay 38-58 /
58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. No Windows state changed.

## B08 Cookie Cruncher source backoff, 2026-10-17

See the [application record](migrations/application-migration-review.md#b08-cookie-cruncher-source-backoff-2026-10-17).
GitHub API rate limit prevented revision/payload inspection; no fallback request
or artifact execution. Resolved/retired/excluded: none. Partial: applications.
Deferred: acquisition, licensing/runtime and native acceptance. Existing source
validation remains current. All ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180; no legacy closure. Continue independent local batches.

## B09 user language override inventory, 2026-10-17

See the [regional override record](migrations/remaining-migrations-follow-up.md#b09-user-language-override-inventory-2026-10-17).
Explicit display/input capture is separate from ordered language inventory. Each
edition passed 28 new/28 existing tests and 347-operation/eight-group/five-profile/
183-file validation. Resolved: observation/absence contracts. Retired/excluded: none.
Partial: regional configuration. Deferred: native provider semantics, GUI and
durable mutation/recovery. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 /
8-12, rounded 150-205/about 180; no legacy closure or native state change.

## B02 wireless profile identity inventory, 2026-10-17

See the [wireless identity record](migrations/remaining-migrations-follow-up.md#b02-wireless-profile-identity-inventory-2026-10-17).
Basic interface/profile capture and saved lookup are source-ready; 35 distinct
mocked tests passed per edition, with 347 operations/eight groups/five profiles/
186 PowerShell files validated. Resolved: discovery/lookup contract. Retired/
excluded: none. Partial: Wi-Fi/resource configuration. Deferred: native hardware/
service/user visibility, Q12/Q30, content ownership and exact recovery. Five ranges
stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; no closure.

## B01 update and maintenance presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-update-and-maintenance-presentation-2026-10-17).
Eight controls now distinguish device policy, preference and unverified legacy
behavior. Wake-key mismatch, driver-search omission and Microsoft Update service
enrollment remain explicit partial outcomes. Both editions passed 122 focused
tests (one integration exclusion) and validation of 347 operations/eight groups/
five profiles/186 files. Presentation 80/279, 199 open. Resolved: presentation
and reverse/reference distinctions. Retired/excluded: none. Deferred: native,
GUI, managed, wake and default-profile acceptance. All five ranges stay 38-58 /
58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180, with no legacy closure.
The user extended the autonomous window to 08:00 Copenhagen (06:00 UTC); the
existing follow-up was updated, and a separate decision chat was created.

## B01 security control presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-security-control-presentation-2026-10-17).
Resolved eight presentation reviews plus UAC/legacy/recovery distinctions; no new
retirement/exclusion. Legacy firewall, HVCI request and exclusion visibility remain
partial. Native GUI, protection, hardware/boot and management acceptance remain.
Each edition passed 122 tests (one integration exclusion) and validation of 347
operations/eight groups/five profiles/186 files. Presentation 88/279, 191 open;
no accepted legacy closure. All ranges unchanged: 38-58 / 58-73 / 20-25 / 25-35 /
8-12, rounded 150-205/about 180. No Windows state or supported target changed.

## B01 Defender exclusion capture and recovery, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-defender-exclusion-capture-and-recovery-2026-10-17).
Resolved captured-path drift and ignored-write reporting in source, with inner
snapshot version 1 and old Boolean/path record compatibility. Both editions
passed 109 focused tests (one integration exclusion) and validation of 347
operations/eight groups/five profiles/187 files. Retired/excluded: none. Partial:
exclusion ownership/observability. Deferred: native, managed, GUI and default
profile acceptance. Presentation remains 88/279, 191 open. No legacy closure;
all five ranges unchanged: 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded
150-205/about 180. No protection, directory or workstation state changed.

## B09 regional provider inventory, 2026-10-17

See the [subject record](migrations/remaining-migrations-follow-up.md#b09-regional-provider-inventory-2026-10-17).
Resolved four separate read-only provider contracts and export; 35 tests per
edition and validation of 347 operations/eight groups/five profiles/190 files.
Retired/excluded: none. Regional preparation remains partial; full recovery,
native/GUI and setter acceptance remain deferred. No catalog/Windows state change
or accepted legacy closure. Presentation 88/279, 191 open; all ranges unchanged:
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180.

## B01 desktop and Explorer visibility presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-desktop-and-explorer-visibility-presentation-2026-10-17).
Fourteen presentation reviews resolved; 102/279 now explicit, 177 open. No new
retirement/exclusion. Legacy reverse differences, version label and cache behavior
remain partial; GUI/media/provider/cache and profile recommendation acceptance
remain deferred. Both editions passed 122 tests (one integration exclusion) and
validation of 347 operations/eight groups/five profiles/190 files. No runtime
change or new target. All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180: metadata analysis is not native legacy closure.

## B07 explicit deployment identity preparation, 2026-10-17

See the [application record](migrations/application-migration-review.md#b07-explicit-deployment-identity-preparation-2026-10-17).
Q01/Q02 intent resolved; pure named identity/inspection/selection implemented.
Each edition passed 37 distinct tests after two completion failures were fixed;
validation passed 347 operations/eight groups/five profiles/192 files. Existing
records and commands remain unchanged. No retirement/exclusion or native legacy
closure. Durable compatibility, adoption/replacement ownership, coexistence and
kit acceptance remain partial/deferred. All five ranges unchanged: 38-58 / 58-73 /
20-25 / 25-35 / 8-12, rounded 150-205/about 180. Presentation 102/279, 177 open.

## B07 installed registration inventory, 2026-10-17

See the [application record](migrations/application-migration-review.md#b07-installed-registration-inventory-2026-10-17).
Bounded per-view observation/export source-ready; 36 distinct tests passed per
edition after fixture isolation repair. Validation passed 347 operations/eight
groups/five profiles/195 files. No new retirement/exclusion or native acceptance.
Catalog matching, product/ownership validation, adoption/replacement and durable
compatibility remain partial/deferred. All five ranges remain 38-58 / 58-73 /
20-25 / 25-35 / 8-12, rounded 150-205/about 180. Presentation 102/279, 177 open.

## B07 offline package adoption review, 2026-10-17

See the [application record](migrations/application-migration-review.md#b07-offline-package-adoption-review-2026-10-17).
Offline matching/source validation and opt-in metadata-only variant resolution
implemented; Q03 host-folder publication intent reconciled. Both editions passed
104 distinct checks and validation of 347 operations/eight groups/five profiles/197
files. No new retirement/exclusion or native legacy closure. Adoption/state/ownership,
Q04 and kit/offline publication acceptance remain partial/deferred. All five ranges
unchanged: 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180.
Presentation remains 102/279, 177 open. No workstation or VM runtime changes.

## B07 legacy selection mapping preparation, 2026-10-17

See the [application record](migrations/application-migration-review.md#b07-legacy-selection-mapping-preparation-2026-10-17).
Logical compatibility/recovery API implemented and Q04 intent reconciled. Both
editions passed 20 tests and validation of 347 operations/eight groups/five profiles/
199 files. Original-byte/store/journal migration and actual toolkit commit/recovery
remain partial/deferred. No retirement/exclusion or native legacy closure. All five
ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180.
Presentation 102/279, 177 open. No existing engine state or runtime changed.

## B07 toolkit owned-file update preparation, 2026-10-17

See the [application record](migrations/application-migration-review.md#b07-toolkit-owned-file-update-preparation-2026-10-17).
Stage/keep/remove/preserve/conflict comparison implemented; 37 distinct tests passed
per edition after a UNC-path fix. Validation passed 347 operations/eight groups/
five profiles/201 files. No publication or native legacy closure. No new retirement/
exclusion. Full artifact/ownership manifest, collection, staging, commit/recovery
and native acceptance remain partial/deferred. All five ranges remain 38-58 /
58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. Presentation 102/279, 177 open.

## B06 client-component source preparation, 2026-10-17

See the [component/decision record](migrations/remaining-migrations-follow-up.md#b06-client-component-source-preparation-2026-10-17).
Both editions passed 29 preparation tests and validation of 347 operations/eight
groups/five profiles/203 files. Accepted Q05-Q12 and partial Q13 reconciled; no
component was serviced. Source, policy, dependencies, durable recovery and native
acceptance remain partial/deferred. No retirement/exclusion or legacy closure.
All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180. Presentation remains 102/279, 177 open.

## B03 persistent user PATH observation and recovery, 2026-10-17

See the [setting record](migrations/settings-post-migration-review.md#b03-persistent-user-path-observation-and-recovery-2026-10-17).
Literal observation and pure owned-entry append/recovery implemented; 44 distinct
tests passed per edition after two fixture corrections. Validation passed 347
operations/eight groups/five profiles/205 files. Q14/Q15 and partial Q16 decisions
reconciled. Native writes, durable state, environment refresh and acceptance remain
partial/deferred. No retirement/exclusion or legacy closure. All five ranges stay
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. Presentation
remains 102/279, 177 open.

## B08 Wireshark machine MSI candidate, 2026-10-17

See the [package record](migrations/application-migration-review.md#b08-wireshark-machine-msi-candidate-2026-10-17).
Official MSI/hash/signature and read-only association-table evidence retained;
18 focused tests per edition and validation of 348 operations/eight groups/five
profiles/206 files passed. No native install or retirement/exclusion in this batch.
Wireshark lifecycle, associations, data/runtime ownership and separate interactive
Npcap remain partial/deferred. All five ranges stay 38-58 / 58-73 / 20-25 /
25-35 / 8-12, rounded 150-205/about 180. Presentation remains 102/279, 177 open.

## Accepted Volatility 2 and ImproHound retirements, 2026-10-17

See the [authoritative application dispositions](migrations/application-migration-review.md#accepted-volatility-2-and-improhound-retirements-2026-10-17).
Two explicit user retirements remove two planned package outcomes. Exact selector
rows remain, no active catalog IDs existed, and no existing installation/data was
changed. Other accepted decisions are partial workflow/product direction; deferred
Neo4j/APOC, optional backend deployment and unfinished native acceptance stay counted.

Arithmetic: packages 58-73 minus two = 56-71. Other ranges remain settings 38-58,
components 20-25, accounts/assets 25-35 and maintenance 8-12. Summed endpoints
149-203 minus two = 147-201; nearest-five rounded range 145-200, midpoint about
175. This changes disposition counts, not the catalog's 348 declarations or native
acceptance. Two retired, no newly excluded, no newly runtime-accepted outcome.
Presentation remains 102/279, 177 open. Mapping/links/whitespace verified; no
passed runtime suite rerun for documentation. Continue remaining authorized batches.

## B01 visual effects and first-sign-in presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-visual-effects-and-first-sign-in-presentation-2026-10-17).
Eight presentation reviews resolved; 110/279 explicit, 169 open. No retirement or
exclusion in this batch. Whole visual-bundle coverage and session effects remain
partial; GUI, policy precedence and first-sign-in acceptance are deferred. Both
editions passed 122 tests (one integration exclusion) and validation of 348
operations/eight groups/five profiles/206 files. All five ranges remain
38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175: source presentation
does not establish native outcome completion. Q17/Q20 retirements stay counted.

## B01 read-only session visual observations, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-read-only-session-visual-observations-2026-10-17).
Five bounded GET contracts and identity/failure handling are source-ready; 40
tests passed in each edition, using fakes/mocks only. Validation passed for
348 operations/eight groups/five profiles/208 files. No retirement or exclusion;
visual-effects migration remains partial, native/GUI acceptance deferred. All
five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.
No legacy outcome closed and no live Windows configuration was changed.

## B01 network control presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-network-control-presentation-2026-10-17).
Thirteen presentation reviews resolved, including corrected ICS service scope and
exact administrative-share reference. Presentation is 123/279, 156 open. No new
retirement/exclusion; network/remote-access bundles remain partial and native,
GUI, service, peer and managed-policy acceptance deferred. Both editions passed
122 tests (one integration exclusion) and validation of 348 operations/eight
groups/five profiles/208 files. All five ranges stay 38-58 / 56-71 / 20-25 /
25-35 / 8-12, rounded 145-200/about 175; source review closes no legacy outcome.

## B10 inert Office configuration review, 2026-10-17

See the [application record](migrations/application-migration-review.md#b10-inert-office-configuration-review-2026-10-17).
Q21 and OneDrive Q22 design decisions reconciled; bounded redacted XML review is
source-ready. Forty distinct cases passed per edition; repository validation
passed for 348 operations/eight groups/five profiles/210 files. No new retirement
or exclusion. Office/Visio/Teams/OneDrive remain partial; native compatibility,
extra-language, deployment, activation and data-preservation acceptance deferred.
All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about
175. No legacy outcome closed and no installer, account or setting changed.

## B10 Click-to-Run observation, 2026-10-17

See the [application evidence](migrations/application-migration-review.md#b10-click-to-run-observation-2026-10-17).
The read-only collector/export passed 36 mocked cases per edition and validation
of 213 PowerShell files. Native product/technology/language/channel and deployment
acceptance remain deferred; no retirement, exclusion or legacy outcome closure.
All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about
175. No Office registry, MSI provider, installer, account or setting was changed.

## B10 FTK source and decision reconciliation, 2026-10-17

See [application source evidence](migrations/application-migration-review.md#b10-ftk-source-and-decision-reconciliation-2026-10-17)
and [settings decision closure](migrations/settings-post-migration-review.md#accepted-remaining-decisions-and-r29-bookkeeping-closure-2026-10-17).
Q22-Q31 reconciled; ADR ownership accepted. R29 bookkeeping closed with audit and
reopen condition, not counted as migration/retirement. Official FTK ZIP and two
Valid signatures inspected; CodeMeter/layout/driver/native lifecycle remain open.
No installer/VM/workstation change, publication or target expansion. No new
retired/excluded outcomes. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 /
8-12, rounded 145-200/about 175: prior audit prevented a numeric outcome for R29,
and no actual product/setting acceptance was completed here.

## B10 read-only desired-configuration reference, 2026-10-17

See the [settings evidence](migrations/settings-post-migration-review.md#b10-read-only-desired-configuration-reference-2026-10-17).
Schema-1 export binds source hashes, retains typed registry intent and explicit
ReportOnly/Unknown boundaries, and provides read-only completion. Thirty-seven
distinct cases passed per edition; repository validation passed for 216 files.
No other repository, Windows state, package, profile selection or VM changed.
No retirement/exclusion or legacy closure; consumer/native mapping remains deferred.
All five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B10 local offline bundle preflight, 2026-10-17

See the [application record](migrations/application-migration-review.md#b10-local-offline-bundle-preflight-2026-10-17).
Accepted offline scope reconciled; local manifest preflight passed 41 distinct
cases per edition and validation of 219 files. Selected declared dependency/file
completeness is separate from actual profile/source coverage and native offline
readiness. KAPE publisher form/agreement input deferred; no installation, assembly
or target change. No retired/excluded outcome or legacy closure. All five ranges
remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B01 logon and boot presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-logon-and-boot-presentation-2026-10-17). Twelve reviews resolved; no new retirement/exclusion or legacy closure. Presentation is 135/279, 144 open. Boot/logon, managed policy and hardware outcomes remain partial/deferred. Both editions passed 122 tests (one integration exclusion) and validation of 348 operations/eight groups/five profiles/219 files. All five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B10 offline profile package coverage, 2026-10-17

See the [application record](migrations/application-migration-review.md#b10-offline-profile-package-coverage-2026-10-17). Thirty-six tests passed in each native edition. Package-declaration gaps and design decisions are resolved; offline assembly/integration remains partial, native/hardware/driver/workload acceptance deferred. No new retirement/exclusion or legacy closure. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B10 byte-bound offline profile preflight, 2026-10-17

See the [application record](migrations/application-migration-review.md#b10-byte-bound-offline-profile-preflight-2026-10-17). Parsed-source binding and runtime decisions resolved; no retirement/exclusion or legacy closure. Offline assembly/integration remains partial and native acceptance deferred. Both editions passed 22 new tests plus affected completion, and validation of 348 operations/eight groups/five profiles/220 files. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B10 explicit local offline bundle assembly, 2026-10-17

See the [application record](migrations/application-migration-review.md#b10-explicit-local-offline-bundle-assembly-2026-10-17). Local copy/verification/recovery implemented; planning/integration remains partial and native acceptance deferred. Twenty-seven tests and validation of 348 operations/eight groups/five profiles/222 files passed per edition. No new retirement/exclusion or legacy closure. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B11 Sysinternals reviewed snapshot candidate, 2026-10-17

See the [application record](migrations/application-migration-review.md#b11-sysinternals-reviewed-snapshot-candidate-2026-10-17). Frozen inventory and whole-Suite candidate resolved; no retirement/exclusion. Individual/native collection scope stays partial/deferred. Seven tests and validation of 349 operations/eight groups/five profiles/223 files passed per edition. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no legacy outcome closed.

## B01 suggestion and input presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-suggestion-and-input-presentation-2026-10-17). Nineteen presentation reviews resolved; no new retirement/exclusion or legacy closure. Presentation is 154/279, 125 open. Whole bundles, numeric-channel meaning, GUI and learned-data recovery outcomes remain partial/deferred. Both editions passed 122 tests (one integration exclusion) and validation of 349 operations/eight groups/five profiles/223 files. All five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B11 independent Sysinternals products, 2026-10-17

See the [application record](migrations/application-migration-review.md#b11-independent-sysinternals-products-2026-10-17). Three individual source candidates resolved; none retired/excluded. Remaining Suite members and native outcomes stay partial/deferred. Twenty-four tests and validation of 352 operations/eight groups/five profiles/224 files passed per edition. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no legacy outcome closed.

## B11 Sysinternals diagnostic and imaging candidates, 2026-10-17

See the [application record](migrations/application-migration-review.md#b11-sysinternals-diagnostic-and-imaging-candidates-2026-10-17). Three further source candidates resolved; none retired/excluded. Collection/native scope remains partial/deferred. Another 24 tests passed per edition; validations cover 355 operations/eight groups/five profiles/224 files. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175, without a newly completed legacy outcome.

## B01 application feature presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-application-feature-presentation-2026-10-17). Nine presentation reviews resolved; no new retirement/exclusion or legacy closure. Presentation is 163/279, 116 open. Whole bundles, native app/UI, component and cloud-data outcomes remain partial/deferred. Both editions passed 122 tests (one integration exclusion) and validation of 355 operations/eight groups/five profiles/224 files. All five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B01 Start, taskbar and notification presentation, 2026-10-17

See the [settings record](migrations/settings-post-migration-review.md#b01-start-taskbar-and-notification-presentation-2026-10-17). Sixteen reviews resolved; no new retirement/exclusion or legacy closure. Presentation is 179/279, 100 open. Native shell, managed and multi-display behavior remain partial/deferred. Both editions passed 122 tests (one integration exclusion) and validation of 355 operations/eight groups/five profiles/224 files. All five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B11 Sysinternals command-line candidates, 2026-10-17

See the [application record](migrations/application-migration-review.md#b11-sysinternals-command-line-candidates-2026-10-17). Three further source candidates resolved; none retired/excluded. Nine individual products now have source coverage, with remaining collection/native outcomes partial/deferred. Another 24 tests and validation of 358 operations/eight groups/five profiles/224 files passed per edition. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no newly completed legacy outcome.

## B10 final staged bundle integrity check, 2026-10-17

See the [application record](migrations/application-migration-review.md#b10-final-staged-bundle-integrity-check-2026-10-17). Reproduced stale-integrity success repaired; no new retirement/exclusion. Offline integration/native outcomes remain partial/deferred. Both editions passed 28 checks and validation of 358 operations/eight groups/five profiles/224 files. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no legacy outcome closed.

## Morning handoff, 2026-10-17

The [consolidated handoff](migrations/remaining-migrations-follow-up.md#morning-handoff-2026-10-17) records source-ready work, actual static/mocked and publisher evidence, deferred native/resources/decisions, source hashes and concrete next instructions. Work stopped under the expired 08:00 window; safe handoff only followed. All five ranges were reviewed unchanged at 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175. No further retirement/exclusion or whole legacy outcome closure; partial/deferred acceptance remains counted.

## B10 offline declared source comparison, 2026-10-17

See the [application record](migrations/application-migration-review.md#b10-offline-declared-source-comparison-2026-10-17). Resolved explicit-source mismatch detection; no retirement/exclusion or whole legacy closure. Offline integration and native acceptance remain partial/deferred. All five ranges were refreshed unchanged at 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B10 assembly selected-profile gate, 2026-10-17

See the [application record](migrations/application-migration-review.md#b10-assembly-selected-profile-gate-2026-10-17). Resolved optional selected-package coverage during local assembly; no retirement/exclusion or whole legacy closure. Native/dependency/engine integration remains partial/deferred. All five ranges were reviewed unchanged at 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B01 service startup and runtime presentation, 2026-10-17

See the [settings review](migrations/settings-post-migration-review.md#b01-service-startup-and-runtime-presentation-2026-10-17). Presentation 185/279, 94 open. Resolved source presentation only; no new retirement/exclusion or whole-outcome closure. Native/whole-bundle outcomes remain partial/deferred. All five ranges refreshed unchanged at 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B01 scheduled-task presentation, 2026-10-17

See the [settings review](migrations/settings-post-migration-review.md#b01-scheduled-task-presentation-2026-10-17). Presentation 198/279, 81 open. Resolved source presentation only; no new retirement/exclusion or whole-outcome closure. Native/whole-bundle outcomes remain partial/deferred. All five ranges refreshed unchanged at 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B01 scheduled-task observation and readback, 2026-10-17

See the [repair evidence](migrations/settings-post-migration-review.md#b01-scheduled-task-observation-and-readback-2026-10-17). Two isolated baseline regressions reproduced; 20 focused task checks pass per edition. Resolved source verification/typed-state gaps; no retirement/exclusion or whole legacy closure. Native acceptance remains partial/deferred. All five ranges reviewed unchanged at 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.
