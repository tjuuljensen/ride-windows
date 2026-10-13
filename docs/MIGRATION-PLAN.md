# Legacy-to-v3 Migration Plan

## Estimated remaining migration work

| Group | Approximate remaining items | Examples |
| --- | ---: | --- |
| Windows and application settings | 38-58 | Deferred UI and Explorer behavior, security/network handlers, services, Server settings and BitLocker enrollment; Task Manager and Computer Browser selectors retired; optional PowerShell appearance accepted outside the legacy count; browser/Sysmon configuration remains under review; traditional Python association preservation awaits implementation/acceptance |
| Packages, portable tools and downloadable artifacts | 58-73 | Remaining forensic tools, system-tool entries, general software/artifacts, AD tools, browsers and other products; 19 newly accepted distributions (7 installed, 12 portable), 10 earlier outcomes and Opera excluded; R01/R02 preparation remains partial; current BloodHound CE and both collectors selected, container deployment separate; Volatility 2 and ImproHound retirement reviews remain unresolved |
| Windows components and optional features | 20-25 | WSL, Hyper-V, Sandbox, OpenSSH, printing features and built-in app management; RSAT remains a component/applicability decision; BloodHound CE selects no automatic Docker/WSL provisioning or Server Docker Desktop support; no new component acceptance |
| Accounts, configuration and deployed files/assets | 25-35 | Users and administrator membership, Wi-Fi, regional settings, language packs, browser preferences, fonts and wallpapers; user-bin PATH, bin provisioning and WindowsApps repair remain deferred; VMware directory/profile-file and Python environment/symbol/plugin ownership remain under review |
| Maintenance and operational actions | 8-12 | Cleanup, updates, Sysprep, hostname and execution helpers; quota/cache/backoff bridge passed Windows 11 Full with 1,280 tests, eight network and three real cache observations with matching publisher digests; consecutive acceptance Windows 11 2/2, Server 2025 0/2 on the current controller baseline; collector 0.4.1 bounded failure collection accepted, ArtCraft Launcher remains closed and must not be restarted; controller certification and default-branch cutover remain open; no automatic Python installation-time pip upgrade selected; runtime/rule updates and explicit maintenance remain separate review items |
| **Total, rounded** | **150-205** | **About 180 for planning** |

Last reviewed: **2026-10-13**. Latest run: [Windows 11 consecutive Full pair acceptance](#windows-11-consecutive-full-pair-acceptance-2026-10-13).
Second Full Windows 11 passed validation, all 1,280 guest tests, integration
and all 217 source hashes on unchanged published CI/controller baselines.
Eight network and three real cache observations retained matching publisher
digests within metadata expiry; the last lookup had 40 requests remaining.
Cleanup/UAC and final idle checks passed. Windows 11 is now 2/2 consecutive
Full passes; Server 2025 remains 0/2. The next same heartbeat at 12:47
Europe/Copenhagen will attempt Server after the observed reset, with fresh
quota and resource checks. ArtCraft Launcher remains closed and must not be
restarted. All five estimates and rounded total stay unchanged; unrelated
settings acceptance, controller certification and cutover remain open.

Previous run: [focused installed collector failure acceptance](#focused-installed-collector-failure-acceptance-2026-10-13).
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

Approximately **150-205 distinct legacy work items**
remain; use **about 180** for planning. These are candidates for migration,
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

## Purpose and inventory

This is the batch inventory for migrating the selectable commands in `legacy/v2/default.preset` to the v3 catalog and profiles. It includes active and commented selectors. The original inventory contained **732 distinct legacy function names** across **30 family groups**; **731** remain in the preset after the user-requested Opera exclusion on 2026-10-11. The excluded outcome remains accounted for in the application ledger. Active selectors are marked **default**. Paired legacy commands should become states of one v3 operation only when inspection confirms that they control the same setting or package.

The catalog supports `ScheduledTask`, `AdapterBinding`, `DefenderPreference`, `SmbProtocol`, `PowerScheme`, `NetBios`, `RemoteDesktopFirewall`, `SoundScheme`, `RegistryValue`, `RegistryValueSet`, `RegistryKeySet`, `Package`, `DefenderExclusion`, `WindowsService`, `BackgroundAppOverrides`, `BootConfiguration`, `NetworkProfile`, `PowerSetting`, `ShellFolder`, and `ProfileSetting`. Migration of the other groups requires the minimum additional operation kinds and focused handlers for Windows components, account/configuration changes, files/assets, and system tasks. Each handler must participate in planning, `ShouldProcess`, state capture or declared compensating behavior, status/reporting, and partial-failure reporting.

The optional [God Mode desktop folder](GOD-MODE.md) uses the focused `ShellFolder`
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

The [authoring guide](CUSTOM-LIBRARIES.md) documents the contract and the copyable
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
[current example guidance](CUSTOM-LIBRARIES.md#hkcr-and-coordinated-registry-entries)
and [requested hashing additions](CANDIDATE-TOOLS.md#requested-v3-additions-2026-10-11).
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

Package module 0.10.0 implements the [release discovery contract](GITHUB-RELEASE-DISCOVERY.md):
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

The [profile continuation record](migrations/powershell-profile-acceptance.md#continuation-after-the-chat-is-archived)
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

The [AutomatedLab follow-up](../tests/integration/AUTOMATEDLAB-TASKS.md#full-pilot-follow-up-2026-10-12)
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

The [controller unit repair](../tests/integration/AUTOMATEDLAB-TASKS.md#unit-regression-repair-2026-10-12)
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
See the [correlated pilot evidence](../tests/integration/AUTOMATEDLAB-TASKS.md#unit-regression-repair-2026-10-12).

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
See the [dated acceptance evidence](../tests/integration/AUTOMATEDLAB-TASKS.md#full-migration-branch-ci-acceptance-2026-10-12).

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

The 2026-10-11 [hashing additions](CANDIDATE-TOOLS.md#requested-v3-additions-2026-10-11)
queue three new outcomes outside the legacy selector inventory. Correcting the
Certutil authoring example accepts no legacy outcome; all five group estimates
and the rounded **160-215**, about **190**, total remain unchanged.
The same-day [application continuation](migrations/application-follow-up-2026-10-11.md)
accepts Caffeine and NetworkMiner on both targets, bringing these batches to
fifteen accepted distributions. All five ranges in the overview were reviewed;
the two resolved outcomes fit within their coarse uncertainty, so rounded ranges
remain unchanged. Deferred bundle components and runtime decisions remain counted.

The subsequent [installed continuation](migrations/application-installed-follow-up-2026-10-11.md)
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
The subsequent [WinSCP acceptance](migrations/application-winscp-follow-up-2026-10-11.md#final-correlated-acceptance)
resolves one portable product, bringing accepted distributions to eighteen
(six installed, twelve portable). Twelve portable lifecycles and 230 guest checks
passed per target. All five ranges were reviewed again and remain unchanged:
this product and the excluded Opera outcome fit within the coarse uncertainty.
The application ledger contains ten earlier migrations, eighteen newly accepted
outcomes, eighty individual review items and one user-policy exclusion.

The [Thunderbird continuation](migrations/application-thunderbird-follow-up-2026-10-11.md)
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
review backlog. See [application packages](APPLICATION-PACKAGES.md) for schema,
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
See [the session results](migrations/2026-10-08-unattended-results.md) for run IDs,
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
[PACKAGE-VERIFICATION-MATRIX.md](PACKAGE-VERIFICATION-MATRIX.md). The shared
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
implement it. See [profile migration analysis](POWERSHELL-PROFILES.md).
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
See the [handler and migration analysis](POWERSHELL-PROFILES.md) and the
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
[dated acceptance record](migrations/powershell-profile-acceptance.md).
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

Maintain `docs/PACKAGE-VERIFICATION-MATRIX.md` from per-package source investigations. Record whether the official source resolves latest, provides exact versioned URLs, publishes checksums, offers detached signatures and a key identity, or supplies an Authenticode signature. Distinguish publisher-provided evidence from hosting-provider metadata and from hashes RIDE observes itself. The matrix informs a later policy decision; it does not block latest acquisition. The CLI `download` command acquires without installing; artifacts are retained by package and version, and observations are appended to `catalog/artifact-observations.json`.

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
API budget reached zero; see the [pilot evidence](../tests/integration/AUTOMATEDLAB-TASKS.md).
The limit applies to the originating IP across GitHub-release packages, so
substituting another GitHub-hosted test package does not solve it. Complete a
shared, rate-aware `GitHubReleaseApi` resolver before enabling unattended VM
testing on the default branch.

Implementation is now available in package module 0.10.0, with
[documented process-local bounds, freshness and quota behavior](GITHUB-RELEASE-DISCOVERY.md).
Native complete regression passed 1,276 selected tests per edition; consecutive
two-target Full acceptance remains pending. This does not enable default-branch VM testing or complete overall
controller certification.

Design bounded reuse of release metadata with explicit freshness and source
provenance, while preserving the declared latest-release behavior and artifact
digest checks. On 403/429 exhaustion, report the remaining budget and reset time
and defer the run without hammering the endpoint or claiming a pass. Evaluate
scoped authentication separately; never commit a token, log it, or automatically
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
The [README package table](../README.md#future-package-options) distinguishes
distribution (installed or portable), artifact format (MSI, EXE, ZIP or standalone
file), and provider (direct publisher download or WinGet). Scope remains a
separate constraint declared by each supported variant.

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
- Report an existing different edition instead of silently installing a second
  copy or replacing it. Changing installed to portable, or the reverse, requires
  an explicit migration that accounts for configuration and integration.
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

Represent all approved acquisition/install providers for a package in its single package record or referenced manifest. For example, a package can describe both a direct GitHub release artifact and a WinGet source, with each provider's package identifier, exact version mapping, architecture, artifact metadata, and verification requirements. Provider adapters implement the mechanics; package-specific PSM1 files must not duplicate the package lifecycle or make implicit source choices.

Source selection should be deterministic and policy-driven: allow an explicit source choice and a configured preference among approved providers. An explicit provider choice must not fall back to another provider. Auto-selection may move to another provider only when it is approved for the same package/version, distribution, and scope and satisfies that provider's pinned artifact and trust metadata. An acquisition transport or availability failure may permit trying the next approved provider, with the resolved provider reported; an installation failure, version mismatch, hash mismatch, invalid signature, or unexpected publisher must stop the operation. Do not silently retry an integrity failure through a different source.

When providers supply different installers or materially different package builds, model them as distinct artifacts with provider-specific metadata and verification, even when they install the same logical package. Record the selected provider and artifact digest in the download manifest and run report so an installation can be reproduced and audited. Tests should cover provider preference, explicit source selection, approved transport fallback, and fail-closed verification errors.

**Agreed storage choices:** customizable values live in data-only, schema-versioned local configuration, split by scope: machine configuration under `%ProgramData%\RIDE\configuration.psd1` and user configuration under `%LocalAppData%\RIDE\configuration.psd1`. `ToolsDirectory` is machine-scoped and defaults to the system-drive `Tools` directory; it is not a catalog default or process environment variable. Package profiles currently resolve latest; exact-version selection and repository-backed reproducibility are later options, not prerequisites for acquisition.

## Acceptance and later integration

- For every batch, run catalog/profile validation and Pester coverage for planning, handler behavior through mocks, idempotence, `WhatIf`, and applicable restore or compensating behavior before accepting the batch.
- Keep package tests offline and deterministic by mocking download resolution and installer processes.
- Before accepting package migrations that use Defender exceptions, complete the package-specific exclusion metadata step and its mocked and disposable-VM verification above; ensure plans and reports identify every package-scoped exception.
- Defer complex disposable-VM scenarios—including reboot/Sysprep, broad Windows component changes, multi-user or machine-wide configuration, destructive cleanup, and live installer recovery—to a later integration phase.
- Add or retain Windows support declarations only after the affected operations pass their applicable disposable-VM checks on Windows 11 and Windows Server 2025.
