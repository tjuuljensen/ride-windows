# Remaining migration analysis and decisions
Current handoff, 2026-10-17: [all batch dispositions and completion order](remaining-migrations-follow-up.md#archive-handoff-and-closure-order-2026-10-17).
Latest: [archive handoff and closure order, 2026-10-17](#archive-handoff-and-closure-order-2026-10-17). This supersedes the morning handoff's checkout status and next-work order. The expired overnight automation remains paused; direct continuation is authorized without batch-by-batch approval.

Implementation continuation, 2026-10-17: [B03 startup fixtures](settings-post-migration-review.md#b03-startup-closure-fixture-2026-10-17),
[B08 full-source lifecycle](application-migration-review.md#b08-psscripttools-lifecycle-continuation-2026-10-17),
[B10 explicit offline execution](application-migration-review.md#b10-offline-execution-gate-2026-10-17)
and [four appearance presentations](settings-post-migration-review.md#b01-appearance-preference-presentation-2026-10-17)
supersede the corresponding source-ready counts and next steps below. Presentation
is now 279/279 after the [remaining 77 reviews](settings-post-migration-review.md#b01-presentation-review-completion-2026-10-17). Unverified mappings and compatibility gaps retain explicit dispositions. Native acceptance is blocked by denied
non-elevated Hyper-V CIM access. No whole legacy outcome was deducted; the dated
handoff below retains its original baseline. Current work order is in TODO.

Collection continuation, 2026-10-17: [named inventories and MiTeC viewers](application-migration-review.md#b11-named-collections-and-mitec-viewers-2026-10-17)
follow the earlier NTCore/exact ZIP selection batch. Current catalog: 362 operations,
60 packages, 279 settings, one artifact and 22 Store declarations; eight groups/five
profiles. There are 33 pending packages: 20 continuation candidates plus 13 Artcraft
products omitted from the earlier shorthand count. The 41 JoeWare, 22 current MiTeC
and 16 NTCore entries are frozen review inputs. Both native PowerShell editions pass
107 focused checks; VM acceptance remains blocked. NirSoft protection alerts,
JoeWare artifact/distribution review, SSView codec ownership, Zimmerman API quota,
4GB Patch licensing and component source/recovery prerequisites remain explicit.
No native acceptance or legacy deduction is made. The dated handoff below retains
its original counts and order.

## Archive handoff and closure order, 2026-10-17

The user requested reconciliation before archiving both old chats and continuation
through separate implementation and decision chats, with priority on reducing open
legacy outcomes. At reconciliation, HEAD was `87893c6` and the working tree was
clean. That commit includes the overnight/resumed implementation and decision
record. Earlier statements that this work was uncommitted describe those runs,
not the current checkout. This handoff is a documentation-only follow-up.

### What is complete and what remains

| Record | Reconciled result | Still open / closure boundary |
| --- | --- | --- |
| B01 settings | 198/279 setting presentations; 81 remain. Scheduled-task typed observation and readback repaired. Earlier literal/native results retain their original scope. | Finish remaining presentation reviews and user-visible, managed, boot, hardware and recovery evidence per the [30-row settings ledger](remaining-settings-plan.md#complete-remaining-ledger-triage). Presentation is a separate counter, not 198 completed legacy outcomes. |
| B02 identities | Supplied-data inventories for audio endpoints, adapters, volumes, local users and Wi-Fi are source-ready. | Native provider binding and selected-resource lifecycle; unknown/missing/managed states remain explicit. Inventory alone closes no mutation outcome. |
| B03 startup / Terminal / PATH | Two pending user-bin startup candidates, Terminal JSONC preparation and persistent user-PATH capture/preparation exist. | Complete one startup outcome first; then separately own Terminal live files and persistent PATH writes/recovery. Do not merge these outcomes or create a bin directory implicitly. |
| B04 proxy | Default/LAN capture/preparation, documented policy refusal, and an unregistered ShouldProcess-gated apply/restore candidate now compare current values, verify readback, preserve unowned values and attempt compensation after verified partial writes. Focused inventory/preparation/lifecycle regression passes 97/97. | Complete effective-policy coverage, durable saved state, atomic concurrency protection, engine/catalog integration and native/UI acceptance. Snapshot persistence is not part of the candidate; RAS and WinHTTP remain distinct. |
| B05 Store | Five guarded groups implemented; Solitaire basic isolated registration lifecycle accepted. | Clipchamp next when elevation/resources permit; GUI/data, interruption, full intended-user handoff, groups, policy and other targets remain open. News/Weather need usable reinstall sources. |
| B06 components | Namespace-aware inventory, explicit Online/LocalSource preparation and an unregistered guarded lifecycle candidate exist. The latest 2026-10-23 current-code preparation/lifecycle regression passes 47/47 mocked tests; Windows PowerShell 5.1 parses five relevant files; the candidate rejects pre-Windows 11 builds and blocks state-changing Absent transitions until recovery-source validation exists. | Matching-source/no-network proof, servicing-policy/dependency checks, exact payload recovery and disposable Windows acceptance. Hyper-V/CIM access remains blocked; no automatic WSL/Docker/Hyper-V provisioning. |
| B07 deployments | Named identity, registration/adoption review, logical legacy mapping and owned-file update comparisons exist. Q01-Q04 are settled. | Main CLI/profile integration, original-byte preservation, durable store/index migration, ownership, staged publication and interrupted recovery. Coexistence is approved design, not enabled runtime behavior. |
| B08 packages | Sixteen new package declarations are pending: six earlier candidates, whole Sysinternals Suite and nine individual Sysinternals products. Exact acquired bytes/notices are recorded. | Per-product lifecycle and functional acceptance. Source archives are not imported/executed; no new native acceptance came from the overnight or resumed batches. |
| B09 accounts / regional / assets | User/SID, language order/overrides and regional inventories/preparation exist. | Secure credentials, durable writes, exact recovery and native effects; asset source/rights and collision handling remain per deployment. |
| B10 complex products / offline / actions | Office XML/inventory, desired configuration and offline preflight/assembly are source-ready. OfflineBundle 0.7.0 includes source comparison and optional selected-profile assembly coverage. | Mandatory install/apply gate, full requirements/provenance and offline runtime acceptance; Office/driver/hardware/destructive actions retain their separate gates. |

The catalog remains **358 operations: 279 settings, 56 packages, one artifact,
22 Store declarations; eight groups and five profiles**. Eighteen new operations
(sixteen packages/two startup settings) remain pending; their count is not a
legacy burndown deduction. The [application outcome reconciliation](application-review-rounds-2026-10-12.md#current-dispositions-2026-10-17)
covers all R01-R13 review groups; their exact selector index remains authoritative.

Q17 Volatility 2 and Q20 ImproHound are explicitly retired and already deducted.
Q31 User .NET bookkeeping is closed without a numeric deduction. Earlier accepted
distributions, retirements and exclusions are retained, not counted again. The
LOKI Python implementation is excluded while the selected LOKI RS replacement
remains open; no whole LOKI outcome is newly closed. Deferred work remains counted.

### Completion order

[TODO.md](../../TODO.md#migration-closure-queue) owns the active queue. Work on one
closure candidate at a time; keep at most three ready priorities. Finish an
existing outcome before starting another general preparation API. When a real
gate blocks it, record the exact missing resource/acceptance and advance to the
next independent item. Do not wait for approval between authorized batches.

| Priority / existing outcome | First concrete work | Evidence required to close / recovery |
| --- | --- | --- |
| 1: B03 startup user-bin | Inspect the two existing candidates and profile-block ownership tests; finish any missing lifecycle/fixture behavior. Prepare the smallest source-pinned Windows 11 startup scenario for both installed PowerShell runtimes. | Prove intended-user ConsoleHost startup, duplicate/missing-bin behavior, repeat apply, exact prior-profile restore and refusal of unowned legacy snippets. Preserve bin contents and unrelated profile bytes. Only close the startup slice; persistent PATH, directory provisioning and WindowsApps repair stay separate. If resources are unavailable, leave native acceptance pending and advance. |
| 2: B08 / application R06 PSScriptTools | Reuse the pinned 3.2.0 archive and reviewed notices; finish its inert source-deployment lifecycle fixture, then use the existing serialized disposable-VM procedure if available/authorized. | Verify complete files, repeat deployment, owned removal, modified-file preservation and recovery on the declared target. Do not auto-import scripts, install dependencies or infer runtime function compatibility. Reconcile the original legacy outcome before claiming closure; any required functional evidence stays open. Rufus is an additional requested tool with hardware acceptance, not the first legacy-count win. |
| 3: B10 offline deployment gate | Connect the existing byte-bound profile coverage/preflight to actual install/apply entry points, preserving the versioned state/recovery model and explicit bundle selection. | Before any handler runs, fail missing, changed, wrong-source or unsupported dependency requirements; forbid network fallback. Mocked no-network/no-mutation failure checks first, then a minimal reviewed disposable offline deployment. Preserve failed staging, old bundles and saved runs. This is a capability completion; deduct only specifically accepted legacy outcomes it enables. |

Next ready work, after these or a documented blocker: B05 Clipchamp acceptance
when fresh elevation is available; B01 remaining 81 presentation reviews in
small families while preserving the separate GUI queue; B06 selected client
components; R05 exact collection source pinning and extraction/ownership. Do not
open all of these simultaneously. Broader B02/B04/B07/B09 work remains backlog,
not completed or abandoned because it is outside the active queue.

### Decisions, deferrals and retained technical knowledge

The [decision ledger](decision-session-2026-10-17.md) is authoritative for Q01-Q31
and later refinements. The broad policy pass is complete. Ask only a concrete
exception supported by technical evidence, not the same general scope again.
Shared artifacts use one package; licence/activation changes remain optional and
separate. The durable rule now also lives in the [deployment model](package-deployment-decisions.md#shared-installers-and-licence-tiers).

Explicitly deferred: new deployment-profile composition/default selections;
BitLocker/recovery TPM/boot/backup/retrieval setup; BloodHound CE backend-version
choice; standalone Neo4j/APOC pending a use case; MEGAcmd unless needed; dynamic
Store lists. Controller/default-branch certification stays at v3 RC. Entitlements,
credentials, publisher agreements, interactive elevation and GUI/hardware input
remain concrete per-task gates, not unanswered general policy questions.

The latest [artifact/updater review](decision-session-2026-10-17.md#artifact-compatibility-and-updater-review-continuation-2026-10-17)
requires replacement of eight destructive/fragile legacy acquisition wrappers;
those replacements are not yet implemented. The Zimmerman endless-retry suspicion was withdrawn: its
duplicate guard advances after failure. Actual outstanding issues are false
"current" results after discovery failures, early return before Sync, missing
local payload checks and ETag matching without URL identity. Nine bounded fixtures
passed, but no immutable full upstream pin or full updater execution was verified.
Publisher-page NirLauncher hashes are observations, not downloaded-byte proof.
TMOG's local licence file is machine-bound sensitive entitlement data: preserve it
and exclude it from shared kits/logs; copying it is not activation.

### Evidence and two-chat ownership

Read AGENTS.md, the overview, this section and the latest decision entries before
each new work sequence. Existing [resumed evidence](#resumed-implementation-results-2026-10-17)
records 63 coverage, 48 assembly, 122 presentation/catalog/search and 20 focused
task checks per native PowerShell edition, plus 225-file repository validation.
Do not sum repeated runs or rerun passed checks absent relevant changes. The
[231-file source inventory](../archive/evidence/resumed-source-handoff-index-2026-10-17.json)
and earlier inventory remain dated evidence, not VM pins or release provenance.
Preserve ignored `.local` caches, failed staging and recovery evidence; a Git
commit or archived chat alone does not retain those files elsewhere.

The implementation successor owns code, TODO, overview and implementation subject
ledgers. The decision successor owns additions to `decision-session-2026-10-17.md`
and presents only concrete exceptions; it does not edit implementation concurrently.
The implementation chat reads newly accepted decisions between batches and records
their application. This split avoids two writers updating the same status files.
No cross-thread messaging or new automation is required; repository records carry
the handoff. Keep the expired `ride-migration-overnight-to-05-00` automation paused.

Use Windows-native validation in this Windows-filesystem checkout. Disposable VM
work remains serialized, pinned to the actual candidate, and subject to existing
resource/elevation/acceptance gates. Never use the developer workstation as the
integration target, restart ArtCraft Launcher, change protected controllers/pins,
publish/release, or expand targets without applicable evidence and authorization.
This reconciliation changes documentation only and requires no runtime rollback.

All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact endpoints
147-201, rounded **145-200/about 175**. This pass closes stale question bookkeeping
and corrects current status, not a legacy feature. No new migration, retirement,
exclusion or runtime acceptance is claimed. Deferments and partial outcomes above
stay in the estimate until their individual exit evidence is recorded.

## Earlier analysis and batch history

The sections below preserve the planning and dated implementation sequence.
Use the archive handoff above and later decision entries when an earlier proposal,
count, work window or unanswered question has been superseded.

Reviewed 2026-10-17. The remaining source has been triaged across all five
migration groups. B01 presentation/guidance and the first B02 playback-endpoint
inventory slice are source-ready; see the [B02 record](settings-post-migration-review.md#b02-read-only-playback-endpoint-contract-2026-10-16).
B06 read-only component inventory, the requested Rufus candidate and the complete RegRipper 3.0 distribution candidate are also source-ready. See the [RegRipper record](application-migration-review.md#b08-regripper-30-distribution-candidate-2026-10-16) for pending native/runtime/parser acceptance and the retained transient test failure. The B03 user-bin startup renderer is now source-ready as two pending runtime candidates; [native startup and ownership acceptance](../powershell-profiles.md#existing-user-bin-startup-path-candidate) remain open. B08 also adds pending [Hex2text/ChromeSyncParser source archives](application-migration-review.md#b08-pinned-python-source-candidates-2026-10-16), with interpreter/functional acceptance open; ShimCacheParser remains deferred on its Python 2 blocker. B02 also has [adapter](../network-adapter-inventory.md) and [volume](../volume-inventory.md) identity inventories; native provider and selection acceptance remain pending. B03 also has a [pure Terminal JSONC field-preparation contract](../terminal-jsonc-preparation.md); live instance/file binding, selection and activation remain deferred. B04 now has a [default/LAN proxy observation contract](../user-proxy-inventory.md); native/UI/policy evidence, named RAS, setters and WinHTTP remain deferred. Continue independent source batches
under the overnight authorization. Postpone unresolved deployment identity,
interactive acceptance and ownership choices while completing independent work.

This document collects questions for the user's return. It links the existing
decision owners and proposes matching implementation batches. [TODO.md](../../TODO.md)
remains the actionable backlog and [MIGRATION-PLAN.md](../MIGRATION-PLAN.md)
owns estimates. Recommendations below are proposals, not newly approved choices.

## Overnight implementation authorization, 2026-10-16

The user authorized continuous implementation across the remaining batches,
including packages, settings and components, initially until 05:00 and extended
by the user on 2026-10-17 to **08:00 Europe/Copenhagen (06:00 UTC)**. Continue independent work without approval
between batches. Postpone tasks requiring the user's acceptance, credentials,
interactive elevation, entitlement or unresolved product decisions, recording
the exact next input instead of blocking other batches.

This supersedes the earlier package pause for this window. It does not accept
the proposed Q01-Q31 answers, authorize workstation integration tests, change
controller pins, restart ArtCraft Launcher or authorize release/default-branch
publication. Preserve existing accepted choices and prior evidence. Source-ready
changes, disposable runtime evidence and GUI/hardware acceptance remain separate.
At the deadline, start no further batch; complete required safe cleanup and
record the morning handoff here and in the existing subject ledgers.

The user also requested the separate **RIDE migration decisions** chat. Its
dedicated `decision-session-2026-10-17.md` record will hold explicit answers for
reconciliation by this implementation thread. Recommendations are not approval;
preserve the existing runtime and ownership boundaries when applying answers.

## Boundaries and coverage

The original 2026-10-14 planning kept packages paused. It included local source inspection and Microsoft
documentation; it made no GitHub API request, acquired no payload, submitted no
VM test and changed no Windows state. Elevation-dependent work is postponed while
the user is away. No new default selection or supported target was published.

The [source audit](../archive/evidence/remaining-migrations-analysis-2026-10-14.json)
records input hashes, catalog counts, every application review outcome and its
actual next gate, all 30 settings rows, and selectors in the inventory families.
It verifies a one-to-one join between the 79 application outcomes and their
13 review rounds. The 109-row application ledger contains 10 previously migrated,
19 accepted migration, one excluded, four explicitly retired and 75 pending/partial
review outcomes. The original 79-row review map is retained as dated coverage. Its rows
include configuration and Windows components as well as packages.

The documented inventory has 30 legacy families plus the separately requested
PowerShell appearance addition. Its 731 unique selector references are coverage
identifiers, including reverse choices and legacy spelling issues, not remaining
feature counts. Historical preset coverage and source-only functions need the
explicit reconciliation below. Existing accepted families still need post-migration
evaluation; a registry round trip does not establish a visible feature effect.

Static enumeration of all three legacy modules found no defined preset function
outside the inventory and no source-only function outside the documented extras.
Read-only repository validation passed for 340 operations, eight groups, five
profiles and 146 maintained PowerShell files. The planning checks verified all
31 question IDs, ten batch IDs, 17 local file/heading links and 12 input hashes.
These checks establish source/document consistency, not runtime acceptance.

| Estimate owner | Remaining legacy outcomes | Analysis and next gate |
| --- | --- | --- |
| Windows/application settings | 38-58 | All 30 remainder rows and earlier implemented families reviewed; presentation, GUI, managed/default and recovery gaps retained. |
| Packages/portable tools/artifacts | 52-67 | Q17/Q20 and the 2026-10-22 Paradox Data Editor, Weather Agent and Mail Checker retirements plus the 2026-10-23 classic Teams cleanup retirement reduce this range by six from its original 58-73. The dated 79-item review map includes cross-group scope; pending source candidates and deferred Neo4j/backend remain. |
| Windows components | 19-24 | The 2026-10-23 PowerShell 2 retirement reduces this range by one; WSL distro scope, NetFx3 compatibility intent and client-only Internet Printing are recorded. Source, data recovery and exact build/edition acceptance remain. |
| Accounts/configuration/files/assets | 25-35 | User identity, credentials, locale, files, browser preferences and deployment ownership reviewed. |
| Maintenance/actions | 8-12 | Updates, cleanup, hostname and Sysprep need action-specific preview, recovery and reboot contracts. |
| Total, rounded | 145-200 | About 170 for planning. Exact summed endpoints 142-196; rounded to nearest five. Six package outcomes and one Windows component outcome are retired. |

The B01 [session visual observation contract](settings-post-migration-review.md#b01-read-only-session-visual-observations-2026-10-17)
now separates five fixed native GET results from registry and GUI proof. Fake
interop tests passed in both editions; no native visual observation occurred.

## Decisions already settled

Keep these decisions when answering the new questions; do not restart their review.

- Intended-user work uses a separate process in the signed-in user's current
  desktop session. Refuse another session or no desktop. Mixed-profile ordering
  and recovery remain unimplemented; the user-only handoff has separate acceptance.
- Keep both Store workflows: optional grouped user uninstall/reinstall and a
  separate linked device policy. Keep every app unless explicitly selected.
  The five accepted groups include multimedia with Media Player/Sound Recorder,
  core utilities, productivity/support, consumer apps and Xbox dependencies.
- Exact reviewed identities, known `NonRemovable=false` and complete type/stub
  checks are the approved Store protection rule. `IsPartOfSystem` remains visibly
  unknown. News/Weather wait for a usable local reinstall source.
- Installation, portable copies and multiple acquisition kits may coexist where
  a product passes coexistence review. Each deployment owns its own state and
  destination. Current runtime still refuses conflicting editions; approval of
  the design did not implement coexistence.
- Retain the approved Python distribution choices, Gpg4win CLI/Kleopatra scope,
  ImageMagick installed/portable choices and separate interactive Npcap workflow.
  BloodHound CE and collectors are selected; backend deployment remains separate.
- Retain UK English display, Danish formats/keyboard/location/system locale and
  the selected time zone. Preserve the reviewed Office language requirements;
  product/channel licensing is a different question.
- Opera and the custom ISL route remain excluded. Organization content and
  security-agent removal belong to their external owners. PowerShell profile
  appearance is an accepted v3 addition, outside legacy completion counts.

See [application rounds](application-review-rounds-2026-10-12.md),
[settings decisions](remaining-settings-decisions.md),
[deployment decisions](package-deployment-decisions.md) and
[custom-library dispositions](custom-ride-dispositions.md) for exact authority.

## Reconciled decision-session answers, 2026-10-17

The user's [decision-session record](decision-session-2026-10-17.md) now accepts
Q05-Q12 and the selection-policy part of Q13. These supersede proposals below:

- Q05/Q06: OpenSSH Client and Telnet Client first, independently selectable,
  neither default; explicit Online/Offline source modes as described above.
- Q07: new administrator name and secure interactive password; existing accounts
  need a separate choice. No implicit adoption/reset; protect last usable access.
  No passwords in profiles, logs or recovery records. Enrollment is not activated.
- Q08: startup-only user-bin first, persistent user PATH a separate explicit
  setting. Keep the directory and its contents when removing either setting.
- Q09: select an existing Terminal profile identity and own only defaultProfile.
  Missing profile on another computer requires explicit reselection; unattended
  work reports unresolved selection. No profile/shell installation is implied.
- Q10: separate browser user preferences and explicit enforced policies, with
  visible scope/locking and individual-field previews. No blanket file replacement.
- Q11: reviewed operator assets or official sources with rights metadata;
  per-user where supported, machine/new-user defaults separate. Ask on conflicts;
  copying an image and applying it are independent actions.
- Q12: explicit adapter/profile, intended-user Wi-Fi with all-user provisioning
  separate; import and connection separate. Secure credentials and recoverable
  prior content remain prerequisites; ask before replacing an existing profile.
- Q13: curated versioned membership, individual or whole reviewed collection
  selection; propose upstream additions. Actual member lists remain unresolved.

These are accepted design choices, not native activation or proof of recovery.
No account, PATH, browser, asset, Wi-Fi profile or servicing state changed. Existing
dated records retain their historical unanswered status; current work follows
these accepted answers. Q14 onward remain governed by their latest explicit record.

## Matching batches

These are implementation boundaries, not a second task queue. Move a chosen
batch into the existing TODO/owner ledger and report its implementation and
acceptance separately. Package implementation is authorized during the overnight window; unresolved
product, identity and acceptance choices remain gates. Do not bundle a user preference, machine policy and installer together
just because one legacy function performed them all.

| Batch | Proposed scope | Why this order / exit evidence |
| --- | --- | --- |
| B01 | Input/audio, media/privacy, power, Explorer, App Privacy, update/maintenance, security and desktop/Explorer presentation source-ready; 198/279 reviewed | The resumed service/task batches add 19 presentations. Legacy reverse distinctions and exact reference scope retained; 81 presentation reviews and GUI/managed/physical acceptance remain. Unsigned capture/recovery and typed native power reads implemented with 63 tests per edition; native API/locale and physical acceptance stays open. Defender exclusion writes now bind capture path/membership and retain versioned recovery; hidden-list/native acceptance remains open. See the latest setting ledger. |
| B02 | Read-only playback-endpoint, adapter, volume, local-user and Wi-Fi profile identity contracts source-ready; other resources remain | Define selected connection, endpoint, adapter, volume, account SID, feature/capability and owned file identities. Inspect source/availability without mutation. Unknown, missing and managed states must be explicit. |
| B03 | Existing user-bin startup renderer source-ready, 2026-10-16; Terminal file ownership remains | Two optional runtime candidates reuse profile-block recovery and refuse known unmarked legacy writers. Native startup acceptance and directory provisioning remain open. Q08 persistent user PATH now has literal observation and entry-owned append/recovery preparation (44 distinct tests per edition); durable writes/refresh/native acceptance remain. Terminal JSONC root-field byte-preservation/conflict proof is source-ready; live file/instance binding, actual availability, writer and actual per-machine Q09 selection remain open. |
| B04 | Default/LAN capture and in-memory edit/recovery source-ready | 31 capture and 39 preparation tests per edition preserve manual/bypass/PAC/unknown flags and reject owned-field conflicts. Native/UI/policy, durable setter/refresh/partial-failure recovery and RAS remain open. Keep WinHTTP separate. |
| B05 | Store acceptance, one app at a time, then group/policy | Solitaire basic native registration lifecycle passed. Report and retain that result; next candidate is Clipchamp when elevation is available. Add interruption, GUI/data and full handoff evidence without rerunning passed cases merely on a wake. |
| B06 | Guarded OpenSSH Client/Telnet Client lifecycle source candidate, 2026-10-23 | Separate optional-feature/capability/Server-feature namespaces, explicit machine/build/edition guards and saved-data lookup implemented. Q05/Q06 accept separate clients and explicit Online/Offline modes. The unregistered runner saves prior literal state, gates DISM with ShouldProcess, verifies readback and refuses drift on restore. A fresh mocked suite passes 10/10 and Windows PowerShell 5.1 parses the three candidate modules and test file. Microsoft source review confirms OpenSSH Client is a non-satellite FOD capability and requires matching Windows 11 Languages and Optional Features media; Group Policy source fallback means LimitAccess alone does not prove no-network behavior. The candidate checks only local directory existence. Telnet source inventory, dependencies, exact payload recovery and native VM acceptance remain pending. See the [candidate record](#b06-client-component-guarded-lifecycle-candidate-2026-10-23). |
| B07 | Explicit deployment identity API source-ready; live migration remains | Q01 names/ambiguity behavior and Q02 adoption/replacement/bulk review accepted. 37 distinct identity/selection/completion checks passed per edition after a completion fix. Read-only per-view registration inventory now supplies a separate Q02 source slice (36 distinct tests per edition); offline matching now exposes per-distribution and cross-product ambiguity (104 relevant checks per edition). Existing records/CLI stay unchanged; native acceptance, durable compatibility and adoption ownership remain. Q03 host-folder/profile publication and Q04 verified staging/modified-file decisions are accepted. Logical legacy selection mapping is source-ready (20 tests per edition); durable byte/store migration remains. Q04 owned-file comparison now reports stage/remove/keep/conflict decisions (37 distinct tests per edition), with live staging/publication still pending. See the [record](application-migration-review.md#b07-explicit-deployment-identity-preparation-2026-10-17). |
| B08 | Pending portable/source candidates under overnight resumption | Prefer individually reviewed, self-contained tools with immutable file lists and no driver/service or runtime bootstrap. Rufus, RegRipper, Hex2text, ChromeSyncParser, PSScriptTools and Wireshark MSI now have inert candidates. Native/rights/runtime and Q13-Q15 choices remain; no whole-suite acquisition to discover members. |
| B09 | Accounts, regional configuration and owned assets | Read-only local-user SID and intended-user ordered language capture are source-ready, with separate display/input override observations order-only existing-language priority preparation/recovery, and separate format-culture/home-location/system-locale/time-zone observations. None resolves ownership, viable access or native regional mutation acceptance. Implement mutations independently after credentials, SID ownership, content source and reboot choices are settled. Do not disable a last viable administrator or overwrite shared assets. Q07-Q12. |
| B10 | Complex packages, security and maintenance | Drivers, Office/Teams, CE backend, encryption, WSL data, update installation and destructive cleanup follow their distinct dependency/recovery decisions. No default-profile activation or automatic reboot. Q16-Q27. |

The recorded B01 presentation slices and first B02 endpoint source slice are complete; neither whole batch is closed. B02 does not select a
resource for the user; its other resource contracts remain open. B03-B10 contain explicit gates; their
presence in this sequence does not authorize changing unknown state.

## Settings: complete remainder and accepted-family review

The [30-row triage](remaining-settings-plan.md#complete-remaining-ledger-triage)
is the detailed owner. Its exact rows are also captured in the source audit.
The following partition accounts for R01-R30 without treating their mixed
components as new independent legacy outcomes.

| Settings rows | Remaining work and classification |
| --- | --- |
| R01 | Power selection/owned copies have focused evidence; menu ownership and physical power-mode effects remain. Ultimate activation is conditional. Selection recovery, guard refusal and owned-copy compensation remain distinct. |
| R02 | Connection-scoped proxy detection/PAC and machine WinHTTP: B02/B04. |
| R03, R25 | CEIP/App-V and radio/WMDRM: typed lifecycle does not prove a present consumer. Find applicable components; otherwise retain pending evidence. |
| R04, R09, R11-R17, R26, R28 | Feedback, Storage Sense, taskbar/Terminal, shortcut arrows, NumLock, file colors, Explorer Home, three menus, five desktop icons, keyboard/effects and Windows Security icon: GUI/session/build mapping first. Terminal field ownership is separate from taskbar sizing. |
| R05, R08, R21-R23 | Windows RE association, System Protection, BitLocker/protectors/backup and failed-sign-in lockout: recovery readiness precedes state change; deleted restore points, encryption transitions and secrets are not registry undo. |
| R06 | Browser service Hidden selector retired; modern network-discovery outcome remains partial. Preserve retirement and network peer evidence separately. |
| R07, R18, R27 | Update interruption, Server Manager/Shutdown Event Tracker and WAP/Search: literal/fault recovery passed where recorded; actual warning/logon/shutdown/boot workload remains pending. |
| R10 | Accepted native F1 candidate remains experimental until actual Explorer/Desktop and other-app behavior is tested. No IFEO/ACL/AHK replacement. |
| R19 | Maximum-age boundaries/conflict guards passed on both targets. Complexity still needs a narrowly owned backend; IE ESC requires a real Server component and separate admin/user evidence. |
| R20 | Audiosrv native lifecycle passed; selected endpoint mute has its own identity/session/device-loss contract and UI guidance. |
| R24 | Photo Viewer registration must discover a native consumer and preserve exact extension bindings. Default association is a separate user UI step; no UserChoice hash bypass. |
| R29 | Closed 2026-10-17 under Q31/D09 as unsubstantiated bookkeeping. Retain the bounded source audit and reopen on evidence; no assembly deployment/removal or migrated-feature claim. |
| R30 | Store candidates and five groups implemented; Solitaire basic acceptance passed. Policy, other apps, interruption, data/GUI and full handoff acceptance remain open under the component owner. |

The [earlier accepted families](remaining-settings-plan.md#earlier-accepted-controls-that-still-need-evaluation)
also remain in scope: promotions and undocumented numeric channels; input/activity
and privacy controls; admin shares/.NET crypto; driver/metadata updates; maintenance
wake and discovery; notification/accessibility/taskbar/This PC; Explorer and Control
Panel/mouse controls; background apps/power; UAC/Defender/SmartScreen; diagnostic and
Office tasks; developer/trust/media controls; SMB/NetBIOS/NCSI and adapter bindings.
Review the whole legacy bundle, omitted behavior, independent utility, managed
precedence and explicit-value versus override-removal semantics. The catalog
has 279 setting operations. B01 desktop/Explorer review brings explicit presentation
coverage to 179; the other 100 remain unreviewed for explicit presentation. The
[latest B01 record](settings-post-migration-review.md#b01-start-taskbar-and-notification-presentation-2026-10-17) retains legacy reverse semantics and current default-profile recommendation gaps. This is not a count of accepted legacy outcomes.

## Applications: all 13 unresolved review groups

Prefixes here are **App Rxx**, distinct from settings Rxx. Exact selectors,
split ownership and individual next gates for every one of the 79 outcomes are
retained in the [audit crosswalk](../archive/evidence/remaining-migrations-analysis-2026-10-14.json)
and [application ledger](application-migration-review.md). Existing accepted
packages retain their own pending runtime/support evidence; accepted design is
not automatically an accepted installation.

| Group / outcomes | Complete product/component coverage | Remaining decisions or technical evidence |
| --- | --- | --- |
| App R01 / 4 | Gpg4win; installed and portable ImageMagick; Wireshark | Scope/integration preservation, nested installer behavior, installed/portable coexistence. Npcap is a separate interactive/rights/driver review. Q01, Q16. |
| App R02 / 5 | Python; YARA; Loki; Volatility 2; Volatility 3 | Preserve selected Python manager/traditional routes; model runtimes/pip/environment ownership. Pin dependencies/rules and separate updates. Volatility 2 explicitly retired by Q17; preserve its historical mapping and existing copies. Q18 accepts pinned dependencies and separate updates. |
| App R03 / 9 | ADReplStatus; RSAT; OpenJDK; Neo4j/APOC; BloodHound; SharpHound; AzureHound; ImproHound; PingCastle | RSAT is component-owned. CE backend is separately managed; optional deployment deferred. The user decided 2026-10-22 to keep standalone OpenJDK deferred pending an independent use case; BloodHound CE alone does not establish one. Q20 retires planned ImproHound and defers standalone Neo4j/APOC until an independent use case. Legacy Neo4j was Community ZIP plus matched APOC, unrestricted plugin configuration and service; preserve that analysis rather than inventing a modern compatibility guarantee. Q05/Q19/Q20. |
| App R04 / 6 | Office deployment; bundled Teams actions; Teams startup; Store Teams cleanup; classic machine-wide Teams cleanup; Visio | Independent product/channel/license/configuration and destructive cleanup scopes. Installing Office authorizes none of the cleanup actions. Q21. |
| App R05 / 8 | Sysinternals; JoeWare; MiTeC; NTCore; Zimmerman; Nirsoft launcher, x64 tools and package/config files | Freeze reviewed membership and file ownership; separate launch/configuration and restricted tools. No mutable collection crawl or implicit Defender exclusion. Q13/Q14. JoeWare is the latest user-selected next collection for focused review; its existing 41-name membership remains fixed. |
| App R06 / 4 | PSScriptTools; PartDiagParser; GglCookieCruncher; Sigma | Pinned release/source snapshot versus editable checkout; dependencies, import/execution and rule application are independent actions. Q15/Q18. |
| App R07 / 4 | OneDrive package; OneDrive sync policy; WinGet; WinGet AutoUpdate | Data and sync account ownership separate from uninstall. WinGet app presence does not implement a package provider. Scheduler/services/configuration and updater policy require separate ownership. Q22. |
| App R08 / 8 | VMware; its home/Documents directory choices; AutomatedLab; VirtIO; SPICE guest tools; SPICE WebDAV; Lenovo Vantage | User wants VirtIO and SPICE integrations when required for a full GNOME Boxes experience, and selected SPICE WebDAV as an optional guest-folder-sharing component on 2026-10-23. Verify devices, exact artifact and lifecycle on a matching QEMU guest; Hyper-V does not validate these. No default installation; configuration is separate from package installation. Q16/Q23. |
| App R09 / 5 | VeraCrypt installed/portable; Arsenal products; MEGAcmd helper; WinPmem | Coexistence, drivers, mount/encryption ownership and vendor access/license. Q24/R09 now includes all Arsenal publisher products with a free-use scenario; licensed-only products are excluded. MEGAcmd helper is not implicit prerequisite approval. Q01/Q16/Q24. |
| App R10 / 2 | Hashcat; HashcatLauncher | GPU/runtime/resource discovery and executable identity/quoting; controlled lab acceptance, no cracking job on installation. Q23. |
| App R11 / 4 | Olaf Sysmon configuration; legacy Edge prediction; Firefox preference files; Chrome preference file | Config source/pin and owner; reconcile current managed/user meanings and preserve unrelated fields. Sysmon download and policy application are separate. Q10/Q25. |
| App R12 / 9 | KAPE; CCleaner portable; Defraggler; Recuva; Speccy; TMOG; PST viewer; OST viewer; WinHex | Current official access, use terms/edition and supported targets; no product substitution for a stale route. Piriform-family tools are four separate outcomes. Q24. |
| App R13 / 11 | FirewallNotifier; Autorunner; ChromeParser; Hex2text; ShimCacheParser; SSView; ThumbcacheViewer; SuperFetchTools2; UserAssist; ThumbsViewer; RegRipper | Exact official artifacts, architecture/runtime detection, licenses and owned files. Shell/driver/rules/config integration is explicit. Potential first portable batch after source checks and pause removal. Q13-Q15. |

Current package handler supports EXE, MSI, managed portable payloads and its
special Sysmon ZIP path; it has guarded ZIP installer-entry handling. It is not
EXE-only. This does not establish support for arbitrary archives, MSIX, a whole
suite, nested installers or independently coexisting deployments. Provider choice
(publisher HTTPS/API/page or GitHub metadata) and distribution choice are different
dimensions. Future WinGet/PSGallery routes need explicit adapter review, source
provenance and fallback rules; do not silently substitute them.

## Components and concrete resource objects

Discover exact feature/capability identifiers, edition/build, parent/dependency
state, source requirements and whether payload/data are present. Capture before
enabling or removing; a component's inverse command is not proof of exact recovery.
Use existing native object kinds where appropriate. A generic "object" handler
would hide these different ownership boundaries.

The [component inventory tool](../windows-component-inventory.md) implements
bounded read-only provider observations and saved-data lookup. It does not yet
establish dependencies, payload sources or native target acceptance.

| Component/resource family | Plan and recovery boundary |
| --- | --- |
| WSL feature and Debian/Ubuntu/Kali/Fedora registrations | Debian, Ubuntu and Kali remain separately selectable opt-in outcomes, including Debian when available as a WSL distribution. Do not install or unregister distributions automatically; prove export/retrieval before unregister. The unmatched Fedora removal selector remains retired. |
| Store user registrations and device removal policy | Keep accepted inventories/groups/protection rules. Policy consumer and schema need their own sign-in tests; package presence alone is not availability. No AllUsers removal or image deprovisioning in the user groups. |
| Windows Store itself and repair | Distinguish blocking Store UI, Store registration repair and app removal. Require identified local payload/consumer; never reconstruct protected shared packages from a historical wildcard. |
| Xbox features/dependencies | Distinguish policy settings, five reviewed gaming apps and shared frameworks/services. Refuse removal when other consumers or protection evidence are unresolved. |
| Adobe Flash and standalone Internet Explorer | Check actual component and supported release meaning. Propose retirement of absent/obsolete toggles only with source/applicability evidence; existing IE ESC/IE-mode requirements remain separate. |
| Edge preload/shortcut, first run/logon, media sharing/online, developer/fullscreen controls | Reconcile earlier registry implementations with the complete legacy bundle. These are settings/consumer acceptance, not optional-feature installer work. |
| Optional Windows Media Player | Discover native feature versus Store Media Player; separate from radio/WMDRM consumer and multimedia group. |
| Work Folders | Feature/role and configured sync data/credentials have separate lifecycle. Removing the feature does not recover deleted or unsynced files. |
| Windows Hello Face | Capability, camera/hardware and enrollment are separate; no deletion of existing biometric enrollment through generic recovery. |
| Math Recognizer | Enumerate availability per build; absent capability stays not applicable. Do not fetch old payloads to emulate an obsolete component. |
| Windows PowerShell 2 / ISE | The 2026-10-23 decision retires the legacy PowerShell 2 enable/disable outcome and tracks ISE separately. ISE availability does not establish PowerShell 7 support. |
| Hyper-V / Windows Sandbox | Hardware, edition, parent features, restart and existing VM ownership. Sandbox configuration/network/drive exposure is a separate explicit file workflow. |
| OpenSSH Client / Server | OpenSSH Client was selected first; OpenSSH Server is now also in v3 scope as a separate optional outcome. Server service, firewall, host keys and configuration have independent capture/ownership. Neither is selected by default. |
| Telnet Client | Small conditional feature candidate; no server/service/network-use implication. |
| .NET 2.0/3.5 legacy selector | Keep .NET Framework 3.5 as an explicit conditional compatibility outcome, selecting feature versus standalone route from exact build with matching local servicing sources and no network fallback. Do not infer equivalence to the Phoenix .NET 2.0.50727 launch condition. |
| Photo Viewer | Discover consumer; exact Open with registration under intended user, native default-app handoff separately. |
| Microsoft Print to PDF / XPS | Feature and existing queues/ports/drivers separate; preserve custom queue configuration and refuse deleting unknown resources. |
| Fax printer / Windows Fax and Scan | Separate queue, feature/service, devices and stored fax data; no assumption that adding a queue restores the prior fax setup. |
| Internet Printing | The 2026-10-23 decision limits the outcome to the client optional feature used by the legacy functions; the Server role and externally reachable service are out of scope. Native servicing/recovery acceptance remains. |
| RSAT | Client capability versus Server management feature; exact subtools from selected role, matching source/edition. Package App R03 points here. |
| Memory Integrity | VBS/code integrity setting, driver compatibility and reboot evidence; not a generic install/remove feature. |

Microsoft now documents .NET 3.5 as a standalone installation starting with
Windows 11 26H1 build 28000, rather than a Windows component. Choose the route
from exact build and discovery; a release label alone is insufficient. Existing
26300-family VM evidence cannot prove the 28000+ route.
[Microsoft .NET 3.5 guidance](https://learn.microsoft.com/en-us/dotnet/framework/install/dotnet-35-windows-11).

FOD media must match the Windows image and retain required metadata/satellite
packages. An explicitly local source plus `LimitAccess` is required when testing
without Windows Update/WSUS fallback; do not treat capability payload acquisition
as a harmless settings test.
[Microsoft FOD guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11).

The current Store policy guide describes both a static selection list and a
dynamic Package Family Name list, with schema differences during rollout. It
limits the feature to Windows 11 Enterprise/Education, excludes multi-session,
and describes sign-in/provisioning removal and reinstall blocking. Policy removal
does not restore app data. Inspect the local template and exact CSP applicability;
do not extend the existing static candidate or claim Pro/Home/Server support from
the guide alone. Dynamic-list support is a new review item Q26.
[Microsoft policy guidance](https://learn.microsoft.com/en-us/windows/configuration/policy-based-inbox-app-removal/policy-based-inbox-app-removal).

## Accounts, configuration, files and assets

| Remaining outcome | Ownership, implementation and acceptance plan |
| --- | --- |
| New local administrator | Secure interactive enrollment; capture exact SID and created-account ownership. Existing account collision refuses. Never restore by deleting an account with new user data. |
| Built-in Administrator disable / current-user admin membership | Resolve accounts/group by SID, test final viable administrator and recovery access. Remove only owned membership; explicit prompt before lockout-sensitive transition. |
| Display language packs GB/DK/custom | Preserve accepted choice; installed language discovery separate from acquisition/FOD source, removal and dependent user profiles. Reboot/sign-out reported, not automatic. |
| User regional/language/keyboard settings | Preserve approved mixed locale; capture entire relevant ordered user language list without overwriting unrelated choices. Intended-user session required. |
| System locale/time zone and welcome/new-user copying | Independent machine actions with exact scope and restart/default-profile evidence. Copying user settings is not equivalent to restoring every affected account. |
| PowerShell startup user-bin PATH | B03 pending runtime candidates own startup blocks for an existing directory and normalize equivalent PATH entries. Legacy immediate-session changes are not reproduced by apply. Native startup, inherited PATH, unmarked writers, directory provisioning and persistent environment selection remain separate acceptance/decisions. |
| Wi-Fi profiles | Select interface/profile scope; securely capture prior XML/ACL and UTF-8 SSID bytes, escape XML and redact PSK. Legacy creates plaintext temporary content; do not port that workflow. Import does not implicitly connect. |
| Windows activation / product-key inspection | Report licensing state separately from operator activation. No secrets in normal state or logs; vendor entitlement and secure entry/retrieval remain explicit. |
| VMware VM directory preferences | Exact file/field ownership and chosen root, no moving existing VMs or overwriting other preferences. App R08 dependency is availability, not automatic package install. |
| Firefox / Chrome preferences | Decide managed machine policy versus intended-user file/default; field-level recovery and custom profiles before broad preference-file creation. |
| Sysmon configuration / logging settings | Download a pinned reviewed config independently from applying it. [Configuration ownership ADR](../decisions/0001-configuration-ownership.md) is accepted through Q25: RIDE writes explicitly selected configuration, LoggingBaseline observes/reports; export and consumer acceptance remain open. |
| Python environment, associations, plugins and symbols | Distribution-owned environment versus selected user/workspace; preserve existing associations and independent caches. No arbitrary pip/network action on installation. |
| Fonts | Official/licensed source, per-user versus machine scope, exact font identity/collision/registration and ownership. Legacy COM copy/overwrite is not an accepted recovery backend. |
| Wallpaper / lock-screen / default lock-screen | Asset deployment distinct from user preference/device policy. Capture prior file/ACL/config, refuse overwriting shared OS-owned content. Missing/licensed assets need source decision. |
| Context menus, shortcuts and shell resources | Exact bindings/resource paths/quoting/views/ACLs, all relevant consumers and user context. A file or registry subtree is owned only to the declared extent. |
| Deployment/toolkit publication manifests | Q03 accepts a named profile-selected host folder with per-product/distribution ownership, versions/hashes and notices. Manual transfer needs no USB enrollment or persistent volume binding. No formatting, implicit execution or unreviewed redistribution; offline installer bundles are separate. |

Local source review confirms important gaps: legacy account creation takes a
password from process configuration or prompts; disabling Administrator identifies
it by a localized name; Wi-Fi builds a plaintext PSK XML and encodes characters
rather than SSID bytes; font copying removes existing targets; hostname change
prompts and does not reboot. Preserve intent, replace those mechanics with explicit
ownership and recovery. These findings do not authorize a credential migration or
developer-workstation experiment.

## Maintenance and execution actions

| Outcome | Required contract before implementation |
| --- | --- |
| Public desktop cleanup | Preview exact owned/selected shortcut paths; archive restorable bytes/ACLs before deletion. No blanket deletion of user files. |
| Start/taskbar unpinning | Per-user, current-build supported workflow or native guide. Preserve unrelated pins; no guessed shell verbs or broad reset. |
| Windows update action | Pinned PSWindowsUpdate evaluation after acquisition resumes; scan, selected download/install, per-item results, source preservation, pending reboot and rescan separate. Win11 builds and Server Core/DE need distinct acceptance. |
| Windows Update cache cleanup | Check busy operations and capture service identity/state; distinguish metadata/payload cleanup. Deleted update content is not exact restore; no WSUS/source override. |
| Disk Cleanup | Explicit volumes/data classes and preview. Discarded file content cannot be restored through a settings snapshot. |
| Product-key display | Explicit secure display with redaction and no persistent secret in normal logs/manifest. Separate from activation. |
| Sysprep Generalize/OOBE | One-way machine transition, explicit selection and independent recovery image/checkpoint; not an invertible setting or routine maintenance default. |
| Hostname | Validated unique name, captured prior identity and pending restart; domain/management impact guarded. No developer-host change or automatic reboot. |
| Wait/restart/stop helpers | Engine/UI control-flow and explicit terminal actions, not desired-state catalog settings. Pending work/records and partial failures survive restart or cancellation. |

Runtime/rule updates (pip, Loki/Sigma, Volatility dependencies, WinGet AutoUpdate)
belong to separately selected maintenance/configuration workflows. GitHub PAT,
controller certification, release-candidate delivery and default-branch cutover
retain their own ledgers; they are not completed application migrations or a
reason to restart the closed ArtCraft Launcher.

## Custom source, unresolved selectors and additions

The [custom review](custom-ride-dispositions.md) remains authoritative. Coverage
is explicit so private/external work is not silently pulled into RIDE.

| Source class | Disposition and remaining analysis |
| --- | --- |
| RawCopy, Etl2pcapng, FTK Imager | Retain intended capabilities; current supported artifacts, prerequisites and licenses still need product-specific validation. Historical FTK download evidence is dated, not a fresh release check. No harvesting DLLs from an installed application. |
| DumpIt, ProcessCapture, RAMCapture, Encrypted Disk Detector, USB Detective | Conditional source/edition/access and driver/prerequisite review. Local filenames do not establish versions, license or present availability. |
| OpenSauce fonts / generic asset scripts | Licensed font/content handling belongs to the generic owned-asset workflow. Power-plan and Wi-Fi duplicates map to the core outcomes. |
| SOC documents, wallpapers/content, Outlook templates, VPN | Existing external owner decisions retained. Organization IT owns VPN deployment; SOC content storage/repository remains independent of RIDE. |
| Logging/audit/SACL/tenant automation | Keep external scope and confirm the proposed configuration ownership boundary. Do not duplicate security-policy writers. |
| Agent bypass/removal and mutable broad lab runners | Existing exclusions retained. No legacy wrapper/preset compatibility runner. |
| Supplemental README tools | capa/FLOSS, Detect It Easy, x64dbg, peStudio, browser utilities, HxD, Volatility Workbench, Hash Suite Free, Ophcrack, ExifTool, OfficeMalScanner, steghide and related specialists remain explicitly proposed/conditional. ThumbcacheViewer already maps to App R13. No silent substitution of oletools for OfficeMalScanner. |
| SwitchyOmega / HashCalc aggregator route | Preserve disregarded original routes; a maintained proxy extension or native hashing outcome would be a separate reviewed requirement. |
| Requested v3 additions | Rufus has a [pending source candidate](application-migration-review.md#b08-rufus-portable-source-candidate-2026-10-16); idrassi HashCheck and the two hash-context-menu options remain queued separately from legacy estimates. No automatic media writing; attribution/algorithm/quoting/GUI and shell lifecycle need evidence. |
| New shortlist | FTK Imager, Hayabusa, MemProcFS, Velociraptor, Security Compliance Toolkit, WinDbg, YARA-X, capa, FLOSS and Ghidra are research candidates. Their placement in [candidate-tools](../candidate-tools.md) is not selection approval or current release certification. |

For the [23 source-only functions](../MIGRATION-PLAN.md#library-functions-outside-the-preset-inventory),
classify explicitly: six firewall functions overlap modern accepted profiles;
four typo aliases map to BitLocker/browser retirement/Nucleus/WinSCP review;
`DisableWSUS`/`EnableWSUS`, Entra Connect and Nucleus need separate applicability
and scope decisions; ten bootstrap/download/export/query helpers are engine
infrastructure rather than new desired-state outcomes. Nucleus appears in both
alias and prospective product review, so those classifications overlap.
Preserve the actual 23-name list; do not add these counts to the estimates.

The seven [preset reconciliation entries](../MIGRATION-PLAN.md#preset-references-to-reconcile)
remain traceable. The user retired the unmatched `EnableInkingAndTypingData` and
`RemoveWSLFedora` selectors on 2026-10-22; no setter or Fedora removal semantics
are inferred. `RequireAdmin` is a prerequisite directive, not an operation.

## Questions for the user's return

Current status: Q01-Q31 policy answers and subsequent refinements are recorded in
the decision ledger. Question-shaped labels below preserve traceability; they are
not requests to repeat approval. Later accepted membership, shared-installer and
explicit deferral entries control over earlier proposals. Actual per-deployment
inputs and technical acceptance remain open as listed in the current handoff.

The original discussion grouped Q01-Q04 and Q05-Q12; those choices are now settled.
Technical API/build/provenance checks remain implementation research; the user
need not decide undocumented mappings. Earlier settings D02-D10 retain their
technical acceptance questions and later explicit deferrals in the settings plan.

| ID | Decision needed | Recommended starting choice and consequence |
| --- | --- | --- |
| Q01 | Accepted 2026-10-17: explicit named deployment identity | Product-only mutation refuses ambiguity; inspection exposes independent copies. In-memory selection source-ready; main CLI/profile and versioned record migration remain. See [decision](decision-session-2026-10-17.md#q01-explicit-deployment-identity). |
| Q02 | Accepted 2026-10-17: adoption plus explicit replacement | Existing installations must be adoptable without replacement. First-run supported-package review permits bulk adoption; ambiguous matches are handled individually. Ownership/backup/recovery design remains; no workstation adoption authorized. See [decision](decision-session-2026-10-17.md#q02-adopt-existing-installations-and-offer-explicit-replacement). |
| Q03 | Accepted 2026-10-17: named profile-driven host-folder publication | Standard product/distribution layout, chosen root, manifest/hashes/notices. Operator transfers manually; no USB tracking or volume enrollment. Offline profile-selected/full bundles are also accepted; mandatory installation preflight/native acceptance remain. See [decision](decision-session-2026-10-17.md#q03-profile-driven-toolkit-publication-to-a-host-folder). |
| Q04 | Accepted 2026-10-17: staged publication updates and explicit modified-file decisions | Build/verify before changing the host publication; update managed files, remove unchanged obsolete managed files, preserve unrelated/generated data. Ask before replacing modified managed content; retain modified obsolete files. Commit/journal/recovery and conflict handling need validation. See [decision](decision-session-2026-10-17.md#q04-staged-toolkit-updates-with-explicit-modified-file-decisions). |
| Q05 | Accepted: separate OpenSSH Client and Telnet Client | Start individually with OpenSSH Client/Telnet Client where available; add Server/RSAT/Hyper-V/Sandbox/WSL only as separate roles with their dependencies. None selected by default. |
| Q06 | What servicing media/source may be used? | Accepted: explicit Online respecting configured sources/policy, or Offline with matching local source and no network fallback. No implicit default; source and offline-boundary acceptance remain. |
| Q07 | Accepted 2026-10-24: include guarded local administrator enrollment in v3 | Use an explicit new account name and secure interactive password; store no secret in profile/config/state; refuse existing-account collision and protect the last viable administrator. Credential rotation/recovery and native acceptance remain separate gates. |
| Q08 | Does user-bin mean PowerShell startup only or also persistent Windows PATH? | Migrate the actual legacy startup-only block first. Offer persistent user PATH only as a separate explicit outcome; preserve directory contents on removal. |
| Q09 | Which Terminal default profile may be selected? | Discover current profiles and ask for an existing identity; own only root defaultProfile. No guessed executable/path or Terminal installation. |
| Q10 | Should browser preferences be managed policies or user preferences? | Separate explicit managed policy from user-file preference choices. Import no blanket legacy preference file; preview owned fields per existing profile. |
| Q11 | Where should fonts/wallpapers/lock-screen assets come from and what scope? | User-supplied reviewed manifest plus official license/source; start per-user where supported. Machine/default-user changes stay separate and collision-refusing. |
| Q12 | Which Wi-Fi scope and connection behavior? | Explicit current-user profile and interface, import without connecting; machine/all-user provisioning separate. Secure credential entry and recoverable existing profile are prerequisites. |
| Q13 | Accepted: reviewed collections and later membership decisions | Follow the later Sysinternals, Zimmerman, NirSoft, JoeWare, MiTeC and NTCore scopes in the decision ledger. Pin exact member inventories; new upstream members need review. The prior RIDE v2 specialist approval covers Sysinternals in RIDE; the current package migration is not blocked by licensing. |
| Q14 | Accepted: separate local review, installation and publication | Pending local review alone does not block unattended installation. Keep exact product/version/owner assessments local; publication omits members lacking applicable redistribution review. No catalog approval default. |
| Q15 | Pinned source snapshot or editable development checkout? | Pinned inert snapshot for deployment; explicitly separate clone/update/import/execute workflows for development tools and rules. |
| Q16 | Which integrations should drivers/nested installers enable? | Minimum product-specific reviewed integration; service/driver/reboot requirements explicit. Preserve earlier Gpg4win/ImageMagick/Npcap decisions and collect only unresolved installer flags. |
| Q17 | Accepted: retire planned Volatility 2 deployment | Preserve selector history and all existing installations/data. Continue separately selected Volatility 3; do not claim every historical workflow is replaced. |
| Q18 | What rules/plugins/dependency set should be maintained? | Pinned core deployment and separate explicit rule/plugin update actions; broader analyst extras selectable, no arbitrary network execution during install. |
| Q19 | Which BloodHound CE backend deployment should RIDE own? | Keep workstation collectors/client separate; choose a managed backend/container environment explicitly. No implicit Docker/WSL or Server Docker Desktop installation. |
| Q20 | Accepted: defer standalone Neo4j/APOC, retire planned ImproHound | Neo4j/APOC remains counted pending an independent use case. Preserve existing installations and data for both. ImproHound is an explicit retired outcome, not implicit CE equivalence. |
| Q21 | Office/Visio choices accepted; technical acceptance open | Microsoft 365 Apps enterprise, Monthly Enterprise default/Current option; fresh x64/existing match/explicit x86; standard sign-in with activation-pending continuation. Separate 2016 Retail/Plan 2 Visio, en-US/da-DK exception, optional Teams and separate startup/cleanup. Extra-language compatibility and native recovery remain open. [Record](application-migration-review.md#b10-inert-office-configuration-review-2026-10-17). |
| Q22 | Accepted: OneDrive preservation and opt-in updater | Preserve accounts/sync/files. Updater defaults to an explicit package list; broad eligible-except-exclusions mode is explicit. Approved sources/pins, separate schedule, no automatic reboot or forced app closure. Eligibility, identity and upstream behavior still require implementation. |
| Q23 | Accepted priority: VMware workstation installation first; GNOME Boxes guest integrations include VirtIO and SPICE when needed for full experience | Preserve VMs/preferences; directory configuration separate with no relocation. Verify which VirtIO drivers, SPICE agent and SPICE WebDAV are required on a matching QEMU guest. Edition/source, hardware/GPU roles and native acceptance remain open; Hyper-V cannot establish QEMU guest behavior. Decision 2026-10-22. |
| Q24 | Accepted: FTK Imager, then KAPE; eight Arsenal products selected | Later Arsenal/KAPE entries settle scope; MEGAcmd remains deferred unless needed. Artifacts, terms, drivers and functional evidence remain. FTK source inspection found CodeMeter; no installer was executed. |
| Q25 | Accepted: RIDE owns configuration | ADR 0001 is accepted. LoggingBaseline remains read-only observation/evaluation/reporting, with separate measurement thresholds. Schema-1 desired-reference export is source-ready; consumer/native mapping acceptance pending. Sysmon download and application separate. |
| Q26 | Accepted: validate existing reviewed Store selection first | Preserve optional uninstall/reinstall groups and separate device policy. Dynamic-list support is deferred to an independently validated extension; no identities or target support expanded. |
| Q27 | Accepted: explicit destructive maintenance and disposable-cache exception | Preview affected data and recovery limits. External backup/checkpoint required for destructive transitions including Sysprep; explicitly selected, defined disposable caches may omit backup. No implicit reboot/shutdown or ordinary-install cleanup. |
| Q28 | Accepted acceptance order | Explorer/desktop icons/keyboard first, then Server sign-in/shutdown, then application and hardware-dependent cases. Defer unavailable resources; no GUI/boot/hardware result accepted from ordering. |
| Q29 | Accepted: visible but unavailable when reliable recovery is absent | Retain menu requirements with limitations and accurate manual guidance. No guessed registry/ACL reconstruction and no retirement; resume after exact recovery is demonstrated. |
| Q30 | Accepted: explicit resource identity, optional captured current-default audio | Show friendly names but retain stable audio/adapter/volume identity; recovery uses the same resource. Missing device is reported without fallback. Existing all-visible adapter compatibility remains explicit. |
| Q31 | Closed: unsubstantiated User .NET assemblies bookkeeping | Retain the bounded audit; reopen when a source/use case appears. No guessed deployment or removal. This is not a migrated/retired feature or a numeric legacy outcome deduction. |

## Deferred elevation and VM work

| Deferred work | What is ready / why it waits |
| --- | --- |
| Clipchamp isolated Store lifecycle | Separate UAC-enabled offline test desktop exists, with original pins unchanged. Its PowerShell Direct host runner requires a fresh elevation prompt; do not launch while AFK. No app was selected or removed by this planning pass. |
| Store interruption/group/full handoff and policy tests | Basic Solitaire already passed; use new explicit focused modes and exact current-source snapshot for genuinely missing evidence. Sign-in/GUI/data and policy schemas stay distinct from registration recovery. |
| Feature/capability installation and OS/FOD sources | Read-only inventories can be prepared independently; actual servicing may need media, acquisition and elevated worker access. Use available pinned disposable flow only, never the workstation. |
| Local accounts, locale/welcome settings, drivers, boot/security transitions | Postpone any host enrollment/provisioning or interactive credential/elevation action. Secure recovery resources, explicit SID/hardware scope and staged fixture are required before VM mutation. |

When a test is needed, follow [AutomatedLab tasks](../../tests/integration/automatedlab-tasks.md):
verify idle workers/empty queues/no recovery block, pin/config/script hashes,
exclusive serialization and current local source hashes, including relevant
uncommitted files. Use settings-focused isolated fixtures, bounded failure
collection and final checkpoint recovery. Do not substitute frozen CI source for
current changes, repoint original controllers, run Full/default acquisition suites,
or treat a passing guest run with failed recovery as acceptance. No completed
fixture needs rerunning merely because the thread wakes.

This analysis covers the documented remaining scope; implementation and runtime
acceptance remain separate. After B01, the next source batch is B02: prepare a
bounded read-only selected-endpoint capture contract and fixtures, retaining
D08/Q30 as the decision boundary for a future mute setter. Do not select a
device, resolve that preference implicitly or change Windows during preparation.

## B06 component inventory implementation, 2026-10-16

Source: f53ce6ab102a plus the focused working patch. RIDE maintainers own this
observation schema and source validation; target operators supply native evidence.
The [operator guide](../windows-component-inventory.md) is the authoritative procedure.
The new RIDE.ComponentInventory module and Export-RideComponentInventory tool keep
OptionalFeature, Capability and ServerFeature identifiers separate. OptionalFeature
covers the Windows Foundation Package, not all packages. Raw states remain literal,
including future unfamiliar states. No dependency, payload, policy or reboot claim
is derived from presence. No component is selected or changed.

Capture requires existing elevation and explicit machine/build/edition, refuses
nonnative bitness and unknown product type, and rechecks context/update revision
afterward. Each selected provider either completes within the 4096-row bound or
reports Unavailable with no partial rows. Known client product type makes only the
ServerFeature provider NotApplicable. Native calls have no hard timeout. DISM logs
use unique explicit local evidence paths; failures retain diagnostics. No fallback
provider, online source, mount, remote query or automatic elevation is attempted.

Saved lookup reports Observed, NotObserved within declared coverage, Unavailable,
NotApplicable or NotCollected. It requires exact names and does not substitute a
similar capability/role. Completion reads only the supplied successful namespace.
ReadyForMutation and RecoverySupported remain false; this is not engine saved state.

From the Windows checkout, run ComponentInventory.Tests.ps1 using installed Pester
5.7.1 on native PowerShell 5.1.26100.9711 and 7.6.5, workspace-local process TEMP/TMP,
TestRegistry disabled and WindowsIntegration excluded. **20 tests passed per edition**.
Cases cover pre-query identity/elevation, casing/duplicates, missing evidence path,
literal unknown states, empty versus failed enumeration, partial-output discard,
row bounds, client/server provider separation, post-query update drift, saved JSON,
lookup/completion and preview/non-overwriting export. Initial test splatting used the
automatic args variable; the dedicated target-splat correction passed. Repository
validation passed on both editions: 340 operations, eight groups, five profiles and
152 PowerShell files. No live DISM, Server Manager, registry write, acquisition or VM.

Native acceptance remains postponed for fresh elevation. On an authorized disposable
Windows 11/Server target, follow the guide, compare each provider against its native
output, record exact build/edition and failure logs, then inspect saved JSON without
elevation. A successful inventory is not component activation. Q05/Q06, matching
local media, dependencies, pending reboot, existing consumers and removal recovery
precede any servicing candidate. Do not enable Telnet/OpenSSH merely because they
appear in an example.

Source recovery removes only the new module/tool/tests and related links. No runtime
state needs reversing. Retain/export or explicitly delete only the chosen evidence;
a failed JSON write can be incomplete and requires a new name after correcting the
error. No automatic cleanup of shared log directories. Prior engine records unchanged.

Resolved: B06 read-only source slice. Retired/excluded: none. Partial: conditional
components and other B02 resource families. Deferred: native collection, selection,
source and servicing acceptance. All five estimate ranges reviewed and unchanged:
38-58 settings, 58-73 packages, 20-25 components, 25-35 accounts/assets and 8-12
maintenance, rounded 150-205/about 180. No complete legacy outcome is established
by observation contracts. Next: B08 individually reviewable portable products;
continue independent batches until the authorized deadline.

## B02 local user identity inventory, 2026-10-17

Source f53ce6ab102a plus the overnight patch. RIDE.LocalUserInventory and its
exclusive JSON exporter 0.1.0 capture bounded local-user SIDs with Name, nullable
Enabled and literal PrincipalSource. They call module-qualified Get-LocalUser
only after expected local machine/build/edition/native-process checks, then reject
context/update-revision drift. Missing SIDs stay visible but unselectable; malformed,
duplicate, failed or over-1024-row results discard all partial rows as Unavailable.
Captured-empty remains distinct. Provider duration has no hard timeout.

Saved-data lookup and completion use exact normalized account-form SIDs, never
names, RID guesses or built-in-account defaults. UInt32 bounds are checked before
Windows SID parsing. An initial boundary test found that the native parser accepted
an oversized component: both editions initially passed 25/26. Explicit bounds
were added to capture and completion; both then passed all 26 focused tests.
Initial failed summaries remain in local evidence. No real Get-LocalUser/context
query or workstation account change ran. Export tests write isolated fixture JSON.

Native PowerShell 5.1.26100.9711 and 7.6.5 passed repository validation: 347
operations, eight groups, five profiles and 176 PowerShell files. Catalog, profiles,
supported targets, controller pins and existing B01 work remain unchanged.
The [operator guide](../local-user-inventory.md) defines privacy, prerequisites,
preview, exclusive output, saved lookup and the distinction from account recovery.

Next: collect on a serialized disposable target with independently supplied identity;
compare local/built-in/renamed/Microsoft-connected users and failed-provider cases.
Native provider, domain-controller applicability and permissions remain acceptance
items. Before any account change, separately resolve SID ownership, membership,
credentials, independent viable administrator access and recovery. Q07/Q30 are
not answered by enumeration. No directory, group, profile, password or sign-in
viability is inferred. Output is not an account backup and cannot undo deletion.
Preserve partial output after write failure and choose a new path; no account
recovery is needed for collection. Source rollback removes this isolated module,
exporter, tests and guide only; preserve collected evidence.

Resolved: bounded local-user identity observation contract. Retired/excluded: none.
Partial: account/resource identity preparation. Deferred: native collection and
all account/membership/credential decisions and mutation acceptance. All five
ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180: no
legacy account outcome is closed. Presentation remains 55/279, 224 open.

## B09 user language list inventory, 2026-10-17

Source f53ce6ab102a plus the overnight patch. RIDE.UserLanguageInventory and its
exclusive JSON exporter 0.1.0 capture ordered language tags, literal InputMethodTips
and available nullable Handwriting/Spellchecking flags. Expected local machine,
build, edition, native process, interactive execution SID and nonzero session are
checked before collection and again afterwards, including update revision. Import,
lookup and completion never query Windows. A matching session does not establish
active-desktop ownership. Native International provider acceptance remains open.

The collector preserves list/input order and duplicate input strings. Missing tag
identities remain unselectable. Malformed/duplicate tags, provider failure or more
than 128 languages/128 inputs per row discard partial output as Unavailable;
Captured-empty and nullable fields remain distinct. Input strings are bounded but
not interpreted as installed keyboard/TSF identities. Saved lookup checks tag
uniqueness and positions; completion filters identified supplied tags only.
ReadyForMutation/RecoverySupported remain false. No language list is reconstructed.

Legacy SetRegionalSettings cleared the entire language/input list, combined user
format/home-location/UI settings with machine locale/time zone, installed a language
and copied welcome/new-user defaults. Its default Culture was en-GB; retain the
later approved Danish-format intent rather than restoring that old default.
This batch implements observation only. UK English display, Danish formats/input/
location/system locale and selected time zone remain accepted intent, with their
different installation, scope, recovery and reboot effects separate. No list wipe,
language acquisition, regional setter or welcome/default-user copy was performed.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed 28 focused tests with all
providers/identity calls mocked. Fixtures cover context mismatch/drift, ordered
mixed languages, null/empty/false distinctions, literal/duplicate TSF strings,
malformed and bounded data, failure, saved completion and exclusive/racing export.
Repository validation passed on both: 347 operations/eight groups/five profiles/
179 PowerShell files. Existing catalog, profiles and supported targets are unchanged.
See the [operator contract](../user-language-inventory.md).

Next: native disposable collection for the intended identity, mixed layouts and
TSF/provider availability; compare GUI and captured field types without setting
anything. Before regional mutation, capture every owned field, preserve unrelated
languages/input methods, define conflict-aware exact restore and validate pack/
default-input/UI/format/system scope separately. No native setter or current-user
selection is accepted by this preparation. Preserve partial export on failure;
the JSON is not an engine restore record. Source rollback removes only this
isolated module/exporter/test/guide and leaves collected evidence untouched.

Resolved: ordered language observation contract and legacy bundle boundary.
Retired/excluded: none. Partial: regional/account configuration preparation.
Deferred: native provider, installed-capability/GUI/managed and mutation recovery
acceptance. All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded
150-205/about 180; no legacy outcome closed. Presentation remains 55/279, 224 open.

## B09 existing language priority preparation, 2026-10-17

Source f53ce6ab102a plus the overnight patch. RIDE.UserLanguagePreparation 0.1.0
uses supplied captured observations to move one explicit existing tag first while
preserving every other tag's relative order. It neither invents a language nor
selects en-GB for the user. Only DesiredOrder is proposed; no native language
objects, input strings, flags, display override or regional settings are rewritten.
An already-first/sole language creates an unowned no-op snapshot.

The version-1 snapshot owns order only. Recovery validates/reconstructs the edit,
requires the same machine/build/edition/update/SID/session and refuses added/removed
languages or a third ordering. Already-restored order is a no-op. An unchanged
proposal preserves later order/membership. Current input methods, handwriting,
spellchecking and unknown unowned fields must survive any later writer; they are
deliberately absent from this snapshot. Data consistency is not authentication.
ReadyForMutation/MutationAuthorized stay false; no native query, setter or writer.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed 53 focused tests (25 priority
and 28 inventory integration cases). Initial runs passed 52/53 because a test
used PowerShell's automatic input variable inside a throw assertion; renaming the
fixture variable fixed the test and exercised the intended guards. Initial summaries
are retained. No production failure was hidden or native provider invoked.
Both editions validated 347 operations/eight groups/five profiles/181 PowerShell
files. The catalog and support declarations are unchanged.

See the [preparation/recovery contract](../user-language-inventory.md#prepare-an-existing-language-priority-in-memory).
Next: define durable state, fresh intended-user comparison and native row
reconstruction preserving all unrelated fields before adding an operational setter.
Then separately verify priority, display override, default input and GUI/managed
effects on disposable targets. Native list mutation can affect more than display
priority; no complete mixed-locale outcome is claimed. Source rollback removes
this isolated preparation API/tests/docs; retain snapshots for review, never run
them as code. No system recovery is needed for in-memory work.

Resolved: order-only preparation/recovery and unchanged-request ownership. Retired/
excluded: none. Partial: regional configuration. Deferred: native persistence,
setter, side-effect/recovery and GUI acceptance. Five ranges stay 38-58 / 58-73 /
20-25 / 25-35 / 8-12, rounded 150-205/about 180; no legacy closure. Presentation
remains 55/279, 224 open. VM, controller/pins and developer settings remain unchanged.

## B09 user language override inventory, 2026-10-17

RIDE.UserLanguageInventory 0.2.0 adds explicit DisplayLanguage/DefaultInputMethod
provider selection and a separate schema-1 UserLanguageOverrideObservation.
Export-RideUserLanguageOverrides 0.1.0 supports WhatIf and exclusive CreateNew
output. Existing list observations and order snapshots are unchanged. Both providers
are module-qualified International queries; no setter, input switch or sign-out.

Captures preserve a literal language Name or InputMethodTip without inferring
current display/input from list order. A successful no-output UI query is NotSet
per Microsoft's contract; it may otherwise report a pending override. The input
provider's exact absent-output representation needs native evidence, so no-output
and empty-string remain distinct Unverified cases. Null/missing/malformed rows,
multiple rows and partial failures are Unavailable with no partial value. Queries
are independent, and pre/post machine/build/edition/update/SID/session/native/
interactive drift refuses the whole observation. Unknown fields/error text are
not exported; no private runtime settings were queried for these tests.

Each native PowerShell edition passed 28 new override tests and 28 existing
language-inventory tests. Initial combined runs were 53/56: the three drift tests
used a factory outside their mock's module scope. Passing a copied explicit fixture
fixed the test scope; the 28 override cases then passed on both editions. Initial
summaries remain local; no production failure was hidden. Passed list tests were
not rerun after the fixture-only repair. Validation passed on both editions with
347 operations/eight groups/five profiles/183 PowerShell files. Catalog/profile/
support declarations are unchanged.

See the [operator contract](../user-language-inventory.md#observe-display-and-default-input-overrides-separately).
Next: collect explicit/absent override cases in the intended user's disposable
session, compare UI/pending sign-out behavior and a TSF input identity, then design
narrow durable override ownership and exact recovery before introducing a setter.
Keep UK display and Danish regional/input intent; do not infer a current installed
identity or clear the language list. Source rollback removes this isolated export/
API/tests/docs while retaining prior list APIs; no Windows recovery is required.

Resolved: separate override observation and absence/failure boundaries. Retired/
excluded: none. Partial: regional configuration. Deferred: native output semantics,
GUI, setter/state ownership and complete mixed-locale acceptance. Five ranges stay
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; no legacy closure.
Presentation remains 72/279, 207 open. GitHub acquisition backoff remains in force.

## B02 wireless profile identity inventory, 2026-10-17

RIDE.WirelessInventory and Export-RideWirelessProfileInventory 0.1.0 add bounded
read-only interface GUID/profile-name discovery with an explicit expected machine/
build/edition/user/session. The native bridge opens a WLAN version-2 client, reads
enabled interfaces and basic preference-ordered profile lists, then frees buffers
and closes the handle even on failure. It loads only the system WLAN library and
has no profile XML/key/EAP retrieval, scan, connect, import/delete or service calls.

Exact case-sensitive profile names, flags and order survive JSON; GUID lookup and
profile completion use supplied saved metadata only. Both documented flag bits
and unknown unsigned bits remain visible; missing policy bit is not permission to
mutate. Header dwIndex is not treated as an active connection. The local Windows
SDK wlanapi.h 10.0.22621.0 confirms flag values 1/2 and fixed structures; Microsoft
references are linked in the [operator guide](../wireless-profile-inventory.md).
Capture is bounded to 64 interfaces and 256 profiles each, not a hard duration.
Any provider/malformed-data/cleanup failure discards partial rows; identity/update
drift refuses the whole observation. Empty success is distinct from Unavailable.
Names can be private; evidence stays local. No device profile was queried here.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed the initial 32 cases. Three
export tests and the expanded malformed-UTF16 case then passed in a four-case
focused run on both editions; the other 31 passed cases were not rerun. This
covers 35 distinct tests, using fake unmanaged buffers and mocked identity only.
Both editions validated 347 operations/eight groups/five profiles/186 PowerShell
files. No catalog/profile/target change, acquisition or native WLAN invocation.

Next: use an authorized disposable target with suitable WLAN hardware and an
already available service to compare GUID/name/order/scope visibility, no-profile,
policy, missing-service and alternate-user cases. Do not install/enable components,
export keys or create networks merely for inventory acceptance. Before a future
importer, settle Q12 scope/connection behavior, credential handling and recoverable
profile-content ownership; Q30 still owns selection. A stored name is mutable,
not a content backup. Source rollback removes this isolated module/tool/tests/docs;
no Windows recovery is needed. The existing adapter inventory remains separate.

Resolved: WLAN basic identity/metadata observation and saved lookup contracts.
Retired/excluded: none. Partial: Wi-Fi configuration/resource identity. Deferred:
native hardware/service/visibility, profile ownership, import and exact recovery.
Five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180;
no legacy closure. Presentation remains 72/279, 207 open. GitHub backoff retained.

## B09 regional provider inventory, 2026-10-17

Source f53ce6ab102a plus overnight changes. Added RIDE.RegionalInventory 0.1.0,
an exclusive previewable exporter and 35 focused cases. Four explicitly selected
providers separate observing-process format culture, current-user home location,
machine system locale and time zone. Capture checks expected native interactive
machine/build/edition/SID/session before providers and rejects identity/update
revision drift afterward. Each provider permits one bounded row, with independent
Unavailable status, partial-output discard and error type instead of raw text.

Format culture preserves name/LCID, flags and selected custom separators,
date/time patterns and currency symbol. It is not every custom format or a fresh
persisted-user read: Set-Culture documents subsequent-session effect. HomeLocation
retains signed GeoId and localized HomeLocation text without country inference.
Static inspection of the installed International 2.1.0.0 module's WinGeoId type
confirmed Int32 GeoId and String HomeLocation properties; no regional provider was
invoked. System-locale identity does not capture UTF-8 compatibility mode or reboot
state. Time-zone ID/base-offset/daylight-support metadata omits adjustment rules
and dynamic-DST-disabled state, and is not the current seasonal UTC offset.

The approved UK display/Danish format/input/home/system-locale and Romance
Standard Time reference remains intent, not an automatic selection. This is
separate from legacy SetRegionalSettings rebuilding the language list, installing
a fixed display pack and copying settings to welcome/new-user contexts. No
setter, copy, pack acquisition, restart, clock change or native collector ran.
The output is observation only, not an engine restore record.

Both Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 passed all 35 mocked
tests: provider selection/scope, custom/invariant data, malformed/bounded fields,
context mismatch/drift, independent and partial failures, completion, WhatIf and
exclusive output/competing-file preservation. Both validated 347 operations/eight
groups/five profiles/190 maintained PowerShell files. Catalog/profile selections
are unchanged. The [operator procedure](../user-language-inventory.md#observe-regional-providers-separately)
contains the exact providers and recovery limits.

Next: run the explicit collector on a disposable intended-user desktop with
known regional choices. Compare each provider independently to its native UI;
repeat the format observation in a fresh process after any separately authorized
format change. Test International availability and localized/neutral/invariant
outputs without changing the collector into a setter. Before mutation, define
ownership and complete recovery for custom formats, opt-out, UTF-8 mode and DST
configuration rather than reconstructing them from these partial observations.
Preserve exports; retry with a new filename. No runtime rollback is required.

Resolved: four separated observation contracts and exclusive export. Retired/
excluded: none. Partial: regional preparation. Deferred: native output, full
recovery/ownership, GUI, new-process and setter acceptance. Presentation remains
88/279, 191 open. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180; no accepted legacy closure or support expansion.

## B06 client-component source preparation, 2026-10-17

Implemented RIDE.ClientComponentPreparation 0.1.0 against saved component inventory
for accepted Q05/Q06: exact OpenSSH.Client~~~~0.0.1.0 capability and TelnetClient
optional feature, separately selected and never defaulted. Explicit Online respects
configured sources; Offline requires a local source and records the no-network
requirement. LimitAccess alone is not proof of complete offline behavior. Provider
namespaces remain distinct; no Server/RSAT/Hyper-V/Sandbox/WSL activation is inferred.

Unknown/pending/missing states and domain controllers receive no command outline.
No-op observations are explicit. Feature disable retains payload; capability remove
and previously removed feature payloads retain recovery warnings. No automatic
restart or dependency activation is outlined. All results keep ReadyForMutation=false
and RecoverySupported=false. No native servicing query or command was executed.

Both Windows PowerShell 5.1 and PowerShell 7 passed all 29 focused tests, covering
source modes, command boundaries, provider identity, pending states, malformed
context, no-op states, completion and input preservation. Static validation passed
347 operations, eight groups, five profiles and 203 maintained PowerShell files.
No supported target/default profile changed. The operator procedure and Microsoft
parameter references are in [component guidance](../windows-component-inventory.md#prepare-the-first-client-components).

Also reconciled explicit Q05-Q12 and partial Q13 design acceptance from the separate
decision session. Q06's former local-only proposal is superseded; neither mode is
implicit. Actual selections, credentials, sources and native acceptance are separate.

Next: prove matching-source completeness and no-network behavior without policy
overrides, then implement durable captured-state servicing with post-state checks,
pending-reboot reporting and component-specific recovery in disposable targets.
Keep unverified outlines out of executable catalog profiles. Larger components
remain independently scoped. Source recovery removes this pure module/tests and
guidance; no OS rollback is needed.

Resolved: client/source intent and preparation boundaries; retired/excluded: none.
Partial: component implementation; deferred: source/policy/dependency/recovery and
native consumer acceptance. No legacy outcome closed. All five ranges remain
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. Presentation
remains 102/279, 177 open; decisions do not count as completed legacy behavior.

## B03 user PATH and later decision reconciliation, 2026-10-17

See the [PATH implementation evidence](settings-post-migration-review.md#b03-persistent-user-path-observation-and-recovery-2026-10-17).
Observation/preparation and entry-owned recovery are source-ready; activation,
durable ownership and new-process behavior remain pending. No folder is owned.

The [decision-session record](decision-session-2026-10-17.md) also now accepts:

- Q14: keep tools and reviews visible; local licensing review bookkeeping alone
  must not interrupt or block explicit unattended installation. Report pending
  reviews without marking them approved. Shared kits default to omitting
  unreviewed restricted members and reporting omissions. Credentials, entitlement,
  publisher responses and technical interactive prerequisites are not invented.
- Q15: normal deployments use pinned releases/revisions; editable Git checkouts
  are separate. Download, update, import and execution remain separate actions.
- Q16, partial: Wireshark all-user install preserving existing associations;
  making capture-file defaults is a separate choice. Earlier interactive Npcap
  and administrator-only capture choices remain. Compatibility flags and other
  integrations still require review.

No licensing assessment, installer, source import or association changed. Actual
member/version/driver choices and unattended capabilities require evidence. The
local review store is already informational; this does not implement a complete
unattended runner or kit exporter. No legacy closure; all five ranges unchanged.

## B08 Wireshark and Npcap compatibility follow-up, 2026-10-17

The [machine MSI candidate](application-migration-review.md#b08-wireshark-machine-msi-candidate-2026-10-17) is source-ready
with exact publisher hash/signature, read-only table proof and 18 focused checks
per edition. Native lifecycle and associations are unverified. No driver installed.
Q16's follow-up now selects Npcap WinPcap compatibility off by default and an
explicit opt-in with existing-driver replacement preview. Administrator-only
capture and interactive enrollment remain. No compatibility flag is silently
inherited from installer defaults. All five ranges remain unchanged; no closure.

## Q17-Q21 dispositions and estimate update, 2026-10-17

See the [two explicit retirement records](application-migration-review.md#accepted-volatility-2-and-improhound-retirements-2026-10-17).
Volatility 2 and ImproHound are retired from planned deployment only. Exact legacy
selectors and existing installations remain. Q18 dependency/update ownership and
Q19 collectors-first/external-backend design accepted; concrete manifests and
backend compatibility remain open. Standalone Neo4j/APOC is deferred, still counted.
Q21 selects Microsoft 365 Apps for enterprise; Visio edition, channel, architecture,
activation and supported language mapping remain unresolved. No runtime work.

Packages decrease 58-73 to 56-71; settings 38-58, components 20-25, accounts/assets
25-35 and maintenance 8-12 remain unchanged. Sum 147-201 rounds to 145-200/about
175. Two retirements are actual dispositions, not source-ready migration acceptance.
Presentation remains 102/279, 177 open. Continue independent authorized work.

## B10 Office configuration inspection, 2026-10-17

See the [application record](application-migration-review.md#b10-inert-office-configuration-review-2026-10-17) for accepted
Q21/partial Q22 reconciliation and the pure XML review contract. Forty distinct
cases passed in each PowerShell edition; no deployment, activation or source
rewriting occurred. Native lifecycle, language/compatibility and preservation
remain pending. All five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded
145-200/about 175, with no new legacy outcome closure.

## B10 Office metadata observation, 2026-10-17

See the [application evidence](application-migration-review.md#b10-click-to-run-observation-2026-10-17). The
read-only eight-field Click-to-Run collector and exclusive export passed 36 mocked
cases per edition and repository validation (213 files). Actual installed-product,
channel, per-product language, licence/activation and native recovery remain open.
No legacy outcome closed; all five ranges remain 38-58 / 56-71 / 20-25 / 25-35 /
8-12, rounded 145-200/about 175.

## B10 FTK source and decision reconciliation, 2026-10-17

Q22-Q31 are reconciled from the [decision session](decision-session-2026-10-17.md).
ADR 0001 now records accepted ownership; no LoggingBaseline repository was touched.
R29/D09 closes as unsubstantiated bookkeeping, preserving its bounded audit and
reopen condition. The audit explicitly did not add a separate legacy outcome, so
closure is not a subtraction from the five estimates. Menus stay visible/unavailable
when recovery is missing; device identity and acceptance ordering are accepted
designs, not runtime passes.

FTK official archive/signature inspection is recorded in the [application ledger](application-migration-review.md#b10-ftk-source-and-decision-reconciliation-2026-10-17).
CodeMeter/prerequisite layout, deployment arguments, drivers/reboots, bundled terms
and native preservation/recovery remain open. FTK has no catalog declaration yet.
No installer, setting, VM or schedule changed. All five reviewed ranges remain
38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B10 desired-configuration reference, 2026-10-17

The [source export and test record](settings-post-migration-review.md#b10-read-only-desired-configuration-reference-2026-10-17)
implements the first Q25 contract without changing LoggingBaseline. Registry
intent is explicit; other mappings remain ReportOnly, live compliance Unknown.
Thirty-seven distinct cases passed per edition and repository validation passed
for 216 PowerShell files. Native consumer/mapping and actual configuration remain
open. No legacy closure; all five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12,
rounded 145-200/about 175.

## B10 local offline bundle preflight, 2026-10-17

See the [application evidence](application-migration-review.md#b10-local-offline-bundle-preflight-2026-10-17) and
[accepted offline scope](package-deployment-decisions.md#offline-installation-bundles-2026-10-17).
Forty-one distinct tests passed per edition, validation passed for 219 files.
Declared selected-content completeness is now checked locally; real dependency
coverage, source assembly and install/apply gating remain open. Partial unrelated
omissions do not block complete selected content. KAPE acquisition waits for its
publisher form/agreement input; no bypass or installer execution occurred.
All five ranges stay 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

### Offline package coverage and Q23 follow-up, 2026-10-17

See the [coverage and decision record](application-migration-review.md#b10-offline-profile-package-coverage-2026-10-17). Continue byte-bound local profile/catalog parsing, bundle assembly and mandatory preflight. Preserve explicit guest, AutomatedLab, Lenovo conditional, Hashcat launcher and driver/workload boundaries; no host detector or package installation is accepted by the design. All five legacy ranges remain unchanged.

### Byte-bound offline coverage and runtime choices, 2026-10-17

The [latest record](application-migration-review.md#b10-byte-bound-offline-profile-preflight-2026-10-17) supersedes the prior byte-binding prerequisite. Continue exclusive assembly and engine integration; Volatility/Python/ImageMagick/OpenJDK decisions are recorded, with exact pins and native acceptance still open. No legacy count changed.

### Explicit local bundle assembly, 2026-10-17

[Local assembly](application-migration-review.md#b10-explicit-local-offline-bundle-assembly-2026-10-17) now copies and verifies explicit sources into a new directory, retaining failed staging and old versions. Automatic planning, complete dependency/source packaging and install integration remain. Arsenal/Sysinternals scope is recorded; MEGAcmd and exact CE backend matching remain deferred as specified. All five legacy ranges are unchanged.

### Sysinternals snapshot candidate, 2026-10-17

The [B11 record](application-migration-review.md#b11-sysinternals-reviewed-snapshot-candidate-2026-10-17) pins 164 official files and adds a pending whole-Suite candidate. Continue individual grouping and native acceptance; replace destructive v2 wrappers without retiring their useful acquisition intent. Zimmerman tools/maps remain separate reviewed scope, with upstream GitHub acquisition deferred under backoff. All five ranges remain unchanged.

### Independent Sysinternals products, 2026-10-17

The [B11 record](application-migration-review.md#b11-independent-sysinternals-products-2026-10-17) adds pinned Process Explorer, Autoruns and TCPView candidates with separate owned folders and 24 passing inert checks per edition. Remaining Suite members and native acceptance stay open. Presentation remains 154/279 and all five ranges remain unchanged.

### Sysinternals diagnostic and imaging candidates, 2026-10-17

The [B11 record](application-migration-review.md#b11-sysinternals-diagnostic-and-imaging-candidates-2026-10-17) adds Process Monitor, RAMMap and Disk2vhd as three independent pinned file-staging candidates. Another 24 tests passed per edition; six individual products now have source coverage. Native and remaining collection scope stay open, with all five ranges unchanged.

### Sysinternals command-line candidates, 2026-10-17

The [B11 record](application-migration-review.md#b11-sysinternals-command-line-candidates-2026-10-17) adds Sigcheck, Strings and Handle, bringing independent pinned products to nine. Another 24 tests passed per edition; native and remaining collection scope stay partial. All five ranges remain unchanged.

### Final staged bundle integrity, 2026-10-17

The [B10 repair](application-migration-review.md#b10-final-staged-bundle-integrity-check-2026-10-17) reproduces and fixes stale per-file success when an earlier staged file changes during a later copy. Both editions passed 28 assembly tests. Native/air-gap acceptance remains separate and all five ranges stay unchanged.

Final count reconciliation, 2026-10-17: direct catalog enumeration found sixteen, not seventeen, members in the last Start/taskbar batch. Presentation is 179/279, 100 open, with 149 additions this window. The earlier prose tally was corrected; no operation, state, test outcome, target or legacy estimate changed. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## Morning handoff, 2026-10-17

The authorized window ended at **08:00 Europe/Copenhagen (06:00 UTC)**. No further
implementation or VM batch starts under that expired window. The separate **RIDE
migration decisions** chat and its [decision ledger](decision-session-2026-10-17.md)
remain available. This checkout contains uncommitted work; no commit, release,
publication, controller/pin change or workstation installation was performed.

### Source-ready work

| Area | Verified source result | Remaining boundary |
| --- | --- | --- |
| Setting presentation | 149 additional controls reviewed this window; 179/279 now have explicit presentation, 100 remain. Literal write/removal, legacy bundle differences and uncertain GUI mappings are visible. | Current-build GUI, policy, hardware and whole legacy outcomes remain separate. |
| Settings and preparation | Audio, adapter, volume, local-user, wireless, component, regional/language, proxy, visual, Office and installed-registration inventories; Terminal JSONC, user PATH, deployment identity/adoption/mapping, toolkit updates, Office XML and desired-configuration preparation. Existing versioned recovery patterns are retained. | Most new preparation APIs do not mutate live settings. Native binding, durable commit, exact runtime recovery and activation still need implementation/acceptance. |
| Package candidates | Six earlier candidates (Rufus, RegRipper, Hex2text, ChromeSyncParser, PSScriptTools, Wireshark), the frozen 164-file Sysinternals Suite and nine independent Sysinternals products. All sixteen new package declarations remain pending native acceptance. | Runtime dependencies, per-product behavior, remaining collection members, installer/driver and target acceptance. |
| Startup candidates | Windows PowerShell 5.1 and PowerShell 7 existing-user-bin startup renderers. | Live profile ownership, intended-user startup, PATH and GUI acceptance. |
| Offline preparation | Manifest integrity/dependency preflight, byte-bound catalog/profile coverage, and explicit local assembly. OfflineBundle 0.5.0 rechecks all staged files before commit metadata; failed staging and old versions are retained. | Mandatory install/apply integration, complete dependencies, engine provenance, actual offline installers and servicing compatibility. ReadyForMutation remains false. |

Final catalog: **358 operations, eight groups and five profiles**: 279 settings,
56 packages, one artifact and 22 Store declarations. The eighteen new operations
comprise sixteen pending packages and two pending startup settings; they are not
eighteen completed legacy outcomes. Existing B01 and unrelated changes were preserved.

The [230-file source index](../archive/evidence/overnight-source-handoff-index-2026-10-17.json)
identifies local catalog/module/profile/tool/test bytes over base
f53ce6ab102a5d8558fa5833e752c0dd6fd883f5, including uncommitted files. Its aggregate is
9a6cb16bdd0dda64ad12b3a33a0ee9ea71458913ef56ae89678692e35deb6d8a.
It is a handoff inventory, not a VM pin, release or complete engine provenance proof.

### Actual validation and acceptance

Both native Windows PowerShell 5.1 and PowerShell 7 passed repository validation
for 358 operations/eight groups/five profiles/224 PowerShell files. Focused evidence
is recorded per batch, without summing repeated tests into a misleading total.
The latest presentation/catalog/search batch passed 122 checks per edition with one
WindowsIntegration exclusion. Whole-Suite tests passed seven per edition; the nine
independent products passed 72 distinct inert checks per edition across three batches.
The final assembly repair passed 28 per edition after a regression first reproduced
the stale-integrity false success. Earlier inventory/preparation checks remain at
their recorded source versions.

Real acquisition evidence includes official publisher bytes, observed hashes,
notices, PE versions and signature checks; no acquired program or installer ran.
No new disposable-VM, GUI, driver, hardware, boot or full offline installation
acceptance was obtained in this window. Earlier VM evidence remains valid only for
its recorded scope/source and must not be inherited by these new candidates.
ArtCraft Launcher was not restarted; the final read-only process check found none
running. Protected controllers/pins were not altered. Local-link and whitespace
checks passed. Retain the ignored .local source caches, failure evidence and recovery
material; they are not preserved merely by keeping tracked files.

### Accepted choices and unresolved work

Explicit Q17/Q20 decisions retired planned Volatility 2 and ImproHound deployment,
preserving existing installations and historical mappings. Q31 closed unsupported
User .NET assemblies bookkeeping without another count deduction. Other decisions
resolve substantial design scope (deployment identity, preservation, collections,
Office, guest tools, languages, runtime choices and offline preparation); acceptance
of design is not acceptance of runtime behavior. The full decision ledger remains
authoritative, including later Zimmerman membership/maps and updater-review choices.

The BloodHound CE backend-version compatibility input is explicitly deferred; do
not choose a version silently. FTK installer/CodeMeter/driver behavior and KAPE's
publisher agreement/download gate remain open. Arsenal product entitlement and
activation, Office/Visio native compatibility/languages, hardware-dependent tools,
credentials and interactive elevation remain separate acceptance inputs. Pending
internal license-review status alone must not become an unattended install gate.

Sysinternals has a frozen whole-Suite candidate and nine independent products;
remaining product groupings are not complete. Zimmerman has 26 accepted members
plus compatible reviewed maps/batch definitions, but pinned helper/payload admission
is still pending. Preserve useful updater functionality while replacing mutable
execution and destructive replacement. GitHub acquisition backoff remains in force
for this window; no further request was used to bypass it. Future requests need the
normal backoff/provenance checks, not an automatic retry of failed endpoints.

### Next instructions and recovery

1. Read this handoff and the latest decision ledger before resuming; inspect the
   dirty checkout and source index, preserving all unrelated work and retained
   caches. Obtain a new work window or direct instruction for further implementation.
2. Continue remaining reviewed collections/dependencies and the 100 setting
   presentations. Keep unresolved meanings experimental and outside recommendations.
   Select exact official sources/pins/notices and validate bounded acquisition/helper
   failures without running mutable upstream installers on the workstation.
3. Complete live ownership/durable-state integration for prepared settings and the
   offline install preflight gate. A successful local bundle copy does not authorize
   deployment or establish complete source/dependency coverage.
4. When required resources and authority exist, use the serialized pinned current-source
   disposable-target workflow. Start with the accepted Explorer/icons/input sequence,
   then Server logon/shutdown and application/hardware acceptance. Verify repeat apply,
   baseline versus exact restore, drift/partial failures, intended user and actual UI.
   Do not alter controllers/pins or restart ArtCraft Launcher to obtain resources.
5. Preserve prior versions and failed staging. Source recovery is a focused revert
   of the selected batch plus regenerated OPERATIONS, never a broad checkout reset.
   Runtime recovery uses the existing versioned snapshots; source preparation is
   not permission to delete data, prune caches or replace external installations.

All five remaining ranges were reviewed: **38-58 / 56-71 / 20-25 / 25-35 / 8-12**,
rounded **145-200, about 175**. The two explicit retirements are already included;
later source candidates, presentation reviews and the assembly repair close no
additional whole legacy outcome. Partial/deferred scope remains counted. No new
exclusion or native acceptance is claimed by this handoff.

### Resumed offline source comparison, 2026-10-17

See the [application record](application-migration-review.md#b10-offline-declared-source-comparison-2026-10-17). Both editions passed 63 focused tests; explicit source mismatches now fail package coverage. Continue independent batches under the new direct instruction and defer unresolved acceptance. All five ranges remain unchanged; no whole legacy outcome closed.

### Assembly selected-profile gate, 2026-10-17

See the [application record](application-migration-review.md#b10-assembly-selected-profile-gate-2026-10-17). Both editions passed 48 assembly tests. Selected package coverage can now gate local completion; final integrity, retained failed staging and explicit unrelated omissions remain. Native installation integration stays pending. All five ranges are unchanged.

### B01 service startup and runtime presentation, 2026-10-17

See the [settings record](settings-post-migration-review.md#b01-service-startup-and-runtime-presentation-2026-10-17). 185/279 presentations, 94 open; native acceptance and whole legacy outcomes remain separate. All five ranges unchanged; no retirement or new whole-outcome closure.

### B01 scheduled-task presentation, 2026-10-17

See the [settings record](settings-post-migration-review.md#b01-scheduled-task-presentation-2026-10-17). 198/279 presentations, 81 open; native acceptance and whole legacy outcomes remain separate. All five ranges unchanged; no retirement or new whole-outcome closure.

## Resumed implementation results, 2026-10-17

Five independent batches followed the direct continuation instruction:
explicit offline source comparison; optional selected-profile assembly coverage;
six service presentations; thirteen task presentations; task observation/readback
repair. Presentation is **198/279, 81 open** (19 added after the morning handoff).
The catalog remains 358 operations/eight groups/five profiles. Both native editions
passed 63 package-coverage tests, 48 assembly tests, 122 presentation/catalog/search
checks per presentation batch (one integration exclusion), 20 selected task checks,
and final repository validation of 225 PowerShell files. These totals identify
focused runs, not a sum of distinct whole-suite tests.

See the [task repair and latest decision reconciliation](settings-post-migration-review.md#b01-scheduled-task-observation-and-readback-2026-10-17)
and the [offline gate](application-migration-review.md#b10-assembly-selected-profile-gate-2026-10-17).
The [updated source index](../archive/evidence/resumed-source-handoff-index-2026-10-17.json)
preserves the original overnight index separately. Compared with that baseline,
seven existing catalog/module/tool/test files changed and one task-test file was
added; protected infrastructure and unrelated implementation source are unchanged.

No installer, service, task, device setting, VM or profile activation occurred.
No commit or release was made; local test/recovery evidence is retained. Source-ready
preparation is not native acceptance. New profile composition and BitLocker/recovery
test setup are explicitly deferred; CE-backend compatibility remains deferred.
Shared installation artifacts must not gain artificial licence-tier variants or
mandatory tier selection; activation changes stay separately explicit.

Continue remaining 81 setting presentations and reviewed collections/source
integration without reopening accepted product scope. Complete mandatory offline
install/apply integration and native lifecycle acceptance before calling a bundle
deployable. Respect provider backoff and original publisher sources; defer missing
entitlements, interactive elevation and unresolved product exceptions. Preserve
existing B01 work, profiles, prior bundle versions, failed staging and saved runs.
All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded
**145-200/about 175**. No new whole legacy outcome closure, retirement or exclusion
is inferred from these source improvements.

## B06 client component local regression, 2026-10-22

The current checkout's `ComponentInventory.Tests.ps1` and
`ClientComponentPreparation.Tests.ps1` passed **49/49** on Windows PowerShell
**5.1.26100.9711** and **49/49** on PowerShell **7.6.5**. TestRegistry was
disabled. No DISM, servicing source, elevation, VM, network policy, component or
reboot operation ran. This confirms local inventory/preparation behavior only;
matching-source/no-network proof, durable state and exact component recovery, and
native consumer acceptance remain pending. No legacy outcome was resolved,
retired or excluded. Current migration estimates remain **38-58 / 53-68 / 20-25 /
25-35 / 8-12**, exact **144-198**, rounded **145-200/about 170**. See the
[sanitized run record](../archive/evidence/b06-component-local-regression-2026-10-22.json)
and [component guide](../windows-component-inventory.md#prepare-the-first-client-components).

## Deferred package and guest-integration decisions, 2026-10-22

The user decided to keep standalone OpenJDK deferred until an independent use
case is identified; BloodHound CE backend use alone is insufficient. For a full
GNOME Boxes guest experience, include both VirtIO and SPICE integrations when
required. Verify the driver, SPICE agent and WebDAV requirements on a matching
QEMU guest; the available Hyper-V guest cannot validate them. The user also
rejected carrying the broad legacy `C:\Tools` Defender exclusion into v3; see
the [System Tools disposition](system-tools-dispositions.md).

No package or component outcome was resolved, retired or excluded by this
decision run. All five estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**,
exact **144-198**, rounded **145-200/about 170**. Hyper-V CIM access and
protected-queue submission remain blocked; QEMU guest acceptance needs its own
matching VM.
## QEMU guest integration source review, 2026-10-22

The user's conditional scope now has upstream source evidence: GNOME's documented
Windows guest path points to spice-guest-tools; SPICE identifies QXL and the
SPICE agent/driver in that installer, and says spice-webdavd is separate for
Windows guest folder sharing. The upstream virtio-win guest-tools installer
bundles VirtIO drivers with SPICE components. Avoid duplicate SPICE installation
and choose drivers for the virtual devices present in the guest. Confirm the
GNOME Boxes release because its newer experimental implementation may differ.

This is source review only. No artifacts were retrieved or pinned, and the
candidate licenses, publisher signature, target devices, install/repeat/remove,
service behavior and recovery remain unverified. A matching QEMU guest is needed;
Hyper-V cannot close this acceptance. No legacy outcome was resolved, retired or
excluded; estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact
**144-198**, rounded **145-200/about 170**. See the [application review](application-migration-review.md#qemu-guest-integration-source-review-2026-10-22).

## RIDE-Win11-Test access recheck, 2026-10-23

The current read-only `Get-VM -Name RIDE-Win11-Test` call returned CIM access
denied, so neither the VM nor its checkpoint can be verified or used for the
prepared batches. No submission, VM/controller/service/Defender change or
Defender-blocked tool selection occurred. Resume the already authorized guest
acceptance once the existing Hyper-V and registered-controller access path is
available. Sysinternals licensing is cleared for RIDE's approved download/install
workflow; only technical acceptance remains. No legacy outcome changed, and all
five estimate ranges remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact
**144-198**, rounded **145-200/about 170**. See [access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23.json).

## User migration decisions, 2026-10-23

The user retired the legacy Windows PowerShell 2 enable/disable outcome, kept
ISE separate, limited Internet Printing to the client optional feature, and
retired the classic Teams MSI cleanup outcome. Windows PowerShell 2 and classic
Teams account for two retired legacy outcomes; Internet Printing remains in scope
as a client-feature outcome. No component/package code or Windows state changed.

The two retirements reduce the active estimates by one package outcome and one
Windows-component outcome. The ranges are now **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. The rounding is
unchanged. See the [decision record](decision-session-2026-10-17.md#windows-component-and-classic-teams-scope-decisions-2026-10-23).
## WSL, .NET 3.5 and QEMU guest integration decisions, 2026-10-23

The user kept Debian, Ubuntu and Kali as separate opt-in WSL distribution
outcomes, including Debian when available as a WSL distribution. No automatic
distro installation or unregister is authorized; the Fedora removal selector
remains retired. .NET Framework 3.5 remains a conditional explicit compatibility
outcome selected by exact Windows build, with matching local servicing sources
and no network fallback. SPICE WebDAV is included as a separate optional guest
folder-sharing integration, not a default install. These choices resolve user
scope but close no legacy outcome. Exact source, data recovery and native guest
acceptance remain pending. The estimate ranges remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See the
[decision record](decision-session-2026-10-17.md#wsl-net-35-and-qemu-guest-integration-decisions-2026-10-23).

## B06 client-component guarded lifecycle candidate, 2026-10-23

Added `RIDE.ClientComponentLifecycle.psm1` as an unregistered source candidate for
the separately accepted OpenSSH Client and Telnet Client choices. Each transition
obtains a fresh local component observation, checks computer/build/edition, refuses
Server installations or a pending servicing reboot, writes a unique prior-state
snapshot before DISM, requires `ShouldProcess`, and verifies the literal post-state.
Restore requires the same target and update-build revision and refuses state drift.
No restart is initiated. Offline mode only checks that the explicitly supplied local
directory exists; source completeness, matching payload identity, all-network-source
exclusion and exact payload/version recovery are not proven. The runner adds no
catalog operation or supported target.

The focused mocked lifecycle suite passed **8/8** on PowerShell **7.6.5** with
TestRegistry disabled. The preparation module, lifecycle module and tests parsed
without errors on Windows PowerShell **5.1.26100.9711** and PowerShell **7.6.5**.
No DISM command, Windows servicing, source acquisition, elevation prompt or guest
run occurred. The tests reject Server targets until declared and modified saved
provider/name identity before a restore command. A read-only
`Get-VM -Name RIDE-Win11-Test` check returned CIM access
denied; no checkpoint query was made. See the [candidate evidence](../archive/evidence/b06-component-guarded-lifecycle-candidate-2026-10-23.json),
[latest VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0705.json)
and [operator guidance](../windows-component-inventory.md#local-transition-runner-candidate).

Resolved, retired and excluded: none. Deferred: source/no-network and dependency
acceptance, native apply/repeat/status/restore on a disposable Windows target, exact
payload recovery and target support declaration. Partial: local guarded source
candidate only; no legacy outcome closed. Estimates remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**.

## B06 servicing-source requirement cross-check, 2026-10-23

Microsoft's Windows 11 Features on Demand inventory identifies OpenSSH Client as the non-satellite OpenSSH.Client~~~~0.0.1.0 capability with an OpenSSH-Client-Package CAB and specifies matching Windows 11 Languages and Optional Features media. The official OpenSSH troubleshooting guide documents target-version media, administrator, configured update-source and policy requirements. DISM may check configured Group Policy sources after a supplied source misses content; LimitAccess prevents Windows Update lookup but does not by itself rule out network locations supplied by policy. TelnetClient is confirmed as the optional-feature identity; its complete matching-source inventory remains separate. The current lifecycle candidate checks only local directory existence, so no-network and source-readiness are not proven. No source was acquired, DISM or network used, or system changed. No legacy outcome closed, retired or excluded. Estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured source evidence](../archive/evidence/b06-servicing-source-requirements-2026-10-23.json), [Microsoft FOD inventory](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod?view=windows-11), [Microsoft DISM source order](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11), and [B06 preparation and lifecycle instructions](../windows-component-inventory.md#prepare-the-first-client-components).

## Deferred package and client-component recovery decisions, 2026-10-23

The user kept NTCore 4GB Patch deferred after its synthetic-target test showed
unsafe modification when the backup path was occupied and no recoverable copy
was created. Reconsider only after establishing safe recovery; see the [functional
rejection evidence](../archive/evidence/ntcore-4gb-patch-functional-failure-2026-10-22.json).
The user selected RIDE-managed ownership for PSScriptTools' ThreadJob 2.2.0
dependency. Exact official package bytes and digest remain unavailable after
publisher DNS failures; package acquisition, managed lifecycle and dependency-present
acceptance remain open. The user also approved gating OpenSSH Client and Telnet
Client removal on a validated recovery source; matching-source/no-network proof,
payload recovery and disposable Windows acceptance remain open. No legacy outcome
closed and all five estimate ranges remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See the [decision
ledger](decision-session-2026-10-17.md#deferred-package-and-client-component-recovery-decisions-2026-10-23).

## Zimmerman, Arsenal and OpenSSH Server scope decisions, 2026-10-24

The user selected Zimmerman as the next collection for focused review; the
accepted 26-member list is unchanged. The user's later 2026-10-24 choice of
JoeWare supersedes this review ordering only. Continue Zimmerman source/helper
and pinned-artifact provenance work after the prioritized JoeWare review.

Arsenal v3 review now covers every publisher product for which the publisher
offers a free-use scenario, including products with paid editions; only
licensed-only products are excluded. Verify current terms and exact artifacts
per product. The original eight-member selection is retained. MEGAcmd, driver
changes, AV exceptions and forensic execution are not implicit. No Arsenal
artifact was acquired or installed.

OpenSSH Server is added to v3 as a separate optional component outcome. Service,
firewall, host-key and configuration ownership and recovery need their own
implementation and acceptance. It remains off by default; no component or
Windows state changed. The existing ranges remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**; no legacy
outcome closed or retired. See the [decision record](decision-session-2026-10-17.md#zimmerman-arsenal-and-openssh-server-scope-decisions-2026-10-24).

## Mixed-scope profiles and TPM/boot acceptance, 2026-10-24

The user confirmed mixed-scope profiles are expected and do not need special
ordering or recovery work merely because they include both user and machine
settings. A report/analysis feature showing the scopes in a profile is optional
future work, not a prerequisite. Close the mixed-scope portion of D01 while
retaining the existing intended-user handoff and identity-safe recovery
requirements.

For D04, explicitly defer acceptance that depends on unavailable resources and
continue checks that do not. Request a specific additional setup only when an
acceptance requirement needs it.

For D06, the user will prepare a standalone Lenovo laptop running Windows 11 Pro
for the TPM/boot scenario. Treat it as a focused physical-hardware acceptance
target alongside, not a replacement for, the disposable-VM validation model.
Prepare the test setup and verification procedure before the run. Remaining
prerequisite at this point was the recovery-key retrieval plan; the user's later
clarification below supersedes the destination/verifier requirement. Do not
place secrets in repository evidence. Keep recovery-changing checks deferred
until the laptop is ready and the required user confirmation can be obtained.

The latest recorded Hyper-V CIM check in the migration plan failed before VM or
checkpoint inspection; this decision update did not retry it. Keep VM-based
acceptance batches deferred behind restored access, while continuing independent
source and local-preparation work. No test, package, profile, or Windows state
changed. No legacy outcome closed; all estimate ranges remain unchanged. See the
[settings decision record](remaining-settings-plan.md#mixed-scope-profiles-and-acceptance-resources-2026-10-24).

### User clarification, 2026-10-24

The user accepts the JoeWare `rdp-sec-check` discrepancy and directs RIDE to
resolve and download the latest publisher-offered version for each selected
product at acquisition time. Document page/list/archive differences when
observed and add a short note to the affected package description. Do not
reuse the older `V01.00.00` digest for the page's `V02.00.00` release without
archive evidence. See the [decision ledger](decision-session-2026-10-17.md#joeware-latest-download-and-acceptance-resource-decisions-2026-10-24).

For QEMU/GNOME Boxes acceptance, keep Fedora 44 selected and do not pre-pin
Debian, Ubuntu, or Boxes versions. Record versions actually available at the
guest run. GNOME Boxes 50.0 was the latest release verified for this decision;
it is an observation, not a required version.

For TPM/boot recovery-changing acceptance, either USB storage or a password
manager is acceptable. Ask the user to confirm that the key was saved and can
be retrieved before continuing, unless the procedure has verified storage on a
portable drive. A specific destination or independent verifier is not required.
Do not record key material in repository evidence. The laptop and confirmation
remain prerequisites; this decision does not authorize a recovery-changing run.
## B06 client-source preflight and current-source regression follow-up, 2026-10-24 16:38 UTC

The current OpenSSH Client LocalSource candidate is more specific than the earlier
2026-10-23 handoff: it checks the exact native-architecture CAB filename, rejects
empty/reparse CABs, reads one CBS package identity, matches the publisher package
and Windows build, and records SHA-256. Restore repeats the checks and refuses a
changed architecture, identity or digest. The current client-component and OpenSSH
Server mocked preparation/observation/lifecycle suites passed 65/65 on PowerShell
7.6.5/Pester 5.7.1 with Pester TestRegistry disabled and WindowsIntegration
excluded. No DISM servicing, capability acquisition, service/firewall/registry
change, VM run or target support declaration occurred.

Still deferred: policy-configured source fallback and other network paths,
servicing dependency/completeness validation, Telnet LocalSource validation,
exact payload/version recovery, and Windows 11/Server 2025 acceptance. The RIDE-
Win11-Test ApplicationsBatch5 request `929ea539ce89404d8ed0d50a8fbbac52` remains
in the running queue without an accessible guest result at 16:38 UTC; no overlap
was submitted. No legacy outcome closed; estimates remain 37-57 / 50-65 / 19-24 /
25-35 / 8-12, exact 139-193, rounded 140-195/about 170. See the [current-source
evidence](../archive/evidence/client-components-openssh-current-source-regression-2026-10-24-1638.json)
and [operator guidance](../windows-component-inventory.md#local-transition-runner-candidate).
## B06 component inventory current-source regression follow-up, 2026-10-24 16:48 UTC

`tests/ComponentInventory.Tests.ps1` passed **20/20** on PowerShell 7.6.5/Pester
5.7.1 with Pester TestRegistry disabled and WindowsIntegration excluded. Provider
calls, host identity and elevation checks were mocked; JSON output used a temporary
file. No DISM, Server Manager, registry, Windows servicing, VM or supported-target
state was queried or changed. Together with the separate 65/65 client-component
and OpenSSH Server lifecycle/observer run, the local component regression evidence
is 85/85 across five focused suites; it does not establish native behavior or close
a legacy outcome. Native collection, configured-source fallback, dependency and
exact recovery validation, and Windows 11/Server 2025 acceptance remain deferred.
Estimates remain 37-57 / 50-65 / 19-24 / 25-35 / 8-12, exact 139-193, rounded
140-195/about 170. See the [inventory evidence](../archive/evidence/client-component-inventory-current-source-regression-2026-10-24-1648.json)
and [earlier lifecycle evidence](../archive/evidence/client-components-openssh-current-source-regression-2026-10-24-1638.json).
