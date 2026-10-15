# Remaining migration analysis and decisions

Reviewed 2026-10-14. The remaining source has been triaged across all five
migration groups. Start with a small presentation and guidance batch; resolve
deployment identity before resuming package implementation. Components, accounts,
files and maintenance need explicit ownership and recovery contracts rather than
translation of legacy command sequences.

This document collects questions for the user's return. It links the existing
decision owners and proposes matching implementation batches. [TODO.md](../../TODO.md)
remains the actionable backlog and [MIGRATION-PLAN.md](../MIGRATION-PLAN.md)
owns estimates. Recommendations below are proposals, not newly approved choices.

## Boundaries and coverage

Packages remain paused. Planning included local source inspection and Microsoft
documentation; it made no GitHub API request, acquired no payload, submitted no
VM test and changed no Windows state. Elevation-dependent work is postponed while
the user is away. No new default selection or supported target was published.

The [source audit](../archive/evidence/remaining-migrations-analysis-2026-10-14.json)
records input hashes, catalog counts, every application review outcome and its
actual next gate, all 30 settings rows, and selectors in the inventory families.
It verifies a one-to-one join between the 79 application outcomes and their
13 review rounds. The 109-row application ledger contains 10 previously migrated,
19 accepted migration, one excluded and 79 individual-review outcomes. Its rows
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
| Packages/portable tools/artifacts | 58-73 | All 79 application review outcomes mapped; some belong to other groups. Coexistence/state design precedes resumed product batches. |
| Windows components | 20-25 | Store workflows, optional features/capabilities, distributions and printer resources separated; exact build/edition discovery precedes mutation. |
| Accounts/configuration/files/assets | 25-35 | User identity, credentials, locale, files, browser preferences and deployment ownership reviewed. |
| Maintenance/actions | 8-12 | Updates, cleanup, hostname and Sysprep need action-specific preview, recovery and reboot contracts. |
| Total, rounded | 150-205 | About 180 for planning. Analysis closes no legacy outcome, so all five ranges remain unchanged. |

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

## Matching batches

These are implementation boundaries, not a second task queue. Move a chosen
batch into the existing TODO/owner ledger and report its implementation and
acceptance separately. Package batches stay preparation-only until the pause is
lifted. Do not bundle a user preference, machine policy and installer together
just because one legacy function performed them all.

| Batch | Proposed scope | Why this order / exit evidence |
| --- | --- | --- |
| B01 | Existing setting presentation and accepted native UI guidance | Smallest changes: compare metadata with actual handler states; label literal/effective defaults and reverse behavior; add selected playback mute guidance. No new setter or component acquisition. GUI mapping remains a separate gate. |
| B02 | Read-only resource contracts and isolated capture fixtures | Define selected connection, endpoint, adapter, volume, account SID, feature/capability and owned file identities. Inspect source/availability without mutation. Unknown, missing and managed states must be explicit. |
| B03 | User bin/profile and Terminal file ownership | Reuse proven profile-block mechanics for the legacy startup PATH requirement; directory provisioning is separate. Terminal JSONC root-field editing requires byte-preservation and conflict proof before implementation. Q08/Q09. |
| B04 | User connection proxy controls | Prove documented connection API capture, manual settings preservation, PAC/detection refresh and intended-user recovery. Keep machine WinHTTP separate. This is backend work, not a quick scalar registry change. |
| B05 | Store acceptance, one app at a time, then group/policy | Solitaire basic native registration lifecycle passed. Report and retain that result; next candidate is Clipchamp when elevation is available. Add interruption, GUI/data and full handoff evidence without rerunning passed cases merely on a wake. |
| B06 | Conditional Windows components | Begin with explicit read-only capability/feature inventories, then a single low-dependency available component such as Telnet Client or OpenSSH Client if selected. Source, applicability, prior enablement and recovery must be proved first. Q05/Q06. |
| B07 | Package deployment/state design | Specify stable product/distribution/deployment identity and versioned recovery migration. Resolve Q01-Q04 before implementing coexistence or kit commands. Preserve old records and their current semantics. |
| B08 | Small portable products, after package resumption | Prefer individually reviewed, self-contained tools with immutable file lists and no driver/service or runtime bootstrap. Start with the relevant application round; do not download a whole collection to discover its members. Q13-Q15. |
| B09 | Accounts, regional configuration and owned assets | Implement each independently after credentials, SID ownership, content source and reboot choices are settled. Do not disable a last viable administrator or overwrite shared assets. Q07-Q12. |
| B10 | Complex packages, security and maintenance | Drivers, Office/Teams, CE backend, encryption, WSL data, update installation and destructive cleanup follow their distinct dependency/recovery decisions. No default-profile activation or automatic reboot. Q16-Q27. |

B01 can start without a product decision. B02 can reduce technical uncertainty
without selecting a resource for the user. B03-B10 contain explicit gates; their
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
| R29 | User .NET assemblies still have no identified source requirement. Keep the provenance question visible; do not create a generic load-assembly setting. |
| R30 | Store candidates and five groups implemented; Solitaire basic acceptance passed. Policy, other apps, interruption, data/GUI and full handoff acceptance remain open under the component owner. |

The [earlier accepted families](remaining-settings-plan.md#earlier-accepted-controls-that-still-need-evaluation)
also remain in scope: promotions and undocumented numeric channels; input/activity
and privacy controls; admin shares/.NET crypto; driver/metadata updates; maintenance
wake and discovery; notification/accessibility/taskbar/This PC; Explorer and Control
Panel/mouse controls; background apps/power; UAC/Defender/SmartScreen; diagnostic and
Office tasks; developer/trust/media controls; SMB/NetBIOS/NCSI and adapter bindings.
Review the whole legacy bundle, omitted behavior, independent utility, managed
precedence and explicit-value versus override-removal semantics. The catalog
currently has 277 setting operations, of which only 28 have explicit presentation
metadata in the earlier audit; verify that count again when B01 starts.

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
| App R02 / 5 | Python; YARA; Loki; Volatility 2; Volatility 3 | Preserve selected Python manager/traditional routes; model runtimes/pip/environment ownership. Pin dependencies/rules and separate updates. Decide specialist Volatility 2 retention; do not declare retired by age. Q17/Q18. |
| App R03 / 9 | ADReplStatus; RSAT; OpenJDK; Neo4j/APOC; BloodHound; SharpHound; AzureHound; ImproHound; PingCastle | RSAT is component-owned. CE backend is a separate deployment. Legacy Neo4j was Community ZIP plus matched APOC, unrestricted plugin configuration and service; preserve that analysis rather than inventing a modern compatibility guarantee. Q05/Q19/Q20. |
| App R04 / 6 | Office deployment; bundled Teams actions; Teams startup; Store Teams cleanup; classic machine-wide Teams cleanup; Visio | Independent product/channel/license/configuration and destructive cleanup scopes. Installing Office authorizes none of the cleanup actions. Q21. |
| App R05 / 8 | Sysinternals; JoeWare; MiTeC; NTCore; Zimmerman; Nirsoft launcher, x64 tools and package/config files | Freeze reviewed membership and file ownership; separate launch/configuration and restricted tools. No mutable collection crawl or implicit Defender exclusion. Q13/Q14. |
| App R06 / 4 | PSScriptTools; PartDiagParser; GglCookieCruncher; Sigma | Pinned release/source snapshot versus editable checkout; dependencies, import/execution and rule application are independent actions. Q15/Q18. |
| App R07 / 4 | OneDrive package; OneDrive sync policy; WinGet; WinGet AutoUpdate | Data and sync account ownership separate from uninstall. WinGet app presence does not implement a package provider. Scheduler/services/configuration and updater policy require separate ownership. Q22. |
| App R08 / 8 | VMware; its home/Documents directory choices; AutomatedLab; VirtIO; SPICE guest tools; SPICE WebDAV; Lenovo Vantage | Edition/entitlement, host versus guest role, hardware, service/driver and reboot evidence. Configuration is separate from package installation. Q16/Q23. |
| App R09 / 5 | VeraCrypt installed/portable; Arsenal products; MEGAcmd helper; WinPmem | Coexistence, drivers, mount/encryption ownership and vendor access/license. MEGAcmd helper is not implicit prerequisite approval. Q01/Q16/Q24. |
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

| Component/resource family | Plan and recovery boundary |
| --- | --- |
| WSL feature and Debian/Ubuntu/Kali/Fedora registrations | Feature enablement, distribution installation and distribution data are separate. Export/retrieval proof precedes unregister; missing Fedora inverse remains a source gap. No implicit distro/package download. |
| Store user registrations and device removal policy | Keep accepted inventories/groups/protection rules. Policy consumer and schema need their own sign-in tests; package presence alone is not availability. No AllUsers removal or image deprovisioning in the user groups. |
| Windows Store itself and repair | Distinguish blocking Store UI, Store registration repair and app removal. Require identified local payload/consumer; never reconstruct protected shared packages from a historical wildcard. |
| Xbox features/dependencies | Distinguish policy settings, five reviewed gaming apps and shared frameworks/services. Refuse removal when other consumers or protection evidence are unresolved. |
| Adobe Flash and standalone Internet Explorer | Check actual component and supported release meaning. Propose retirement of absent/obsolete toggles only with source/applicability evidence; existing IE ESC/IE-mode requirements remain separate. |
| Edge preload/shortcut, first run/logon, media sharing/online, developer/fullscreen controls | Reconcile earlier registry implementations with the complete legacy bundle. These are settings/consumer acceptance, not optional-feature installer work. |
| Optional Windows Media Player | Discover native feature versus Store Media Player; separate from radio/WMDRM consumer and multimedia group. |
| Work Folders | Feature/role and configured sync data/credentials have separate lifecycle. Removing the feature does not recover deleted or unsynced files. |
| Windows Hello Face | Capability, camera/hardware and enrollment are separate; no deletion of existing biometric enrollment through generic recovery. |
| Math Recognizer | Enumerate availability per build; absent capability stays not applicable. Do not fetch old payloads to emulate an obsolete component. |
| Windows PowerShell 2 / ISE | Separate features and security/compatibility intent. Retirement review for v2; ISE availability does not establish PowerShell 7 support. |
| Hyper-V / Windows Sandbox | Hardware, edition, parent features, restart and existing VM ownership. Sandbox configuration/network/drive exposure is a separate explicit file workflow. |
| OpenSSH Client / Server | Capabilities separate; Server service, firewall, host keys and configuration have independent capture/ownership. Client first if selected. |
| Telnet Client | Small conditional feature candidate; no server/service/network-use implication. |
| .NET 2.0/3.5 legacy selector | Build-specific feature versus installer path; distinguish .NET 4.x/runtime SDK from NetFx3. No automatic servicing download. |
| Photo Viewer | Discover consumer; exact Open with registration under intended user, native default-app handoff separately. |
| Microsoft Print to PDF / XPS | Feature and existing queues/ports/drivers separate; preserve custom queue configuration and refuse deleting unknown resources. |
| Fax printer / Windows Fax and Scan | Separate queue, feature/service, devices and stored fax data; no assumption that adding a queue restores the prior fax setup. |
| Internet Printing | Client feature versus Server role and externally reachable service require explicit scope and exposure choice. |
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
| PowerShell startup user-bin PATH | Legacy modifies session PATH and profile startup, not persistent user environment PATH. Own a bounded profile block and normalize duplicate entries; directory provisioning/collision/data retention is separate. |
| Wi-Fi profiles | Select interface/profile scope; securely capture prior XML/ACL and UTF-8 SSID bytes, escape XML and redact PSK. Legacy creates plaintext temporary content; do not port that workflow. Import does not implicitly connect. |
| Windows activation / product-key inspection | Report licensing state separately from operator activation. No secrets in normal state or logs; vendor entitlement and secure entry/retrieval remain explicit. |
| VMware VM directory preferences | Exact file/field ownership and chosen root, no moving existing VMs or overwriting other preferences. App R08 dependency is availability, not automatic package install. |
| Firefox / Chrome preferences | Decide managed machine policy versus intended-user file/default; field-level recovery and custom profiles before broad preference-file creation. |
| Sysmon configuration / logging settings | Download a pinned reviewed config independently from applying it. [Configuration ownership ADR](../decisions/0001-configuration-ownership.md) is proposed; confirm mutation ownership before overlapping LoggingBaseline work. |
| Python environment, associations, plugins and symbols | Distribution-owned environment versus selected user/workspace; preserve existing associations and independent caches. No arbitrary pip/network action on installation. |
| Fonts | Official/licensed source, per-user versus machine scope, exact font identity/collision/registration and ownership. Legacy COM copy/overwrite is not an accepted recovery backend. |
| Wallpaper / lock-screen / default lock-screen | Asset deployment distinct from user preference/device policy. Capture prior file/ACL/config, refuse overwriting shared OS-owned content. Missing/licensed assets need source decision. |
| Context menus, shortcuts and shell resources | Exact bindings/resource paths/quoting/views/ACLs, all relevant consumers and user context. A file or registry subtree is owned only to the declared extent. |
| Deployment/USB kit manifests | Independent product/distribution/version/destination and media identity; no drive-letter-only ownership, implicit formatting, tool execution or unreviewed redistribution. |

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
| Requested v3 additions | Rufus, idrassi HashCheck and the two hash-context-menu options remain queued separately from legacy estimates. No automatic media writing; attribution/algorithm/quoting/GUI and shell lifecycle need evidence. |
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
remain traceable. `EnableInkingAndTypingData` has no implementation and Fedora
removal has no matching legacy function. `RequireAdmin` is a prerequisite
directive. Resolve source intent or explicitly retire/defer; do not manufacture
a setter from its name.

## Questions for the user's return

Answer in batches, starting with Q01-Q04 when packages are ready to resume,
or Q05-Q12 for components/configuration. Technical API/build/provenance checks
remain implementation research; the user need not decide undocumented mappings.
Earlier settings D02-D10 retain their exact questions in the settings plan.

| ID | Decision needed | Recommended starting choice and consequence |
| --- | --- | --- |
| Q01 | How should commands/profiles address independent deployments? | Product selects distributions; an explicit stable deployment ID identifies update/remove/status targets. Refuse ambiguous product-only mutation when multiple deployments exist. Preserve old records through a versioned adapter. |
| Q02 | How should destination and configuration collisions be handled? | Refuse overwrite/adoption by default; require an explicit separately reviewed replacement or adoption workflow. Shared configs cannot belong to two deployments without a defined owner. |
| Q03 | What is the first acquisition-kit layout and identity? | A manifest-owned tools tree with per-product/distribution directories; explicit destination plus volume identity, not drive letter alone. No formatting or copying tools with unknown redistribution rights. |
| Q04 | How should kits update and remove content? | Preserve existing kit until a complete staged replacement passes hashes/member checks; remove only manifest-owned unchanged files, retain tool-generated data and report conflicts. |
| Q05 | Which components should the first selectable group offer? | Start individually with OpenSSH Client/Telnet Client where available; add Server/RSAT/Hyper-V/Sandbox/WSL only as separate roles with their dependencies. None selected by default. |
| Q06 | What servicing media/source may be used? | Explicit locally supplied matching OS/FOD source initially; refuse download fallback while packages are paused. Separate approval for later online servicing. |
| Q07 | What should replacement admin enrollment expose? | Explicit new name and secure interactive password, no secret in profile/config/state; refuse existing-account collision and disabling a last viable administrator. Keep credential rotation/recovery separate. |
| Q08 | Does user-bin mean PowerShell startup only or also persistent Windows PATH? | Migrate the actual legacy startup-only block first. Offer persistent user PATH only as a separate explicit outcome; preserve directory contents on removal. |
| Q09 | Which Terminal default profile may be selected? | Discover current profiles and ask for an existing identity; own only root defaultProfile. No guessed executable/path or Terminal installation. |
| Q10 | Should browser preferences be managed policies or user preferences? | Separate explicit managed policy from user-file preference choices. Import no blanket legacy preference file; preview owned fields per existing profile. |
| Q11 | Where should fonts/wallpapers/lock-screen assets come from and what scope? | User-supplied reviewed manifest plus official license/source; start per-user where supported. Machine/default-user changes stay separate and collision-refusing. |
| Q12 | Which Wi-Fi scope and connection behavior? | Explicit current-user profile and interface, import without connecting; machine/all-user provisioning separate. Secure credential entry and recoverable existing profile are prerequisites. |
| Q13 | Which tools belong in each collection? | Approve exact members/versioned manifest; start small with independently licensed tools. Keep launcher/configuration separate from content; do not equate suite archive with permission for every member. |
| Q14 | Should restricted/free-for-personal-use tools be offered to company users? | Keep licensing review visible per exact product/version/owner in the local review store; no catalog approval default. Omit unreviewed members from shared kits. |
| Q15 | Pinned source snapshot or editable development checkout? | Pinned inert snapshot for deployment; explicitly separate clone/update/import/execute workflows for development tools and rules. |
| Q16 | Which integrations should drivers/nested installers enable? | Minimum product-specific reviewed integration; service/driver/reboot requirements explicit. Preserve earlier Gpg4win/ImageMagick/Npcap decisions and collect only unresolved installer flags. |
| Q17 | Retain Volatility 2 as a specialist optional tool? | Hold pending demonstrated workflow need and usable isolated runtime/source; do not bundle it by default or declare retirement until decided. |
| Q18 | What rules/plugins/dependency set should be maintained? | Pinned core deployment and separate explicit rule/plugin update actions; broader analyst extras selectable, no arbitrary network execution during install. |
| Q19 | Which BloodHound CE backend deployment should RIDE own? | Keep workstation collectors/client separate; choose a managed backend/container environment explicitly. No implicit Docker/WSL or Server Docker Desktop installation. |
| Q20 | Keep standalone Neo4j/APOC and ImproHound outcomes? | Treat standalone graph service as distinct from CE; review actual use/version compatibility. ImproHound retirement remains a user decision. |
| Q21 | Which Office/Visio product, channel and Teams actions? | Explicit licensed product/channel config while retaining reviewed languages. Teams startup/Store/classic cleanup are independent optional actions; no forced process closure/data removal through Office install. |
| Q22 | Should OneDrive/WinGet AutoUpdate policy affect existing user data or scheduling? | Installation/presence separate from sync restrictions and updater schedules. Retain existing data/account setup and require explicit updater targets/source/reboot policy. |
| Q23 | Which virtualization/hardware/GPU roles must be supported? | Host versus guest and actual hardware-specific profiles; no hardware claim from a generic VM. Preserve current controller pins; do not migrate the test host as an application test. |
| Q24 | Which gated/edition-dependent products are needed first? | Prioritize KAPE/FTK/Arsenal or selected viewers individually; supplied entitlement and official artifacts required. Defer unavailable legacy routes rather than substitute products silently. |
| Q25 | Who owns Sysmon/logging/security configuration? | RIDE applies explicitly selected Windows configuration; LoggingBaseline observes/reports, subject to confirming the proposed ADR. Pin config and separate content deployment from live application. |
| Q26 | Should the newer dynamic Store-policy list be included? | Keep the current static workflow first; research an independently schema-gated dynamic-list extension after local-template/CSP consumer acceptance. Do not broaden the 22 app candidates or Pro/Home/Server claims. |
| Q27 | What recovery contract may destructive maintenance offer? | Explicit preview and declared compensating/configuration recovery; require external backup/checkpoint for cache/content deletion and Sysprep. Reboot/stop only explicit operator choices. |
| Q28 | Which settings GUI/boot/hardware cases should run first? | Start Explorer/keyboard visibility on the prepared desktop, then Server logon/shutdown, conditional media/Office/App-V and hardware-dependent cases. Existing D02-D06 contain the detailed resource choices. |
| Q29 | If exact menu subtree/ACL recovery cannot be proved, unavailable or retire? | Keep candidate unavailable and use native guidance. Existing D07 controls retirement; do not silently weaken recovery. |
| Q30 | Endpoint, adapter and volume selection by explicit identity or current default? | Explicit stable identity first with disappearance/conflict refusal. Default-device selection is a separate captured choice. Existing D08/D10 retain device-specific decisions. |
| Q31 | Can the unidentified user .NET assembly requirement be identified? | Provide an actual selector/source/use case; otherwise leave provenance pending and consider evidenced retirement later. Existing D09. |

## Deferred elevation and VM work

| Deferred work | What is ready / why it waits |
| --- | --- |
| Clipchamp isolated Store lifecycle | Separate UAC-enabled offline test desktop exists, with original pins unchanged. Its PowerShell Direct host runner requires a fresh elevation prompt; do not launch while AFK. No app was selected or removed by this planning pass. |
| Store interruption/group/full handoff and policy tests | Basic Solitaire already passed; use new explicit focused modes and exact current-source snapshot for genuinely missing evidence. Sign-in/GUI/data and policy schemas stay distinct from registration recovery. |
| Feature/capability installation and OS/FOD sources | Read-only inventories can be prepared independently; actual servicing may need media, acquisition and elevated worker access. Use available pinned disposable flow only, never the workstation. |
| Local accounts, locale/welcome settings, drivers, boot/security transitions | Postpone any host enrollment/provisioning or interactive credential/elevation action. Secure recovery resources, explicit SID/hardware scope and staged fixture are required before VM mutation. |

When a test is needed, follow [AUTOMATEDLAB-TASKS](../../tests/integration/AUTOMATEDLAB-TASKS.md):
verify idle workers/empty queues/no recovery block, pin/config/script hashes,
exclusive serialization and current local source hashes, including relevant
uncommitted files. Use settings-focused isolated fixtures, bounded failure
collection and final checkpoint recovery. Do not substitute frozen CI source for
current changes, repoint original controllers, run Full/default acquisition suites,
or treat a passing guest run with failed recovery as acceptance. No completed
fixture needs rerunning merely because the thread wakes.

This analysis is complete across the documented remaining scope; implementation
and runtime acceptance remain separate. The user can select B01 immediately or
answer a small related question group without revisiting approved choices.
