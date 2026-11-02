# Migration completion reassessment, 2026-11-02

## Status

Migration execution is paused at the user's request. The next step is to reassess
how to close the remaining work before starting another implementation or test
batch.

## Why the completion approach is being reassessed

The user asked to fast-track the remaining tests because the migration appeared
unlikely to finish. Multiple source-test batches were run and committed, but the
overview stayed at **126-180 estimated legacy outcomes**. That estimate is not a
count of tests remaining. The batches established current-source behavior; most
did not resolve, retire, or exclude a legacy outcome. The work therefore needs
an outcome-oriented closure plan, rather than another unprioritized sweep of
passing source suites.

## Durable reporting and completion rules

For each requested workstream, report its concrete components one workstream at
a time. Label each component as one of:

- **Resolved**: the defined legacy outcome is implemented or otherwise met and
  its required acceptance evidence is complete.
- **Open**: implementation or mapping exists, but a stated acceptance or
  recovery requirement remains incomplete.
- **Unmigrated**: a legacy outcome still lacks an implementation or a recorded
  disposition.
- **Candidate**: optional or new work exists in candidate form and has not
  passed its declared acceptance gate. Candidates that are new features do not
  count as completed legacy outcomes.
- **Retired**: a durable decision removes the legacy outcome from the target
  platform scope.
- **Excluded**: a durable scope decision leaves an outcome out of this
  migration; retain its reason and any operational caveat.
- **Partial/deferred**: only some legacy behavior is covered or remaining work
  is intentionally postponed. Keep it visible and counted until reconciled.

Each status report should name the component, link its source-of-record entry,
state the remaining closure evidence, and identify blockers. Keep source
regression, artifact review, activation, and verified Windows behavior separate.

The five estimates in [MIGRATION-PLAN.md](../MIGRATION-PLAN.md#estimated-remaining-migration-work)
count legacy feature/product outcomes, not test cases or catalog IDs. A passing
source test updates validation evidence; it does not reduce an estimate unless
the linked ledger establishes that a legacy outcome was resolved, retired, or
excluded. Partial and deferred outcomes remain visible and counted according to
the migration model. Recalculate the ranges from the reconciled outcome ledger,
not from the number of tests passed.

## Checkpoint at pause

- **Settings:** presentation review is complete at 279/279. The estimate remains
  37-57 outcomes. The [remaining-settings plan](remaining-settings-plan.md) and
  [post-migration review](settings-post-migration-review.md) identify open
  mappings and candidate-only controls, including hibernation, modern BitLocker
  drive-method policies, Storage Sense policy, local password complexity,
  advanced WinHTTP proxy, desktop shortcuts, and File Explorer F1. Their source
  tests do not establish native acceptance. New controls such as Click to Do
  are candidates, not legacy closures.
- **Packages:** the estimate remains 37-52. Current-source package regressions
  cover many pins and file lifecycles. PSScriptTools' generated inert 360-member
  lifecycle passed 7/7; this does not establish package activation or close a
  legacy product outcome. The WFN 531-member case remains incomplete after a
  bounded attempt. Sysinternals licensing is settled under the prior RIDE v2
  specialist approval; Defender exclusions are independent of that decision.
- **Components:** the estimate remains 19-24. Source preparation and mocked
  lifecycle work do not establish Windows feature installation, service
  behavior, or recovery on declared targets.
- **Files/assets:** the estimate remains 25-35. Source checks do not establish
  Explorer menu, desktop, or other native shell behavior.
- **Maintenance:** the estimate remains 8-12. Source checks do not establish
  runtime ACL, scheduled-task, or screen-lock acceptance.

The exact ranges and dated test evidence remain in the migration plan. The
current Windows PowerShell 5.1 source batch passed 331/331; the PSScriptTools
suite passed 7/7; the WFN full synthetic suite did not finish its large case.
The broader 3,698-case aggregate remains incomplete. Native VM acceptance is
blocked because host CIM access fails before VM/checkpoint inspection. Keep
Defender-alerted NirSoft files excluded and do not materialize them during test
work. See the linked per-batch evidence in the [migration plan](../MIGRATION-PLAN.md).

## Settings component register at pause

These rows follow the active 30-row settings ledger. A row can contain multiple
legacy outcomes, so the row count is not an estimate. “Candidate” means target
support remains gated; “partial” means the listed remaining behavior is not
covered by the implemented subset.

| Ledger | Component | Status | Remaining work or closure evidence |
| --- | --- | --- | --- |
| R01 | Existing and owned power plans; desktop Power Options shortcut | Partial; shortcut/owned-copy candidates | Balanced and High Performance owned-plan lifecycle has two-target evidence. Ultimate Performance activation failed previously. Verify selection and recovery on current targets; separately accept shortcut UI, intended session, and file recovery. |
| R02 | LAN proxy detection, setup script, machine WinHTTP proxy detection | Integrated plus candidate | LAN detection/setup is guarded and integrated. WinHTTP automatic detection is candidate-only; exact underlying recovery, effective policy, consumers, RAS/GUI behavior, and target support remain open. The host build lacks `netsh winhttp show advproxy`. |
| R03 | Windows CEIP, conditional App-V CEIP, native/WOW telemetry mirrors | Partial; CEIP candidates | Windows CEIP typed lifecycle is implemented. Verify App-V client/policy/consumer before enabling it. Native and WOW mirrors remain intentionally unexposed until their effect is established. |
| R04 | Paired feedback-frequency values | Partial; mapping unresolved | Resolve current GUI choices, value types and units, managed precedence, and paired restore. Preserve custom or mixed prior values; do not guess the large-period DWORD representation. |
| R05 | Windows RE enable/disable registration | Unmigrated lifecycle | Build read-only OS/image/partition identity capture and exact prior-registration recovery. Refuse identity or servicing conflicts; readiness guidance alone is not lifecycle support. |
| R06 | Browser service `Hidden` override | Legacy selector retired; modern discovery partial | Preserve legacy history and existing values. Complete current Network Discovery peer/profile behavior separately; do not claim it is equivalent to the retired selector. |
| R07 | MusNotification interception; supported update-notification controls | Interception retired; replacement open | Do not restore IFEO interception. Verify replacement warnings, active-hours/deadline combinations, effective policy, and restart behavior without claiming that reboot is prevented. |
| R08 | System Protection / restore-point controls | Guide and inventory only; lifecycle open | Verify enabled-volume inspection, system-drive coupling, storage allowance and asynchronous completion. Turning protection off may destroy history, which setting restore cannot recover. |
| R09 | Storage Sense bundle and machine policy | On/Off implemented; policy candidate | Verify actual switch, policy precedence, default/removal semantics and cleanup choices using disposable files. Never represent registry restoration as recovery of deleted files. |
| R10 | Windows-native Explorer/Desktop F1 suppression | Candidate; manual target acceptance queued | On the prepared Windows 11 Pro laptop, test Explorer/Desktop Help and unrelated-app F1, then both setting states and exact typed-value/key restoration. Do not use IFEO, ACL changes, AutoHotkey, or a download. |
| R11 | Taskbar sizing; Windows Terminal profile | Mapping open; Terminal backend candidate | Observe actual taskbar choices/rollout rather than assuming `TaskbarSmallIcons`. Preserve Terminal profiles and validate its broader normal-launch behavior beyond Win+X. |
| R12 | Shortcut-arrow icon resource | Unmapped cosmetic outcome | Verify resource index 29, type/expansion, actual image resource and Windows 11 rendering. Preserve custom values; do not force an Explorer restart. |
| R13 | Sign-in and post-sign-in NumLock | Setting candidates; hardware/session evidence open | Compare both registry preferences against the user's reliable combined legacy behavior on real boot/sign-in hardware. Preserve type/encoding and unrelated lock-key state; no SendKeys. |
| R14 | Compressed/encrypted file-name colors | Mapping open | Establish the current GUI mapping before choosing between `ShowCompColor` and the legacy value. Check ordinary, compressed and EFS names/themes without changing file attributes. |
| R15 | Explorer start location and experimental Home hiding | Existing start-location control; Home mapping candidate | Test `HubMode` independently from `LaunchTo`, including user/machine precedence. Do not reconstruct namespaces, reset pins/history, or force restart. |
| R16 | Include in Library, Give access to, Share menus | Three accepted outcomes; implementation/recovery open | Identify physical registry roots/views and all bindings. Use bounded reversible changes; if subtree deletion is needed, prove typed content/subkey/ACL recovery and conflict handling. |
| R17 | Five desktop icons and ClassicStartMenu mirrors | Existing IDs retained; mapping/compatibility open | Compare each icon and any conflicting legacy mirror against GUI/rendering. Keep IDs stable and recover old scalar snapshots without inventing omitted history. |
| R18 | Server Manager startup; Shutdown Event Tracker | Server 2025 candidates | Literal and fault-recovery source evidence exists. Verify logon/console precedence and the actual shutdown prompt on Desktop Experience and Core separately. |
| R19 | Local password complexity; maximum password age; IE ESC | Mixed: max-age evidence, complexity candidate, IE ESC unmigrated | Maximum age has both-target lifecycle evidence but remains a candidate pending remaining acceptance. E08 complexity has template/validation work, not an accepted native apply path. IE ESC needs actual Server component/class/profile-effect evidence and separate admin/user controls. |
| R20 | Windows Audio service; selected playback-device mute | Service candidate; endpoint mute unmigrated | Audiosrv lifecycle/fault recovery passed both targets, but dependency/trigger acceptance remains. Implement endpoint mute around stable device identity and session/device-loss recovery without changing volume/default device. |
| R21 | BitLocker enrollment, decryption, TPM+PIN, modern drive-method policies | Multiple candidates; full workflow open | The three OS/fixed/removable drive-method policies remain unsupported candidates. Complete the staged enrollment/decryption/boot workflow, preserve methods/protectors, redact secrets, and verify recovery before any real boot test. |
| R22 | BitLocker recovery-password backup, creation and selected-key display | Guided workflows open | Implement secure selection by protector type/ID, off-device retrieval and redacted output. Never expose secrets in logs/state or implicitly rotate, upload, print, or copy keys. |
| R23 | Failed-sign-in machine lockout | Unmapped security experiment | Verify the local GUI/legacy mapping, real counting and recovery behavior only after OS-volume protection and retrievable recovery backup. Keep Windows sign-ins separate from TPM PIN, Hello, and account lockout. |
| R24 | Windows Photo Viewer Open with and default-app handoff | Open with candidate | Bounded intended-user registration candidate exists. Windows 11 acceptance must verify exact extensions, installed component, visibility, managed behavior, rendering and recovery. Default-app selection remains a separate native UI step. |
| R25 | Radio preset retrieval; Windows Media DRM Internet access | Conditional policy candidates | Verify actual current radio and DRM consumers, effective policy and Server coverage. Typed setting recovery does not restore remote servers/licenses; do not install players or repair license stores. |
| R26 | Keyboard repeat delay; packed visual-effects mask | Delay implementation; effects partial/unmapped | Stored delay positions and typed recovery pass. Compare native effective delay before changing backend. Map each visual effect independently and preserve custom masks; no broad fixed preset. |
| R27 | WAP Push and Windows Search delayed/startup-only states | Implemented lifecycle; boot acceptance open | Stored/runtime lifecycle and controlled recovery pass. Verify boot scheduling, workload, dormant flags, trigger/dependency effects and Server behavior; no reboot or fixed-delay guarantee is implied. |
| R28 | Windows Security startup icon | Guidance/policy exists; intended-user handoff open | Verify the exact startup entry, user/machine scope, managed precedence, tray overflow and visible icon. Keep handoff as a user action; do not reconstruct a historical Run entry automatically. |
| R29 | User .NET assemblies label | Closed as unsubstantiated bookkeeping | No known feature or selector was found. Reopen only if a concrete source/use case appears; do not invent an assembly operation or deduct a numeric outcome. |
| R30 | Store app selection, policy and user uninstall | Five guarded group candidates; native acceptance open | Solitaire's basic registration lifecycle passed. Complete Clipchamp next when elevation is available, then GUI/full handoff, group behavior, policy, app/data recovery, sign-in and other-target acceptance. Keep existing apps installed meanwhile. |

Additional settings/control candidates outside those legacy rows include the
Domain/Private/Public and all-profile Windows Firewall operations. Their basic
lifecycle evidence exists, but effective ActiveStore state, active-network,
connection/GUI and target evidence remain open. Click to Do is a new-feature
candidate, not a legacy outcome. These and other candidate declarations are not
support claims merely because they appear in the catalog.

## Package component register at pause

The current catalog has **52 package operations marked `PendingAcceptance`**;
each has empty `SupportedTargets` and one or more `CandidateTargets`. This is a
catalog-operation count, not the **37-52 legacy package-outcome estimate**.
Some candidates are new additions, and some legacy selectors remain without a
catalog operation.

### Catalog package candidates

All components listed here remain candidate-only until their applicable target
acceptance closes. Source and local lifecycle coverage varies by product. The
fast-track evidence threshold for ordinary user-mode packages is the exact
source/version pin, package-level install/repeat/remove and owned-file recovery,
plus recorded Defender active/no-alert state. Per-utility feature testing is
not a default requirement; add it only where the product or integration needs
it. Drivers, services, firewalls, file associations, setup prerequisites, and
security-sensitive workflows keep their specific acceptance requirements.

**General applications and source utilities (9):**

- `package.chromeparser` — ChromeSyncParser (pinned Python source).
- `package.docker-desktop` — Docker Desktop.
- `package.etl2pcapng` — Microsoft ETL2PCAPNG.
- `package.exiftool` — ExifTool.
- `package.google-analytic-cookie-cruncher` — Google Analytic Cookie Cruncher.
- `package.gpg4win` — Gpg4win command line and Kleopatra.
- `package.hex2text` — Hex2text (pinned Python source).
- `package.joeware-admod` — JoeWare AdMod.
- `package.microsoft-powershell-threadjob` — Microsoft.PowerShell.ThreadJob dependency.

**MiTeC applications (23):**

- `package.mitec-dfm-editor` — DFM Editor.
- `package.mitec-dirlist` — DirList.
- `package.mitec-exe-explorer` — EXE Explorer.
- `package.mitec-hexedit` — HexEdit.
- `package.mitec-icon-explorer` — Icon Explorer.
- `package.mitec-infobar` — InfoBar.
- `package.mitec-interbase-query` — Interbase Query.
- `package.mitec-json-viewer` — JSON Viewer.
- `package.mitec-mail-checker` — Mail Checker.
- `package.mitec-network-meter` — Network Meter.
- `package.mitec-network-scanner` — Network Scanner.
- `package.mitec-ole-com-explorer` — OLE/COM Object Explorer.
- `package.mitec-paradox-data-editor` — Paradox Data Editor.
- `package.mitec-project-maker` — Project Maker.
- `package.mitec-smbios-explorer` — SMBIOS Explorer.
- `package.mitec-sqlite-query` — SQLite Query.
- `package.mitec-ssview` — Structured Storage Viewer.
- `package.mitec-system-information` — System Information eXtra.
- `package.mitec-tapi-monitor` — TAPI Monitor.
- `package.mitec-task-manager-deluxe` — Task Manager DeLuxe.
- `package.mitec-windows-file-analyzer` — Windows File Analyzer.
- `package.mitec-windows-registry-recovery` — Windows Registry Recovery.
- `package.mitec-xml-viewer` — XML Viewer.

**NirSoft collections (2):**

- `package.nirsoft-launcher` — NirLauncher 1.30.26 filtered collection.
- `package.nirsoft-x64-tools` — reviewed x64-tools snapshot.

**NTCore tools (8):**

- `package.ntcore-dynlogger` — DynLogger.
- `package.ntcore-explorer-suite` — Explorer Suite installer candidate.
- `package.ntcore-net-generic-unpacker` — .NET Generic Unpacker.
- `package.ntcore-nodel` — NoDel.
- `package.ntcore-screenwriter` — ScreenWriter MSI.
- `package.ntcore-snsremover` — SNSRemover.
- `package.ntcore-virtualreg-manager` — VirtualReg Manager.
- `package.ntcore-wim-installer` — WIM Installer.

**Other selected tools (10):**

- `package.phoenix-protector` — Phoenix Protector.
- `package.psscripttools` — PSScriptTools pinned source candidate.
- `package.raspberry-pi-imager` — Raspberry Pi Imager.
- `package.rawcopy` — RawCopy.
- `package.regripper` — RegRipper.
- `package.rufus` — Rufus portable x64.
- `package.tmog` — Task Manager TMOG.
- `package.windows-firewall-notifier` — Windows Firewall Notifier.
- `package.winpmem` — WinPmem.
- `package.wireshark` — Wireshark machine MSI.

### Component-specific acceptance status

The rows below are intentionally one catalog component per row. Every row is
still a candidate with no declared supported Windows target; source tests and
local archive checks do not by themselves promote a package. For ordinary
user-mode packages, closure follows the fast-track threshold above. Where a
clustered source suite is named, it provides evidence for the listed component
only to the extent covered by that suite; it does not imply Windows acceptance.

| Catalog component | Evidence and present state | Remaining component work |
| --- | --- | --- |
| `package.chromeparser` — ChromeSyncParser | Pinned Python source; candidate. | Verify selected source/version and runtime dependency, then exact package install/repeat/remove/recovery, Defender state, and Windows 11 acceptance. |
| `package.docker-desktop` — Docker Desktop | Source and mocked package coverage; candidate. | Verify exact pin, prerequisite and VM requirements, package lifecycle/recovery, Defender state, and Windows 11 acceptance. |
| `package.etl2pcapng` — Microsoft ETL2PCAPNG | Source coverage exists; retained-payload lifecycle was skipped without its explicit fixture. | Provide the exact retained fixture if needed, finish package lifecycle/recovery and Defender evidence, and accept on Windows 11. Do not launch the utility for package-presence acceptance. |
| `package.exiftool` — ExifTool | Source or mocked package coverage; candidate. | Finish exact source/version pin, install/repeat/remove and owned-file recovery, Defender state, and Windows 11 acceptance. |
| `package.google-analytic-cookie-cruncher` — Google Analytic Cookie Cruncher | Candidate with source coverage; retained-archive case skipped without its explicit fixture. | Verify exact source/version and fixture-backed package lifecycle/recovery, then Defender state and Windows 11 acceptance. |
| `package.gpg4win` — Gpg4win command line and Kleopatra | Source or mocked package coverage; candidate. | Verify exact package pin and installer lifecycle; test recovery boundaries for user data separately; record Defender state and Windows 11 acceptance. |
| `package.hex2text` — Hex2text | Pinned Python source; candidate. | Verify runtime dependency and selected source/version, package lifecycle/recovery, Defender state, and Windows 11 acceptance. |
| `package.joeware-admod` — JoeWare AdMod | Version 1.29.00 pinned with synthetic route checks; archive-route case skipped without its explicit fixture and publisher DNS is blocked. | Complete retained-artifact lifecycle and Windows 11 acceptance when the fixture/source is available; capture Defender state. `NeedsReview` is administrative, not a migration gate. |
| `package.microsoft-powershell-threadjob` — Microsoft.PowerShell.ThreadJob | Exact retained ThreadJob 2.2.0 `.nupkg` and local owned-file lifecycle evidence exist; candidate dependency. | Complete managed dependency activation and Windows 11 acceptance with the dependent PSScriptTools scenario; verify recovery/removal guard. |
| `package.mitec-dfm-editor` — DFM Editor | Delphi 11/12 archive-variant source lifecycle covered; candidate. | Verify chosen variant in package lifecycle, owned-file recovery, Defender state, and Windows 11 acceptance. |
| `package.mitec-dirlist` — DirList | Included in the 2026-11-02 DirList/Network Meter/Paradox/Mail Checker source regression (8/8 cluster result); candidate. | Capture component-specific pin/lifecycle result, Defender state, and Windows 11 acceptance. |
| `package.mitec-exe-explorer` — EXE Explorer | Registered Windows 11 package staging and checkpoint recovery passed; utility not run. | Record Defender active/no-alert evidence and package-level install/repeat/remove/recovery acceptance; keep utility feature testing out unless an integration requires it. |
| `package.mitec-hexedit` — HexEdit | Registered Windows 11 package staging and checkpoint recovery passed; utility not run. | Record Defender active/no-alert evidence and package-level install/repeat/remove/recovery acceptance; keep utility feature testing out unless an integration requires it. |
| `package.mitec-icon-explorer` — Icon Explorer | Retained-archive lifecycle passed in prior cross-shell evidence; candidate. | Record Defender state and registered Windows 11 package acceptance. |
| `package.mitec-infobar` — InfoBar | Deferred; not part of the active candidate acceptance batch. | Keep deferred until the source/version and acceptance scope are deliberately resumed. |
| `package.mitec-interbase-query` — Interbase Query | x86/x64 retained-archive lifecycle covered; 2026-11-02 Interbase/mail/history source regression reported 18/19. | Resolve the remaining source case/fixture, then record Defender state and Windows 11 package acceptance. |
| `package.mitec-json-viewer` — JSON Viewer | Current-source x86/x64 archive tests passed within the JSON/XML Viewer regression; candidate. | Record Defender state and Windows 11 package acceptance. |
| `package.mitec-mail-checker` — Mail Checker | Included in the 2026-11-02 DirList/Network Meter/Paradox/Mail Checker source regression (8/8 cluster result); candidate. | Capture component-specific pin/lifecycle result, Defender state, and Windows 11 acceptance. |
| `package.mitec-network-meter` — Network Meter | Included in the 2026-11-02 DirList/Network Meter/Paradox/Mail Checker source regression (8/8 cluster result); candidate. | Capture component-specific pin/lifecycle result, Defender state, and Windows 11 acceptance. |
| `package.mitec-network-scanner` — Network Scanner | x86/x64 retained-archive lifecycle covered; 2026-11-02 DFM/Task Manager/Network Scanner source regression reported 11/13. | Resolve the remaining source cases/fixtures, then record Defender state and Windows 11 package acceptance. |
| `package.mitec-ole-com-explorer` — OLE/COM Object Explorer | Retained-archive lifecycle covered in prior cross-shell evidence; candidate. | Record Defender state and registered Windows 11 package acceptance. |
| `package.mitec-paradox-data-editor` — Paradox Data Editor | Included in the 2026-11-02 DirList/Network Meter/Paradox/Mail Checker source regression (8/8 cluster result); candidate. | Capture component-specific pin/lifecycle result, Defender state, and Windows 11 acceptance. |
| `package.mitec-project-maker` — Project Maker | Installation lifecycle accepted in existing evidence; candidate operation remains pending target support. | Confirm current package source/version and capture the remaining Defender/target acceptance record; do not repeat product-feature testing by default. |
| `package.mitec-smbios-explorer` — SMBIOS Explorer | Retained-archive lifecycle covered in prior cross-shell evidence; candidate. | Record Defender state and registered Windows 11 package acceptance. |
| `package.mitec-sqlite-query` — SQLite Query | Actual-archive staging/removal/recovery passed in both PowerShell editions; included in 20/21 viewers/UUID/SQLite source regression. | Resolve the remaining cluster case if applicable, then record Defender state and Windows 11 acceptance. No database or utility ran in the lifecycle tests. |
| `package.mitec-ssview` — Structured Storage Viewer | Retained publisher archive lifecycle passed in both PowerShell editions; certificate/SSView source regression reported 7/7. | Record Defender state and registered Windows 11 package acceptance. |
| `package.mitec-system-information` — System Information eXtra | Registered Windows 11 file staging and checkpoint recovery passed; utility not run. | Record Defender active/no-alert evidence and package-level acceptance. Staging does not establish utility behavior. |
| `package.mitec-tapi-monitor` — TAPI Monitor | Registered Windows 11 file staging and checkpoint recovery passed; utility not run. | Record Defender active/no-alert evidence and package-level acceptance. Staging does not establish utility behavior. |
| `package.mitec-task-manager-deluxe` — Task Manager DeLuxe | x86/x64 retained-archive lifecycle covered; 2026-11-02 DFM/Task Manager/Network Scanner source regression reported 11/13. | Resolve remaining cluster source cases/fixtures, then record Defender state and Windows 11 acceptance. |
| `package.mitec-windows-file-analyzer` — Windows File Analyzer | Retained-archive lifecycle passed in prior cross-shell evidence; candidate. | Record Defender state and registered Windows 11 package acceptance. |
| `package.mitec-windows-registry-recovery` — Windows Registry Recovery | Retained-archive lifecycle covered in prior cross-shell evidence; candidate. | Record Defender state and registered Windows 11 package acceptance. |
| `package.mitec-xml-viewer` — XML Viewer | Current-source x86/x64 archive tests passed within the JSON/XML Viewer regression; candidate. | Record Defender state and Windows 11 package acceptance. |
| `package.nirsoft-launcher` — NirLauncher filtered collection | 647/668 entries selected; filtered lifecycle deferred after staging provenance failed to explain repeated PasswordScan alerts. | Keep the reported alert tools and both PasswordScan architecture paths omitted. Do not restore, inspect, launch, allow, or add Defender exclusions for them. Resolve staging provenance before any lifecycle rerun. |
| `package.nirsoft-x64-tools` — reviewed x64-tools snapshot | Local encrypted publisher-archive lifecycle passed for 47 selected members; ProduKey and WirelessKeyView omitted; no utility launched. | Windows 11 package acceptance and Defender active/no-alert evidence remain open. Never rematerialize the reported alert files. |
| `package.ntcore-dynlogger` — DynLogger | Candidate; source/current-archive staging checks exist within NTCore coverage. | Record exact package pin, install/repeat/remove/recovery and Defender evidence on Windows 11. |
| `package.ntcore-explorer-suite` — Explorer Suite | Windows 11 build 26300 install/repeat/remove/presence recovery passed; 432/436 tests passed, four skipped. | Record Defender active/no-alert state before target support. No additional feature tests by default. |
| `package.ntcore-net-generic-unpacker` — .NET Generic Unpacker | Candidate; source/current-archive staging checks exist within NTCore coverage. | Record exact package pin, install/repeat/remove/recovery and Defender evidence on Windows 11. |
| `package.ntcore-nodel` — NoDel | Candidate; source/current-archive staging checks exist within NTCore coverage. | Record exact package pin, install/repeat/remove/recovery and Defender evidence on Windows 11. |
| `package.ntcore-screenwriter` — ScreenWriter MSI | Candidate; installer routing/source coverage exists. | Record exact package pin, install/repeat/remove/recovery and Defender evidence on Windows 11. |
| `package.ntcore-snsremover` — SNSRemover | Candidate; source/current-archive staging checks exist within NTCore coverage. | Record exact package pin, install/repeat/remove/recovery and Defender evidence on Windows 11. |
| `package.ntcore-virtualreg-manager` — VirtualReg Manager | Candidate; source/current-archive staging checks exist within NTCore coverage. | Record exact package pin, install/repeat/remove/recovery and Defender evidence on Windows 11. |
| `package.ntcore-wim-installer` — WIM Installer | Candidate; source/current-archive staging checks exist within NTCore coverage. | Record exact package pin, install/repeat/remove/recovery and Defender evidence on Windows 11. |
| `package.phoenix-protector` — Phoenix Protector | Version 1.7.1 MSI pinned; source, prerequisite and installer-routing checks pass. | Windows install/repeat/remove/recovery, prerequisite-conflict acceptance and Defender state remain open. |
| `package.psscripttools` — PSScriptTools | Generated inert 360-member current-source lifecycle passed 7/7; upstream code and installer were not run. | Compare the retained publisher archive when explicitly available; verify ThreadJob acquisition/dependency, package activation, notices, Defender state and Windows 11 acceptance. Source pass closes no package outcome. |
| `package.raspberry-pi-imager` — Raspberry Pi Imager | Version 2.0.12 candidate and source checks exist. | Complete Windows package lifecycle/recovery and Defender evidence. Removable-media acceptance is separate; do not image or alter a device during package-presence testing. |
| `package.rawcopy` — RawCopy | Source/package test coverage exists; retained-payload lifecycle was skipped without explicit fixture. | Provide exact retained fixture if required, then complete package lifecycle/recovery, Defender evidence and Windows 11 acceptance without launching the utility. |
| `package.regripper` — RegRipper | Source regression coverage exists; candidate. | Complete exact source/version and package lifecycle/recovery, Defender evidence and Windows 11 acceptance. |
| `package.rufus` — Rufus portable x64 | Local retained-artifact lifecycle and exact recovery exist. | Complete Windows 11 package staging and Defender evidence; keep application/hardware acceptance separately scoped. |
| `package.tmog` — Task Manager TMOG | Source/mock package coverage; candidate. | Complete package lifecycle/recovery and Windows 11 acceptance. Confirm the selected free-versus-paid entitlement boundary. |
| `package.windows-firewall-notifier` — Windows Firewall Notifier | Catalog/source and compact synthetic checks passed 2/2; 531-member lifecycle stalled; product not launched. | Resolve with bounded package proof; then Windows package acceptance, Defender evidence and firewall-interaction/policy behavior acceptance. Host CIM currently blocks VM access. |
| `package.winpmem` — WinPmem | Signed production acquisition asset pinned; source checks do not execute it. | Complete Windows package install/recovery and Defender evidence. Driver loading and memory acquisition are outside package-presence acceptance. |
| `package.wireshark` — Wireshark machine MSI | Version-pinned MSI metadata/source boundaries covered. | Complete deterministic installer lifecycle, optional Npcap handling, removal/recovery, Defender evidence and Windows target acceptance. |

The 2026-11-02 MiTeC/NTCore source regressions reported 119/131 cases across
their scoped suites, with 12 retained-archive fixture skips; they close no
legacy outcome. The PSScriptTools generated 360-member pass above is likewise
source-only. The test evidence is archived by component family alongside this
register: [MiTeC DFM/Task Manager/Network Scanner](../archive/evidence/mitec-dfm-task-manager-network-scanner-regression-2026-11-02.json),
[MiTeC DirList/Network Meter/Paradox/Mail Checker](../archive/evidence/mitec-dirlist-network-paradox-mailchecker-regression-2026-11-02.json),
[MiTeC historical/review data](../archive/evidence/mitec-historical-review-data-regression-2026-11-02.json),
[MiTeC Interbase/mail/history](../archive/evidence/mitec-interbase-mail-history-regression-2026-11-02.json),
[MiTeC certificate/SSView](../archive/evidence/mitec-certificate-ssview-regression-2026-11-02.json),
[MiTeC viewers/UUID/SQLite](../archive/evidence/mitec-viewers-uuid-sqlite-source-regression-2026-11-02.json),
[NTCore/Phoenix current-source regression](../archive/evidence/ntcore-phoenix-current-source-regression-2026-11-02.json),
and [PSScriptTools 360-member source lifecycle](../archive/evidence/psscripttools-360-member-lifecycle-regression-2026-11-02.json).
Defender active/no-alert and target acceptance remain distinct from source test
results.

### Legacy selectors still unmigrated or partially represented

These are not all represented by the 52 catalog candidates above:

| Legacy component | Status and remaining work |
| --- | --- |
| Standard ImageMagick installer | Unimplemented. Exact installer bytes/hash/signature, machine PATH ownership, reversible install/remove and target acceptance remain open. Its separate portable Q16 package passed Windows 11 lifecycle and bounded image smoke acceptance; activation remains pending and Server support is not claimed. |
| Microsoft OpenJDK 25/21/17/11 side-by-side packages | Partial. Server 2025 lifecycle passed for all four versions, preserving shared `JAVA_HOME`/`PATH`/`.jar` state. Windows 11 acceptance and exact previous-version recovery remain open; no Windows 11 support claim. |
| Three Sysmon Modular profiles | Selected pinned download-only artifacts for Sysmon 15.21. Live acquisition, retained-file recovery, and user acceptance remain open. This does not authorize installing Sysmon or applying/replacing a configuration. |
| Python runtime selectors | Partial. The auto-install setting candidate exists, but selected runtime bytes/manifests, offline-index ownership, manager/launcher coexistence, PATH/alias conflicts, recovery, and Windows acceptance remain open. |
| CCleaner, Recuva, Speccy | Selected outcomes, no exact current publisher artifact pins/lifecycle yet. CCleaner installer route is versionless and its portable version is stale; Recuva/Speccy offer installer routes without a verified artifact. DNS/acquisition has blocked byte verification. |
| Defraggler | User-selected legacy outcome remains unresolved; publisher EOL is confirmed and no local artifact was found. Needs a user disposition or a publisher-authorized retained source; do not invent a replacement package. |
| JoeWare UserDump and other unregistered JoeWare tools | Source/acquisition and exact member identities remain incomplete. AdMod is separate and remains the candidate described above. |
| NTCore Filter Monitor, Vista4Experts, AntiMida | Unmigrated/unpinned. Publisher pages were reviewed, but exact archive bytes/hash/inventory are unavailable; no catalog candidate is claimed. |
| BloodHound CE, SharpHound, AzureHound | Exact selected versions/notices/digests are documented, but selected archives are not retained locally; archive inventory, candidate package design, lifecycle and Windows acceptance remain open. Do not substitute a different AzureHound release. |
| KAPE | Unmigrated. Publisher acquisition is form/EULA gated and the selected definitions snapshot is unavailable. The separately approved dedicated-directory Defender exclusion policy does not establish package availability or acceptance. |
| VeraCrypt installed and portable variants | Deferred. Driver lifecycle, reboot and exact recovery require an orchestrated VM scenario; managed-file ownership alone is insufficient. |
| ADReplStatus | Deferred pending evidence that the upstream distribution remains available and supported. |
| Legacy Firewall Notifier behavior | Package presence is separate from its legacy firewall-policy effects. Exact policy capture, rollback, and interaction acceptance remain open. |
| Zimmerman tools and associated maps/batches | Legacy mutable helper self-updates and executes discovered utilities. Immutable versions, complete inventories, safe managed updating and content ownership remain open; helper-source pinning alone is not package migration. |
| WinGet and WinGet AutoUpdate | Unmigrated servicing workflows. WinGet MSIX dependencies/registration and WAU scheduled-task/service/update behavior need their own lifecycle and recovery design. |
| NirSoft launcher package metadata | `.nlp` and language files are launcher configuration/content, not an independent software package. Define their ownership and relationship to the launcher without staging Defender-alerted tools. |
| Arsenal Recon selection | Selected free-use products still need exact commits/artifacts/hashes/inventories and package lifecycle review. Keep each product separate; don't infer collection-wide acceptance. |
| Wireshark legacy installer selector | The current MSI candidate does not by itself close the legacy EXE selector; deterministic variant selection and optional Npcap lifecycle/recovery remain open. |

Across package work, **Defender active/no-alert evidence and RIDE-Win11-Test
access remain blockers** because host CIM access fails before VM/checkpoint
inspection. The user has settled Sysinternals licensing under prior specialist
approval; `NeedsReview` markers are owner/version administration and do not
block RIDE direct-download/install planning. Keep security exclusions separate
from both decisions.

## Resume criterion

Resume when the completion approach has been reviewed. Start with an explicit
legacy-outcome inventory for the workstream being discussed, separating
implemented-but-open outcomes from unmigrated outcomes, candidates, and accepted
or retired outcomes. Prioritize batches by the number of outcomes they can
actually close and the acceptance resources they require. Preserve the existing
authorization to run approved batches without pauses between them and commit
each completed batch separately; do not resume automatically while this
reassessment is pending.
