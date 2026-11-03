# Migration completion reassessment, 2026-11-03

## Current status

### Default-image catalog integration, 2026-11-03

`windows.default-wallpaper` and `windows.default-lock-screen` now route through
RIDE discovery, show/status, planning, set/apply and saved-run restore. The optional
`profiles/default-images.psd1` requires explicit local PNG paths and reviewed
SHA-256 pins; the normal workstation profile does not select personal images.
Completion, catalog/profile validation, generated reference and operator guidance
are updated. Image payloads are checked before profile mutation; sibling image
policy values no longer break repeat apply, and shared-key recovery is reversed.

The accepted image behavior reuses the attended EnterpriseEval 26300.9711 records.
The new catalog adapter is covered by mocked lifecycle/preview/recovery tests in
both native PowerShell editions, not a new VM catalog execution. Other theme
defaults, separate clock-overlay rendering, other targets and per-user lock-screen
modes remain unverified or unimplemented. See [integration evidence](../archive/evidence/default-images-catalog-integration-2026-11-03.json)
and [operator guidance](../image-personalization.md). No VM cleanup or unrelated queue
was started. No further legacy outcome is deducted: this completes integration of
the already tracked image outcomes. All five ranges were reviewed and remain
37-57 / 34-49 / 19-24 / 23-33 / 8-12, exact 121-175 and rounded 120-175.

### Attended wallpaper visual acceptance and closeout, 2026-11-03

The corrected retained run 5e17e9ff4ec446b08445e84f804d26a0 passed the scoped
wallpaper visual checks on Windows 11 EnterpriseEval 26300.9711:

- The fresh test account received the selected fedora/suit/red-tie wallpaper.
- The user confirmed a replacement background persisted through sign-out/in.
- The pre-existing control account retained its original black/BGInfo background.
- After RIDE's exact policy/file restore, a new recovery account received Windows
  scenery and "Learn about this picture", consistent with the original Spotlight
  default. Rotating scenery need not match the original pixels.

Account/profile inspection correlated both new-user desktop observations. Apply,
repeat, exact machine restore and repeat restore passed with verified exports.
All three owned accounts/profiles were removed. A conservative cleanup guard
initially refused residual CIM logon records after actual sign-out; a normal
restart cleared them. This remains a fixture diagnostic follow-up, not a failed
wallpaper observation. The guard was not bypassed.

AutomatedLab BGInfo was isolated during testing. Final lab cleanup used the
known checkpoint as the user requested, without separately undoing BGInfo.
ResetAndOff, the 26-file evidence export and retained-hold release all verified.
The stop marker is restored; unrelated test queues remain stopped.

Other theme defaults were not independently compared; catalog integration is recorded above. Other
targets and current-user lock-screen modes remain separate. Scripted visual flags
remain false; the linked record supplies the attended visual evidence. No further
legacy deduction is made: 37-57 / 34-49 / 19-24 / 23-33 / 8-12, exact 121-175,
rounded 120-175. See [wallpaper evidence](../archive/evidence/wallpaper-attended-visual-native-2026-11-03.json)
and the [migration run summary](../MIGRATION-PLAN.md#attended-image-acceptance-2026-11-03).

### Wallpaper fixture correction, 2026-11-03

The original control-user creation failed before image application. Native
conversion checks reproduced a defect in passing SecurityIdentifier to a
LocalPrincipal parameter, consistent with that failure; the original underlying
exception was not retained. Saved-SID cleanup and checkpoint recovery passed.
Version 0.1.1 passes a SID string and
preserves underlying error details; all 33 focused tests passed in each shell.
The corrected native run above verified standard-user creation and profile
cleanup. See [failure and correction evidence](../archive/evidence/wallpaper-fixture-member-binding-fix-2026-11-03.json).

### Attended image testing resumed, 2026-11-03

The attended default-lock test on 2026-11-03 verified the signed-out sign-in
background changing from the original lakeside image to the selected suit/red
tie and back after RIDE restore. Six durable lifecycle checks, evidence export
and checkpoint reset/hold release passed. Screenshots are retained locally with
hashes. Scope is EnterpriseEval 26300.9711, signed-out sign-in background only;
other users/targets and current-user image modes remain open; catalog integration is recorded above.
Wallpaper's later scoped visual run and checkpoint closeout are recorded above. No legacy
outcome is deducted: all five ranges remain 37-57 / 34-49 / 19-24 / 23-33 / 8-12,
exact 121-175, rounded 120-175.

See [correlated visual evidence](../archive/evidence/default-lock-attended-visual-native-2026-11-03.json).


### Requested stop and final result, 2026-11-03

The user requested a stop after the active test. Gpg4win's corrected retry
finished Failed at 13:20 Copenhagen, reproducing installer exit `0xC0000005`.
All 76 guest regression tests passed; Defender and separate checkpoint recovery
passed. Product recovery was false and startup was not reached. Corrected NSIS
destination syntax did not resolve the crash; its cause remains unproven. See
[final Gpg4win evidence](../archive/evidence/gpg4win-corrected-installer-failure-native-2026-11-03.json).

At 13:21 Copenhagen the pinned VM was Off, both workers Ready, queues empty,
and no recovery hold or retained request remained. The correction queue stopped
after three runs. Font and InfoBar waiting clients exited with zero requests;
their generic StoppedForInspection status records the explicit stop request,
not a new native failure. TMOG and System Information/TAPI were not admitted.
The stop marker remains; existing expiring workers are registered but idle.
See [stop evidence](../archive/evidence/attended-requested-stop-2026-11-03.json).

Project Maker's latest native pass brings MiTeC to 31 passing variants / 26
products. Windows shared-scenario and status tests now have both-edition evidence;
the stale search assertion was corrected and its full file passed. No further
native tests are scheduled by this client. No new legacy outcome closed, retired
or was excluded: all five ranges remain 37-57 / 34-49 / 19-24 / 23-33 / 8-12,
exact 121-175, rounded 120-175. The remaining components and next-session order
are in the [v3 remaining-components report](v3-remaining-components-status-2026-11-03.md).


### Project Maker native fast-track pass, 2026-11-03

Project Maker 1.9.0 passed all nine native lifecycle checks, including eight-second
startup with its pinned executable, repeat installation/removal and compensating
presence recovery. All 464 guest regression tests passed (four skipped); Defender
and separate checkpoint recovery passed. Previous-version recovery, interactive
UI and product features are not claimed. See
[native evidence](../archive/evidence/project-maker-fast-track-native-2026-11-03.json).
The distinct MiTeC tally is now 31 passing variants across 26 products. Gpg4win,
TMOG and the corrected System Information/TAPI route follow unattended, then the
font diagnostic and InfoBar retry. No additional legacy outcome is counted again:
all five ranges remain 37-57 / 34-49 / 19-24 / 23-33 / 8-12, exact 121-175,
rounded 120-175; unresolved acceptance stays included.

### InfoBar timeout and unattended continuation, 2026-11-03

InfoBar's corrected regression gate passed 464 tests (four skipped), but the
installer run timed out after acquisition. Its transcript was locked and omitted;
startup, uninstall and product recovery were not established. Separate checkpoint
recovery passed. See [native timeout](../archive/evidence/infobar-installer-timeout-native-2026-11-03.json).
The pending candidate now uses the existing root-process completion policy and
retains an installer log. Exit-code and installed-state checks remain required.
Both PowerShell editions passed 178 focused tests (three skipped), and repository
validation passed. This is a hypothesis to verify, not an established cause or a
native pass. See [source checks](../archive/evidence/infobar-installer-completion-source-2026-11-03.json).
Project Maker and the remaining correction queue continue unattended; the font
diagnostic retry follows verified recovery. No additional legacy outcome closes:
all five ranges remain 37-57 / 34-49 / 19-24 / 23-33 / 8-12, exact 121-175,
rounded 120-175. Failed, partial and deferred outcomes remain counted.

### Attended resumption decisions, 2026-11-03

Evidence through 13:21 Copenhagen: **31 MiTeC variants across 26 products passed
installation, bounded startup, removal and recovery**. This includes Mail Checker,
which passed nine explicit lifecycle checks and 63 guest regression tests. Its
old uninstall registration omits DisplayVersion; the exact executable hash and
FileVersion 7.2.0.0 were verified instead, including after compensating recovery.
No mail accounts, credentials or mail operations were used. See the
[Mail Checker result](../archive/evidence/mail-checker-fast-track-native-2026-11-03.json)
and [product fast-track register](package-fast-track-register.md).

Ten viewer/development variants passed in the guest while the old outer controller
incorrectly rejected their startup flag. Both results remain recorded; the
controller fix was installed and subsequently passed the six system-viewer cases.
Network Scanner x64 passed, but x86 produced APPCRASH `0x0eedfade` in session 0.
The reordered follow-up reached DirList and Network Meter: both passed all 15
lifecycle/startup checks, and Scanner x64 passed again. Scanner x86 reproduced
the same crash; the batch remains failed despite successful checkpoint recovery
and Defender. See [network coverage](../archive/evidence/mitec-network-coverage-native-2026-11-03.json).
No interactive UI or deeper product
functionality is claimed; that work is deferred to v3.1.

EXE Explorer (both executables) and HexEdit subsequently passed all 15 checks,
Defender and checkpoint recovery. See [analysis tools](../archive/evidence/mitec-analysis-fast-track-native-2026-11-03.json).
System Information stopped at GetSys.exe exit 1; neither MSIX nor TAPI startup
was reached. Its failed product recovery and successful separate checkpoint
recovery remain distinct. See [original failure](../archive/evidence/mitec-system-telephony-startup-failure-native-2026-11-03.json).
The corrected route starts both MSIX primary applications and runs TAPI first;
GetSys helpers retain exact file lifecycle coverage with execution/report
behavior deferred to v3.1. Thirty-six source tests passed and two skipped per
PowerShell edition; the corrected native retry is queued. See
[source checks](../archive/evidence/mitec-system-startup-selection-source-2026-11-03.json).

Mail Viewer, Email History Browser, Internet History Browser and Instant
Messaging History Browser then passed all 15 checks each, Defender and
checkpoint recovery. No accounts, messages or history files were supplied.
See [mail/history evidence](../archive/evidence/mitec-mail-history-fast-track-native-2026-11-03.json).

UUID Generator, Certificate Generator and Certificate Information passed all 15
checks each, Defender and checkpoint recovery. No certificate issuance, key
generation or certificate-management action was selected. See
[utility evidence](../archive/evidence/mitec-utilities-fast-track-native-2026-11-03.json).

SQLite Query then passed all 15 checks, Defender and checkpoint recovery without
supplied databases or queries. See [SQLite evidence](../archive/evidence/mitec-sqlite-fast-track-native-2026-11-03.json).
PSScriptTools and ThreadJob then passed their package lifecycles, Defender and
checkpoint recovery. All four dependency-present/missing probes passed in
Windows PowerShell 5.1 and PowerShell 7.6.5. Core used the signed run-local ZIP
fixture; its temporary host staging copy was removed after verified recovery.
See [dual-edition runtime evidence](../archive/evidence/psscripttools-dual-edition-runtime-native-2026-11-03.json).
The seven-run coverage queue is exhausted: five outer passes and two failures,
all with verified checkpoint recovery. Retained font/Wi-Fi diagnostics also
completed collection and reset/release without a new prompt.

Fonts again passed durable file/registration/security recovery, but failed native
enumeration at Remove, RestoreInitial and RepeatRestore. The fresh child reader
failed with a generic output/exit error; separate collection still saw Open Sauce
Sans Light with no selected files or registrations present. See
[font diagnostic](../archive/evidence/font-fresh-process-diagnostic-native-2026-11-03.json).
An inert test shows that PowerShell progress can populate stderr on a successful
exit. The reader now suppresses progress and retains bounded failure details;
52 mocked tests passed per shell. This does not prove the original failure cause.
One corrected font follow-up is queued after the five package retries. See
[source correction](../archive/evidence/font-child-reporting-correction-source-2026-11-03.json).

Wi-Fi preparation recorded `WlanSvc=Stopped`; native profile acceptance did not
run. No service start, profile content read, import or connection occurred.
Collection and checkpoint recovery passed. See
[WLAN observation](../archive/evidence/wireless-stopped-service-native-2026-11-03.json).

Rufus and RegRipper each passed their native file lifecycle with Defender and
verified reset/off recovery. Neither tool was launched. See
[Rufus](../archive/evidence/attended-routes-activation-and-rufus-native-2026-11-03.json)
and [RegRipper](../archive/evidence/regripper-native-file-lifecycle-2026-11-03.json).
Gpg4win subsequently failed installation again with `0xC0000005`, despite valid
publisher signing and 73 passing guest regression tests. No startup was reached.
The failed application recovery remains distinct from successful checkpoint
recovery, which allowed the queue to advance to TMOG without intervention.
See [Gpg4win failure](../archive/evidence/gpg4win-installer-failure-native-2026-11-03.json).
Remaining prepared package routes continue without another controller refresh; the queue
checks recovery and the user's 10% usage reserve before each new admission.

TMOG installed and reported version 1.0.1.0, then the test's expectation of 1.0.1
failed; its 61 guest regression tests and separate checkpoint recovery passed.
The exact release-to-registration expectation is corrected. Gpg4win's quoted
NSIS `/D=` destination also violated documented installer syntax and is now
unquoted. Fifty-four tests passed per PowerShell edition, including a destination
with spaces. Neither source fix establishes native acceptance or crash cause.
One corrected retry per product is queued after the independent packages and
retained font/WLAN diagnostics. See [TMOG failure](../archive/evidence/tmog-version-assertion-native-2026-11-03.json)
and [source checks/references](../archive/evidence/gpg4win-tmog-installer-corrections-source-2026-11-03.json).

WFN subsequently passed all 14 file lifecycle checks, Defender and checkpoint
recovery for its full selected 531-member payload. No tool was launched and no
firewall settings changed. See [WFN evidence](../archive/evidence/wfn-native-file-lifecycle-2026-11-03.json).
InfoBar subsequently stopped before installation: three guest assertions still
expected runner version 0.22.0. Its original result retains 461 passed, three
failed and four skipped tests, with verified checkpoint recovery. The source
checks now compare CLI/documented versions and test OpenJDK uninstall admission
without requiring an obsolete literal batch list. The complete application
package file passed 138 tests with three skips per shell. Project Maker's earlier
snapshot also stopped at the same three assertions before installation, with
the same guest counts and verified recovery. Corrected retries for both products
are queued. Explorer Suite subsequently passed its installer lifecycle,
compensating presence recovery and Defender checks, with 464 guest tests passed
and four skipped. Its ARP version remains absent and suite utilities were not
launched. See [Explorer Suite evidence](../archive/evidence/explorer-suite-native-installer-lifecycle-2026-11-03.json).
See [InfoBar failure](../archive/evidence/infobar-regression-gate-native-2026-11-03.json),
[Project Maker failure](../archive/evidence/project-maker-regression-gate-native-2026-11-03.json)
and [regression corrections](../archive/evidence/application-regression-version-corrections-source-2026-11-03.json).
TMOG's later retry also includes a pinned eight-second
startup check; 50 startup/selection/candidate tests passed per shell. This
preparation is [source evidence](../archive/evidence/tmog-fast-track-startup-source-2026-11-03.json),
not a native startup result.

The first queue finished eight runs (four passes and four failures), all with
verified checkpoint recovery. Its coverage handoff initially stopped on a
status-file lock before submitting a request. Bounded shared reads now tolerate
short writes and still refuse an unavailable record after approximately five
seconds; an inert Windows PowerShell check verified both cases. Only empty
waiting clients were restarted; original records were preserved. The network
coverage request was then submitted without new UAC. See
[handoff evidence](../archive/evidence/coverage-queue-handoff-recovery-2026-11-03.json).

OpenSSH Client preparation passed, but lifecycle preflight rejected a pending
servicing restart. Evidence-preserving attended recovery reset the pinned VM,
released its hold and removed the capability queue. Preflight reporting is fixed
in source; OpenSSH/RSAT native acquisition remains deferred. See
[capability failure/recovery](../archive/evidence/client-capability-native-preflight-and-recovery-2026-11-03.json).
The package queue has since demonstrated unattended submission, failure capture,
recovery and continuation. No host integration tests or new release occurred.

All VMware installation support and profile/path preferences are retired from
v3. Installation was already retired on Oct 24; the Nov 3 decision retires one
additional directory-preference outcome (home/Documents are alternatives).
Existing installations, preferences and VM files are untouched. No VMware entry
exists in the current catalog/profiles. Remaining work is now **121-175 exact /
120-175 rounded**, retaining partial and deferred outcomes.

### Overnight checkpoint

The fast track produced substantial Windows 11 package lifecycle evidence, but
**the requested testing is not complete**. This assessment reconciles progress
since the [2026-11-02 assessment](migration-completion-reassessment-2026-11-02.md)
through the [overnight closeout](../archive/evidence/overnight-closeout-2026-11-03.json).
The following overnight results retain their original acceptance boundaries;
attended progress is recorded above and in the fast-track register. The earlier
document retains detailed component inventories and approved decisions. The
[migration plan](../MIGRATION-PLAN.md) remains authoritative for estimates.

The main results are **29 passing package/variant cases across 28 catalog IDs**,
one bounded disconnected Caffeine installation, and three Sysmon configuration
lifecycles. Fonts, images and PSScriptTools have partial acceptance. Wi-Fi,
OpenSSH Client/RSAT and several newly prepared package routes still need native
execution. Successful file lifecycle tests do not establish utility features,
other Windows targets, catalog promotion or release readiness.

## Change since yesterday

| Workstream | Nov 2 morning remaining outcomes | Nov 3 remaining outcomes | What changed |
| --- | ---: | ---: | --- |
| Settings | 37-57 | 37-57 | Existing evidence retained; icon observation did not run and BitLocker remains gated by effective policy and boot/recovery evidence. |
| Packages | 37-52 | 34-49 | Recuva, Speccy and Defraggler excluded from v3 by the user. Native acceptance advanced for already-migrated candidates; those tests do not constitute additional legacy closures. |
| Windows components | 19-24 | 19-24 | OpenSSH preparation passed; native lifecycle stopped at pending-restart preflight before DISM changes. Evidence recovered, capability queue removed; RSAT unrun. |
| Files and assets | 25-35 | 23-33 | Sysmon configuration replacement completed one legacy outcome; VMware directory preferences retired one more. Font/image partial results and Wi-Fi prerequisites remain. |
| Maintenance | 8-12 | 8-12 | Bounded offline Caffeine evidence improved; general maintenance and release acceptance remain open. |
| **Total** | **126-180** | **121-175** | **Three product exclusions, one Sysmon closure and one VMware-preference retirement. Current rounded estimate: 120-175, about 150.** |

These are legacy feature/product estimates, not counts of catalog IDs or failed
tests. After yesterday's three exclusions the intermediate total was 123-177;
the overnight Sysmon closure reduced it to 122-176 and the VMware-preference
retirement to 121-175. Native package tests improve acceptance without counting
already-migrated outcomes again. All five ranges retain partial/deferred scope.

## Verified native progress

### Package lifecycle fast track

Every case below passed 14 lifecycle/recovery/preservation checks, with active
Defender and no reported alerts. The closeout index links the individual records.

| Family | Passing cases / catalog IDs | Accepted scope and limits |
| --- | ---: | --- |
| MiTeC | 12 / 12 | System Information eXtra, TAPI Monitor, EXE Explorer, HexEdit, Mail Viewer, Email History Browser, Internet History Browser, Instant Messaging History Browser, UUID Generator, Certificate Generator, Certificate Information and SQLite Query. File lifecycle accepted; feature checks remain deferred to 3.1. |
| NTCore | 6 / 5 | PE Detective, CFF Explorer, 4GB Patch, Driver List x64/x86 and Rebel.NET. The 4GB Patch also passed nine bounded functional checks on a generated x86 PE fixture with exact backup/restore; no real application was patched. |
| Sysinternals | 10 / 10 | Suite plus Process Explorer, Autoruns, TCPView, Procmon, RAMMap, Disk2vhd, Sigcheck, Strings and Handle. Suite contained 164 files. Utilities were not launched; no additional per-utility feature or licensing gate was introduced. |
| WinPmem | 1 / 1 | Exact retained publisher payload and license, installation/repeat/removal and recovery. No executable launch, driver/service activation or memory capture. Outer wrapper is Authenticode `NotSigned`; the older embedded-driver signing claim is not an outer-signature result. |
| **Total** | **29 / 28** | **Scoped Windows 11 package evidence; support/promotion decisions remain separate.** |

Evidence: [package case index](../archive/evidence/overnight-closeout-2026-11-03.json),
[NTCore main batch](../archive/evidence/ntcore-main-night-native-2026-11-03.json),
[WinPmem](../archive/evidence/winpmem-night-native-2026-11-03.json).

### Other completed or partial native checks

| Component | Result | Remaining acceptance |
| --- | --- | --- |
| Caffeine offline portable package | Latest changed-handler run passed 34 checks, including disconnected guest execution, owned recovery and Defender. Earlier production assembly/transfer proof retained. | One package proves a bounded offline route; broader bundles, installer types and `ALIGN-TARGET-01` remain open. No Caffeine launch. [Latest evidence](../archive/evidence/portable-path-offline-native-2026-11-03.json), [assembly/disconnection evidence](../archive/evidence/offline-target-exploration-night-native-2026-11-03.json). |
| PSScriptTools and ThreadJob | File lifecycle/recovery and all four Desktop/Core runtime probes now passed, including exact ThreadJob dependency origin, drawing/thread-job checks and missing-dependency behavior. [Current evidence](../archive/evidence/psscripttools-dual-edition-runtime-native-2026-11-03.json). | Earlier Core-absent partial result remains [historical evidence](../archive/evidence/psscripttools-desktop-night-native-2026-11-03.json). Broader features and other Windows targets remain separate; no persistent runtime installation or PATH edit. |
| Sysmon configurations | Three selected profiles passed five checks each, including repeat apply, synthetic prior-XML restore and service/event observation. Verified export and reset/off. | Closes the one `GetSysmonOlafXML` replacement outcome. Does not prove unknown-baseline recovery, package uninstall or other targets. [Evidence](../archive/evidence/sysmon-night-native-2026-11-03.json). |
| Machine fonts | Fourteen approved OpenSauceSans fonts tested; six of seven native checks and four of four durable recovery checks passed. Both saved restores passed; final/repeated native enumeration and three later processes were clean. | Immediate removal enumeration failed. Native acceptance remains failed; later clean observations do not explain that failure or prove interactive/restart behavior. No forced unload, cache deletion or consumer termination. [Evidence](../archive/evidence/font-process-night-native-2026-11-03.json). |
| Default/new-user lock image | Six durable file/policy/ACL and recovery checks passed. | Visual and new-user acceptance remain open; current-user Picture/Slideshow/Spotlight recovery is separate. [Evidence](../archive/evidence/default-lock-night-native-2026-11-02.json). |
| Wallpaper | Six durable checks and exact recovery passed. | Visual/new-user acceptance remains open. [Evidence](../archive/evidence/wallpaper-night-native-2026-11-02.json). |
| Wi-Fi | Generated XML and synthetic-profile source tests are prepared. Native batch was `NotRun/WlanServiceUnavailable`. | Establish WLAN service/interface prerequisites before import/repeat/owned removal/restore. Hardware absence was not established. No real Wi-Fi credentials are required for this test. [Prerequisite evidence](../archive/evidence/wireless-night-prerequisite-2026-11-03.json). |

The supplied `custom-ride` images and fonts are sufficient for the selected
asset tests. The previous blanket requirement for asset inputs or real Wi-Fi
credentials is no longer current. RIDE generates Wi-Fi XML from supplied
settings; acceptance uses a synthetic profile without connecting to a network.

## Route execution and remaining native proof

Source checks establish implementation readiness only. The protected package
controller was refreshed during attended resumption. Further fixes to startup
classification and the application snapshot are installed; native verification
is running. Capability activation was removed after its failed preflight and
verified recovery. Do not infer acceptance from registration or source tests.

| Route | Preparation completed | Next native proof |
| --- | --- | --- |
| RegRipper / Rufus | Both native file lifecycle/recovery/Defender routes passed. | Neither executable was launched; startup and utility actions remain separate. |
| Remaining MiTeC portable batches | 29 portable variants / 24 products passed guest startup/lifecycle checks, plus installed Mail Checker and Project Maker for 31 variants / 26 products overall. System viewers, analysis, mail/history, utility and SQLite tools have passing outer results. Scanner x86 crashed; earlier viewer/development outer reporting failure retained. | System Information/TAPI has a corrected retry; the original GetSys failure remains. Features stay deferred. |
| Gpg4win / TMOG | Retained signed installers and bounded routes; 124 selected source tests per shell. [Evidence](../archive/evidence/gpg4win-tmog-routes-source-2026-11-03.json). Native Gpg4win installation failed again; TMOG installed but failed version assertion. Both checkpoints recovered; corrected Gpg4win retry reproduced the crash with 76 guest tests passed. TMOG correction/startup remains unrun at the requested stop. | Diagnose Gpg4win installation before startup; finish machine TMOG lifecycle. Preserve synthetic user data. |
| MiTeC Mail Checker | Install/startup/uninstall, exact executable/version readback, Defender and compensating recovery passed. [Evidence](../archive/evidence/mail-checker-fast-track-native-2026-11-03.json). | Fast-track gate passed; features and interactive UI deferred to v3.1. |
| WFN | Full pinned 531-member payload passed 14 native file lifecycle checks, Defender and checkpoint recovery. [Evidence](../archive/evidence/wfn-native-file-lifecycle-2026-11-03.json). | Executable startup and firewall behavior are separate; neither was exercised. |
| InfoBar / Project Maker / NTCore Explorer Suite | InfoBar subsequently timed out after its corrected regression gate; checkpoint recovered. Project Maker passed nine native lifecycle/startup/recovery checks. Explorer Suite passed native installer lifecycle/recovery and Defender with corrected guest tests. | InfoBar completion/logging retry was stopped before admission. Project Maker fast-track passed. Explorer Suite executable startup and version readback remain separate. |
| OpenSSH Client / full available client RSAT | Preparation passed; OpenSSH lifecycle rejected a pending servicing restart before installation. Evidence exported and checkpoint recovered; capability queue removed. Preflight reporting fix passed 53 tests per shell. | Resolve baseline readiness, then activate the corrected queue and run native DISM with already-approved Windows Update acquisition. RSAT has not run; payload availability remains unverified. |

The capability queue is separate from the package controller. Its
[operator procedure](../windows-component-inventory.md#expiring-capability-queue)
requires exact bindings, bounded expiry and collection of partial servicing
evidence. A timeout does not establish that DISM stopped; restart is never
automatic. Matching local Features on Demand media is not a prerequisite for
the two batches authorized to use Windows Update.

## Remaining work by workstream

| Workstream | Next useful acceptance | Retained remainder |
| --- | --- | --- |
| Settings | Attended observation of five desktop icons and ClassicStartMenu mirror; effective BitLocker policy, boot/recovery and decryption prerequisites. | Existing F1/File Explorer and PowerShell appearance evidence remains scoped. BitLocker still reports `EffectivePolicyEstablished=false`; no encryption batch started. TPM/WinRE, off-device test-key retrieval, preboot console, TPM+PIN/recovery boot and method policies require their own proof. Unmapped and deferred settings remain counted. |
| Packages | Activate finite prepared batches above, then collect scoped acceptance and decide target/variant promotion. | Paradox Data Editor still needs native nested BDE ownership/coexistence/recovery; CCleaner needs its exact artifact/lifecycle route. OpenJDK Windows 11, Python coexistence and other legacy selectors remain in the [unmigrated/partial register](migration-completion-reassessment-2026-11-02.md#legacy-selectors-still-unmigrated-or-partially-represented). |
| Windows components | OpenSSH Client/RSAT native DISM and recovery. | Telnet source identity and other [component register](migration-completion-reassessment-2026-11-02.md#windows-component-workstream-status-at-pause) entries remain; Hyper-V, Sandbox, WSL distributions and hardware-dependent printer/fax work remain deferred. Source implementation is now present for the selected client capability batches. |
| Files and assets | Diagnose immediate font visibility, retain the completed image/new-user visual and catalog evidence, establish WLAN prerequisites and run synthetic profile lifecycle. | Current-user lock-screen modes, accounts, locale/browser/Python preferences and other [asset register](migration-completion-reassessment-2026-11-02.md#files-assets-accounts-and-configuration-status-at-pause) entries retain ownership and recovery requirements. VMware preferences are retired from v3. |
| Maintenance | Native run-retention/task recovery when its isolated procedure is ready; broaden offline/bootstrap acceptance only within defined scope. | Controller operation does not prove guest maintenance workflows. Destructive cleanup, updates/cache cleanup, unpinning, Disk Cleanup, Sysprep and display helpers remain deferred. Standalone WaitForKey/Restart/StopComputer selectors remain retired, without additional numerical closure. See the [action register](migration-completion-reassessment-2026-11-02.md#maintenance-and-execution-actions-status-at-pause). |

The existing approved scope is unchanged: all MiTeC feature checks are deferred
to 3.1; ETL2PCAPNG remains accepted as download-only; Sysinternals licensing is
settled under the user's prior review. NirSoft/PasswordScan alert files remain
excluded from restoration/staging, with no expanded Defender exclusions.
Docker, Wireshark/Npcap, WFN firewall features, WinPmem driver use, VeraCrypt
reboots, collectors/KAPE, mutable Zimmerman sources and WinGet/WAU retain their
explicit deferrals. Detailed decisions remain in the
[approved scope](migration-completion-reassessment-2026-11-02.md#approved-scope-and-boundaries)
and [exclusions](migration-completion-reassessment-2026-11-02.md#v3-package-exclusions-and-remaining-inputs-2026-11-02).

## Unattended execution result and next session

The package/retained tasks ran independently, but the chat did not remain fully
unattended: a read-only Explorer observation required computer-use app approval
and timed out, consuming about 90 minutes (approximately 04:42-06:15 Copenhagen).
No screenshot or UI input was obtained and no icon state changed. This was an
app approval dependency, not evidence that the operating-system UAC path was
solved for every future route. UI-dependent work must be performed while the
operator is present or have its required access demonstrated beforehand.

At the last recorded host observation, **06:18:33 Copenhagen on Nov 3**, the VM
was Off, both tasks were Ready with result 0, queues were empty, and no recovery
hold was present. A local stop marker prevented new night requests. The retained
task's later self-unregister trigger was not observed after expiry. These are
last-observed facts, not a new inspection of today's host. The last recorded
token balance was 35%; the night closed before the 06:30 deadline. No push,
tag or release was performed.

Historical execution order after attended activation (superseded by the requested stop above; no automatic continuation):

1. The protected controller refresh and unattended terminal/export/reset cycle
   are verified. Continue the active finite package queue without another UAC
   request. Check the fresh 10% usage reserve, expiry and recovery before each
   admission; an unresolved hold stops use of the VM.
2. The first queue and seven-run coverage queue are exhausted with all 15
   checkpoint recoveries verified. Preserve their product failures separately
   from passing cases; PSScriptTools now has both-edition runtime acceptance.
3. The retained font diagnostic and read-only WLAN observation are complete;
   both collections and reset/releases are verified. Continue the active
   source-corrected InfoBar, Project Maker, Gpg4win, TMOG and System Information/
   TAPI retries. Then run one corrected font reader follow-up through the same
   registered retained task. Keep the original font failure gate and collect/
   reset/release requirements. Do not repeat unchanged failed scenarios.
4. OpenSSH/RSAT remain deferred because the baseline requires servicing restart
   and the capability task was removed after recovery. Resolve readiness and
   demonstrate corrected preflight reporting before future activation; explicit
   Windows Update remains approved. Image/new-user/icon observation still needs
   a demonstrated interactive route.
5. Handle BitLocker and Paradox/BDE through their distinct policy/boot/shared
   dependency procedures. Neither a package-presence pass nor checkpoint reset
   substitutes for RIDE recovery. Keep unrelated package work moving.
6. Reconcile accepted target/variant decisions, remaining legacy outcomes,
   cross-platform alignment and offline/bootstrap/release gates separately.
   Record exclusions, deferrals and failures alongside passes; do not equate an
   exhausted test queue with migration completion.

This document records activation and native evidence separately from remaining
preparation; updating the status is not itself execution evidence.
