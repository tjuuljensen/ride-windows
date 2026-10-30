# Remaining settings migration plan and decisions

## Storage Sense machine-policy acceptance runner preparation, 2026-10-29

Added `windows.storage-sense-global-policy` to `Invoke-RideRemainingSettings.ps1 -Batch 1` and reconciled the runner's stale inventory count. The current catalog selects 21 existing batch operations plus five pending candidates, for 26 total; the previous expected count of 23 would have refused before acceptance. The runner checks the target's `EditionID` against the Microsoft-listed Pro, Enterprise, Education and IoT Enterprise families before reading or writing the candidate policy. It enables candidates only in its private test catalog and restores the exact captured registry state; it does not configure or run Storage Sense cleanup. `tests/OptionalWindowsSettings.Tests.ps1` passes 365/365 in Windows PowerShell 5.1/Pester 5.7.1, including the candidate's metadata and state-matching tests; this remains mocked local coverage. `SupportedTargets` remains empty; effective policy source, visible switch behavior and cleanup behavior require separate acceptance. Host CIM still blocks VM inspection, so no guest test was dispatched. See [structured runner evidence](../archive/evidence/storage-sense-policy-remaining-settings-batch1-runner-preparation-2026-10-29-0054.json) and [focused regression evidence](../archive/evidence/storage-sense-optional-settings-current-winps51-regression-2026-10-29-0102.json).

## Current-user shortcut candidate acceptance preparation, 2026-10-29 01:04 UTC

Added `windows.bitlocker-wizard-shortcut` and `windows.power-options-shortcut` to `SettingsRemainingBatch1`. The full selection is 21 existing operations plus seven pending candidates (28 total). Both shortcut cases use exact saved-run recovery and do not launch the target executable or control panel. The current `DesktopShortcuts.Tests.ps1` suite passed 8/8 in Windows PowerShell 5.1/Pester 5.7.1; this checks metadata/path resolution only, not a real desktop. Both operations remain unsupported until disposable Windows 11 acceptance. Host CIM blocks the VM, so no guest dispatch occurred. See [runner evidence](../archive/evidence/remaining-settings-batch1-desktop-shortcut-candidates-2026-10-29-0104.json).

## BitLocker modern drive-type policy Server 2025 candidate targets, 2026-10-29 00:44 UTC

Microsoft's current `Configure BitLocker` guidance applies the GPO policy to Windows Server 2025 and Windows 11, provides separate OS/fixed/removable drive settings, recommends XTS-AES, and specifies XTS-AES 128-bit as the unconfigured default. Added Server 2025 to `CandidateTargets` for the three modern policy operations while keeping `SupportedTargets` empty and `PendingAcceptance` true. The user's approved XTS-AES 256-bit default profile selections remain unchanged. The focused tests now assert both candidate targets and that application is blocked on both releases until native acceptance. No setting or volume state changed. See [structured evidence](../archive/evidence/bitlocker-drive-type-policy-server2025-candidate-2026-10-29-0044.json) and [Microsoft's current BitLocker guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure#choose-drive-encryption-method-and-cipher-strength).

## RIDEWin11Test settings and MiTeC queue write blocker, 2026-10-29 00:39 UTC

The current non-elevated host CIM check cannot retrieve either VM's state. The authorized MiTeCSystemAndTelephony pre-registered task submission also failed before request creation because the controller denied creation of its temporary `queue/pending` file. A follow-up found no pending/running request or temporary file; the scheduled task did not start. The controller's required capabilities and account match, but host CIM cannot query task state. No checkpoint reset, guest request, setting change or elevation occurred. Keep native setting and package acceptance deferred, continue independent implementation, and do not bypass the registered queue. See [structured evidence](../archive/evidence/mitec-system-telephony-preregistered-queue-write-block-2026-10-29-0039.json).

## RIDE-Win11-Test and RIDE-S25-Test host CIM acceptance blocker, 2026-10-28 23:48 UTC

Fresh non-elevated read-only `Get-VM` queries for both exact registered names failed before state retrieval with `Access to a CIM resource was not available to the client`. No checkpoint/task state was queried and no guest request was dispatched. Keep Windows 11 and Server 2025 native setting acceptance deferred; continue independent implementation and mocked regressions. No elevation or Windows state change occurred. See [structured evidence](../archive/evidence/ride-win11-and-s25-test-cim-access-recheck-2026-10-28-2348.json).

## E08 read-only Secedit template validation candidate, 2026-10-28 23:44 UTC

Candidate version 0.4.0 adds a Windows-only `secedit /validate` adapter that first verifies the supplied template exactly matches the module-generated one-setting PasswordComplexity bytes. The focused Windows PowerShell 5.1/Pester 5.7.1 suite passed 20/20 with the process boundary mocked and TestRegistry/TestResult disabled; no Secedit process ran and no policy changed. The candidate remains unregistered, has no apply/configure path, and claims no mutation readiness. Native syntax validation, one-setting isolation, exact `NotDefined` restoration, managed-policy precedence, and Windows 11/Server 2025 acceptance remain deferred; the current host cannot read VM state at CIM. No legacy setting outcome closed; estimates unchanged. See [structured regression evidence](../archive/evidence/local-password-complexity-native-template-validation-current-source-regression-2026-10-28-2344.json).

## RIDE-Win11-Test and RIDE-S25-Test current acceptance blocker, 2026-10-28 23:38 UTC

A fresh non-elevated Get-VM query for both disposable targets failed before state retrieval because host CIM access was unavailable. No checkpoint/task/queue state was queried and no guest request was dispatched. Windows 11 setting acceptance remains deferred; no elevation or state change occurred. Continue independent source implementation and mocked regressions. See [structured evidence](../archive/evidence/ride-win11-and-s25-test-cim-access-recheck-2026-10-28-2338.json).

## B02 local user identity inventory current-source regression, 2026-10-28 23:13 UTC

	ests/LocalUserInventory.Tests.ps1 passed 26/26 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1 with TestRegistry and TestResult integrations disabled. Provider and registry calls were mocked; no local accounts or credentials were queried. Tests cover target-context guards, SID-based identity independent of display names, malformed/missing/duplicate/bounded observations, privacy-filtered export, and safe completion/output handling. Native LocalAccounts provider and intended-account behavior remain open. No legacy setting outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/b02-local-user-identity-inventory-winps51-regression-2026-10-28-2313.json).

## B02 audio endpoint inventory current-source regression, 2026-10-28 23:12 UTC

	ests/AudioEndpointInventory.Tests.ps1 passed 21/21 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1 after disabling optional TestRegistry/TestResult integrations in Pester configuration. The first default run stopped before test bodies because creating Pester's HKCU test key was denied; no successful registry write occurred. The suite mocks identity/Core Audio boundaries, tests exact opaque-ID saved selection, missing/unavailable states, bounded completion and output collision handling, and compiles the interop reader without invoking Core Audio. Native endpoint behavior, intended-user/session acceptance and hardware/default-role evidence remain open. No legacy setting outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/b02-audio-endpoint-current-source-winps51-regression-2026-10-28-2312.json).

## RIDE-Win11-Test access recheck, 2026-10-28 18:16 UTC

`Get-VM -Name RIDE-Win11-Test` failed before state retrieval because host CIM access was denied. No checkpoint or task state was read and no guest request was dispatched. The VM was shown running at 17:43, but checkpoint membership and guest task readiness remain unconfirmed. Native settings acceptance remains deferred; no legacy outcome closed and estimates unchanged. See [evidence](../archive/evidence/ride-win11-test-vm-cim-access-block-2026-10-28-1816.json).

## Remaining settings Windows PowerShell regression, 2026-10-28 18:15 UTC

`RemainingSettings.Tests.ps1` passed 77/77 in Windows PowerShell 5.1.26100.9711/Pester 5.7.1. Pester loaded with process-only ExecutionPolicy Bypass; persistent policy was unchanged. TestRegistry/TestResult were disabled; settings handlers/providers were mocked or synthetic, including Defender preference. No live setting, registry, Defender, VM or elevation state changed. Native Windows acceptance remains deferred pending RIDE-Win11-Test checkpoint/task confirmation. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/remaining-settings-winps51-current-source-regression-2026-10-28-1815.json).

## Cross-shell regression update, 2026-10-28 18:04 UTC

Windows PowerShell 5.1.26100.9711/Pester 5.7.1 passed the six component suites plus BitLocker workflow, drive-method policy and F1 suites 145/145. Pester loaded with process-only ExecutionPolicy Bypass; persistent policy was unchanged. TestRegistry/TestResult were disabled and Windows/BitLocker providers were mocked or synthetic. No live system state changed. Native acceptance remains pending RIDE-Win11-Test checkpoint and task readiness confirmation. No legacy setting outcome closed; estimates unchanged. See [cross-shell evidence](../archive/evidence/component-settings-cross-shell-pester-regression-ps51-2026-10-28-1804.json).

## Current regression update, 2026-10-28 18:00 UTC

The current-source `RemainingSettings`, BitLocker workflow, drive-method policy and F1 candidate suites passed 113/113 in PowerShell 7.6.5/Pester 5.7.1. TestRegistry and TestResult plugins were disabled; registry, BitLocker and Windows provider boundaries were mocked or synthetic. No live setting, volume, protector, VM or Defender state changed. Local regression is verified; native Windows 11 acceptance remains pending because RIDE-Win11-Test checkpoint membership and task readiness are unconfirmed. No legacy setting outcome closed; the settings range remains 37-57. See [structured evidence](../archive/evidence/settings-current-source-pester-regression-ps7-2026-10-28-1800.json).

## Current handoff update, 2026-10-28 17:25 UTC

The three Windows 11 future BitLocker drive-method candidates are now selected by the existing `SettingsRemainingBatch1` VM runner (22 operations total, up from 19). The private guest catalog enables each pending candidate only for this explicit acceptance run and cycles all five declared methods/default states with preview, repeat and exact saved-run restore. It never encrypts or converts a volume. Parser/version and exact catalog-selection checks passed, and repository validation passed. No Pester assertions or guest run occurred: Windows PowerShell Pester 5.7.1 import fails before discovery under AuthorizationManager, and the registered task state and live target checkpoint remain inaccessible. Keep candidate support pending until the focused VM results are collected and reviewed. No legacy setting outcome closed; all estimate ranges remain unchanged. See [runner evidence](../archive/evidence/bitlocker-method-policy-runner-preparation-and-vm-block-2026-10-28-1725.json) and [runner instructions](../../tests/integration/README.md#remaining-settings-session).

## Current handoff status, 2026-10-28 16:34 UTC

Cross-group estimates remain settings **37-57**, packages **37-52**, components **19-24**, files/assets **25-35** and maintenance **8-12** (exact **126-180**; rounded **125-180/about 155**); the [migration plan](../MIGRATION-PLAN.md) remains authoritative. Presentation review is complete at 279/279, Q01-Q31 decisions remain recorded, and R29/D09 is closed as unsubstantiated bookkeeping with no estimate deduction. `tools/validate.ps1 -Root .` passed for 446 operations, 8 groups, 5 profiles and 301 PowerShell files. Earlier focused Windows PowerShell 5.1/Pester 5.7.1 regressions passed for RemainingSettings (77/77), Photo Viewer (3/3), Raspberry Pi Imager (2/2) and NTCore packages (20/20); these do not replace Windows behavior acceptance. Current Storage Sense Pester assertions remain unverified: Windows PowerShell 5.1 blocks repository/Pester module import at AuthorizationManager, while the PowerShell 7 attempt returned no test summary after a FileSystem provider error. A direct synthetic engine-state probe passed only in PowerShell 7.6.5; no registry was accessed. Package dependency planning passed 11/11 and adoption/evidence passed 54/54. The complete inert 360-member PSScriptTools lifecycle suite passed 7/7 in 652.06 seconds; Pester reported zero failed or skipped cases, while its wrapper exited 1 because its result check omitted -PassThru. See [full lifecycle evidence](../archive/evidence/psscripttools-inert-360-member-full-local-regression-2026-10-28-1543.json). The RIDE-Win11-Test configuration still pins RIDE-clean-test-base and advertises FocusedPortableV1. A fresh Get-VM preflight failed before VM/checkpoint inspection; the preregistered PSScriptTools request then failed before enqueue because writing its protected pending-queue temporary file was denied. Read-only pending/running queue checks were empty. The earlier SettingsRemainingBatch1 attempt also remains host-WinRM-blocked. No service, queue permission or VM state was changed, no per-run UAC was requested, and no guest test ran. No new legacy setting outcome closed. See [PSScriptTools dispatch evidence](../archive/evidence/psscripttools-preregistered-task-pending-queue-access-block-2026-10-28-1607.json), [VM access evidence](../archive/evidence/ntcore-explorer-suite-vm-access-recheck-2026-10-28-1603.json), [SettingsRemainingBatch1 evidence](../archive/evidence/ride-win11-settings-remaining-batch1-preregistered-winrm-block-2026-10-28-1448.json), and [current migration plan](../MIGRATION-PLAN.md).

WinHTTP inventory, preparation and lifecycle Pester suites pass 22/22 in both Windows PowerShell 5.1 and PowerShell 7 using the existing Pester 5.7.1 installation. The machine-scope candidate is now registered and wired through catalog planning, read-only status, saved-run preparation, guarded lifecycle dispatch and recovery. Five focused catalog/engine tests pass. All native calls remain mocked; no native WinHTTP command ran. The operation has no supported targets and cannot be selected in profiles until acceptance. Host build 26300 lacks `netsh winhttp show advproxy`, and RIDE-Win11-Test access failed at host CIM before VM inspection. The guarded candidate includes the documented setter form, but no native capture/set/readback ran. Exact underlying recovery, policy/consumer behavior and Windows acceptance remain deferred. See [engine/catalog integration evidence](../archive/evidence/winhttp-engine-catalog-integration-regression-2026-10-28-0529.json), [cross-shell regression](../archive/evidence/winhttp-cross-shell-pester-regression-2026-10-28-0517.json), [native command availability check](../archive/evidence/winhttp-netsh-advproxy-host-capability-check-2026-10-27-0821.json), and [VM access evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-0453.json).

Microsoft’s current [netsh WinHTTP reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-winhttp) documents the `set advproxy` `settings-file` form, machine/user scopes and required Proxy, ProxyBypass, AutoconfigUrl and AutoDetect properties. This matches the existing guarded WinHTTP lifecycle candidate. The local Windows build 26300 still reports `show advproxy` as unavailable, so the doc page does not establish native availability on this build or the registered VM. RIDE-Win11-Test access remains blocked before inspection at host CIM. The candidate remains unsupported pending native command/readback, exact recovery, effective-policy and consumer acceptance. See [source reconciliation evidence](../archive/evidence/winhttp-advanced-proxy-source-implementation-reconciliation-2026-10-28-1630.json).

At 16:34 UTC, Windows PowerShell 5.1 parsing passed for the WinHTTP lifecycle module and `tools/validate.ps1 -Root .` passed after all source and ledger updates for 447 operations, 8 groups, 5 profiles and 301 PowerShell files. Native command availability/readback and VM acceptance remain open; see [validation evidence](../archive/evidence/winhttp-repository-validation-after-source-reconciliation-2026-10-28-1634.json).

The three modern BitLocker future-encryption policy operations retain their documented method choices and the default profile's XTS-AES 256 intent, but now have Windows 11 only in CandidateTargets, empty SupportedTargets and PendingAcceptance until disposable Windows policy acceptance. The fail-closed Invoke-RidePlan -WhatIf guard and focused policy tests passed 4/4 on PowerShell 7 and Windows PowerShell 5.1; the targeted legacy-selector catalog test passed 1/1. The broader 98-test run passed 97 and had one unrelated sandbox denial on a registry security-descriptor assertion. Repository validation passed for 432 operations, 8 groups, 5 profiles and 296 PowerShell files, with generated docs current. VM inspection again failed at CIM. No legacy outcome or estimate changed. See [apply-guard and cross-shell evidence](../archive/evidence/bitlocker-policy-apply-guard-and-cross-shell-regression-2026-10-27-1246.json) and [candidate correction evidence](../archive/evidence/bitlocker-policy-target-candidate-correction-and-acceptance-regression-2026-10-27-1240.json).

`RemainingSettings.Tests.ps1` and `SixtySettings.Tests.ps1` each passed **207/207** across the two suites on PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711. On PowerShell 7 the combined 207 tests completed in 705.7 seconds; the Windows PowerShell 5.1 run also passed 77 and 130 respectively. ProfileSettings passed 37/37, presentation passed 14/14, and Catalog plus CatalogProfileValidation passed 95 runnable checks with one WindowsIntegration check excluded. These are local/mock checks and do not establish Windows behavior; no host setting changed. See [cross-shell evidence](../archive/evidence/settings-remaining-sixty-current-source-cross-shell-2026-10-26-1911.json), [Windows PowerShell settings/catalog evidence](../archive/evidence/settings-focused-current-source-regression-and-catalog-profile-rerun-2026-10-26-1531.json), and [full UnitOnly run triage](../archive/evidence/win11-unitonly-current-source-full-pester-failure-2026-10-26-1219.json).

The UnitOnly request `d7ea59b8cb38496a80fe3d98ae487c5c` remains a failed historical full run: Windows 11 build 26300 / PowerShell 5.1 reported 3,313 passed, 14 failed and 7 skipped. None of those failures was a setting suite, but focused local passes do not replace a full rerun or native acceptance.

A full local current-source Pester run on 2026-10-27 discovered 3,380 tests in 128 files: 3,376 passed, 1 failed and 3 skipped. `RemainingSettings`, `SixtySettings`, `OptionalWindowsSettings`, and the current E08 candidate all passed. The sole failure was direct registry security-descriptor access denied by this sandbox; skipped test names were not listed by Pester. It does not replace VM behavior acceptance. See [full-run evidence](../archive/evidence/full-current-source-pester-regression-and-vm-access-2026-10-27-0514.json).

Fresh read-only `Get-VM` access at 16:36 UTC for `RIDE-Win11-Test` and `RIDE-Server2025-Test` failed before inspection because CIM access was unavailable. Hyper-V Manager was also unreadable to the lower-integrity UI helper; its VM list and checkpoints remain unknown. No checkpoint query or runner dispatch occurred, and no VM, host, setting, Defender or elevation state changed. Keep target acceptance deferred and continue independent source work. See [latest VM/UI access evidence](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json), [current BitLocker/VM evidence](../archive/evidence/bitlocker-policy-target-candidate-correction-and-acceptance-regression-2026-10-27-1240.json), and [previous full-run evidence](../archive/evidence/full-current-source-pester-regression-and-vm-access-2026-10-27-0514.json).

The standalone WinHTTP advanced-proxy inventory, preparation and guarded-lifecycle candidate passed **22/22** focused tests in each PowerShell edition. These use mocked native commands and do not establish a usable setter, exact underlying recovery or supported target. The prior local command check found `netsh winhttp show advproxy` unavailable; catalog integration remains deferred. See [current WinHTTP evidence](../archive/evidence/winhttp-proxy-current-source-cross-shell-regression-and-access-2026-10-27-1648.json).

The local license store has exact-version `NeedsReview` markers for all **44/44** packages marked PendingAcceptance; markers are administrative, not planning gates. Sysinternals remains settled under the prior RIDE v2 specialist approval for direct download-and-install; Defender-blocked utilities remain separate exclusions. E08 prepares conflict-checked recovery for explicit local `Enabled`/`Disabled` observations, passing 11/11 focused tests in each PowerShell edition. Microsoft documents `secedit /generaterollback` as a candidate native route; database initialization, `NotDefined` recovery and managed-policy behavior still require disposable Windows evidence. The read-only `RIDE.WinHttpProxyInventory` and `RIDE.WinHttpProxyPreparation` candidates and mocked lifecycle pass 22/22 focused tests in each PowerShell edition but do not prove exact native literal state or target behavior. No legacy setting outcome closed and estimates remain unchanged. See [E08 evidence](../archive/evidence/local-password-complexity-explicit-recovery-preparation-2026-10-26-1936.json), [WinHTTP regression evidence](../archive/evidence/winhttp-proxy-current-source-cross-shell-regression-and-access-2026-10-27-1648.json), and [latest VM access evidence](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json).
Decision-baseline handoff, 2026-10-17: [all batch dispositions and completion order](remaining-migrations-follow-up.md#archive-handoff-and-closure-order-2026-10-17).
Presentation review is complete at 279/279; see the [final evidence](settings-post-migration-review.md#b01-presentation-review-completion-2026-10-17). Source presentation and native/user-visible
acceptance are separate. B03 startup fixtures pass, with native acceptance blocked by denied Hyper-V access. Q01-Q31
policy choices and subsequent refinements are recorded; BitLocker/recovery setup
and new deployment profiles are explicitly deferred, not awaiting repeated prompts.
The thirty rows below retain partial outcomes and their exact acceptance gates.

Source review: **2026-10-24 11:58 UTC**. The source-only review found no current-build evidence for Explorer F1 behavior; see the [source evidence](../archive/evidence/f1-file-explorer-current-source-recheck-2026-10-24.json). On **2026-10-25**, the user confirmed they use the RIDE v1 F1 setting successfully and wants it retained in the default profile; v3 removal remains untested. The default profile now selects `Blocked`; remove that selection only if acceptance shows exact rollback cannot succeed. The candidate has no supported target, so profile application remains blocked until Windows 11 behavior and exact v3 rollback are accepted. No Windows state changed by the source review or profile edit. Current catalog audit: **2026-10-25 16:36 UTC**; 415 operations comprise 282 setting/control declarations, 103 packages (33 pending acceptance), 22 Store apps, 4 profile settings and 4 standalone artifacts; 22 setting/control declarations and 3 profile settings remain pending acceptance. Repository validation confirms 8 groups, 5 profiles and 278 PowerShell files. B01 presentation review remains complete at 279/279. Read-only VM queries for RIDE-Win11-Test and RIDE-Srv2025Test failed at CIM before VM/checkpoint inspection. See the [catalog and VM evidence](../archive/evidence/current-catalog-count-and-vm-access-recheck-2026-10-25-1636.json). B01 adds reviewed presentation for keyboard delay,
pointer precision, registered sound schemes and startup sound, plus manual
playback-device mute guidance. B02 read-only playback-endpoint capture contracts
are source-ready; see the [B02 record](settings-post-migration-review.md#b02-read-only-playback-endpoint-contract-2026-10-16).
The B03 existing user-bin startup renderer is also source-ready as two pending runtime candidates; see the [profile contract](../powershell-profiles.md#existing-user-bin-startup-path-candidate). Retain GUI, startup and hardware acceptance separately. Native proxy,
Terminal profile and local password-complexity work follow after their recovery
contracts are demonstrated. E08 now has an inert, unregistered template builder/parser; focused Pester passes 8/8 and Windows PowerShell 5.1 parsing passes. Native secedit isolation, managed precedence and exact rollback remain unproven. Small registry changes with uncertain current effects
remain investigations, even when their code would be short.

This plan consolidates all 30 entries
in the remaining-settings ledger, earlier accepted setting reviews, shared engine
gaps and the separate acceptance backlog. It collects decisions and test resources
without reopening accepted designs. Implementation priorities remain in
[TODO.md](../../TODO.md); legacy counts remain in
[MIGRATION-PLAN.md](../MIGRATION-PLAN.md). This document owns the consolidated
settings analysis and questions, not a second catalog or release plan.

Regional preparation also has [separate process/user/machine observations](remaining-migrations-follow-up.md#b09-regional-provider-inventory-2026-10-17); they are not complete recovery snapshots or setters.

As of **2026-10-28 07:10 UTC**, the Power Options shortcut's missing-target
failure now names the declared shortcut target rather than the BitLocker wizard.
The focused DesktopShortcuts suite passes 8/8 in both PowerShell editions. The
candidate remains unsupported pending Windows 11 UI and lifecycle acceptance;
correct-name VM access again failed at host CIM before inspection. See the
[diagnostic and VM evidence](../archive/evidence/power-options-shortcut-missing-target-diagnostic-cross-shell-and-vm-block-2026-10-28-0710.json).
## Current implementation and validation

Current-source validation on **2026-10-28 18:42 UTC** passed for **447 operations**, eight groups, five profiles and 301 PowerShell files. See [current repository validation evidence](../archive/evidence/repository-validation-2026-10-28-1842.json). The catalog contains **300** setting/control operations with `SettingPresentation`, **119** packages (**49 PendingAcceptance**), 22 Store app declarations and four standalone artifacts. Catalog validation enforces presentation metadata for all 300 setting/control operations. The workspace-local review store has exact operation-ID/version `NeedsReview` entries for all **49/49** pending packages; these are administrative markers and do not block planning or technical migration. These are declarations, not counts of remaining legacy outcomes.

Of the 300 setting/control operations, 39 currently remain pending candidates. Unverified mappings, obsolete behavior and native acceptance gaps remain identified in catalog metadata; coverage does not certify behavior or close legacy outcomes. Do not widen published support from local lifecycle or mock regression alone.
The retained BitLocker `EncryptionMethod` mapping is not established as a current
Windows 11 cipher policy. On 2026-10-27, the user directed RIDE to investigate
and implement support for multiple Windows 11 encryption methods, especially
when improving defaults. Preserve the stable operation ID while verifying the
modern Microsoft policy mapping, method choices, defaults, and target behavior;
do not equate a future-encryption policy with conversion of an existing volume.
Whole accessibility Flags presets likewise need narrower ownership and live-
session evidence before being recommended as prompt controls.

Microsoft's current BitLocker guidance recommends XTS-AES and leaves the
128-bit/256-bit key-length choice to device-performance needs. The default
profile's XTS-AES 256-bit intent remains the user's approved choice; the
operator guide now explains the 128-bit performance option. The CSP's
EncryptionMethodByDriveType requires all three settings in one SyncML request,
while these RIDE candidates write local Group Policy values and do not use
CSP/MDM. No catalog/profile change was made; current Windows 11 policy
acceptance remains pending. See [source recheck evidence]
(../archive/evidence/bitlocker-current-source-and-default-profile-recheck-2026-10-28-1126.json).

All five accepted Store groups have guarded declarations and a separate
current-user/desktop-handoff tool. App-specific native acceptance remains pending;
[Store follow-up decisions and resources](store-app-follow-up-decisions.md) owns
the approved reviewed-identity guard, interactive actor and retained-payload boundaries.

The completed [validation matrix](settings-validation-resume.md) includes stored
keyboard delay, WAP Push/Search startup/runtime/delay, update-notification policy,
CEIP, all local firewall profiles, conditional media policies, Server Manager,
Shutdown Event Tracker, local SAM maximum age and guarded Windows Audio service.
It includes controlled failure recovery where recorded, not universal OS-denial
or managed-policy acceptance.

All three owned plans passed creation, repeat apply, metadata-drift refusal and
compensation on Windows 11 and Server 2025. The shared Balanced handler also passed
active-copy refusal with separate selection recovery, real setting-drift refusal
and interrupted creation retaining Intent on both targets. Drift and interruption
have **checkpoint-only cleanup**, not RIDE recovery. The first interruption fixture
compared preliminary random inspection IDs with the actual creation IDs; its failed
run remains archived. The corrected capture comparison passed. Fixture 0.7.2 fixes
the generic progress sentence to describe guard acceptance accurately; this last
reporting edit has parser evidence, not another VM run.

The earlier package pause is lifted for the authorized overnight implementation window. No GitHub publisher request or package acquisition is
needed for this analysis. The shared controller remains the installed 0.4.6
baseline; concurrent PAT/controller source is separate work.

## Recommended implementation order

The order below uses accepted designs. An item described as ready still needs its
focused diff review and validation; it is not a promise that its runtime behavior
has already passed.

| Order | Work that can start without another product decision | Prerequisite and completion boundary |
| --- | --- | --- |
| E01 | First six-control batch implemented 2026-10-14: hidden/protected files, Explorer recent/frequent items, Control Panel view and Edge background mode | Metadata-only contract comparison passed; generated documentation current; 122 tests passed on each native PowerShell edition. The initial 5.1 authorization deferral was resolved using README's process-only launch. Broader metadata review and actual GUI/managed acceptance remain open |
| E01 follow-up | B01 input/audio presentation implemented 2026-10-16 for four existing controls | Whole-catalog comparison permits only four new presentation blocks; baseline, unset and saved recovery stay distinct. See the [batch record](settings-post-migration-review.md#b01-input-and-audio-presentation-review-2026-10-16); GUI, boot, managed and hardware evidence remains open |
| E01 Start/taskbar presentation follow-up | Sixteen controls reviewed on 2026-10-17 | Removal states and legacy shell limitations explicit; actual UI/multi-display acceptance remains. See the [record](settings-post-migration-review.md#b01-start-taskbar-and-notification-presentation-2026-10-17) |
| E01 Application presentation follow-up | Nine controls reviewed on 2026-10-17 | Development references and complete-UI limits clarified; gaming remains unverified. See the [record](settings-post-migration-review.md#b01-application-feature-presentation-2026-10-17) |
| E01 Suggestion/input presentation follow-up | Nineteen experimental controls reviewed on 2026-10-17 | Numeric channels remain unnamed/unverified; legacy reverse and diagnostic-data limits are explicit. See the [record](settings-post-migration-review.md#b01-suggestion-and-input-presentation-2026-10-17) |
| E01 Logon/boot presentation follow-up | Twelve existing controls reviewed on 2026-10-17 | BCD removal states and sign-in acrylic wording corrected; native boot/logon acceptance remains. See the [record](settings-post-migration-review.md#b01-logon-and-boot-presentation-2026-10-17) |
| E01 Network presentation follow-up | Thirteen existing controls gained presentation on 2026-10-17 | ICS service-policy wording corrected; LLMNR/mDNS, WinHTTP, NCSI and remote-access component boundaries retained. See the [record](settings-post-migration-review.md#b01-network-control-presentation-2026-10-17) |
| E01 Session visual observations | Five fixed native GET contracts implemented on 2026-10-17 | Fake interop and mocked identity tests passed; stored registry, actual GUI and target acceptance remain separate. See the [record](settings-post-migration-review.md#b01-read-only-session-visual-observations-2026-10-17) |
| E01 Visual effects follow-up | Eight existing controls gained presentation on 2026-10-17 | Seven visual requests and first-sign-in policy reviewed; four remain Unverified, whole-bundle and new-user GUI acceptance open. See the [record](settings-post-migration-review.md#b01-visual-effects-and-first-sign-in-presentation-2026-10-17) |
| E01 Desktop/Explorer follow-up | Fourteen existing controls gained presentation on 2026-10-17 | Legacy reverse differences, icon content ownership and two unverified cache mappings retained; the network-cache policy path differs from the stable legacy ID. See the [record](settings-post-migration-review.md#b01-desktop-and-explorer-visibility-presentation-2026-10-17) |
| E01 Exclusion recovery follow-up | Captured-path apply and versioned recovery repaired on 2026-10-17 | 109 focused tests per edition, one integration exclusion; valid older paths supported, hidden/managed/native membership still pending. See the [record](settings-post-migration-review.md#b01-defender-exclusion-capture-and-recovery-2026-10-17) |
| E01 Security follow-up | Eight existing controls gained presentation on 2026-10-17 | UAC shared secure-desktop effect, HVCI prerequisites, sample and exclusion recovery limits and legacy firewall scope reviewed; native acceptance remains. See the [record](settings-post-migration-review.md#b01-security-control-presentation-2026-10-17) |
| E01 Update/maintenance follow-up | Eight existing controls gained presentation on 2026-10-17 | Wake-path discrepancy, MSRT uncertainty, driver-search omission and Microsoft Update service-enrollment gap retained; native/GUI/profile recommendation remains pending. See the [record](settings-post-migration-review.md#b01-update-and-maintenance-presentation-2026-10-17) |
| E01 App Privacy follow-up | Seventeen existing device controls gained presentation on 2026-10-17 | Default versus per-app policy, Enabled removal and voice/background legacy bundles reviewed; native app/GUI/managed acceptance remains open. See the [record](settings-post-migration-review.md#b01-app-privacy-policy-presentation-2026-10-17) |
| E01 Explorer follow-up | Eight existing folder-option controls gained presentation on 2026-10-17 | Reverse removal versus explicit values and adjacent features are documented. GUI, touch, logon, process and sharing acceptance remain open; see the [record](settings-post-migration-review.md#b01-explorer-folder-options-presentation-2026-10-17) |
| E01 power follow-up | Seven power-control presentation reviews implemented 2026-10-16 | Dedicated button, screen-off, idle sleep and advanced menu effects/reverse are separate. Unsigned capture/legacy recovery and typed read backend implemented 2026-10-17; additional states, native API/locale and transition evidence remain open; see the [batch record](settings-post-migration-review.md#b01-power-control-presentation-2026-10-16) |
| E02 | Reconcile current acceptance pointers and history | Keep failed evidence and older holds as dated history. Current summaries must point to the later accepted runs. Distinguish implementation, lifecycle, guard, consumer/GUI and target acceptance. This closes no legacy outcome by itself |
| E03 | Terminal default-profile [native guidance](../windows-terminal-profile.md) and selected [playback-device mute guidance](../audio-service.md#mute-a-selected-playback-device) implemented | Manual workflows retain prior selection/mute and same-device recovery; GUI/playback acceptance remains pending. Terminal file editing and automated endpoint mute still need separate ownership, identity/session and conflict contracts. Acquire no components |
| E04 | Extend focused maximum-age boundary evidence | NoExpiry/90/999 and 1/2/998-day repeat/reverse/fault recovery passed on both targets. MinimumAgeConflict guard passed on both targets with a one-day fixture seed, zero primary native writes and separate exact seed recovery. GUI, managed/default and complexity-backend acceptance remain pending. Preserve all other fields; no user passwords change |
| E05 | Extend isolated intended-user and managed-source validation | Current desktop identity guards and alternate-account snapshot rejection have a guarded VM runner; the current-source handoff and runner-preflight regression passed 35/35. Mixed-scope application, managed-source precedence and alternate administrator desktop handoff remain pending current VM evidence. Decision D01 keeps mixed-scope profiles valid and governs the explicit cross-account route. See the [latest regression and VM access evidence](../archive/evidence/intended-user-identity-current-regression-and-vm-access-2026-10-25-1601.json) |
| E06 | JSONC preparation, guarded exact-path writer and current-user packaged-instance inventory/selection implemented | The [preparation API](../terminal-jsonc-preparation.md) preserves supplied bytes and refuses conflicts; `Set-RideTerminalInstalledInstanceDefaultProfile` re-queries current-user AppX inventory, binds the chosen package identity to its exact settings path and delegates to the identity-bound writer. Only a live query sets `InstanceVerified`; injected records cannot authorize writes. Full regression passes 57/57; Windows PowerShell 5.1 parsing and repository validation pass. Live AppX query, profile availability/launchability, unpackaged/portable discovery and disposable native acceptance remain open. Q09 selection behavior is accepted; each target still requires an actual instance/profile choice; no Terminal installation or default-terminal-host change |
| E07 | Default/LAN capture, owned edit/recovery, guarded WinINet lifecycle and engine RunId integration implemented | `windows.proxy-auto-detect` uses intended machine/user/session identity, checks documented proxy policy and current values, persists a snapshot before the setter, verifies readback, compensates detected failures, and records restore completion. The machine-scope WinHTTP candidate now includes inventory, preparation, guarded lifecycle dispatch, readback and conflict-checked restore, and is wired through catalog/engine planning and status. It uses Microsoft’s documented `set advproxy settings-file` form. Preparation rejects omitted Proxy, ProxyBypass or AutoconfigUrl values rather than normalizing unknown prior strings to empty; its 9-case supplied-object suite passed on Windows PowerShell 5.1 and PowerShell 7. This does not prove native command availability, exact underlying registry state or target behavior. Full effective-policy coverage, controlled PAC-consumer behavior, RAS, GUI and disposable Windows acceptance remain open; catalog target support remains empty. The latest read-only Get-VM query at 19:50 UTC again failed at host CIM before state inspection or dispatch. The three current UserProxy suites passed 103/103 in Windows PowerShell 5.1/Pester 5.7.1 with native calls mocked; see [regression and blocker evidence](../archive/evidence/b04-userproxy-inventory-preparation-lifecycle-winps51-and-vm-block-2026-10-28-1950.json). After the 2026-10-28 16:30 WinHTTP source reconciliation, the separate advanced-proxy inventory/preparation/lifecycle suites passed 22/22 in Windows PowerShell 5.1 with netsh and state boundaries mocked; see [current-source regression](../archive/evidence/winhttp-proxy-current-source-postreconciliation-winps51-regression-2026-10-28-1952.json). See the [operator/API guide](../user-proxy-inventory.md), [2026-10-27 guard evidence](../archive/evidence/winhttp-proxy-preparation-incomplete-state-guard-and-vm-access-2026-10-27-0731.json), and [WinINet lifecycle evidence](../archive/evidence/proxy-engine-lifecycle-current-regression-and-vm-access-2026-10-25-1201.json) |
| E08 | Investigate a focused local complexity backend | Microsoft Learn current-source recheck (2026-10-28 23:40 UTC) confirms /import rollback preparation and /validate requirements, but not one-setting isolation or exact NotDefined restoration; see [evidence](../archive/evidence/local-password-complexity-secedit-import-isolation-source-recheck-2026-10-28-2340.json). Existing maximum-age code does not supply a complexity setter. The inert UTF-16LE one-setting `secedit` template builder and bounded local/merged export parser also prepare conflict-checked recovery for explicit local `Enabled`/`Disabled` prior values; focused tests pass 11/11 in both PowerShell editions. Microsoft documents `/generaterollback` as a candidate native route. The 2026-10-28 source recheck confirms supported command applicability and explicit local versus merged export modes. The 21:24 Microsoft command-reference review confirms `/configure` `securitypolicy` scope includes account policies and requires proof that a one-setting template remains isolated; `/import` documentation directs validation and rollback preparation. The docs do not prove one-setting isolation, exact `NotDefined` restore or managed-policy behavior, which still need disposable Windows evidence. See [command-contract review evidence](../archive/evidence/local-password-complexity-secedit-apply-rollback-doc-review-2026-10-28-2124.json). See [source recheck evidence](../archive/evidence/local-password-complexity-secedit-source-recheck-2026-10-28-1847.json). The unregistered module 0.3.0 now adds a read-only export observer; its mocked suite passes 17/17 in both PowerShell editions and does not invoke Secedit. See [cross-shell candidate evidence](../archive/evidence/local-password-complexity-readonly-secedit-export-candidate-crossshell-2026-10-28-1854.json). Verify unrelated-field preservation, exact three-state recovery and guarded mutation before catalog integration. See the [rollback source follow-up](settings-post-migration-review.md#local-password-complexity-rollback-backend-source-follow-up-2026-10-26-1938), [preparation evidence](../archive/evidence/local-password-complexity-explicit-recovery-preparation-2026-10-26-1936.json), and [dated investigation](settings-post-migration-review.md#e08-local-password-complexity-backend-investigation-2026-10-23) |
| E09 | Click to Do per-user policy candidate implemented | `windows.click-to-do-policy` maps the documented `DisableClickToDo` user policy to `Blocked=1`, `Allowed=0` and exact override removal. The user's local toggle, conflicting device policy, Copilot+ hardware, Policy CSP Insider Preview applicability and visible effect remain separate. The focused catalog test passed 1/1; no profile selects the candidate and `SupportedTargets` remains empty pending Windows 11 acceptance. `Invoke-RideRemainingSettings.ps1 -Batch 1` includes this candidate in the 28-operation private Windows 11 acceptance catalog. This verifies current-user policy lifecycle and exact restore only; current-build applicability, device-policy precedence and visible feature behavior remain separate acceptance. See the [dated implementation record](settings-post-migration-review.md#click-to-do-policy-candidate-implementation-2026-10-24) and [Storage Sense batch-preparation evidence](../archive/evidence/storage-sense-policy-remaining-settings-batch1-runner-preparation-2026-10-29-0054.json). |
| E10 | Storage Sense machine policy candidate prepared for lifecycle acceptance | `windows.storage-sense-global-policy` covers only the Allow Storage Sense machine override. The Windows 11 private acceptance runner checks a Microsoft-listed policy edition, every explicit/default state and exact recovery, without requesting cleanup. `SupportedTargets` remains empty; visible switch behavior, effective policy precedence and cleanup effects still require separate disposable-VM acceptance. No profile selects the policy. See the [dated preparation record](settings-post-migration-review.md#storage-sense-machine-policy-candidate-added-to-remaining-settings-runner-2026-10-29) and [runner evidence](../archive/evidence/storage-sense-policy-remaining-settings-batch1-runner-preparation-2026-10-29-0054.json). |
| E11 | BitLocker Wizard and Power Options current-user shortcut candidates added to acceptance batch | `windows.bitlocker-wizard-shortcut` and `windows.power-options-shortcut` use the existing exact shortcut lifecycle. The 28-operation private Windows 11 batch checks shortcut presence/removal and recovery without launching either target. `DesktopShortcuts.Tests.ps1` passed 8/8; both candidates remain unsupported until disposable-VM desktop path and recovery acceptance. See the [dated record](settings-post-migration-review.md#bitlocker-wizard-and-power-options-shortcut-candidates-added-to-remaining-settings-runner-2026-10-29) and [runner evidence](../archive/evidence/remaining-settings-batch1-desktop-shortcut-candidates-2026-10-29-0104.json). |

**E01's first batch and D01's explicit user-only handoff are implemented.** Native
interactive handoff acceptance and mixed-profile recovery remain pending; see the
[handoff guide](../intended-user-handoff.md). Continue the other independent work.
E06-E09 now have distinct implementation and acceptance records. Terminal's
read-only packaged inventory and exact-path writer are tied together in source,
but live packaged-instance/profile availability and disposable Windows behavior
remain unaccepted. The proxy lifecycle is connected to the engine for the
automatic-detection control, while complete policy coverage, controlled
PAC-consumer behavior and native recovery acceptance remain open. Click to Do is
a separate per-user candidate. None of these controls gains target support until
its specific recovery and visible behavior are accepted on Windows.

The first concrete batch is `windows.hidden-files-visibility`,
`windows.protected-files-visibility`, `windows.explorer-recent-shortcuts`,
`windows.explorer-frequent-shortcuts`, `windows.control-panel-view` and
`application.edge-background-mode`. All six now have explicit presentation
metadata. Hidden files uses 1/2, while protected files uses 1/0/removal; preserve
that difference. Both Explorer shortcut controls' published `Visible` state removes
the override, rather than writing an explicit On value. Control Panel is already
one paired setting with four named choices. Edge background mode is a machine
policy with distinct Enabled/Disabled/removal semantics. Metadata must describe
those contracts accurately, not rewrite them to make the labels look uniform.

Microsoft documents separate Terminal default-profile and default-terminal-host
choices. Its [installation and configuration guide](https://learn.microsoft.com/en-us/windows/terminal/install)
also lists several settings-file locations. Discover the applicable installed
instance rather than assume one Store path. Preserve the user's file syntax when
editing it.

The [WinINet connection options](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optiona)
identify detection flags and setup-script URL, while
[query/set guidance](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)
defines the connection list and returned-string ownership. This provides a backend
candidate, not current Settings GUI or managed-policy acceptance. A service account
or SYSTEM test does not establish intended-user behavior.

[NetUserModalsSet](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset)
lists maximum-age and related modal fields but no focused complexity information
level. The [SAMR domain information classes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/3e8738b2-5df6-499f-907d-ac2471bf0281)
describe protocol structures; that alone does not make an undocumented local DLL
export an approved Win32 backend. Evaluate a supported narrow route instead of
replaying a whole security export.

## Complete remaining ledger triage

The following numbers correspond to every current remaining-ledger row. Multiple
controls within a row keep separate evidence and recovery boundaries. These 30
rows do not replace the 38-58 remaining-feature estimate. R30 evaluates an already
counted built-in app/component outcome rather than adding another legacy count.

| Row | Outcome and current state | Next work and edge cases | Classification |
| --- | --- | --- | --- |
| R01 | Existing-plan selection, owned creation and desktop Power plans access | Creation and shared guards now have two-target evidence. Keep Ultimate activation separate; earlier native activation failed. Legacy source review confirms writes through merged HKCR and recursive deletion of the whole Switch Power Plan tree without prior-state capture. Do not carry that behavior forward. The accepted handoff is implemented as the current-user windows.power-options-shortcut candidate with an exact desktop-file ownership/recovery handler. It remains unsupported pending current Windows 11 UI, intended-session and lifecycle acceptance. Physical device/power-mode effects and template absence remain separate | Implemented core; menu and physical acceptance pending |
| R02 | Proxy detection, setup script and WinHTTP | E07/B04. Default/LAN automatic-detection apply/restore is integrated with the engine and guarded by identity, policy, durable pre-change state, readback and compensation. Preserve manual proxy and unrelated fields. The machine-scope WinHTTP AutoDetect candidate is now catalogued and wired through engine status, planning, saved-run preparation, lifecycle dispatch and conflict-checked restore. Five focused catalog/engine tests pass; the inventory/preparation/lifecycle suites pass 22/22 mocked tests in both PowerShell editions. Machine/user identity, scope and drift checks remain in place; lifecycle records and restores only the reported configuration, so exact underlying registry recovery remains unproven. The operation has no supported targets, cannot enter profiles pending acceptance, and host build 26300 lacks `netsh winhttp show advproxy`. Effective-policy coverage, consumer behavior, RAS, GUI and native Windows acceptance remain separate; a PAC test needs a controlled local server | Integrated pending candidate; disposable Windows acceptance pending |
| R03 | Telemetry mirrors, Windows CEIP and conditional App-V CEIP | Windows CEIP typed lifecycle is done. Verify an actual App-V client, policy mapping and consumer before availability. Leave Native/Wow telemetry mirrors untouched and unexposed; do not infer effect from duplicate values | Conditional consumer evidence; D04 |
| R04 | Paired feedback frequency | R04 is a partial overlap with legacy `DisableFeedback`: v2 writes `NumberOfSIUFInPeriod=0` as REG_DWORD, but leaves `PeriodInNanoSeconds` untouched. The machine notification policy and both task flags are mapped separately. Microsoft Learn labels both SIUF values REG_DWORD while daily/weekly period values exceed the unsigned DWORD range; do not coerce or expose those choices. Preserve mixed/custom prior pairs and unrelated Rules values. Current-build GUI choices, exact types, units, managed precedence and paired restore remain unverified. See [2026-10-28 traceability review](../archive/evidence/legacy-feedback-selector-catalog-traceability-2026-10-28-2035.json) and [Microsoft source recheck](../archive/evidence/feedback-frequency-current-microsoft-source-recheck-2026-10-28-1232.json) | Mapping investigation; D02 |
| R05 | Windows RE registration lifecycle | Read-only registration/OS/image/partition capture first. Existing readiness guide covers independent recovery. The [volume inventory](../volume-inventory.md) provides GUID-path observation only, without boot-role or protection inference. Prove restoring a prior registration association, not merely calling the opposite command. Refuse identity/servicing conflicts; no image or partition changes | High dependency recovery work; D06 |
| R06 | Browser service Hidden override | Accepted retirement is complete. Preserve legacy source and existing values. Network discovery guidance is implemented; peer/profile acceptance is separate | Retired selector; modern outcome partial |
| R07 | Retired MusNotification interception and supported update interruption control | Interception remains retired and untouched. Notification literal lifecycle/fault recovery and guidance are implemented. Validate visible warnings, active-hours combinations, deadlines and effective policy without promising no reboot | Consumer/restart acceptance; D03 |
| R08 | System protection | Native guidance and read-only GUID-path inventory exist. Prove enabled-volume inspection, system-drive coupling, storage allowance and asynchronous completion. Off may destroy history; restoring configuration cannot restore deleted points | Recovery/volume investigation; D06 |
| R09 | Storage Sense | Existing On/Off and guide preserve cleanup preferences. Verify actual switch, policy precedence, default/removal and cleanup-choice meanings using disposable test files. Never restore a deleted-file outcome by claiming registry recovery | GUI/content acceptance; D02 |
| R10 | Windows-native F1 suppression | Queued for manual physical Lenovo Windows 11 Pro validation: capture baseline; test Explorer and desktop Help plus F1 in an unrelated app; apply and remove the candidate setting; verify both states and exact restoration of typed prior values and operation-created keys. Record build and intended-user context. Do not substitute IFEO, file ACL changes, AutoHotkey or a download | Manual target acceptance queued; D05 |
| R11 | Taskbar sizing and Terminal profile | Native taskbar choices and rollout must be observed; no TaskbarSmallIcons assumption or feature-enablement forcing. E03/E06 cover Terminal selection separately, preserving existing profiles and broader normal-launch effect | Taskbar GUI investigation; Terminal backend candidate |
| R12 | Shortcut arrow appearance | Verify the actual resource and rendering before Hide availability. Retain machine/admin scope, typed value 29 and unrelated overlays. No guessed resource index or forced Explorer restart | Cosmetic mapping investigation; D02 |
| R13 | Sign-in and post-sign-in NumLock | Compare the two accepted registry preferences with the user's reliable combined legacy result on real boot/sign-in hardware. Preserve type/encoding and unrelated lock-key state. Do not silently reintroduce SendKeys | Hardware/session evidence; D05 |
| R14 | Compressed/encrypted file-name colors | Observe the current GUI mapping before selecting ShowCompColor versus the legacy value. Test ordinary/compressed/EFS names and themes; preserve file attributes. Existing EFS capability is a prerequisite, not permission to acquire it | Read-only GUI mapping first; D02/D04 |
| R15 | Explorer start location and experimental Home hiding | Preserve the existing start-location ID and states. Test HubMode independently of LaunchTo and user/machine precedence. No namespace reconstruction, pin/history reset or forced restart | Home-hiding mapping investigation; D02 |
| R16 | Include in Library, Give access to and Share menus | Three accepted outcomes. Identify physical roots/views and all bindings before suppression. Prefer bounded reversible binding changes; if subtree deletion is unavoidable, typed content/subkeys/ACLs and conflict-safe recovery must be proved | Multi-binding ownership work; D07 |
| R17 | Five desktop icons and ClassicStartMenu mirrors | Preserve the five published IDs. Compare independent/conflicting mirrors with the GUI and rendering before adding or retiring a mirror. A coordinated handler must read old scalar snapshots without inventing omitted history | Mapping/compatibility investigation; D02 |
| R18 | Server Manager and Shutdown Event Tracker | Both pending candidates now have Server 2025 literal/fault-recovery evidence. Logon/console precedence and actual shutdown prompt remain open. Desktop Experience and Core are distinct applicability cases | Feature/session acceptance; D03/D04 |
| R19 | Local complexity, maximum age and IE ESC | Maximum age has both-target native evidence; E04 adds bounded cases. E08 investigates complexity. IE ESC needs real Server component/class/profile-effect evidence and separate admin/user controls; no Edge/IE-mode equivalence | Complexity backend; conditional ESC evidence; D04 |
| R20 | Audio service and selected playback endpoint mute | Audiosrv lifecycle/fault recovery passed both targets. More dependencies/triggers remain. E03 provides mute UI guidance; direct mute needs stable endpoint identity, saved boolean and session/device-loss recovery without volume/default-device changes | Endpoint/session backend; D04/D08 |
| R21 | BitLocker encryption/decryption and TPM+PIN enrollment | Guided policy, protectors, secure input/redaction and staged nonsecret records first. Preserve current methods/protectors. Encryption progress and added PIN do not prove boot/unlock. No implicit hardware-test skip, reboot or protection suspension | Staged security workflow; D06 |
| R22 | Recovery protector backup, creation and selected-key display | Existing guide separates backup, creation and display. Choose by protector type/ID, reuse existing keys for backup, and use an accessible off-device destination. Never put recovery secrets in routine state/logs | Secure presentation/retrieval work; D06 |
| R23 | Failed-sign-in machine lockout | Confirm mapping and real counting/recovery behavior with protected OS volume and retrievable backup first. Separate Windows sign-ins from TPM PIN/Hello/account lockout; policy restore cannot undo enacted transitions | Recovery-dependent security experiment; D06 |
| R24 | Photo Viewer Open with registration and default-app handoff | Verify an installed native consumer and exact quoting/extensions. Intended-user registration must preserve existing entries; default-app selection is a separate native UI step. No UserChoice hash bypass or component download | Component/registration ownership work; D04 |
| R25 | Conditional radio and Windows Media DRM | Both typed policies and interruption/recovery passed where applicable. Player presence is not radio consumer behavior; WMDRM client/backend/license effects remain unresolved. No installation or license-store repair | Conditional consumer investigation; D04 |
| R26 | Keyboard effective delay and packed visual effects | All stored delay positions and typed recovery passed. Compare native active delay with stored state before backend changes. For effects, reconcile each GUI feature independently and preserve custom masks; no fixed broad preset | Session/native comparison; D02 |
| R27 | WAP Push/Search delayed and startup-only states | Implementation, stored/runtime lifecycle and controlled recovery passed. Test boot scheduling, workload, dormant flags and trigger/dependency effects. No reboot or fixed-delay guarantee is implicit | Boot/workload acceptance; D03 |
| R28 | Windows Security startup icon | Guide and policy presentation exist. Verify intended-user startup entry, overflow and managed precedence. Native handoff remains pending user work; no historical Run-entry reconstruction | GUI/session acceptance; D02 |
| R29 | User .NET assemblies: bookkeeping closed | Q31/D09 accepts closure of the unsubstantiated label; retain the bounded audit and reopen on identified source/use case. No guessed assembly action or migrated-feature claim | Closed 2026-10-17; no numeric outcome deduction |
| R30 | Reviewed Store app selection, policy and user uninstall | [Five optional uninstall/reinstall groups](../store-app-groups.md) accepted, with Media Player/Sound Recorder in multimedia and Xbox dependencies reviewed together. Device policy stays a separate linked workflow. Both references collected; reviewed protection/source rule retained. Solitaire basic native registration lifecycle accepted; policy schema, interruption, app/data recovery and sign-in acceptance remain open | All five groups implemented as guarded candidates; Clipchamp next when elevation available; GUI/full handoff/group/policy and other targets pending; components owner; D11 |

## Earlier accepted controls that still need evaluation

The remaining-ledger table is not the whole acceptance backlog. The earlier
[post-migration review](settings-post-migration-review.md) contains the following
families. Preserve its accepted designs while adding evidence. A catalog-supported
operation may still have unresolved GUI meaning or an incomplete legacy bundle.

| Family | Required follow-up before complete acceptance |
| --- | --- |
| Promotions and numbered suggestion channels | Keep useful individual controls and optional Reduce Windows promotions guidance. Establish each numeric channel's effect; unknown channels remain experimental and outside recommended profiles |
| Input personalization, diagnostics and recognition data | Reconcile multiple local preferences and policies with current GUI/consumer behavior. Separate personalization, uploads and clearing data; no blanket privacy claim |
| Activity history | Verify current supported surfaces and the distinction between local storage, publishing and upload; reconcile removed or conditional behavior without reusing old labels |
| Location, voice activation and app file access | Check global versus per-app, user versus machine, component availability and permission enforcement. Preserve app-specific choices and distinguish consent from enterprise policy |
| Administrative shares and .NET strong cryptography | Validate actual consumers, native/Wow views, service/boot timing and compatibility. Do not equate a flag with complete sharing security or all-runtime cryptography |
| Driver updates and device metadata | Separate update-source inclusion from metadata retrieval; validate effective policy and real update/metadata effects without triggering broad maintenance |
| Maintenance wake and SSDP/UPnP | Verify timers, power/hardware support and service dependencies. Network discovery behavior needs a peer/profile fixture; service state is partial evidence |
| Notifications and accessibility shortcuts | Match actual per-user choices, runtime notifications and shortcuts while preserving unrelated accessibility settings; preference recovery does not undo notifications already delivered |
| Taskbar grouping and This PC folders | Verify current GUI, modern surface and build capability; reconcile namespace/policy scope, omitted branches and exact ownership of removed keys |
| Hidden/protected files and Explorer recent/frequent items | E01 metadata first, followed by GUI/default and policy-precedence checks. Preserve independent controls and existing reverse-state semantics |
| Background apps | Verify current app eligibility and per-app override ownership; global flags do not establish that every app stopped running |
| Power, sleep button/menu/timeouts and hardware clock | Keep system plan, power mode, hardware-dependent actions and menu visibility distinct. Capture concrete resource identity and prove compatible recovery on actual devices |
| Control Panel view and mouse precision | Validate visible mode and effective session values. Registry-only round trips do not establish current runtime behavior |
| UAC | Accepted four slider positions require the exact coordinated values and actual prompt behavior on both targets. Preserve EnableLUA. Mixed-user evidence and reboot behavior remain separate; D01/D03 |
| Fullscreen optimization and visual effects | Verify feature-specific semantics and current GUI before broad presets. Preserve per-app overrides and custom masks |
| Defender cloud, samples, CFA, memory integrity and SmartScreen | Confirm prerequisites, effective modes and real protected/blocked behavior with harmless controlled fixtures. Built-in versus separately licensed services remains visible; do not acquire or disable components to obtain a pass |
| Search web results and automatic network-device setup | Determine current consumer, policy precedence and actual visible result. Background references do not prove an undocumented value's mapping |
| Developer Mode, trusted sideloading and Xbox/media metadata | Separate independently useful features and installed consumers; distinguish policy from prerequisite installation and app acquisition |
| Boot recovery, diagnostics/Office tasks and drive optimization | Existing task identity/schedule tests do not establish payload or workload suppression. Missing tasks/components remain unavailable; preserve automatic recovery and maintenance meanings |
| Start most-used list and Ctrl+Alt+Delete | Validate positive GUI labels, disabling policy inversion, launch tracking, credential/accessibility effects and managed precedence; no implicit sign-out |
| Adapter bindings, LLTD, NetBIOS, NCSI and network profile | The [adapter inventory](../network-adapter-inventory.md) provides a source-ready GUID observation contract; native acceptance and selection remain open. Add paired flags, DHCP/static/VPN behavior, GUI refresh and peer evidence. Preserve GUID-bound restore and new-adapter exclusion; D04/D10 |
| SMB and Remote Desktop | Local flag/rule evidence is partial. Verify prerequisites, exact local/effective sources, authenticated/rejected peers, firewall scope and real session behavior. Missing SMB1 is unavailable, not accepted enablement |
| Sound scheme, startup sound and Edge policies | Preserve customized presets and existing files; test GUI/playback and managed behavior. Edge installation-shortcut policy requires an applicable installer/version and cannot reverse a shortcut already created |
| Scope, enforcement and intended-user execution | E01/E05. Audit roots, account/license/build/hardware prerequisites, configured versus effective sources and all discovery/detail/plan/status surfaces. Displaying the execution account alone is not a target guard |

## Questions and follow-up decisions

Leave answers beside the IDs or provide an ID and answer in chat. No answer is
required while the user is away. Work with an accepted design and independent
evidence can continue. A question about a test resource does not authorize installing
it or acquiring a package.

| ID | Question | Proposed course while awaiting an answer |
| --- | --- | --- |
| D01 | Answered 2026-10-14 and clarified 2026-10-24: use a separate process handoff to the intended user; mixed-scope profiles are valid and expected | First delivery targets the signed-in user in the current desktop session; other sessions or no desktop are refused. Preserve user-owned saved recovery and explicit identity/session checks; no fallback to another administrator's HKCU. Do not block profiles that combine user and machine settings. A mixed-scope overview/report is optional future work, not a migration prerequisite |
| D02 | Answered Q28: Explorer/icons and keyboard/input first | Preserve other GUI checks as pending; use independently authorized disposable targets and defer unavailable resources |
| D03 | Answered Q28: Server sign-in/shutdown next | Application-dependent checks then hardware/peer checks; retain explicit credentials, elevation and recovery gates |
| D04 | Answered 2026-10-24: defer unavailable resources explicitly and proceed with independent acceptance; a standalone Lenovo Windows 11 Pro laptop will be prepared for the TPM/boot test | Match each acceptance case to the available target. Defer only checks that require unavailable resources, and request another scenario when its evidence need is concrete. The dedicated physical laptop is a scoped TPM/boot acceptance target; document why this hardware scenario uses it alongside the disposable-VM validation model |
| D05 | Answered 2026-10-25: the user uses the RIDE v1 F1 setting successfully and wants it retained in the default profile. Remove that selection only if v3 acceptance shows it cannot be rolled back successfully. Historical NumLock build/hardware/boot conditions remain unknown | The default profile now selects `Blocked`, while the candidate remains pending with no supported target. Complete Windows 11 acceptance for both setting states, unrelated-application behavior, and exact restoration of prior typed values and operation-created keys. Profile application is blocked until that acceptance; remove the selection only if rollback fails. Do not use SendKeys, IFEO, or a remapper. Keep NumLock historical evidence open. See the [latest user decision](decision-session-2026-10-17.md#ccleaner-variants-defraggler-retention-and-f1-default-profile-decision-2026-10-25), [candidate lifecycle review](settings-post-migration-review.md#experimental-file-explorer-f1-help-lifecycle-candidate-2026-10-25), and [structured source evidence](../archive/evidence/f1-file-explorer-current-source-recheck-2026-10-24.json) |
| D06 | Updated 2026-10-24: the user will prepare a standalone Lenovo Windows 11 Pro laptop; USB storage and a password manager are both acceptable recovery-key destinations | Before a recovery-changing step, ask the user to confirm the key was saved and can be retrieved, unless the procedure verified that it saved the key to portable storage. Do not require an independent verifier or a particular destination, and do not record recovery secrets. Keep testing deferred until the laptop and confirmation are available |
| D07 | Answered Q29: visible but unavailable until reliable recovery | Explain the limitation and provide accurate manual guidance. No guessed content/ACL reconstruction or retirement |
| D08 | Answered Q30: explicit endpoint plus separately selected current-default option | Resolve/capture actual identity before mutation and restore that same endpoint; no fallback when missing |
| D09 | Answered Q31: close unsubstantiated bookkeeping | Retain bounded audit and reopen on evidence; no assembly deployment/removal or feature-completion claim |
| D10 | Answered Q30: explicit stable adapter/volume identities | Friendly selection display, same captured identity for recovery, report disappearance. Existing all-visible adapter compatibility scope remains explicit |
| D11 | Answered: modern v3 scope; five optional uninstall/reinstall groups; device policy separate | [Accepted membership](../store-app-groups.md) includes 22 apps, with Media Player/Sound Recorder in 2B. All five groups implemented as candidates. Reviewed identity/removability rule approved; usable local reinstall source required. Start native acceptance with Clipchamp/Solitaire after desktop acceptance. Current apps stay installed; packages paused; no automatic policy changes or v2 replay |

## Testing and elevation while the user is away

Use Windows-native parser/catalog/profile/generated-document checks and focused
mocked Pester tests. Keep TestRegistry disabled and WindowsIntegration excluded on
the workstation. Data inspection and plan/completion checks must not invoke setters.

Authorized disposable settings tests can use the existing unattended controller
when both controllers are idle, queues empty, locks available, pins and installed
hashes match and no competing request exists. Use current Local source with the
relevant uncommitted implementation, a bounded explicit fixture and a retained
source hash manifest. Serialize runs; inspect collection and checkpoint recovery
before another submission. No Full/default-profile or package-acquiring suite.

If a task requires an interactive elevation prompt, enrollment/credential entry,
approval response or workstation administration, postpone it and add its exact
action and dependency below. The existing authorized controller can run elevated
inside a disposable guest without an interactive UAC response; that does not
authorize a new host configuration or an unattended security transition.

| Deferred resource or action | Why it cannot be counted as accepted now | Independent work available |
| --- | --- | --- |
| Interactive elevated host/controller configuration | User is AFK; existing installed controller is sufficient and must be preserved | Read installed evidence; prepare changes for later review without applying |
| GUI/interactive session and alternate-user fixtures | WinRM/SYSTEM or a registry value does not establish visible intended-user behavior | Prepare observation/assertion checklist and identity boundaries |
| Physical keyboard, firmware/Fast Startup and power behavior | Disposable VM lifecycle does not represent the user's historical NumLock/power outcome | Design controlled boot comparisons and record D05 resources |
| Office/App-V/legacy media/ESC consumers and installation-time Edge effect | Required installed versions may be absent; package acquisition remains paused | Read source and official prerequisites; retain explicit unavailable dispositions |
| Peer network/domain/managed policy and vendor adapters | Local PersistentStore or a single synthetic NIC is incomplete acceptance | Define restrictive peer scenarios, inventory requirements and source comparison |
| BitLocker secure input, key retrieval and actual boot/unlock | Requires usable independent recovery, secret handling and a representative boot route | Design nonsecret records, ownership, staged failure and native handoffs |
| System protection deletion/history and Windows RE association mutation | Configuration restore cannot recover lost history or an unverified boot/image state | Implement read-only capture proposals and conflict checks before writes |

[SystemParametersInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow)
documents keyboard delay 0-3 and hardware variation. A future delay fixture should
compare its read-only effective value with stored state before changing the stable
registry backend. [Core Audio endpoint volume](https://learn.microsoft.com/en-us/windows/win32/api/endpointvolume/nn-endpointvolume-iaudioendpointvolume)
documents hardware versus software mute and exclusive-mode limitations. A no-endpoint
VM or software-only exclusive stream cannot prove universal audio silence.

## Cross-group estimate authority

This settings plan records ownership boundaries but does not maintain a second estimate table. Use the current five-group ranges, rounded total and estimate history in the [migration plan](../MIGRATION-PLAN.md#estimated-remaining-migration-work).
## Next handoff

Continue the accepted settings work and independent package/component batches. Do not reopen accepted designs or wait between authorized batches. Keep settings, package, component, file/asset and maintenance outcomes distinct; track implementation, local lifecycle, Windows behavior, supported targets and user-visible effects separately.

The immediate constraints are access and source availability, not another design pause: disposable Windows acceptance remains deferred until VM/CIM and registered-task access recover; fresh-UAC scenarios stay saved for an attended session. Telnet LocalSource remains blocked pending matching Languages and Optional Features media. Some GitHub source pins/acquisitions remain DNS-blocked. Continue local code, source and mocked lifecycle work wherever the inputs are available; do not claim native acceptance from mocks or archive inspection.

Use [MIGRATION-PLAN.md](../MIGRATION-PLAN.md) for current estimates and run history, [TODO.md](../../TODO.md) for the latest work log, [remaining-migrations-follow-up.md](remaining-migrations-follow-up.md) for component/package handoffs and open questions, and [settings-post-migration-review.md](settings-post-migration-review.md) for dated setting decisions and acceptance evidence. The separate migration decisions chat remains the place for user answers; do not infer answers from repository notes.
## Decision-session reconciliation, 2026-10-17

Q07-Q12 now accept interactive administrator enrollment, separate startup/persistent
user PATH, existing-profile Terminal selection, separate browser preferences and
policies, scoped reviewed assets and per-user Wi-Fi/import boundaries. See the
[authoritative reconciliation](remaining-migrations-follow-up.md#reconciled-decision-session-answers-2026-10-17).
These choices remove design questions, not identity/ownership/recovery or native
acceptance. No settings changed; presentation remains 102/279 with 177 open.

Persistent user PATH now has [literal observation, entry recovery and an internal guarded write boundary](../powershell-profiles.md#persistent-user-path-preparation).
The focused suite passes 50/50 in each native edition using mocked registry
handles. The startup renderer remains separate; the RIDE engine does not dispatch
the writer, and durable run recovery, refresh and native acceptance are pending.
No legacy outcome or presentation count changed.

## Accepted remaining decisions, 2026-10-17

The [Q25-Q31 decision record](decision-session-2026-10-17.md) accepts configuration
ownership, static Store-first ordering, explicit destructive-action recovery with
a disposable-cache exception, GUI/Server/hardware acceptance order, unavailable
menu controls where recovery is absent, and stable resource identity. R29/D09 is
closed as unsubstantiated bookkeeping; the bounded audit remains authoritative
and a source/use case reopens it. No legacy estimate is deducted because the
audit did not establish an extra outcome. Actual implementation/GUI/native
acceptance remains separate; all five ranges remain 38-58 / 56-71 / 20-25 /
25-35 / 8-12, rounded 145-200/about 175.

## B01 service startup and runtime presentation, 2026-10-17

See the [dated review](settings-post-migration-review.md#b01-service-startup-and-runtime-presentation-2026-10-17). Presentation is 185/279, 94 open. Both editions passed 122 focused checks (one integration exclusion); native/GUI/whole-outcome acceptance stays separate. All five ranges remain unchanged; continue independent source batches.

## B01 scheduled-task presentation, 2026-10-17

See the [dated review](settings-post-migration-review.md#b01-scheduled-task-presentation-2026-10-17). Presentation is 198/279, 81 open. Both editions passed 122 focused checks (one integration exclusion); native/GUI/whole-outcome acceptance stays separate. All five ranges remain unchanged; continue independent source batches.

## B01 scheduled-task observation and readback, 2026-10-17

See the [repair evidence](settings-post-migration-review.md#b01-scheduled-task-observation-and-readback-2026-10-17). Twenty selected task tests passed per edition; native workload acceptance remains pending. Presentation is 198/279, 81 open. Existing profiles remain unchanged under the new explicit profile-selection deferral. All five ranges remain unchanged.

## Mixed-scope profiles and acceptance resources, 2026-10-24

The user confirmed that mixed-scope profiles are expected because RIDE users
commonly apply settings from both user and machine scopes. Mixed scope is not a
design or migration blocker. A report or analysis view that summarizes scope
within a profile may be considered as separate future functionality; it is not
required before completing profile work. D01 remains answered for intended-user
handoff and identity-safe recovery; its mixed-scope follow-up is closed.

Unavailable acceptance resources are explicitly deferred while independent
checks proceed. A standalone Lenovo laptop running Windows 11 Pro is the selected
target for the TPM/boot recovery scenario, and the user will prepare it. This is
a focused hardware acceptance case alongside the repository's disposable-VM
validation model, not a general change to that model.

The user clarified on 2026-10-24 that either USB storage or a password manager
may hold the recovery key. Before a recovery-changing test, ask whether the key
has been saved and can be retrieved, unless the procedure itself verified the
key was saved to portable storage. Do not require a specific destination or an
independent verifier. Never record the key in repository evidence. The laptop
and this confirmation remain prerequisites; no recovery-changing test is
authorized by this clarification. See the [follow-up decision record](remaining-migrations-follow-up.md#mixed-scope-profiles-and-tpm-boot-acceptance-2026-10-24)
and the [authoritative decision ledger](decision-session-2026-10-17.md#joeware-latest-download-and-acceptance-resource-decisions-2026-10-24).

## RIDE v3 Windows AI, passkey and presence controls, 2026-10-24

The user added the following recent Windows controls to the RIDE v3 candidate
scope. They are new feature work, not legacy outcomes; do not change migration
estimates or count these as completed legacy selectors. Click to Do now has an
unregistered, pending catalog candidate; no profile selection or Windows
behavior is claimed by recording this scope.

| Candidate | Intended RIDE control | Implementation and acceptance boundary |
| --- | --- | --- |
| Click to Do | Per-user `Blocked`/`Allowed`/`WindowsDefault` policy candidate implemented; keep independent from Copilot and Recall | `windows.click-to-do-policy` maps the documented `DisableClickToDo` DWORD. `Allowed` does not force the user's local toggle on, and a conflicting device policy remains outside this operation. The CSP lists Insider Preview applicability. Verify current target policy behavior, visible entry points and exact saved-state restore before declaring support. It is not selected in any default profile. |
| Passkey app access | Keep per-app access and user choice; do not default-deny all applications | Windows 11 24H2 exposes per-app consent in Settings; declining prevents registration/authentication for that app. The 2026-10-25 Microsoft Privacy Policy CSP recheck still marks the device-scoped default, allow/deny/user-control PFN lists, and passkey enumeration policies Windows Insider Preview, despite the passkey feature page's end-of-June 2026 general-availability target. The host's build-26300 AppPrivacy ADMX has the named entries, but host template presence does not establish stable target support. Do not ship policy-backed operations until the published support discrepancy and target behavior are resolved. Preserve each app's prior choice; a global Boolean is not equivalent. |
| Presence sensing | Keep app access at user control by default; offer OS lock-on-leave separately as a security control | The current Privacy Policy CSP documents device-scoped default and per-app controls from build 10.0.25000+, but that build floor does not identify a released Windows target. Do not combine app access, lock-on-leave and wake-on-approach. Verify exact policy consumers, sensor availability, supported target, lock timing, wake behavior and prior-state restore. |
| Administrator protection | Offer an explicit enable choice; consider it for a hardened profile after acceptance | The current feature page says Administrator protection is available with KB5120998 on Windows 11 Home/Pro/Enterprise/Education, off by default, and requires restart; Windows Server is excluded. The LocalPoliciesSecurityOptions CSP still labels its elevation-prompt control Insider Preview, and its UI guidance retains a preview note. Reconcile the exact policy state/backend on a supported Windows 11 build before implementation; do not infer registry values. Verify prompt behavior, restart and exact restoration in a disposable VM. |
| Smart App Control | Inspect Off/Evaluation/Enforcement and offer enablement only where Windows exposes a supported transition | Microsoft says registry configuration is for testing and may compromise protection. Its documented Settings transition is one-way outside Evaluation on the current guidance; verify the new on/off rollout and a supported recovery route before adding a state-changing operation. Test app compatibility and restart requirements in a disposable VM. |

Click to Do's source-backed candidate has state observation, apply and exact
saved-run restore through the existing `RegistryValue` handler; target
applicability and visible effects remain unaccepted. The other four remain
source-review and implementation candidates until their state, apply,
saved-run restore, target applicability and visible effects meet RIDE's
lifecycle contract. The default-profile recommendations above remain deferred;
none of these controls is selected in `profiles/default.psd1`.
Authoritative references: [WindowsAI Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai),
[passkeys in Windows](https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/),
[Privacy Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy),
[Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection),
and [Smart App Control testing and configuration](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control).

### 2026-10-28 Microsoft passkey enterprise-policy recheck

The current Microsoft passkey support page still describes enterprise consent
policies as available in Windows Insider builds and targeted for general
availability by the end of June 2026. The current Privacy Policy CSP continues
to label the device-scoped base policy, per-app ForceAllow/ForceDeny/UserInControl
lists, and enumeration policy Windows Insider Preview. Windows 11 24H2's
per-app consent UI remains a separate user-facing capability: declining consent
blocks that app's passkey registration and authentication, and users can change
per-app access in Settings. The date target has passed, but Microsoft has not
updated these policy declarations to stable applicability. Do not infer support
from the host ADMX or implement a global Boolean; retain user choice and defer
the policy-backed candidate until a released target and reversible policy
semantics are documented. No catalog or profile changed. See [current source
evidence](../archive/evidence/windows-passkey-enterprise-policy-current-source-recheck-2026-10-28-1112.json).

### 2026-10-25 Microsoft source recheck

The passkey consent policy's published end-of-June 2026 general-availability
target has passed, but the current Privacy Policy CSP still labels its base and
per-app policy nodes Windows Insider Preview. Administrator protection is now
described as available for Windows 11 clients with KB5120998, while the
administrator-protection prompt CSP and Windows Security UI guidance still carry
preview applicability. Do not interpret either inconsistency as stable support.
The current CSP identifies presence-sensing app privacy controls as device-scope
and lists build 10.0.25000+, which does not establish a released product target.
Smart App Control's supported Settings transitions remain one-way outside
Evaluation; the documented registry route is for testing and may compromise
protection. No catalog operation or profile was changed in this source batch.
See [structured Microsoft source evidence](../archive/evidence/windows-ai-passkey-presence-policy-source-recheck-2026-10-25-1206.json).
