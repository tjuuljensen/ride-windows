## BitLocker workflow, engine projection and target-policy source regressions, 2026-10-29 02:55 UTC

`BitLockerWorkflows.Tests.ps1` passed 25/25; `BitLockerEngineProjection.Tests.ps1` and `BitLockerEncryptionMethodPolicies.Tests.ps1` passed 6/6 combined after correcting the policy tests to mock `Get-RidePlatform` inside `RIDE.Engine`. The isolated policy rerun passed 5/5. Current repository validation passed for 451 operations, 8 groups, 5 profiles and 306 PowerShell files. Synthetic values and mocks were used; no registry, BitLocker/TPM state, recovery secret, VM or Windows state was changed. The four workflow operations and three method-policy candidates remain pending native target acceptance. Fresh host CIM failure still prevents VM/checkpoint inspection. No legacy outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/bitlocker-engine-policy-current-source-regression-and-cim-block-2026-10-29-0255.json) and [workflow evidence](../archive/evidence/bitlocker-workflows-current-source-winps51-regression-and-cim-block-2026-10-29-0252.json).

## MiTeC System and Telephony pre-registered VM request, 2026-10-29 00:39 UTC

The saved `RIDEWin11Test` configuration matches the current account and advertises `FocusedPortableV1` and `MiTeCSystemAndTelephonyV1`; cleanup was not blocked and pending/running queues were empty. Submission failed before request creation because `Set-Content` was denied writing the temporary file in `queue/pending`. A follow-up found no pending/running request or temporary file, so no scheduled task or guest test ran. Host CIM also denied VM/task-state queries. Keep native acceptance deferred and continue independent source work; do not modify task ACLs or request fresh elevation in this batch. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/mitec-system-telephony-preregistered-queue-write-block-2026-10-29-0039.json).

## MiTeC TAPI Monitor Server 2025 candidate target, 2026-10-29 00:36 UTC

The official TAPI Monitor 1.2.0 page lists Windows XP-11 and Windows Server 2003-2025. Added Server 2025 to the candidate target set; supported targets remain empty. A fresh non-elevated `Get-VM` query this turn failed at host CIM before VM state retrieval for RIDE-Win11-Test and RIDE-S25-Test, with no checkpoint/task query or guest request. Keep lifecycle and simulated-provider acceptance deferred; continue independent source work. No utility or real telephony data was used; no legacy outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/mitec-tapi-monitor-server2025-candidate-target-2026-10-29-0036.json).

## MiTeC System Information eXtra Server 2025 candidate target, 2026-10-29 00:34 UTC

The official MiTeC page for version 16.0.0 claims Windows XP-11 and Windows Server 2003-2025. The candidate now includes Windows Server 2025 alongside Windows 11; supported targets remain empty pending package lifecycle/recovery and synthetic report-handling acceptance. A fresh non-elevated `Get-VM` check this turn failed at host CIM before VM state retrieval for RIDE-Win11-Test and RIDE-S25-Test; no checkpoint/task query or guest request occurred. Keep both target acceptances deferred and proceed with independent source work. No utility ran, no report was created, and no legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/mitec-system-information-server2025-candidate-target-2026-10-29-0034.json).

## RIDE-Win11-Test and RIDE-S25-Test CIM access recheck, 2026-10-29 00:24 UTC

Fresh non-elevated Get-VM calls for both registered targets failed before state retrieval with host CIM access denied. No checkpoint/task query or guest request occurred; no elevation or state change. Keep Mail Checker and Paradox Data Editor native acceptance deferred and continue independent source work. See [structured evidence](../archive/evidence/ride-win11-s25-mitec-acceptance-cim-block-2026-10-29-0024.json).
## RIDE-Win11-Test and RIDE-S25-Test CIM access recheck, 2026-10-29 00:18 UTC

Fresh read-only Get-VM calls for both registered targets failed before state retrieval with host CIM access denied. No checkpoint/task state was queried and no guest request or elevation occurred. Defer native package acceptance and continue independent source work. See [structured evidence](../archive/evidence/ride-win11-s25-paradox-acceptance-cim-block-2026-10-29-0018.json).
## RIDE-Win11-Test and RIDE-S25-Test CIM access recheck, 2026-10-29 00:07 UTC

Fresh non-elevated Get-VM calls for both registered names failed before state retrieval with host CIM access denied. No checkpoint, task or queue was queried and no guest request or elevation occurred. Keep native Windows acceptance deferred; independent local source and mocked work may continue. See [structured evidence](../archive/evidence/ride-win11-s25-test-cim-access-recheck-2026-10-29-0007.json).
## RIDE-Win11-Test and RIDE-S25-Test host CIM acceptance blocker, 2026-10-28 23:48 UTC

Fresh non-elevated read-only `Get-VM` queries for both exact registered names failed before state retrieval with `Access to a CIM resource was not available to the client`. No checkpoint/task state or queue was queried; no guest request or elevation occurred. Keep native Windows 11/Server 2025 acceptance deferred and proceed with independent source work. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/ride-win11-and-s25-test-cim-access-recheck-2026-10-28-2348.json).

## Repository static validation, Windows PowerShell 5.1, 2026-10-28 22:51 UTC

`tools/validate.ps1 -Root <workspace root>` passed under Windows PowerShell 5.1.26100.9818: 447 operations, 8 groups, 5 profiles and 301 PowerShell files; generated operation documentation is current. The invocation used process-only `ExecutionPolicy Bypass`; no persistent policy change or elevation occurred. This confirms static repository consistency only. No installer, VM, Defender or Windows state was accessed. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/repository-static-validation-windows-powershell-2026-10-28-2251.json).
## B06 Telnet registered LabSources root recheck, 2026-10-28 22:18 UTC

The four registered setup ISO filenames and the README-only SoftwarePackages and OSUpdates top-level roots are unchanged from the 2026-10-26 inspection. No matching Languages and Optional Features source is present in the inspected LabSources roots. The prior read-only archive listings found no Telnet-named package in those four images and no Telnet source under sources\\sxs; this recheck did not open an ISO. Telnet LocalSource remains unimplemented because package identity, repository completeness, dependencies, architecture/build/language fit and exact recovery cannot be validated without matching media. No code, Windows, VM, checkpoint, Defender or elevation state changed. Resolved: the current registered root inventory is unchanged. Deferred: matching media, Telnet source validation and native acceptance. No legacy outcome closed; ranges remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). See [current root evidence](../archive/evidence/telnet-labsources-current-root-recheck-2026-10-28-2218.json) and [prior ISO listing](../archive/evidence/telnet-labsource-fod-media-inventory-2026-10-26-0606.json).

## OpenSSH Server component current-source cross-shell regression and VM access recheck, 2026-10-28 21:19 UTC

The capability lifecycle, service lifecycle, and observation suites passed 16/16, 11/11, and 7/7 respectively in both PowerShell 7.6.5/Pester 5.7.1 and Windows PowerShell 5.1.26100.9818/Pester 5.7.1. All servicing, service, firewall, privilege, target-observation and snapshot providers were mocked. A fresh `Get-VM -Name RIDE-Win11-Test` call failed at host CIM before VM state retrieval; no guest request occurred. Native Windows 11 and Windows Server 2025 acceptance remains deferred, and catalog target support stays empty. No legacy outcome closed; estimates remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/openssh-server-current-source-cross-shell-regression-and-vm-block-2026-10-28-2119.json).
## Package review reminders and non-blocking planning regression, 2026-10-28 19:15 UTC

The workspace-local review store now includes exact-version owner-administration reminders for Visual C++ Redistributable 14.51.36247.0, Chrome 156.0.8078.48, Slack 4.52.182 and Discord 1.0.9264. A backup export was retained before the update. The focused accepted-package plan regression passed 1/1 in both PowerShell editions with Pester registry/result integrations disabled; no package was downloaded or installed. The Sysinternals review entries remain unchanged under the prior RIDE v2 specialist approval. No legal gate or legacy outcome closure was introduced. Estimates unchanged. See [structured evidence](../archive/evidence/package-license-review-reminders-and-nonblocking-plan-regression-2026-10-28-1915.json).

## RIDE-Win11-Test preregistered controller access recheck, 2026-10-28 19:07 UTC

The installed controller configuration confirms RIDE-Win11-Test, RIDE-clean-test-base, the current local checkout, and FocusedPortableV1; its block marker is absent and pending/running queues are empty. Task Scheduler access still fails: Get-ScheduledTask is CIM-denied, schtasks /Query returns 'The network address is invalid', and the COM API returns access denied. No task status or VM checkpoint was inspected, and no request was queued. No VM, Windows, Defender, configuration or elevation state changed. Acceptance remains deferred; estimates unchanged; no legacy outcome closed. See [structured evidence](../archive/evidence/ride-win11-test-preregistered-controller-access-block-2026-10-28-1907.json).

## RIDE-Win11-Test read-only CIM access recheck, 2026-10-28 19:02 UTC

Get-VM -Name RIDE-Win11-Test failed before retrieving VM state with host CIM access denied. No checkpoint/task inspection or guest dispatch occurred, and no VM, Windows, Defender or elevation state changed. Native B06 acceptance remains pending. Estimates unchanged; no legacy outcome closed. See [structured access evidence](../archive/evidence/ride-win11-test-cim-access-block-2026-10-28-1902.json).

## B06 OpenSSH Client/Telnet guarded lifecycle cross-shell regression, 2026-10-28 19:00 UTC

	ests/ClientComponentLifecycle.Tests.ps1 passed 26/26 in PowerShell 7.6.5 and 26/26 in Windows PowerShell 5.1 with Pester 5.7.1; TestRegistry/TestResult were disabled. A first default Pester attempt reported 26 framework failures before assertions at its optional HKCU TestRegistry setup, then the documented restricted configuration passed. Lifecycle and provider boundaries were mocked; DISM, VM, Windows and Defender state were untouched. Native OpenSSH/Telnet source recovery and Windows acceptance remain open under the current CIM blocker. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/b06-client-component-lifecycle-cross-shell-regression-and-vm-block-2026-10-28-1900.json).

## PasswordScan Defender repeat report, 2026-10-28 18:56 UTC

The reported alert repeats the same x64 PasswordScan path/GUID. The stage root was absent at the read-only existence check; Defender event identity and creator remain unknown. Current NirSoft staging test inputs are synthetic, and the retained publisher-archive case is inventory-only. Both architectures remain excluded; potentially materializing NirSoft lifecycle runs remain paused pending provenance reconciliation. No executable or Defender state was accessed or changed. Estimates unchanged; no legacy outcome closed. See [structured evidence](../archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1856.json).

## RIDE-Win11-Test read-only CIM access recheck, 2026-10-28 18:49 UTC

`Get-VM -Name RIDE-Win11-Test` failed again before state retrieval with “Access to a CIM resource was not available to the client.” No target checkpoint or registered task could be inspected, and no guest request was dispatched. No VM, checkpoint, Windows, Defender or elevation state changed. Windows acceptance remains deferred; local source and mocked work may continue. No legacy outcome closed; estimates remain Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured VM blocker evidence](../archive/evidence/ride-win11-test-cim-access-block-2026-10-28-1849.json).
## PasswordScan temporary-stage provenance text audit, 2026-10-28 18:45 UTC

A text-only search found no exact reported GUID in local source/log text, and the reported parent temp-directory name does not appear in current runner source. The portable handler generates `RIDE-Portable-<GUID>` under the process temp root; the current NirSoft test source excludes 13 blocked executable names including PasswordScan, uses synthetic inert archives for staging tests, and keeps the retained encrypted-archive review inventory-only. The creator and source revision for the reported stage remain unknown. No reported executable, metadata or hash was accessed; no staging/test rerun, Defender query/change, VM action, Windows change or elevation occurred. Keep PasswordScan x86/x64 excluded and pause NirSoft lifecycle runs that could materialize it pending provenance reconciliation. No legacy outcome closed; estimates remain Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured provenance evidence](../archive/evidence/nirsoft-passwordscan-stage-provenance-text-audit-2026-10-28-1845.json).
## Sysinternals independent products current-source regression, 2026-10-28 18:38 UTC

`tests/SysinternalsProductPackages.Tests.ps1` passed 72/72 across process explorer, Autoruns, TCPView, Process Monitor, RAMMap, Disk2vhd, Sigcheck, Strings and Handle in PowerShell 7.6.5/Pester 5.7.1 (139.36 seconds). Each test container used synthetic inert archive members; TestRegistry and TestResult were disabled. No network discovery, payload download, product executable, installer, Defender-blocked tool, VM, Windows state or elevation was used. Together with the separately recorded Suite regression, all 80 focused assertions pass. These are local source/lifecycle regressions, not new native acceptance and not a legacy-outcome closure. Estimates remain Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). Prior RIDE v2 specialist approval clears Sysinternals direct download/install; Defender exclusions remain separate. See [structured evidence](../archive/evidence/sysinternals-products-current-source-pester-regression-2026-10-28-1838.json) and [Suite regression](../archive/evidence/sysinternals-suite-current-source-pester-regression-2026-10-28-1834.json).
## Sysinternals Suite current-source regression, 2026-10-28 18:34 UTC

`tests/SysinternalsSuitePackage.Tests.ps1` passed 8/8 in PowerShell 7.6.5/Pester 5.7.1 (368.29 seconds), with TestRegistry and TestResult disabled. Synthetic inert ZIP members exercised pinned acquisition boundaries, archive validation, repeat staging, owned-file uninstall/restore and collision handling. No network discovery, payload download, product executable, installer, Defender-blocked tool, VM, Windows state or elevation was used. An initial combined invocation failed before discovery due an invalid Pester configuration property; the corrected combined 80-test invocation remained silent and was interrupted without an aggregate result. Only the isolated 8/8 run is counted. This adds no native acceptance and closes no legacy outcome; estimates remain Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). Sysinternals direct download/install remains cleared under prior RIDE v2 specialist approval; Defender exclusions remain separate. See [structured evidence](../archive/evidence/sysinternals-suite-current-source-pester-regression-2026-10-28-1834.json).
## PasswordScan Defender notification repeat report, 2026-10-28 18:18 UTC

The user reports another Defender block for x64 `passwordscan.exe` at the same filtered-Pester temporary-stage path/GUID reported earlier today. Event identity, detection name, timestamp and stage creator remain unknown; the notification alone does not prove a distinct event. Keep both PasswordScan architectures excluded and pause NirSoft staging/Pester runs that could materialize the member until stage provenance and catalog/source revision are reconciled. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1818.json).

## RIDE-Win11-Test read-only CIM access recheck, 2026-10-28 18:16 UTC

`Get-VM -Name RIDE-Win11-Test` failed before state retrieval because host CIM access was denied. No checkpoint or task was inspected, and no guest request or VM/Windows/Defender change occurred. The target had been visibly running at 17:43, but checkpoint membership and task readiness remain unconfirmed. Keep VM acceptance deferred. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/ride-win11-test-vm-cim-access-block-2026-10-28-1816.json).
## Remaining settings current-source Windows PowerShell regression, 2026-10-28 18:15 UTC

`RemainingSettings.Tests.ps1` passed 77/77 in Windows PowerShell 5.1.26100.9711/Pester 5.7.1 with process-only ExecutionPolicy Bypass and TestRegistry/TestResult disabled. Persistent policy was unchanged; settings handlers/providers were mocked or synthetic, including Defender preference. No live Windows, Defender, VM or registry state changed. Native acceptance remains deferred pending target checkpoint and task readiness. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/remaining-settings-winps51-current-source-regression-2026-10-28-1815.json).
## Windows PowerShell 5.1 component and setting cross-shell regression, 2026-10-28 18:04 UTC

Six component suites plus BitLocker workflow, drive-method policy and F1 suites passed 145/145 in Windows PowerShell 5.1.26100.9711/Pester 5.7.1. Pester loaded with process-only ExecutionPolicy Bypass; persistent policy was unchanged. TestRegistry/TestResult were disabled and providers mocked or synthetic. No VM, Windows, Defender or elevation state changed. Native acceptance remains pending target checkpoint and task confirmation. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/component-settings-cross-shell-pester-regression-ps51-2026-10-28-1804.json).
## Focused current-source settings regression, 2026-10-28 18:00 UTC

`RemainingSettings.Tests.ps1`, `BitLockerWorkflows.Tests.ps1`, `BitLockerEncryptionMethodPolicies.Tests.ps1` and `F1Help.Tests.ps1` passed 113/113 in PowerShell 7.6.5/Pester 5.7.1 with TestRegistry/TestResult disabled and temporary data under `.local`. Calls to registry, BitLocker and Windows providers were mocked or synthetic. No VM, Defender or elevation state changed. Native setting acceptance remains deferred because RIDE-Win11-Test checkpoint and task readiness are unconfirmed. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/settings-current-source-pester-regression-ps7-2026-10-28-1800.json).
## Focused current-source component regression, 2026-10-28 17:51 UTC

The component inventory, client preparation/lifecycle and OpenSSH Server capability/lifecycle/observation suites passed 109/109 in PowerShell 7.6.5/Pester 5.7.1 with TestRegistry/TestResult disabled and temp files under `.local`. All provider/servicing tests were mocked or synthetic. Initial runs failed before assertions because of an invalid parameter combination and denied TestRegistry HKCU setup; the configured run passed all assertions. No VM, checkpoint, DISM, Windows or Defender state changed. Native acceptance remains deferred because target checkpoint membership and task readiness are unconfirmed. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/component-current-source-pester-regression-ps7-2026-10-28-1751.json).
## steghide 0.5.1 official archive acquisition retry, 2026-10-28 17:46 UTC

The official page still lists 0.5.1 and links its Windows ZIP through SourceForge. HEAD requests to both official download hosts failed at local DNS before transfer. No bytes, local hash, member inventory or candidate; no extraction or execution. Keep selected and optional; GPL review metadata is administrative. Exact archive inventory and Windows acceptance remain open. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/steghide-official-download-dns-retry-2026-10-28-1746.json).
## RIDE-Win11-Test running state and checkpoint access recheck, 2026-10-28 17:43 UTC

Hyper-V Manager shows RIDE-Win11-Test running. The visible `RIDE-clean-test-base` checkpoint belongs to selected RIDE-S25-Test, so target checkpoint membership remains unconfirmed. The elevated Hyper-V console does not expose the VM/checkpoint list through read-only accessibility, and host CIM denied `Get-VM` before retrieval. No guest request or VM/checkpoint change occurred. Keep Windows acceptance deferred until checkpoint membership and task readiness can be confirmed. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/ride-win11-test-hyperv-running-checkpoint-unconfirmed-2026-10-28-1743.json).

## PasswordScan Defender alert report, 2026-10-28 17:41 UTC

The user reports a newly received Defender block alert for x64 `passwordscan.exe` at the same filtered-Pester temporary-stage path/GUID recorded earlier. The notification does not provide a detection name, Defender event timestamp or creator, and does not establish whether the underlying event is distinct. Keep both PasswordScan architectures excluded and pause NirSoft staging/Pester lifecycle runs that could materialize the member until provenance and catalog/source revision are reconciled. No file, path metadata, hash or Defender state was accessed; no test or staging ran. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/nirsoft-passwordscan-user-defender-alert-2026-10-28-1741.json).
## Ophcrack and steghide current-source review, 2026-10-28 17:37 UTC

The Ophcrack publisher lists portable 3.8.0 with Windows support through Windows 10; its linked SourceForge file page lists SHA-256, but local DNS prevented acquisition before transfer. Steghide's official site lists 0.5.1, a 1.8 MB Windows ZIP, and included libraries; the publisher page does not list a checksum. The project identifies GPL. No package candidate has exact local bytes/member inventory, and no Windows 11 acceptance is established. Keep both selected, optional and unsupported pending acquisition and lifecycle work. Exact-version `NeedsReview` / `Unassigned` owner records should be added after candidate IDs are created; this is administrative, not a migration gate. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/ophcrack-steghide-current-source-review-and-acquisition-2026-10-28-1737.json), [Ophcrack publisher download](https://ophcrack.sourceforge.io/download.php) and [steghide publisher download](https://steghide.sourceforge.net/download.php).
## Hash Suite Free 4.1 publisher-source recheck, 2026-10-28 17:34 UTC

The official publisher lists Hash Suite Free 4.1 (2026-10-17), a 28.3 MB ZIP, a published SHA-256 and Windows 10 64-bit minimum. The exact download route was attempted from Windows PowerShell but local DNS failed before transfer. No bytes, local hash, archive inventory or catalog candidate are available, so the portable file contract is still undefined. Keep Free separate from Standard and Pro. The publisher's download page says Free is for any legal use while the separate license page presents paid commercial terms; add exact-version `NeedsReview` / `Unassigned` owner administration when the catalog ID exists. This does not block technical migration. No legacy outcome closed; all estimates remain unchanged. See [structured evidence](../archive/evidence/hash-suite-free-4.1-publisher-source-review-and-dns-block-2026-10-28-1734.json) and [official download page](https://hashsuite.openwall.net/download).
## NirSoft current-source staging safety audit, 2026-10-28 17:30 UTC

The current catalog loaded through `Get-RideCatalog` selects 647 NirLauncher members and 47 x64-tools members, with no PasswordScan path in either selection. The candidates remain PendingAcceptance with no supported targets. The NirSoft test file parses; its only portable staging calls consume a test-created synthetic inert ZIP after blocked-name assertions, and its retained encrypted-archive case is inventory-only. No test or staging ran. This source does not explain the reported temporary file; an older catalog snapshot, another caller or previous output remains possible. Keep both architectures excluded and pause any NirSoft staging/Pester run that could materialize the blocked member until provenance is reconciled. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/nirsoft-current-source-staging-safety-audit-2026-10-28-1730.json) and [latest alert report](../archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1726.json).
## BitLocker method policy lifecycle added to SettingsRemainingBatch1, 2026-10-28 17:25 UTC

Extended the existing package-free Windows 11 `SettingsRemainingBatch1` guest runner from 19 to 22 operations by selecting the OS, fixed-data and removable-data BitLocker method policy candidates. The runner enables pending candidates only in its private guest catalog, exercises the five declared policy states, preview, repeat behavior and exact saved-run restoration, and does not encrypt or convert a volume. The CLI/controller suite selector is pre-existing, so no protected-controller refresh is required. Parser and version checks passed; the data-only catalog count is 19 existing operations plus exactly 3 candidates; repository validation passed for 447 operations, 8 groups, 5 profiles and 301 PowerShell files. No Pester assertions ran because Windows PowerShell cannot import Pester 5.7.1 format files under the current AuthorizationManager policy. The current Hyper-V Manager view shows RIDE-Win11-Test Off, but scheduled-task readiness and live checkpoint membership remain unverified; no guest request was queued. Resolved: source-side runner selection and static validation. Deferred: actual Windows 11 policy lifecycle, exact recovery and any visible/effective Group Policy behavior. No Windows, registry, drive, checkpoint or Defender state changed; no legacy outcome closed. Estimates remain Settings 37-57 / Packages 37-52 / Components 19-24 / Files/assets 25-35 / Maintenance 8-12, exact 126-180, rounded 125-180/about 155. See [structured evidence](../archive/evidence/bitlocker-method-policy-runner-preparation-and-vm-block-2026-10-28-1725.json), [runner](../../tests/integration/Invoke-RideRemainingSettings.ps1) and [acceptance instructions](../../tests/integration/README.md#remaining-settings-session).

## Focused component acceptance preflight and Pester import block, 2026-10-28 17:18 UTC

Hyper-V Manager visibly lists RIDE-Win11-Test as Off. The existing controller configuration matches the current account, pins `RIDE-clean-test-base` and a checkpoint ID, advertises `FocusedPortableV1`, has no pending/running requests and no cleanup block. Scheduled-task status remained unreadable (`Get-ScheduledTask`/`schtasks` unavailable; `Schedule.Service` returned Access Denied), and the live checkpoint could not be confirmed in Hyper-V Manager's elevated console. No request was queued. Windows PowerShell finds Pester 5.7.1, but import fails before discovery because AuthorizationManager rejects its format files; no assertions ran. Resolved: controller capability, matching submit account, empty queues and visible VM Off state. Partial/deferred: controller task readiness, live checkpoint membership, Pester assertions and all guest acceptance. No VM, checkpoint, component, Defender or Windows state changed; no fresh UAC prompt. PasswordScan remains excluded. No legacy outcome closed; estimates remain Settings 37-57 / Packages 37-52 / Components 19-24 / Files/assets 25-35 / Maintenance 8-12, exact 126-180, rounded 125-180/about 155. See [structured evidence](../archive/evidence/focused-component-vm-preflight-and-pester-import-block-2026-10-28-1718.json).

## B06 operator-help and module-version reconciliation, 2026-10-28 17:09 UTC

Corrected `RIDE.ClientComponentLifecycle.psm1` help so it documents the Group Policy LocalSourcePath guard and bumped the module to 0.4.4 for result reporting and restore revalidation. Module and focused test-file parsing passed; repository validation passed for 447 operations, 8 groups, 5 profiles and 301 PowerShell files. Pester assertions remain unverified because only Pester 3.4.0 is available; Windows acceptance remains blocked before VM state retrieval by host CIM access. No registry, CAB, DISM, VM, checkpoint or Defender state changed. No legacy outcome closed; estimates unchanged at 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/b06-client-component-help-version-reconciliation-2026-10-28-1709.json).

## Current review-marker coverage, B06 result reporting and NTCore source review, 2026-10-28 17:03 UTC

The current 447-operation catalog has 49 `PendingAcceptance` package operations, and each has an exact ID/version review record in the 86-record local store; all ten Sysinternals package versions remain `Reviewed`. Owner/version markers do not gate technical planning or installation. The user’s prior RIDE v2 license-specialist approval still settles Sysinternals direct download-and-install; Defender exclusions remain separate. B06 now reports whether Group Policy `LocalSourcePath` was inspected through preview and transition results and repeats the guard on restore. PowerShell parser and focused diff checks passed. Repository validation passed for 447 operations, 8 groups, 5 profiles and 301 PowerShell files, with operation documentation current; Pester assertions and native acceptance remain open. Current NTCore source review confirms the selected versions for Filter Monitor, Vista4Experts and AntiMida; archive bytes and hashes remain unavailable, with technical compatibility and Windows acceptance open and no license exclusion. No registry, package, VM, checkpoint or Defender state changed. No legacy outcome closed; estimates remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12, exact 126-180, rounded 125-180/about 155. See [license review audit](../archive/evidence/migration-review-store-coverage-recheck-2026-10-28-1703.json), [B06 evidence](../archive/evidence/b06-openssh-local-source-fallback-result-reporting-2026-10-28-1703.json), and [NTCore source evidence](../archive/evidence/ntcore-filter-vista-antimida-current-page-recheck-2026-10-28-1703.json).

## B06 Group Policy fallback guard and Sysinternals disposition reaffirmed, 2026-10-28 16:55 UTC

OpenSSH Client LocalSource now reads the target's Group Policy `LocalSourcePath` before CAB metadata, snapshot or servicing; a configured fallback or inspection error fails closed. The inspection result is stored, and restore repeats the guard. PowerShell parser and focused diff checks passed; Pester assertions and Windows acceptance remain open. No registry, CAB, DISM, VM, checkpoint or Defender state was accessed or changed. The user reaffirmed that the prior RIDE v2 license-specialist approval covers direct download-and-install and that redistribution analysis is not a Sysinternals migration gate; Defender exclusions remain separate. Resolved: the source-policy guard and current license disposition. Retired/excluded: none. Deferred: B06 source completeness, dependencies, exact payload recovery, full network isolation and native acceptance; Telnet LocalSource remains unimplemented. No legacy outcome closed; estimates remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12, exact 126-180, rounded 125-180/about 155. See [structured evidence](../archive/evidence/b06-openssh-local-source-gpo-fallback-guard-2026-10-28-1655.json).

## Current Sysinternals license-store alignment and acceptance access, 2026-10-28 16:37 UTC

The current catalog matches all 10 exact Sysinternals package versions to `Reviewed` local store entries. The user’s prior RIDE v2 approval for direct download/install remains controlling; no additional legal review or migration gate applies. Fresh RIDE-Win11-Test `Get-VM` failed before inspection at CIM, and only Pester 3.4.0 is discoverable. No guest/test or Windows/Defender state changed. No technical legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/sysinternals-current-license-catalog-alignment-and-vm-pester-access-2026-10-28-1637.json).

## Final WinHTTP source-reconciliation validation, 2026-10-28 16:34 UTC

The Windows PowerShell 5.1 parser check passed for the lifecycle module and `tools/validate.ps1 -Root .` passed after all source and ledger updates for 447 operations, 8 groups, 5 profiles and 301 PowerShell files, with generated operation documentation current. No native WinHTTP command ran; host `show advproxy` is unavailable and VM access remains CIM-blocked. No legacy outcome closed and estimates remain unchanged. See [validation evidence](../archive/evidence/winhttp-repository-validation-after-source-reconciliation-2026-10-28-1634.json).

## WinHTTP advanced-proxy command contract and implementation reconciliation, 2026-10-28 16:30 UTC

Microsoft documents the guarded candidate’s `set advproxy settings-file` command form and machine/user scopes. The source implementation is integrated with catalog/engine lifecycle, but the local build 26300 reports `show advproxy` unavailable and no native command has run. The latest RIDE-Win11-Test preflight failed before VM/checkpoint inspection at CIM. Keep target support disabled pending native command/readback, exact recovery and policy/consumer evidence. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/winhttp-advanced-proxy-source-implementation-reconciliation-2026-10-28-1630.json) and [Microsoft reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-winhttp).

## Zimmerman current publisher-index version reconciliation, 2026-10-28 16:27 UTC

The official publisher index still matches all 26 selected versions in the existing .NET 10 source map and recommends `.NET 10`. This is page/version evidence only: exact ZIP payloads, hashes/signatures, notices/member inventories, package lifecycle and Windows acceptance remain open. The artifact host was not retried after its earlier DNS failure. No utility ran, no legacy outcome closed, and all five estimates remain unchanged. See [structured evidence](../archive/evidence/zimmerman-current-publisher-version-recheck-2026-10-28-1627.json) and [publisher index](https://ericzimmerman.github.io/).

## B06 RIDE-Win11-Test access preflight, 2026-10-28 16:25 UTC

Fresh read-only VM preflight failed before inspection because host CIM access is unavailable; no checkpoint or guest was inspected or dispatched. No VM, Windows or Defender state changed. B06 code/parser/helper progress is recorded in the [implementation evidence](../archive/evidence/b06-openssh-local-source-reparse-path-guard-2026-10-28-1624.json). Pester assertions and native Windows acceptance remain open. No legacy outcome closed; all estimate ranges unchanged. See [VM blocker evidence](../archive/evidence/b06-openssh-local-source-current-vm-access-block-2026-10-28-1625.json).

## B06 OpenSSH Client LocalSource reparse-path guard, 2026-10-28 16:24 UTC

LocalSource validation now rejects reparse points in any path component from the drive root to the selected folder, in addition to rejecting mapped network drives. The module and test file parse in Windows PowerShell 5.1; the direct helper passed for the repository path; `git diff --check` passed. Pester assertions remain unverified because Pester import is blocked. No junction was created and no VM, Windows or Defender state changed. Network isolation, Group Policy source fallback, exact recovery semantics and Windows acceptance remain open. No legacy outcome closed; all five estimate ranges are unchanged. See [structured evidence](../archive/evidence/b06-openssh-local-source-reparse-path-guard-2026-10-28-1624.json).

## B06 OpenSSH Client LocalSource mapped-drive guard, 2026-10-28 16:21 UTC

The current lifecycle candidate rejects mapped network drives before CAB metadata inspection, state capture or servicing. Parser checks passed for the module and focused test file; Pester assertions remain unverified because Windows PowerShell Pester import is blocked by AuthorizationManager. Fresh RIDE-Win11-Test preflight failed before VM/checkpoint inspection. No VM, Windows or Defender state changed. PasswordScan remains excluded. No legacy outcome closed; estimate ranges remain unchanged. DISM configured-source fallback, network isolation beyond the mapped-drive guard, payload/dependency recovery and Windows acceptance remain open. See [structured evidence](../archive/evidence/b06-openssh-local-source-mapped-drive-guard-and-vm-block-2026-10-28-1621.json).

## PSScriptTools full inert 360-member local lifecycle regression, 2026-10-28 15:43 UTC

The complete current-source `PSScriptToolsPackage.Tests.ps1` suite printed a Pester 5.7.1/PowerShell 7.6.5 summary of 7 passed, 0 failed and 0 skipped after 652.06 seconds. It includes the full 360-member inert fixture and six compact boundary cases. The wrapper process exit code was 1 because its post-run result check omitted supported Pester `-PassThru`; record that separately from the emitted 7/7 assertion summary. No upstream code, VM, Defender or Windows state changed. Local full lifecycle regression is resolved; PSScriptTools runtime/feature behavior and Windows package acceptance remain deferred. The read-only VM query fails in both PowerShell editions before state retrieval. No legacy outcome closed; all five estimates remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/psscripttools-inert-360-member-full-local-regression-2026-10-28-1543.json).

## NTCore Vista4Experts and AntiMida source/acquisition recheck, 2026-10-28 15:24 UTC

Current official pages were rechecked. Vista4Experts is still listed as 1.2.0.1 and changes Vista security/settings including UAC, Defender scanning and updates; the publisher claims reversibility but supplies no per-setting mapping. AntiMida is described as a research utility using a user-mode injected DLL and companion driver for process-memory operations and file/registry monitoring; the article warns its methods are obsolete and PAE is unsupported. Both remain selected by the full NTCore collection decision, with no license gate. The official ZIP links were identified, but the web reader cannot retrieve application/zip, and direct publisher requests failed DNS before response. No archive bytes, digest or member inventory were obtained; no utility/driver ran. Resolved: current page claims. Retired/excluded: none. Deferred: exact archive acquisition, hash/member review, candidate pinning and Windows acceptance. Partial: both products remain selected but unpinned. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [evidence](../archive/evidence/ntcore-vista4experts-antimida-current-source-and-acquisition-block-2026-10-28-1524.json).

## Package dependency/evidence regression and PSScriptTools partial acceptance, 2026-10-28 15:15 UTC

PackageDependencyPlanning.Tests.ps1 passed 11/11. PackageAdoptionReview.Tests.ps1 and PackageEvidence.Tests.ps1 passed 54/54 in PowerShell 7.6.5/Pester 5.7.1 with TestRegistry and TestResult disabled. The package evidence fixture now sets ProgramFiles to a per-test synthetic directory and restores the prior process value; this fixed two environment-dependent test failures caused by this session having no ProgramFiles value. Six focused PSScriptTools metadata, collision and recovery cases passed. Its 360-file repeat/install/uninstall/snapshot-recovery case did not return a result after the 180-second child timeout and a separate 300-second orchestration wait, so leave the full case deferred. No installer or upstream code ran; no VM, Defender or Windows state changed. Repository validation passed for 446 operations, 8 groups, 5 profiles and 301 PowerShell files. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/package-planning-evidence-and-psscripttools-partial-regression-2026-10-28-1515.json).

## NirSoft current catalog blocked-member selection audit, 2026-10-28 14:59 UTC

PowerShell 7.6.5 read the current catalog through the RIDE data-only reader and compared PortableMembers with frozen JSON inventory metadata after applying the documented blocked-name filters. package.nirsoft-launcher matched 647/647 expected members; package.nirsoft-x64-tools matched 47/47. Neither selection contains a blocked basename, and both have zero supported targets and remain PendingAcceptance. No archive, executable payload, temporary stage or Defender state was accessed. This verifies catalog selection only; it does not identify the repeated alert creating run or prove encrypted tar.exe extraction. Keep both architectures excluded and defer retained archive lifecycle pending provenance. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/nirsoft-current-catalog-blocked-member-selection-audit-2026-10-28-1459.json).

## Repository validation and PSScriptTools regression deferral, 2026-10-28 14:57 UTC

`tools/validate.ps1 -Root .` passed in PowerShell 7.6.5: 446 operations, 8 groups, 5 profiles and 301 PowerShell files; generated operation documentation is current. The next `PSScriptToolsPackage.Tests.ps1` attempt did not reach assertions. Windows PowerShell 5.1.26100.9711 discovers Pester 5.7.1 but import fails while loading its format files with `AuthorizationManager check failed`; PowerShell 7.6.5 has no discoverable Pester. No policy bypass was attempted. Defer this local regression until Pester can be loaded normally. No installer, utility, VM or Windows/Defender state changed and no legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/repository-validation-and-psscripttools-pester-import-block-2026-10-28-1457.json).

## NirSoft PasswordScan Defender block, 2026-10-28 14:54 UTC

The user reports another Defender block for x64 `NirSoft/x64/passwordscan.exe` at the same filtered-Pester temporary-stage path, now at 14:54 UTC. No detection name, Defender event time or creating-run identity was supplied. Keep both PasswordScan architectures excluded from selection and acceptance; defer retained NirLauncher lifecycle pending temporary-stage provenance and catalog-revision reconciliation. The reported file, its contents and hash, Defender state, VM and Windows state were not accessed or changed. This does not block unrelated migration batches. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1454.json).

## B06 current-source component regression, 2026-10-28 14:51 UTC

`ComponentInventory.Tests.ps1`, `ClientComponentPreparation.Tests.ps1` and
`ClientComponentLifecycle.Tests.ps1` passed 70/70 in Windows PowerShell
5.1.26100.9711/Pester 5.7.1 with TestRegistry/TestResult disabled and
workspace-local TEMP/TMP. Provider, DISM and servicing behavior was mocked;
no component or Windows/Defender/VM state changed. The same-source native
acceptance remains open because the pre-registered Windows 11 task failed
before guest dispatch when host WinRM was not running. No legacy outcome
closed; all five estimates remain unchanged. See [structured evidence](../archive/evidence/b06-client-components-current-winps51-regression-and-winrm-block-2026-10-28-1451.json).

## SettingsRemainingBatch1 pre-registered task attempt, 2026-10-28 14:48 UTC

The authorized `SettingsRemainingBatch1` request was accepted by the existing
RIDEWin11Test task, using the configured disposable `RIDE-Win11-Test`, local
source and `RIDE-clean-test-base` checkpoint. Preflight found the registered
account/source matched, pending/running queues empty and no recovery block. The
controller failed before source snapshot or guest dispatch because host WinRM
must already be running; no service was started and no UAC prompt appeared.
The final result and post-run queue/recovery checks confirm no VM start,
checkpoint action or Windows setting change. Defer host WinRM startup and rerun
to the later elevated session. No legacy outcome closed; estimates remain
settings 37-57, packages 37-52, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured
evidence](../archive/evidence/ride-win11-settings-remaining-batch1-preregistered-winrm-block-2026-10-28-1448.json).

## NTCore retained-package and candidate regression, 2026-10-28 14:41 UTC

`tests/NtcorePackages.Tests.ps1` passed 20/20 in Windows PowerShell
5.1.26100.9711/Pester 5.7.1 with TestRegistry and TestResult disabled and a
workspace-local temp root. Retained-file lifecycle and pending VirtualReg
Manager, ScreenWriter and WIM Installer candidate checks passed; the retained
ScreenWriter MSI digest matched its review/catalog pin. No utility or Windows
Installer ran and no VM, Windows, registry, Defender or elevation state
changed. Native acceptance remains pending; no legacy outcome closed and all
five estimates are unchanged. See [structured evidence](../archive/evidence/ntcore-packages-winps51-pester-retained-candidate-regression-2026-10-28-1441.json).

## Remaining settings regression rerun, 2026-10-28 14:30 UTC

`tests/RemainingSettings.Tests.ps1` passed 77/77 in Windows PowerShell
5.1.26100.9711/Pester 5.7.1 with TestRegistry disabled and process-scoped
workspace-local TEMP/TMP. Its initial default-temp attempt had 41 passes and 36
failures because the test isolation path denied atomic manifest moves; the
workspace-local rerun passed. The regression used mocks and TestDrive state and
changed no Windows, registry, VM or Defender state. No legacy outcome closed.
See [regression evidence](../archive/evidence/remaining-settings-winps51-pester-workspace-temp-regression-2026-10-28-1430.json).

## NirSoft PasswordScan Defender repeat alert, 2026-10-28 14:31 UTC

The user reported another Defender block for x64
`NirSoft/x64/passwordscan.exe` in the filtered-Pester temporary stage, at the
same path recorded at 13:58 UTC. No detection name, event time or creating run
was supplied. Both PasswordScan architectures remain excluded; retained
NirLauncher archive lifecycle remains deferred pending stage provenance and
catalog-revision reconciliation. The file and Defender state were not accessed
or changed. No legacy outcome closed. Estimates remain settings 37-57,
packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact
126-180; rounded 125-180/about 155). See [alert evidence](../archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1431.json).

## Migration source, validation and acceptance reconciliation, 2026-10-28 12:04 UTC

The retained Wireshark 4.6.9 MSI still matches its catalog pin and the publisher checksum; its exact bytes had prior Valid Authenticode evidence. PGP verification of the checksum file remains open because no verifier is installed, while Windows lifecycle acceptance remains VM-blocked. See [Wireshark evidence](../archive/evidence/wireshark-retained-msi-hash-recheck-and-pgp-tool-availability-2026-10-28-1204.json).

Repository validation passed for 441 operations, 8 groups, 5 profiles and 299
PowerShell files; generated operation documentation is current. VM and
scheduled-task API access still fails before inspection at host CIM. The
read-only `schtasks /Query` for `\RIDE\RIDE-Win11-Test` returns “The network
address is invalid,” so no runner action was inspected or dispatched. Only
Pester 3.4.0 is available. Keep all Windows acceptance and checkpoint/task
dispatch deferred. See [access and validation evidence](../archive/evidence/migration-static-validation-and-task-cli-block-2026-10-28-1200.json).

The JoeWare UserDump acquisition retry failed before publisher form submission
because local DNS could not resolve `www.joeware.net`. The isolated destination
was empty and removed. No archive identity was established; keep catalog
admission open pending exact ZIP/member review and archive SHA-256. This is an
upstream source/identity blocker, not a license gate. See [retry evidence](../archive/evidence/joeware-userdump-acquisition-dns-retry-2026-10-28-1154.json).

The user reported another Defender block alert for the same temporary x64
PasswordScan test-stage path recorded earlier. The detection name, event time,
current path state and creating run remain unknown. Keep both architectures
excluded and the actual encrypted NirLauncher archive lifecycle deferred until
stage provenance and the creating catalog revision are understood. The report
does not change a migration outcome or estimate. See [repeat alert evidence](../archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-1149.json).

JoeWare's current UserDump product page and publisher `versions.txt` agree on
1.01.00, but its version history says 2.02.00 for the same date. The publisher confirms that an email address is not required. `tools/Download-JoeWareCollection.ps1 -Product
UserDump` failed before form submission because the host could not resolve the
JoeWare versions-list host. No archive was downloaded. Keep catalog admission
open until the exact publisher ZIP is retained, its member identity is reviewed,
and archive SHA-256 is recorded; this is an artifact/version blocker, not a
license gate. See [source/acquisition evidence](../archive/evidence/joeware-userdump-current-source-and-acquisition-recheck-2026-10-28-1142.json).

MiTeC Mail/History has already passed Windows 11 package file lifecycle and
recovery 4/4 on `RIDE-Win11-Test` (2026-10-25); current host-CIM denial prevents
fresh VM inspection only. The 2026-10-28 central-directory review matched pinned
inventories and all 28 selected member paths without opening payloads. Functional
and activation behavior remain separate/deferred. Pester 5 is not available in
the current shell (3.4.0 only). No legacy outcome closed; estimates remain
settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and
maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [MiTeC scope
reconciliation](../archive/evidence/mitec-mail-history-acceptance-scope-reconciliation-2026-10-28-1136.json)
and [catalog-selection evidence](../archive/evidence/mitec-mail-history-central-directory-catalog-selection-recheck-2026-10-28-1134.json).

The repository static validator passed at 11:45 UTC for 441 operations, 8 groups, 5 profiles and 299 PowerShell files, with generated docs current. It does not substitute for Pester 5 or native acceptance; the current shell has Pester 3.4.0 only and VM inspection remains host-CIM-blocked. See [validation evidence](../archive/evidence/repository-validation-and-active-migration-blockers-2026-10-28-1145.json).

Next available UserDump step: once JoeWare DNS resolves, retry the reviewed
acquisition tool into a new isolated directory, then verify the ZIP's exact
members and SHA-256 before catalog admission. Keep PasswordScan excluded and
do not retry the retained NirLauncher lifecycle while its stage provenance is
unresolved.

## NirSoft PasswordScan Defender alert, 2026-10-28 11:09 UTC

The user reports a Defender block for x64 `passwordscan.exe` at the same filtered temporary-stage path and GUID reported previously. The detection name, event time and creating-run provenance were not supplied. A metadata-only check found the path absent; no contents/hash or Defender state were accessed. Keep both architectures excluded and defer retained NirLauncher archive lifecycle pending temporary-stage provenance and catalog-revision identity. No legacy outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-1109.json), [prior alert](../archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-1048.json) and [incomplete retry evidence](../archive/evidence/nirsoft-defender-filtered-retry-incomplete-2026-10-27-1835.json).

## Current migration repository validation and VM access recheck, 2026-10-28 11:20 UTC

`tools/validate.ps1 -Root .` passed on PowerShell 7.6.5 with 441 operations,
8 groups, 5 profiles and 299 PowerShell files; generated operation documentation
is current. Pester 5 is unavailable in this shell (only Pester 3.4.0 is
discoverable), so no Pester suite was run. A fresh read-only
`Get-VM -Name RIDE-Win11-Test` failed at host CIM before VM/checkpoint inspection;
no acceptance was dispatched and no elevation or state change occurred. The
previously accepted Sysinternals Windows 11 package lifecycle remains valid. No
new legacy outcome closed in this validation run; estimates remain settings
37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance
8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence]
(../archive/evidence/migration-validation-and-vm-access-recheck-2026-10-28-1120.json),
[Sysinternals scope reconciliation](../archive/evidence/sysinternals-windows11-package-migration-scope-reconciliation-2026-10-28-1114.json)
and [latest VM access evidence](../archive/evidence/sysinternals-migration-vm-cim-recheck-2026-10-28-1117.json).

## CCleaner family current official versions and license-review notes, 2026-10-28 10:46 UTC

Official version pages identify CCleaner 7.13.1573 (2026-10-21), Recuva 1.55.133 (2026-06-22) and Speccy 1.34.84 (2026-06-22); the CCleaner portable ZIP is separately pinned by its release history at 6.41.11567. The CCleaner builds page still labels 7.12.1526 and calls its advanced builds not for distribution or mirroring. Recuva and Speccy say their Free and Professional products are for home use only. Carry these publisher notices into local, exact-version license-review markers when candidates are added; they are informational review items, not migration gates under the user direction. No exact candidates or review-store entries are created until artifacts are acquired and pinned. DNS to the CCleaner payload hosts is denied and Recuva/Speccy download buttons expose JavaScript-only pages; no binaries, hashes or signatures are available. Defraggler's current exact version/source remains unresolved. No package or Windows state changed; no legacy outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/ccleaner-family-current-official-source-and-artifact-acquisition-recheck-2026-10-28-1046.json), [CCleaner history](https://www.ccleaner.com/ccleaner/version-history/), [Recuva download](https://www.ccleaner.com/recuva/download) and [Speccy download](https://www.ccleaner.com/speccy/download).
## CCleaner current official versions and artifact acquisition recheck, 2026-10-28 10:45 UTC

The official homepage reports CCleaner v7.13; the official version history identifies 7.13.1573 dated 2026-10-21 and portable 6.41.11567 dated 2026-06-23. The official builds page still labels v7.12.1526, while exposing generic full-installer and direct portable-ZIP routes; it also says those advanced builds are not for distribution or mirroring. RIDE remains a direct download-and-install tool; preserve that publisher wording as an informational local license-review note when exact candidates are cataloged, not a technical migration gate. DNS for both official payload hosts was denied before HTTP, and the web reader cannot return binary payloads. No bytes, hashes or signatures were verified; no candidate was cataloged. No Defender, Windows or VM state changed. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/ccleaner-current-official-version-source-and-artifact-acquisition-dns-block-2026-10-28-1045.json), [official version history](https://www.ccleaner.com/ccleaner/version-history/) and [official builds page](https://www.ccleaner.com/ccleaner/builds).
## PSScriptTools ThreadJob dependency removal guard, 2026-10-28 10:44 UTC

A direct in-module plan probe confirms an Install plan orders ThreadJob before PSScriptTools with the 2.2.0 minimum. A second read-only probe stubbed only the dependent package's installed state in memory; planning ThreadJob removal then refused with the expected PSScriptTools dependent-package guard. No registry, installer, package, VM, Defender or Windows state was queried or changed. These probes do not replace the unavailable Pester 5 regression or the attested disposable-VM runtime and lifecycle acceptance. No legacy package outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/psscripttools-threadjob-dependency-plan-and-removal-guard-probe-2026-10-28-1044.json).
## PSScriptTools ThreadJob 2.2.0 current-source and real-archive handler lifecycle, 2026-10-28 10:41 UTC

The PowerShell Gallery still lists Microsoft.PowerShell.ThreadJob 2.2.0 as its current version. The retained official `.nupkg` is 49,678 bytes and matches the catalog SHA-256; its nuspec and module manifest both report 2.2.0, with ten package files, a `.signature.p7s` entry, `LICENSE` and `ThirdPartyNotices.txt`. The signature entry was not cryptographically verified. RIDE's portable handler passed install, repeat, exact 10-file health, uninstall, installed-snapshot restore, prior-absence restore and operator-sentinel preservation from isolated workspace scratch, which was cleaned. The module was not imported or invoked, its DLL was not loaded, and no installer, VM, Defender or Windows state changed. Pester 5 regression, cryptographic signature verification, engine dispatch, dependency-removal guard, runtime use and Windows target acceptance remain open. No legacy package outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/psscripttools-threadjob-2.2.0-current-source-and-handler-lifecycle-2026-10-28-1041.json).
## PSScriptTools current-catalog prerequisite plan, 2026-10-28 10:38 UTC

A read-only `Get-RideSingleOperationPlan` for `package.psscripttools` expands `package.microsoft-powershell-threadjob` first, with the declared `Microsoft.PowerShell.ThreadJob` version 2.2.0 minimum and the resolved portable tools directory; `package.psscripttools` follows at its own portable directory. No handler, package, installer or network source was invoked. This confirms current-catalog plan expansion only; Pester regression, managed installation/removal/recovery, actual module health/version, dependent-removal guard and Windows acceptance remain open. No legacy package outcome closed; estimates remain unchanged. See [structured evidence](../archive/evidence/psscripttools-current-catalog-prerequisite-plan-readonly-2026-10-28-1038.json).
## Current migration repository validation and package-test/VM access recheck, 2026-10-28 10:36 UTC

The retained Wireshark 4.6.9 MSI still matches its catalog pin and the publisher checksum; its exact bytes had prior Valid Authenticode evidence. PGP verification of the checksum file remains open because no verifier is installed, while Windows lifecycle acceptance remains VM-blocked. See [Wireshark evidence](../archive/evidence/wireshark-retained-msi-hash-recheck-and-pgp-tool-availability-2026-10-28-1204.json).

Repository validation passed for 441 operations, 8 groups, 5 profiles and 299 PowerShell files; generated operation documentation is current. The focused `ApplicationPackages.Tests.ps1` suite was not run because the current Windows PowerShell 5.1 and PowerShell 7.6.5 environments expose Pester 3.4.0 only, with no Pester 5 module found in the configured module roots or targeted workspace test-module paths. Fresh read-only `Get-VM` and `Get-ScheduledTask` queries remain denied at host CIM before VM/checkpoint inspection or task enumeration. No test, package, utility, VM, Defender or Windows state changed and no elevation was requested. No legacy outcome closed; estimates remain unchanged at settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/current-migration-repository-validation-pester-vm-access-2026-10-28-1036.json).
## NirSoft PasswordScan Defender repeat alert, 2026-10-28 10:32 UTC

A new user-reported Defender block names the same x64 PasswordScan temporary-stage path. The detection name, event time and creating-run provenance were not supplied. A fresh metadata-only existence check found the path absent; no contents/hash or Defender state was accessed. Keep both architectures excluded and defer retained NirLauncher archive lifecycle pending stage provenance. No legacy outcome closed; estimates remain unchanged. See [structured evidence](../archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-1032.json).
## WinPmem focused runner regression and host access recheck, 2026-10-28 10:30 UTC

WinPmem selector and inert-payload cases passed 2/2; the mocked fixed-controller
dispatch matrix passed 10/10 including WinPmem. Windows PowerShell 5.1.26100.9711
and Pester 5.7.1 were used with TestRegistry/TestResult disabled. The initial
attempt failed at sandbox temp rename before assertions; a process-local
workspace TEMP/TMP rerun passed and cleaned its scratch. No executable/driver,
VM, checkpoint or Defender state was touched. Fresh Get-VM and scheduled-task
queries were denied at host CIM before inspection. Publisher bytes, protected
controller refresh and the guest file-only lifecycle remain open. No legacy
outcome closed; estimates unchanged at settings 37-57, packages 38-53,
components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded
125-180/about 155). See [structured evidence](../archive/evidence/winpmem-runner-current-source-regression-and-vm-cim-block-2026-10-28-1030.json).
## Phoenix current-source package regression, 2026-10-28 10:25 UTC

PhoenixPackage.Tests.ps1 passed 4/4 in Windows PowerShell 5.1.26100.9711/Pester
5.7.1 with registry/result plugins disabled. It tests metadata, machine scope,
prerequisite boundaries and mocked MSI dispatch; no MSI or .NET feature ran. The
Phoenix page/MSI/embedded executable versions remain 1.8.0.1/1.7.1/1.9.0.1 with
no publisher mapping. NeedsReview/Unassigned is informational. VM acceptance remains
blocked at host CIM before inspection. No legacy outcome closed; estimates
unchanged. See [regression evidence](../archive/evidence/phoenix-current-source-package-regression-2026-10-28-1025.json)
and [version evidence](../archive/evidence/ntcore-phoenix-explorer-current-version-source-recheck-2026-10-28-1021.json).
## NTCore Phoenix/Explorer Suite current version/source recheck, 2026-10-28 10:21 UTC

Current official NTCore pages still report Phoenix Protector 1.8.0.1 and Explorer
Suite III (18/11/2012). The retained full-suite installer hash matches the current
publisher hash; its internal label remains IV. The standalone x86 CFF Explorer
hash matches the publisher page and catalog pin 8.0.0.0. Phoenix's retained MSI
hash matches its catalog pin 1.7.1, but the page has no mapping to MSI ProductVersion
1.7.1 or contained executable 1.9.0.1. Phoenix/current bytes were not downloaded.
Exact-version local NeedsReview/Unassigned markers are present for Phoenix and CFF;
these markers are informational, not migration gates. No installer, utility, VM,
Defender or Windows state changed. No legacy outcome closed; estimates unchanged
at settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
evidence](../archive/evidence/ntcore-phoenix-explorer-current-version-source-recheck-2026-10-28-1021.json).
## Wireshark focused package regression and VM access recheck, 2026-10-28 10:17 UTC

WiresharkPackage.Tests.ps1 passed 8/8 in Windows PowerShell
5.1.26100.9711/Pester 5.7.1 with TestRegistry and TestResult disabled. The suite
used catalog metadata, inert MSI bytes and mocked installer calls. The first
Pester invocation was blocked during HKCU plugin setup; the bundled PowerShell 7
runtime has no Pester 5. Fresh read-only Get-VM failed at host CIM before either
target or checkpoint inspection. No installer or Windows state changed.
Wireshark's Windows lifecycle, existing-install transitions and publisher PGP
verification remain open. No legacy outcome closed; estimates unchanged at
settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
evidence](../archive/evidence/wireshark-package-focused-regression-and-vm-cim-block-2026-10-28-1017.json).
## NirSoft PasswordScan Defender repeat alert, 2026-10-28 10:12 UTC

The user reported another Defender block for x64 NirSoft/x64/passwordscan.exe
in the same filtered temporary Pester stage. The alert did not include a
classification or event time. A metadata-only existence check found the
reported path absent; no contents/hash or Defender state were accessed. Keep
both PasswordScan architecture paths excluded and defer the retained NirLauncher
archive lifecycle until stage provenance and the creating catalog revision are
understood. No VM or Windows state changed and no legacy outcome closed.
Estimates remain settings 37-57, packages 38-53, components 19-24,
files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about
155). See [structured evidence](../archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-1012.json).
## WinPmem inert single-file handler lifecycle, 2026-10-28 10:10 UTC

The real RIDE portable handler passed a direct local lifecycle with inert text
bytes under the exact WinPmem file name: install, repeat, exact owned-file
verification, remove, capture and restore the installed snapshot, remove again,
and restore original absence. An operator-owned sentinel outside the product
directory survived. The payload was never launched, and the handler used its
explicit Offline mode so Authenticode was not inspected. A unique workspace-local
scratch directory was cleaned. This is implementation-level handler evidence;
it does not verify publisher bytes/signature, engine routing or Windows behavior.
No VM, Defender, driver or Windows state changed. No legacy outcome closed;
estimates remain settings 37-57, packages 38-53, components 19-24,
files/assets 25-35, maintenance 8-12 (exact 127-181; rounded
125-180/about 155). See [structured evidence](../archive/evidence/winpmem-inert-single-file-handler-lifecycle-2026-10-28-1010.json)
and [prepared guest runner](../archive/evidence/winpmem-focused-file-acceptance-runner-preparation-2026-10-28-1008.json).
## WinPmem focused file-lifecycle VM runner preparation, 2026-10-28 10:08 UTC

Added the exact `WinPmem` single-file lifecycle selection to the local case
resolver, host/guest runners and fixed controller request path. It is limited to
`package.winpmem` and the catalog-pinned executable; archive selection behavior
is unchanged. The guest route uses the portable file handler for install,
repeat, removal and saved-state recovery only. It does not execute WinPmem or
load/unload its driver. Manual inert-payload checks and parsing for all 7 changed
PowerShell files passed. Full repository validation passed for 441 operations,
8 groups, 5 profiles and 299 PowerShell files; operation docs remain current.
Pester 5 was unavailable (only Pester 3.4.0 installed), so new Pester cases did
not run.

No local publisher binary exists. The installed protected controller must be
refreshed once under elevation before this batch can be queued. A fresh read-only
Get-VM recheck failed at CIM before inspecting either Windows 11 or Server 2025;
no checkpoint was inspected or changed. No driver/tool ran, and no Windows or
Defender state changed. WinPmem remains unsupported with local bytes,
Authenticode and VM lifecycle acceptance open. No legacy outcome closed;
estimates remain settings 37-57, packages 38-53, components 19-24, files/assets
25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See
[structured evidence](../archive/evidence/winpmem-focused-file-acceptance-runner-preparation-2026-10-28-1008.json),
[runbook](../../tests/integration/README.md), and
[expanded asset source evidence](../archive/evidence/winpmem-expanded-release-asset-source-recheck-2026-10-28-1000.json).
## WinPmem expanded release asset source recheck, 2026-10-28 10:00 UTC

The official [expanded GitHub release-assets page](https://github.com/Velocidex/WinPmem/releases/expanded_assets/v4.1.dev1) lists the production-designated go-winpmem_amd64_1.0-rc2_signed.exe, uploaded 2025-09-03 at 05:58:51 UTC, displayed as 5.01 MB, with SHA-256 86691bb4af2c17dd9ec4834c04a99ad51e04f780a07d1b05bc382a5d1892e0c4. This matches the catalog pin and refreshes publisher metadata. Direct asset fetch followed an expired signed URL; local bytes and Authenticode remain unverified. No executable, driver or Windows state changed. WinPmem remains unsupported pending Windows 11/Server 2025 owned-file lifecycle and recovery; driver load/unload and memory capture remain separate explicit acceptance. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/winpmem-expanded-release-asset-source-recheck-2026-10-28-1000.json).

## Current migration repository validation and status, 2026-10-28 09:57 UTC

`tools/validate.ps1 -Root .` passed for 441 operations, 8 groups, 5 profiles
and 299 PowerShell files. `tools/Export-RideCatalog.ps1 -Check` confirmed the
generated operation documentation is current. This was repository/catalog
validation only: no Pester tests, VM/checkpoint query, Defender or Windows
state change, blocked-file access or utility execution occurred.

The user's new PasswordScan report matches the x64 temporary path already
recorded at 09:39 UTC. Both PasswordScan architectures remain excluded, and
the retained NirLauncher archive lifecycle remains deferred until the staging
run is identified. Sysinternals Suite Windows 11 package install/remove and
recovery already passed 1/1; the prior RIDE v2 license-specialist approval
settles RIDE's direct-download-and-install use, so licensing is not a gate.
No new legacy outcome closed. Estimates remain settings 37-57, packages
38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact
127-181; rounded 125-180/about 155). VM acceptance remains blocked at host
CIM before inspection, and the Win11 checkpoint is still unverified. See
[structured evidence](../archive/evidence/repository-migration-validation-and-status-2026-10-28-0957.json),
[PasswordScan alert](../archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-0939.json),
and [Sysinternals lifecycle evidence](../archive/evidence/sysinternals-suite-win11-current-lifecycle-acceptance-2026-10-25-0201.json).

## Wireshark retained MSI current digest/signature recheck, 2026-10-28 09:52 UTC

The exact cached x64 MSI continues to match the catalog and official checksum.
Authenticode reports Valid for Wireshark Foundation with a Microsoft timestamp
signer. No installer was executed. Windows lifecycle, existing-install and
shared-runtime acceptance remain pending; no outcome closed and estimates are
unchanged. See [evidence](../archive/evidence/wireshark-retained-msi-current-digest-signature-check-2026-10-28-0952.json).

## Wireshark 4.6.9 official checksum source recheck, 2026-10-28 09:51 UTC

The publisher's [checksum record](https://www.wireshark.org/download/SIGNATURES-4.6.9.txt)
lists the x64 MSI SHA-256 and size; the digest matches the catalog pin.
No MSI bytes were inspected and the OpenPGP signature was not validated.
Install/repeat/remove/recovery remains pending on Windows. No legacy outcome
closed; estimates are unchanged. See [evidence]
(../archive/evidence/wireshark-4.6.9-publisher-checksum-recheck-2026-10-28-0951.json).

## Wireshark stable release and MSI source recheck, 2026-10-28 09:50 UTC

The official [download page](https://www.wireshark.org/download.html)
identifies 4.6.9 as stable, and the official x64 index lists the catalog-pinned
MSI. No new bytes or signature were checked. The machine-scoped package remains
unsupported pending Windows lifecycle acceptance; VM access is unavailable.
No legacy outcome closed; estimates remain unchanged. See [evidence]
(../archive/evidence/wireshark-stable-release-current-source-recheck-2026-10-28-0950.json).

## Hyper-V Manager read-only VM visibility check, 2026-10-28 09:48 UTC

Hyper-V Manager visibly lists RIDE-Win11-Test as Off. The selected details
pane was RIDE-S25-Test; its visible RIDE-clean-test-base checkpoint does
not establish a checkpoint for the Win11 VM. The Manager reports higher
Windows integrity than the desktop helper. Selecting the Win11 row produced
no visible change, so its checkpoint and guest configuration remain unknown.
No VM or checkpoint state changed; no UAC prompt or acceptance task was
triggered. Continue independent work and defer acceptance until the Win11 target
and its existing checkpoint can be inspected. No legacy outcome closed; estimates
remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded
125-180/about 155. See [structured evidence](../archive/evidence/hyperv-manager-vm-visibility-ui-integrity-block-2026-10-28-0948.json).

## WinPmem current production-asset source recheck, 2026-10-28 09:45 UTC

The official [Velocidex release page](https://github.com/Velocidex/WinPmem/releases)
still says to use go-winpmem_amd64_1.0-rc2_signed.exe for production.
The newer 4.1 development driver is test-signed; the publisher's test flow
requires enabling test-signing mode and rebooting. The asset list did not
render in the source response, so this review refreshed no payload bytes, hash
or Authenticode evidence. No utility, driver, VM or Windows state was touched.
WinPmem remains a machine-scoped staging candidate with empty SupportedTargets.
Fresh Get-VM failed at host CIM for both targets before inspection; this execution environment also has no WinRM service or PowerShell remoting. Exact artifact verification and disposable-Windows file lifecycle remain open;
driver loading and memory capture are separate acceptance items. No legacy
outcome closed; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact
127-181, rounded 125-180/about 155. See [structured evidence](../archive/evidence/winpmem-current-production-asset-source-recheck-2026-10-28-0945.json).

## WFN Nightly actual-archive portable lifecycle, 2026-10-28 09:33 UTC

The retained pinned WFN archive passed full portable-handler file lifecycle in
PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711: install, repeat,
uninstall, recovery of installed files, and restoration of prior absence. All
531 selected files were preserved in recovery; the operator sentinel survived.
No utility ran. This does not verify the RIDE engine route or Windows runtime
acceptance; host CIM still blocks both VMs. No legacy product outcome closed
and estimates remain unchanged. See [structured evidence](../archive/evidence/wfn-actual-pinned-archive-cross-shell-lifecycle-2026-10-28-0933.json).
The official Nightlies/Unstable release still resolves to commit `ac02df2`,
matching the pinned package revision; the release assets did not render during
the source check. No new bytes or hash were obtained. See [source recheck](../archive/evidence/wfn-official-nightly-current-source-recheck-2026-10-28-0936.json).

## Gpg4win configuration key cross-check, 2026-10-28 09:11 UTC

The ten catalog `InstallerConfiguration` keys all appear as
`config_fetch_bool` values in retained Gpg4win 5.1.1 source. This resolves a
static key-name question only; behavior, the prior `0xC0000005`, and native
install/repeat/remove/recovery remain deferred. VM access still fails at host
CIM. No outcome closed or estimate changed. See [structured evidence](../archive/evidence/gpg4win-config-keys-retained-source-cross-check-2026-10-28-0911.json).

## Gpg4win current-user switch source verification, 2026-10-28 09:07 UTC

Retained Gpg4win 5.1.1 source enables NSIS MultiUser command-line mode, and
the NSIS MultiUser implementation maps `/CurrentUser` to current-user install
context. The catalog switch is supported by that configured mode. The prior
Windows 11 `0xC0000005` remains unexplained; runtime lifecycle and exact user
data recovery remain deferred pending disposable-VM access. Read-only
`Get-VM` again failed at host CIM before inspection. No outcome closed and
estimates remain unchanged. See [source evidence](../archive/evidence/gpg4win-currentuser-multiuser-source-verification-2026-10-28-0907.json)
and [VM access evidence](../archive/evidence/gpg4win-source-review-vm-access-block-2026-10-28-0909.json).

## NirSoft PasswordScan Defender repeat alert, 2026-10-28 09:04 UTC

A new user report names the same filtered NirLauncher x64 PasswordScan
`passwordscan.exe` path. Detection and event time are unknown, as is the
creating run. A metadata-only existence check found the file and parent
staging directory absent. Both PasswordScan architectures stay excluded; do
not resume retained NirLauncher archive lifecycle until staging provenance is
understood. The report closes no legacy outcome and changes no estimate. See
[structured evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0904.json).

## Phoenix Protector prerequisite gate current-source regression, 2026-10-28 09:00 UTC

`PhoenixPackage.Tests.ps1` passed 4/4 in Windows PowerShell 5.1.26100.9711
and 4/4 in PowerShell 7.6.5/Pester 5.7.1. The absent-.NET Framework 3.5
path refuses before artifact acquisition/MSI invocation; the present path
uses a mocked MSI call. No DISM, feature query, installer, elevation or Windows
state change occurred. The previous Windows 11 MSI failure remains deferred
until the prerequisite is available on a disposable target; host CIM still
blocks VM inspection. The NeedsReview marker is informational, not a gate. No
legacy outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/phoenix-prerequisite-gate-current-source-cross-shell-2026-10-28-0900.json).

## Gpg4win current-source mocked regression, 2026-10-28 08:57 UTC

`Gpg4winPackage.Tests.ps1` passed 12/12 in Windows PowerShell 5.1.26100.9711
and 12/12 in PowerShell 7.6.5/Pester 5.7.1, with TestRegistry/TestResult
disabled. The tests cover the accepted current-user component selection,
temporary vendor config staging, nested registration conflicts, process guards,
and mocked GnuPG data recovery. No installer or real registry/user data was
accessed. An initial default-temp PowerShell 7 attempt hit protected app
container write failures; both final runs passed with unique workspace-local
temporary roots, which were cleaned. The earlier Windows 11 Gpg4win run still
has an unresolved `0xC0000005` failure; VM access remains blocked at host CIM.
No legacy outcome closed, and estimates remain unchanged. The NeedsReview marker
is administrative, not a migration gate. See [structured evidence](../archive/evidence/gpg4win-current-source-mocked-cross-shell-regression-2026-10-28-0857.json).

## Rufus official version and portable-asset source recheck, 2026-10-28 08:51 UTC

The official GitHub releases page and Rufus download index still list 4.15,
released 2026-06-30, including the x64 portable `rufus-4.15p.exe` variant. The
catalog version and immutable URL remain current. No new bytes were downloaded
or hashed; the earlier exact-byte digest and valid Akeo Consulting signature
remain dated evidence. RIDE-Win11-Test install/repeat/remove/recovery and a
separate application scenario remain open; no USB media was touched. No legacy
outcome closed and estimates are unchanged. See [structured evidence](../archive/evidence/rufus-latest-release-source-recheck-2026-10-28-0851.json).

## Repeated NirSoft PasswordScan Defender alert, 2026-10-28 08:46 UTC

The user reported another Defender block for the same x64 `passwordscan.exe`
temporary-stage path recorded at 07:55 UTC. A metadata-only path check found no
file there; no file content or Defender state was inspected. The detection and
creating run remain unknown. Keep both architectures excluded and defer the
retained NirLauncher archive lifecycle. No legacy outcome closed; estimates
remain unchanged. See [structured evidence](../archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-0846.json).

## WFN Nightly pinned-archive current-source regression, 2026-10-28 08:45 UTC

`WfnPackage.Tests.ps1` passed 4/4 in Windows PowerShell 5.1.26100.9711 and
4/4 in PowerShell 7.6.5/Pester 5.7.1. Three tests exercised the complete
531-member lifecycle and recovery with generated inert ZIP fixtures; the
retained publisher archive matched its catalog hash and member inventory.
The WFN executable and installer were not launched, and firewall state was
not changed. `Get-VM` remained blocked at host CIM for both targets before
inspection. Actual archive staging, runtime behavior and Windows acceptance
remain open; no legacy outcome closed and estimates are unchanged. See
[structured evidence](../archive/evidence/wfn-pinned-archive-cross-shell-synthetic-lifecycle-and-vm-block-2026-10-28-0845.json).

## Full package and portable regression with retained archives, 2026-10-28 08:23 UTC

The complete package-provider and portable-selection suites passed 179/179 in
Windows PowerShell 5.1.26100.9711 and 179/179 in PowerShell 7.6.5/Pester
5.7.1. The RawCopy, ETL2PCAPNG and AdMod archive-backed file lifecycle cases
ran against catalog-pinned retained fixtures. No utility or installer ran;
Defender-blocked collections were excluded. Fresh `Get-VM` again failed before
VM/checkpoint inspection for both acceptance targets at host CIM. No legacy
outcome closed; package Windows acceptance and all estimate ranges remain
open/unchanged. See [structured evidence](../archive/evidence/package-provider-portable-full-retained-archives-cross-shell-regression-and-vm-block-2026-10-28-0823.json).

## Pending package catalog and review-marker readiness audit, 2026-10-28 08:15 UTC

Current-catalog review found 115 package operations, including 45 pending
acceptance. Every pending package has a version, product and license URL,
download source, and SHA-256 or immutable source pin. A read-only join against
the explicitly resolved user-local review store confirmed `NeedsReview` for
45/45 exact package ID/version pairs. The store was not modified. This closes
the catalog/review readiness check only; it does not verify publisher bytes or
package lifecycle. Review markers are not a migration gate. No legacy outcome
closed; estimates are unchanged. See [structured audit evidence](../archive/evidence/pending-package-catalog-and-license-review-readiness-audit-2026-10-28-0815.json).

## Exact pending-package review-marker coverage audit, 2026-10-28 08:12 UTC

The current catalog has 45 pending package operations. A read-only join against
the explicitly resolved user-local review store confirmed an exact
`NeedsReview` marker for each package ID/version (45/45); the store has 60
records. The check exposed no owner details and changed no local data. Review
status is administrative and does not gate direct publisher download/install;
Defender exclusions remain independent. No legacy outcome closed and estimates
are unchanged. See [structured audit evidence](../archive/evidence/package-review-marker-exact-pending-coverage-audit-2026-10-28-0812.json).

## OpenSSH Client and Telnet component source guard regression, 2026-10-28 08:05 UTC

The lifecycle, preparation and component-inventory suites passed 70/70 in
Windows PowerShell 5.1.26100.9711 and 70/70 in PowerShell 7.6.5/Pester 5.7.1.
Coverage includes the OpenSSH Client local-CAB identity/hash checks and
revalidation during restore; providers were mocked and no DISM or servicing
command ran. Fresh read-only `Get-VM` failed before inspection for both
acceptance VMs at host CIM. No component acceptance task was dispatched.
OpenSSH Client/Telnet native source-matched behavior remains deferred; no
legacy outcome closed and estimates are unchanged. See [structured evidence](../archive/evidence/b06-client-component-local-source-guard-cross-shell-regression-and-vm-block-2026-10-28-0805.json).

## Package dependency planning cross-shell regression, 2026-10-28 08:03 UTC

`PackageDependencyPlanning.Tests.ps1` passed 11/11 in Windows PowerShell
5.1.26100.9711 and 11/11 in PowerShell 7.6.5/Pester 5.7.1. No cases were
skipped or left unrun; no installer, utility, Defender-blocked tool, or Windows
state was involved. This source-level regression closes no legacy outcome.
Package lifecycle remains deferred under the host-CIM blocker recorded at
08:01. Estimate ranges remain settings 37-57, packages 38-53, components
19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded
125-180/about 155). See [structured evidence](../archive/evidence/package-dependency-planning-cross-shell-regression-2026-10-28-0803.json)
and [VM evidence](../archive/evidence/package-provider-portable-full-cross-shell-regression-and-vm-block-2026-10-28-0801.json).

## Package provider and portable selection full cross-shell regression, 2026-10-28 08:01 UTC

The complete package-provider and portable-selection Pester suites passed
176/176 in Windows PowerShell 5.1.26100.9711 and 176/176 in PowerShell 7.6.5.
The same three retained-archive tests were skipped for missing explicit
fixtures; no test was filtered or left unrun. Repository validation passed for
441 operations, 8 groups, 5 profiles and 299 PowerShell files, with generated
operation documentation current. `Get-VM` again failed before inspection for
both named acceptance VMs at host CIM; no task was dispatched. Windows package
lifecycle remains deferred, no legacy outcome closed, and estimate ranges are
unchanged. See [structured evidence](../archive/evidence/package-provider-portable-full-cross-shell-regression-and-vm-block-2026-10-28-0801.json).

## NirSoft PasswordScan Defender block, 2026-10-28 07:55 UTC

The user reports a Defender block for x64 `passwordscan.exe` in the filtered
NirLauncher temporary tree. No detection name, event time, or creating-run
provenance was supplied. Keep both PasswordScan architectures excluded and
defer the retained NirLauncher archive lifecycle until staging provenance is
understood. The report adds no verified legacy outcome; estimates remain
settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0755.json).

## Focused package provider and portable selection regression, 2026-10-28 07:37 UTC

Filtered current-source Pester across `ApplicationPackages.Tests.ps1` and
`PortableAcceptanceAutomation.Tests.ps1` passed **62/62** in Windows PowerShell
5.1.26100.9711/Pester 5.7.1 and **62/62** in PowerShell 7.6.5/Pester 5.7.1.
The selected cases cover RIDE-managed PowerShell module prerequisites,
OpenJDK checksum-response parsing, AdMod publisher-form resolution, NuGet
ZIP-format selection, HashCheck candidate metadata and portable acceptance
selection boundaries. Pester discovered 179 tests and did not run 117 outside
the filter. Publisher requests and package actions were mocked or kept behind
selection boundaries; no installer or utility ran.

The retained Wireshark 4.6.9 MSI still matches its catalog pin and the publisher checksum; its exact bytes had prior Valid Authenticode evidence. PGP verification of the checksum file remains open because no verifier is installed, while Windows lifecycle acceptance remains VM-blocked. See [Wireshark evidence](../archive/evidence/wireshark-retained-msi-hash-recheck-and-pgp-tool-availability-2026-10-28-1204.json).

Repository validation passed for 441 operations, 8 groups, 5 profiles and 299
PowerShell files; generated operation documentation is current. Fresh
`Get-VM` checks for `RIDE-Win11-Test` and `RIDE-Server2025-Test` again failed
before VM/checkpoint inspection with `Access to a CIM resource was not
available to the client.` Package installation/removal, saved-state recovery
and Windows target acceptance remain deferred. No legacy outcome closed;
estimates remain settings 37-57, packages 38-53, components 19-24,
files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about
155). See [structured evidence](../archive/evidence/package-provider-and-portable-selection-focused-cross-shell-regression-2026-10-28-0737.json)
and [latest VM access evidence](../archive/evidence/client-component-current-source-cross-shell-regression-and-vm-access-2026-10-28-0731.json).

## OpenSSH Client and Telnet Client current-source regression, 2026-10-28 07:31 UTC

`ClientComponentPreparation.Tests.ps1`, `ClientComponentLifecycle.Tests.ps1`,
and `ComponentInventory.Tests.ps1` passed **70/70** in Windows PowerShell
5.1.26100.9711/Pester 5.7.1 and **70/70** in PowerShell 7.6.5/Pester 5.7.1.
TestRegistry and TestResult were disabled; servicing and inventory providers
were mocked. No DISM, Windows provider or native inventory command ran. The
inventory WhatIf preview and guarded servicing/recovery cases passed.

A fresh read-only check then failed for both `RIDE-Win11-Test` and
`RIDE-Server2025-Test` at `Get-VM` with `Access to a CIM resource was not
available to the client`, before VM/checkpoint inspection. No acceptance task
was dispatched and no machine state changed. Matching-source/no-network proof,
exact servicing payload/dependency recovery and native Windows acceptance
remain deferred. No legacy outcome closed; estimates remain settings 37-57,
packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12
(exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/client-component-current-source-cross-shell-regression-and-vm-access-2026-10-28-0731.json).

## OpenSSH Server component current-source regression, 2026-10-28 07:28 UTC

`OpenSshServerCapabilityLifecycle.Tests.ps1`,
`OpenSshServerObservation.Tests.ps1`, `OpenSshServerLifecycle.Tests.ps1`, and
`NetworkAndSoundControls.Tests.ps1` passed **48/48** in Windows PowerShell
5.1.26100.9711/Pester 5.7.1 and **48/48** in PowerShell 7.6.5/Pester 5.7.1.
TestRegistry and TestResult were disabled; native servicing, service and
firewall providers were mocked. WhatIf coverage confirms the protected
boundaries; no capability was installed or removed, sshd was not started, and
no firewall, VM, checkpoint or Windows state changed. Repository validation
passed for 441 operations, 8 groups, 5 profiles and 299 PowerShell files;
generated operation documentation is current.

This is current-source regression only. Native Windows 11 and Windows Server
2025 capability, activation, firewall, recovery and target acceptance remain
deferred; the 07:24 read-only VM recheck failed at host CIM before inspection.
No legacy outcome closed; estimates remain settings 37-57, packages 38-53,
components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181;
rounded 125-180/about 155). See [structured evidence](../archive/evidence/openssh-server-component-current-source-cross-shell-regression-2026-10-28-0728.json)
and [VM access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-28-0724.json).

## Read-only VM access recheck, 2026-10-28 07:24 UTC

Read-only `Get-VM` checks for `RIDE-Win11-Test` and
`RIDE-Server2025-Test` both failed before VM inspection with
`Access to a CIM resource was not available to the client.` No checkpoint was
inspected, no task was dispatched, no VM state changed and no elevation was
requested. Disposable Windows 11 and Windows Server 2025 acceptance remains
deferred; continue source-level and local regression work that does not require
the guests. No legacy outcome closed; estimates remain settings 37-57,
packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12
(exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-28-0724.json).

## NirSoft PasswordScan Defender block alert, 2026-10-28 07:22 UTC

The user reports a Defender block for the same x64 PasswordScan path in the
filtered NirLauncher temporary tree previously reported at 06:39 UTC. The new
report gives no detection name or Defender event time and does not identify the
process/run that created the temporary file. Both PasswordScan architectures
remain excluded; retained NirLauncher archive lifecycle remains deferred until
staging provenance is understood. The reported file and Defender state were
not inspected or changed, and no elevation was requested. No legacy outcome
closed; estimates remain settings 37-57, packages 38-53, components 19-24,
files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about
155). See [structured evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0722.json).

## Pending package review-marker coverage and license disposition, 2026-10-28 07:18 UTC

The user-local store previously had exact `NeedsReview` / `Unassigned` markers
for 17 of 45 pending package versions. I added the 28 missing exact-version
rows through the review-store import path after exporting a backup at
`%LOCALAPPDATA%/RIDE/license-reviews-before-migration-20261028-0714.json`.
The 32 existing records were preserved; the final store has 60 records, with
45/45 pending package versions covered. Pester 5.7.1 passed all 24
`LicenseReviews.Tests.ps1` cases in PowerShell 7.6.5 and Windows PowerShell
5.1.26100.9711. The tests verify that NeedsReview remains informational during
package planning. No catalog review fields were added and no license or
redistribution decision was made by these markers. Sysinternals remains settled
under the prior RIDE v2 specialist approval for RIDE's direct-download/install
workflow.

Package-specific acquisition, installation, product behavior and Windows
acceptance remain tracked separately. No legacy outcome closed; estimates
remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
evidence](../archive/evidence/package-license-review-pending-marker-coverage-2026-10-28-0718.json),
[license guidance](../package-licensing.md#pending-package-review-marker-coverage-refresh-2026-10-28-0718-utc),
and [verification matrix](../package-verification-matrix.md#pending-package-review-marker-coverage-refresh-2026-10-28-0718-utc).
## Power Options shortcut diagnostic correction and VM recheck, 2026-10-28 07:10 UTC

The shared DesktopShortcut writer reported the BitLocker wizard as unavailable
for a missing Power Options target. It now uses an accurate product-neutral
message. The focused test exercises the missing-target guard and confirms it
stops before COM creation. Pester 5.7.1 passed 8/8 on PowerShell 7.6.5 and 8/8
on Windows PowerShell 5.1.26100.9711. The initial discovery-only failure was
fixed by importing the module during Pester discovery.

Read-only `Get-VM` checks for `RIDE-Win11-Test` and `RIDE-Server2025-Test` failed
before VM/checkpoint inspection at host CIM. UI and actual shortcut lifecycle
acceptance remain deferred. No legacy outcome closed; estimates remain settings
37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12
(exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/power-options-shortcut-missing-target-diagnostic-cross-shell-and-vm-block-2026-10-28-0710.json)
and [focused test](../../tests/DesktopShortcuts.Tests.ps1).
## JoeWare AdMod retained-cache engine route and VM recheck, 2026-10-28 07:05 UTC

The focused route suite passed **2/2** in Windows PowerShell 5.1.26100.9711
and **2/2** in PowerShell 7.6.5/Pester 5.7.1. The retained publisher-pinned
1.29.00 ZIP was copied into an isolated canonical cache fixture; the real
`Save-RidePackageArtifact` cache branch validated its SHA-256 and recorded both
the per-artifact sidecar and a workspace observation. The verified result then
went through offline `Install-RidePackage` into the real portable staging
handler, which staged only the declared `AdMod.exe` member. No network fallback
occurred, and AdMod was never executed.

The first assertion-only test attempt expected `AcquisitionKind` on the summary
object instead of its recorded sidecar; the assertion was corrected. That
failed fixture remains at
`.local/application-package-tests/joeware-admod-managed-cache-323025d70e734eb2b6df3e16abff59c0`;
it contains the copied ZIP and evidence but was stopped before package staging,
and was not inspected or cleaned. Successful fixture runs were cleaned by the
test.

An initial recheck used the shorthand `RIDE-Srv2025Test`; the documented
`RIDE-Server2025-Test` name was then checked directly. At 07:07, read-only
`Get-VM` failed for both `RIDE-Win11-Test` and `RIDE-Server2025-Test` before
VM or checkpoint inspection with `Access to a CIM resource was not available
to the client.` No task was dispatched and no UAC prompt was requested. Guest lifecycle acceptance remains deferred. No legacy
outcome closed; estimates remain settings 37-57, packages 38-53, components
19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded
125-180/about 155). See [structured evidence](../archive/evidence/joeware-admod-managed-cache-route-cross-shell-and-vm-block-2026-10-28-0705.json)
and [focused test](../../tests/JoeWareAdModEngineRoute.Tests.ps1).
## JoeWare AdMod offline engine route and VM recheck, 2026-10-28 06:53 UTC

The new focused route test passed 1/1 in both Windows PowerShell 5.1 and
PowerShell 7.6.5/Pester 5.7.1. It uses an inert synthetic ZIP, exercises the
real offline `Install-RidePackage` to portable-handler path, mocks the
administrator-context assertion and confirms no network acquisition call. The
first default-Pester-temp attempt failed at an access-denied atomic manifest
move; the handler retained staging evidence. The corrected `.local` fixture
passed and was cleaned. The first attempt's inert artifact remains in Pester's
sandbox temp and was not inspected or cleaned. Catalog documentation is current;
validation passed for 441 operations, 8 groups, 5 profiles, and 299 PowerShell
files. `Get-VM` at 06:53 again failed before inspection for both targets at host
CIM; no checkpoint or task was accessed. AdMod guest lifecycle remains deferred.
No legacy outcome closed; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12,
exact 127-181, rounded 125-180/about 155. See [structured evidence](../archive/evidence/joeware-admod-offline-engine-route-cross-shell-and-vm-block-2026-10-28-0653.json)
and [the focused test](../../tests/JoeWareAdModEngineRoute.Tests.ps1).
## NirSoft encrypted-stager current-source trace, 2026-10-28 06:46 UTC

Current package metadata excludes PasswordScan, and source review found that the
encrypted staging path asks `tar.exe` for only exact selected members before
verifying the output set. This is not runtime proof and does not identify which
process, run or catalog revision created the reported temporary file. Keep both
PasswordScan architectures excluded and the retained archive lifecycle deferred
until provenance is understood. No reported file/path metadata, binary, hash,
Defender state, VM or Windows state was accessed. No legacy outcome closed;
estimates remain settings 37-57, packages 38-53, components 19-24,
files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about
155). See [source trace evidence](../archive/evidence/nirsoft-encrypted-stager-current-source-trace-2026-10-28-0646.json)
and [package review](application-migration-review.md#nirsoft-encrypted-stager-current-source-trace-2026-10-28-0646-utc).
## Current-source validation and scope audit, 2026-10-28 06:43 UTC

Generated operation documentation is current; repository validation passed for
441 operations, 8 groups, 5 profiles and 298 PowerShell files. This static check
is not a Pester or Windows behavior run. The settings presentation review is
complete at 279/279; presentation coverage does not close legacy outcomes.
Sysinternals remains cleared under the prior RIDE v2 license-specialist approval
for RIDE's direct download-and-install workflow; all ten Windows 11 package
lifecycles (the Suite and nine products) already passed, and licensing is not a
migration gate. No utility ran. Per-tool runtime/activation, other target support
and Defender-blocked tools remain separate. No legacy outcome closed; estimates
remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). The 06:37 VM
recheck remained blocked at host CIM before inspection. No Windows, VM, Defender,
package or elevation state changed. See [structured validation and scope
evidence](../archive/evidence/migration-current-source-validation-and-scope-audit-2026-10-28-0643.json)
and [the current estimate table](../MIGRATION-PLAN.md#estimated-remaining-migration-work).
## Repeated NirSoft PasswordScan Defender block, 2026-10-28 06:39 UTC

The user reported another Defender block for the same x64 PasswordScan path in
the filtered NirLauncher temporary tree. The report supplies neither a
detection name nor Defender event time, and cannot identify the staging
process/run. Both PasswordScan architectures remain excluded. No file content,
metadata or hash was read; no Defender query, allow rule, exclusion, elevation
or Windows state change occurred. Retained archive lifecycle remains deferred
pending temporary-stage provenance. No legacy outcome closed; estimates remain
settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
evidence](../archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-0639.json)
and the [package review](application-migration-review.md#repeated-passwordscan-defender-block-2026-10-28-0639-utc).
## RSAT, Hyper-V, Windows Sandbox and WSL official source review, 2026-10-27 19:31 UTC

The user-selected outcomes remain four independent optional components; this
review makes no installation, activation or default-profile change. Current
Microsoft guidance defines Windows client RSAT as individual capabilities, not
one fixed bundle. The exact capability inventory varies by image; some tools
depend on other RSAT capabilities, and Windows 11 25H2 Arm64 does not support
RSAT Features on Demand. The role/tool set therefore remains a mapping input,
not a reason to include every tool.

Microsoft documents Hyper-V as a Windows 11 Pro/Enterprise optional feature
with SLAT, VM-monitor extensions, hardware virtualization and at least 4 GB RAM;
enablement is elevated and requires restart. Existing VM registrations,
configuration and data need explicit preservation/recovery guards. Windows
Sandbox uses `Containers-DisposableClientVM`, requires hardware virtualization
(and nested virtualization for a guest VM), and may require restart. Its
network is enabled by default, so opening it and configuring `.wsb` network,
folder and clipboard access remain separate choices. The `wsl --install`
shortcut enables base WSL and Virtual Machine Platform, downloads a kernel and
Ubuntu, defaults to WSL 2 and may restart. That shortcut cannot define a
no-network-fallback component install; WSL version, kernel/distro acquisition,
registration and user-data recovery must remain distinct.

Resolved: authoritative component prerequisites, identities and effects are
recorded. Deferred: RSAT subtool selection; Hyper-V and Sandbox edition/hardware
and recovery guards; WSL 1/2 and offline source mapping; and disposable-target
acceptance. No native query, servicing command, WSL command, Sandbox launch or
VM action occurred. VM/CIM access remains blocked before inspection. No legacy
outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/selected-windows-components-official-source-review-2026-10-27-1931.json), [RSAT and Features on Demand](https://learn.microsoft.com/en-us/windows-server/administration/install-remote-server-administration-tools?pivots=windows-client-11), [Hyper-V requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v?pivots=windows), [Windows Sandbox installation](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install), and [WSL requirements](https://learn.microsoft.com/en-us/windows/wsl/faq).
## RIDE-Win11-Test read-only CIM access recheck, 2026-10-27 19:29 UTC

A fresh read-only `Get-VM -Name RIDE-Win11-Test` failed before VM or checkpoint
inspection with `Access to a CIM resource was not available to the client.` No
task dispatch or host service change followed, and no elevation was requested.
HashCheck ApplicationsBatch11 and other Windows package, setting and component
acceptance remain deferred until VM access returns; protected controller
capability refresh stays reserved for the later elevated session. Source review
and local work continue. No legacy outcome closed; all estimates remain
**37-57 / 38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**, rounded
**125-180/about 155**. See [structured evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-27-1929.json).
## BloodHound CE collector acquisition preflight, 2026-10-27 19:27 UTC

The exact official GitHub release ZIP destinations and API SHA-256 pins remain
known for SharpHound v2.17.0 and AzureHound v3.1.1, but a fresh local preflight
was denied before DNS lookup: `Resolve-DnsName github.com` returned `Access is
denied`. The exact artifact cache paths were absent before the attempt; no ZIP
or sidecar bytes or partial files were created. Do not treat API metadata as
independent artifact verification. Archive inventory/notices, owned lifecycle,
no-collection checks and Windows 11 acceptance remain deferred. No collector,
backend/container, credential, directory data, VM, Windows or Defender state
was accessed or changed; no UAC was requested. No legacy outcome closes and
estimates remain unchanged. See [current preflight evidence](../archive/evidence/bloodhound-collector-current-acquisition-preflight-access-denied-2026-10-27-1927.json)
and [pinned release metadata](../archive/evidence/bloodhound-collector-github-release-digests-2026-10-26-1149.json).
## HashCheck ApplicationsBatch11 route regression, 2026-10-27 18:51 UTC

After isolating each suite's generated preview checkout and result path, the full
`TestAutomation.Tests.ps1` run passed **144/144** with **2 skipped** on PowerShell
7.6.5/Pester 5.7.1. Batch11's exact-package route declaration, controller
capability gate, guest dispatch, read-only preview and request forwarding all
pass. Repository validation passed for 438 operations, eight groups, five
profiles and 297 PowerShell files. The HashCheck installer was not run. The
read-only VM query still fails at CIM before inspection, so controller refresh
and Windows acceptance remain deferred. No legacy outcome closed and estimates
are unchanged. See [regression evidence](../archive/evidence/hashcheck-batch11-route-regression-and-cim-block-2026-10-27-1851.json)
and [route preparation evidence](../archive/evidence/hashcheck-batch11-route-preparation-and-cim-block-2026-10-27-1847.json).
## CCleaner family publisher build-route recheck, 2026-10-27 18:51 UTC

The current official build pages show CCleaner Free 7.13.1573 as the latest
release, with online and offline installers plus a portable ZIP route. The
portable link resolves to `ccsetup641.zip`, a separately versioned build that
must remain distinct from the full installer. Recuva and Speccy pages list
standard installers (`rcsetup155.exe` and `spsetup134.exe`) but expose no
portable variants or on-page version labels. The Defraggler builds URL redirects
to the product page without a current build artifact. These are source-route
observations only: the web reader declined the binary payload content types, so
no artifact bytes, hashes, signatures or archive members were verified. Keep all
four user-selected product outcomes and the publisher-provided variants; do not
invent Recuva/Speccy portable packages or substitute third-party/self-converted
builds. The existing direct-download-and-install disposition is unchanged; no
license gate was added. No legacy outcome closes and estimates are unchanged.
See [structured evidence](../archive/evidence/ccleaner-family-current-official-build-route-recheck-2026-10-27-1851.json)
and the official [CCleaner](https://www.ccleaner.com/ccleaner/builds),
[Recuva](https://www.ccleaner.com/recuva/builds),
[Speccy](https://www.ccleaner.com/speccy/builds), and
[Defraggler](https://www.ccleaner.com/defraggler/builds) pages.
## HashCheck Windows 11 route preparation and VM access, 2026-10-27 18:47 UTC

ApplicationsBatch11 is now prepared for exactly HashCheck Shell Extension 2.6.3.
The route checks pinned installer identity, repeat install, removal/repeat, and
saved install/removal recovery without launching HashCheck or invoking Explorer.
The task client and guest dispatch expose the suite and require controller
capability `ApplicationsBatch11HashCheckV1`. Local automation coverage includes
Batch11's capability gate, dispatch, preview, and forwarding. The full
`TestAutomation.Tests.ps1` run passed 143, failed 1, and skipped 2 after redirecting
TEMP/TMP into `.local`; its unrelated ApplicationsBatch1User preview fixture hit
a transient file lock while rewriting the generated `tools/validate.ps1`. The
initial default-temp run was denied writes by the sandbox. Catalog export and
repository validation passed for 438 operations, eight groups, five profiles,
and 297 PowerShell files.

No request was dispatched, controller capability refreshed, installer run, or VM
changed. `Get-VM -Name RIDE-Win11-Test` failed before VM/checkpoint inspection
because CIM access is unavailable to the client. Defer controller refresh to the
later elevated session. HashCheck lifecycle, Explorer behavior, intended-user
registration, and Windows 11 acceptance remain pending; `SupportedTargets` stays
empty. No legacy outcome closed and all estimate ranges remain unchanged. The
prior RIDE v2 Sysinternals license-specialist approval remains settled for RIDE's
direct download-and-install workflow; no licensing gate applies. Defender
exclusions remain separate. See [structured evidence](../archive/evidence/hashcheck-batch11-route-preparation-and-cim-block-2026-10-27-1847.json),
[HashCheck artifact preflight](../archive/evidence/hashcheck-retained-artifact-catalog-preflight-2026-10-27-1839.json),
and [Sysinternals decision](../package-licensing.md#sysinternals-settled-ride-v2-approval).
## HashCheck retained-artifact preflight, 2026-10-27 18:39 UTC

HashCheck 2.6.3's retained 2,157,368-byte publisher installer matches the
sidecar and release API digest; Authenticode is valid for IDRIX SARL. Its
focused catalog assertion passed 1/1, confirming the pinned asset and machine
uninstall identity. No installer ran or Windows state changed. RIDE-managed
install/repeat/remove/recovery, Explorer and sparse-package behavior, intended
user registration and disposable Windows 11 acceptance remain deferred.
`SupportedTargets` is empty. The BSD-3-Clause marker is administrative, not a
migration gate. No legacy outcome closed; all estimates remain unchanged. See
[HashCheck evidence](../archive/evidence/hashcheck-retained-artifact-catalog-preflight-2026-10-27-1839.json)
and [application ledger](application-migration-review.md).

## NirSoft Defender-filtered retry, 2026-10-27 18:35 UTC

Both PasswordScan paths are excluded after the latest user-reported alert for
`NirSoft/x64/passwordscan.exe`. The NirLauncher catalog candidate now selects
647 of 668 entries, omitting 21 executable paths in total. A focused
actual-archive retry did not return a Pester result and showed no temporary-tree
progress during bounded observation; it was stopped and remains incomplete.
The isolated catalog-pin/exclusion assertion passed 1/1 on PowerShell 7.6.5;
this does not establish the real-archive lifecycle. No utility launched,
package commit occurred, or Defender setting changed.
Fresh read-only `Get-VM` still fails at host CIM before inspecting
`RIDE-Win11-Test` or its checkpoint. No whole legacy outcome closed; estimates
remain settings **37-57**, packages **38-53**, components **19-24**,
files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded
**125-180/about 155**. See [NirSoft retry evidence](../archive/evidence/nirsoft-defender-filtered-retry-incomplete-2026-10-27-1835.json)
and [application ledger](application-migration-review.md).

## NirSoft encrypted-archive lifecycle and Defender-filtered candidates, 2026-10-27 17:35 UTC

Encrypted-ZIP support is now implemented with the signed Windows inbox `tar.exe`,
exact catalog member selectors, bounded batches, and post-extraction count/path/
length checks. The actual x64 archive passed install/repeat/remove/saved-state
recovery and operator-note preservation **1/1** on PowerShell 7.6.5 and **1/1**
on Windows PowerShell 5.1.26100.9711. NirLauncher staging stopped at
`NirSoft/iehv.exe`, then at `NirSoft/lanipscanner.exe` on a rerun after the first
exclusion. Both are excluded now, in addition to the four user-reported alert
basenames. No NirLauncher package commit or utility launch occurred, and RIDE
did not change Defender settings or add allow rules. Fresh read-only VM lookup
again failed at CIM before inspecting RIDE-Win11-Test. Resolved: x64 local
publisher-archive file lifecycle. Excluded: six individual executable
names/paths from staging. Partial: both NirSoft collection outcomes. Deferred:
NirLauncher lifecycle and Windows 11 acceptance for both candidates. Estimates
remain settings **37-57**, packages **38-53**, components **19-24**,
files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded
**125-180/about 155**. Sysinternals has no licensing gate under prior RIDE v2
specialist approval; it is separate from the Defender exclusions. See [evidence](../archive/evidence/nirsoft-encrypted-archive-lifecycle-defender-blocks-2026-10-27-1735.json),
[package guide](../application-packages.md#nirsoft-collection-pending-portable-candidates),
and [VM/CIM access result](../archive/evidence/nirsoft-encrypted-archive-lifecycle-defender-blocks-2026-10-27-1735.json).

## NirSoft publisher-archive encryption diagnostic, 2026-10-27 17:13 UTC

Both retained official NirSoft archives match their pinned size, SHA-256 and
central-directory inventories, but have the ZIP encryption flag set. The
current `System.IO.Compression` handler cannot extract the encrypted entries;
the focused real-archive Pester case failed at extraction (**0/1 passed**) and
did not complete staging or saved-state recovery. The Defender-reported
executables remain omitted and were not opened/extracted; no utility ran and no
Windows or Defender state changed. Implement a supported encrypted-ZIP path
while preserving the exact member filter, bounds, ownership and recovery checks,
then rerun both archives. Fresh `Get-VM` remains blocked at CIM before VM
inspection, so Windows 11 acceptance stays deferred. Resolved: none.
Retired/excluded: none. Partial: both NirSoft collection outcomes. Deferred:
publisher-archive installation and disposable Windows 11 acceptance. Estimates
remain settings **37-57**, packages **38-53**, components **19-24**,
files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded
**125-180/about 155**. Sysinternals licensing remains settled for
RIDE's direct-download-and-install workflow under the prior v2 specialist
approval; it is unrelated to this extraction blocker. See [structured
evidence](../archive/evidence/nirsoft-retained-archive-encryption-lifecycle-block-2026-10-27-1713.json),
[package handling](../application-packages.md#nirsoft-collection-pending-portable-candidates),
and the [current VM access record](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-27-1704.json).

## RIDE-Win11-Test CIM access recheck, 2026-10-27 17:04 UTC

A fresh read-only `Get-VM -Name RIDE-Win11-Test` failed with `Access to a CIM resource was not available to the client.` The failure occurred before VM or checkpoint inspection. No task query, acceptance dispatch, host/guest/Defender change or elevation request followed. Windows 11 acceptance remains deferred; continue independent local/source work. No legacy outcome changed; estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured access evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-27-1704.json) and [migration plan](../MIGRATION-PLAN.md).
## MiTeC JSON/XML Viewer current-source retained-archive regression, 2026-10-27 17:02 UTC

`MitecViewerPackages.Tests.ps1` passed **16/16** on PowerShell 7.6.5 and **16/16** on Windows PowerShell 5.1.26100.9711 with the retained official JSONView and XMLView archives. The matrix covers both x64 and x86 variants. Exact archive length/hash and selected executable evidence matched; each case staged only its architecture-selected executable, repeated installation, verified package state, preserved synthetic user licence/configuration files across removal and restore, refused modified owned files, and refused collisions with unowned executables. No viewer launched, document opened, activation performed, updater checked or network behavior exercised. A fresh VM read-only probe in this turn failed at CIM before inspection, so current-source Windows 11 acceptance remains deferred and `SupportedTargets` stays empty. Resolved: current-source retained-archive file lifecycle for both viewer packages and architectures. Retired/excluded: none. Deferred: Windows 11 lifecycle and GUI/document/activation/updater behavior. Partial: no whole legacy outcome closes. Estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/mitec-json-xml-current-source-retained-archive-cross-shell-regression-2026-10-27-1702.json), [current-source package suite](../../tests/MitecViewerPackages.Tests.ps1), and [current VM access evidence](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json).
## MiTeC Structured Storage Viewer retained-archive lifecycle and VM access, 2026-10-27 16:58 UTC

The retained publisher `SSView.zip` matched its checked-in size and SHA-256, and its selected `SSView.exe` member matched the pinned member digest. The focused current-source Pester suite passed **3/3** on PowerShell 7.6.5 and **3/3** on Windows PowerShell 5.1.26100.9711. The real-archive case stages only the selected executable and verifies repeat install, health, snapshot, removal, saved-state recovery and preservation of an operator note; it does not launch the utility, load the codec, open a structured-storage file or access user documents. The optional ZLib codec, Delphi source and sample remain excluded from staging. A fresh read-only `Get-VM -Name RIDE-Win11-Test` failed before inspection with CIM access unavailable; no VM acceptance or UAC prompt occurred. `SupportedTargets` remains empty. No complete legacy outcome closed; estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/mitec-ssview-retained-archive-cross-shell-lifecycle-and-vm-access-2026-10-27-1658.json), [candidate contract](../application-packages.md#mitec-structured-storage-viewer-portable-candidate), and [current VM blocker](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json).
## Current catalog/package-marker audit and WinHTTP regression, 2026-10-27 16:51 UTC

Current-source validation passed for 438 operations, 8 groups, 5 profiles and 297 PowerShell files. The catalog contains 114 package operations, of which 44 are marked PendingAcceptance; all 44 have exact package-ID/version administrative review-store markers (NeedsReview). These markers do not block planning or migration. Sysinternals remains settled for RIDE's direct Microsoft download-and-install workflow under prior RIDE v2 specialist approval; there is no legal or licensing gate. Defender-detected tools remain separate security exclusions. The WinHTTP inventory/preparation/guarded-lifecycle suites passed 22/22 in PowerShell 7 and 22/22 in Windows PowerShell 5.1 with native commands mocked. It is still a candidate without catalog integration, native state capture/recovery or target acceptance. VM access remains blocked before inspection by CIM; Hyper-V Manager content is inaccessible to the lower-integrity helper. No legacy outcome closed; estimates remain settings 37-57 / packages 38-53 / components 19-24 / files/assets 25-35 / maintenance 8-12, exact 127-181, rounded 125-180/about 155. See [structured audit](../archive/evidence/current-catalog-package-review-marker-audit-2026-10-27-1651.json), [WinHTTP regression](../archive/evidence/winhttp-proxy-current-source-cross-shell-regression-and-access-2026-10-27-1648.json), [VM access evidence](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json), and the [settled Sysinternals disposition](../package-licensing.md#sysinternals-settled-ride-v2-approval).
## MiTeC Project Maker ApplicationsBatch10 preparation and regression, 2026-10-27 15:45 UTC

Prepared the dedicated Windows 11 Project Maker 1.9.0 lifecycle route, pinned to the retained official installer SHA-256 and exact package ID. The focused Pester regression passed **356 tests, 0 failures, 4 skipped and 1 not run** across catalog, package and task automation suites. Catalog docs, parser and script-version checks passed. The task client requires a refreshed controller capability `ApplicationsBatch10ProjectMakerV1`; that refresh remains deferred. Most recent VM and task enumeration checks failed at CIM before inspection, so native acceptance is not dispatched. No package, project, Defender, VM or UAC state changed. The owner/version review marker does not block direct-download/install migration. No legacy outcome closed; estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [Project Maker evidence](../archive/evidence/mitec-project-maker-batch10-local-regression-2026-10-27-1545.json), [source evidence](../archive/evidence/mitec-project-maker-package-candidate-2026-10-27-1440.json), and [InfoBar CIM/task access evidence](../archive/evidence/infobar-batch9-local-regression-2026-10-27-1529.json).

## MiTeC InfoBar catalog/package/controller regression, 2026-10-27 15:40 UTC

The focused current-source run passed **352 tests, 0 failures, 4 skipped and 1 not run** across catalog, package and task automation suites. The host's live-registry integration case was excluded; Pester's optional registry/result plugins were disabled, with TEMP/TMP under writable `.local`. The earlier stale version assertion was corrected to runner version `0.16.0` and its lifecycle-selection expectation now includes batch 9. Generated operation docs are current. Fresh `Get-VM` checks for `RIDE-Win11-Test` and `RIDE-Srv2025Test` and registered-task enumeration again failed at CIM before inspection. The suite remains undispatched; no package, Defender or VM state changed. No legacy outcome closed; estimates stay settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured regression evidence](../archive/evidence/infobar-batch9-catalog-package-controller-regression-2026-10-27-1540.json) and [InfoBar access evidence](../archive/evidence/infobar-vm-acceptance-cim-block-2026-10-27-1511.json).

## MiTeC InfoBar ApplicationsBatch9 local regression, 2026-10-27 15:29 UTC

The InfoBar task/guest routing and capability regression now passes **134/134 executed Pester tests**, with **2 skipped**, after disabling Pester's optional `TestRegistry`/`TestResult` plugins and moving TEMP/TMP under workspace `.local`. This validates local request handling only. PowerShell parser, script version, catalog contract and focused diff checks passed. No VM task or installer ran. CIM access still blocks VM inspection, and controller refresh for `ApplicationsBatch9InfoBarV1` remains a later elevated-session scenario. No legacy outcome closed; estimates stay settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [local regression evidence](../archive/evidence/infobar-batch9-local-regression-2026-10-27-1529.json) and [runner preparation](../archive/evidence/infobar-batch9-runner-preparation-2026-10-27-1519.json).

## MiTeC InfoBar ApplicationsBatch9 runner preparation, 2026-10-27 15:19 UTC

Prepared and routed a Windows 11-only focused lifecycle suite for exact candidate `package.mitec-infobar` 4.6.2. It verifies selected identity, pinned version, repeat install, uninstall, repeat removal, and saved install/removal recovery. InfoBar is never launched and no startup/network, location, API key or RSS behavior is exercised. Production `SupportedTargets` remains empty pending the remaining native checks.

The task client and fixed registration source now require/declare `ApplicationsBatch9InfoBarV1`, so an old registered controller refuses the request before queueing it. Refreshed the catalog-generated operations reference and migration estimates. PowerShell parsing, version reporting, catalog contract and current/stale capability checks passed. Focused TestAutomation Pester could not initialize `TestRegistry` because restricted HKCU access was denied before assertions (0 passed, 136 harness errors). VM acceptance remains blocked before VM inspection by CIM, and refreshing the controller remains deferred to a later elevated session. No request was queued, installer run, UAC prompt opened, Defender state changed, or legacy outcome closed. Estimates unchanged: settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [runner evidence](../archive/evidence/infobar-batch9-runner-preparation-2026-10-27-1519.json), [VM access evidence](../archive/evidence/infobar-vm-acceptance-cim-block-2026-10-27-1511.json), [application ledger](application-migration-review.md), and [estimate table](../MIGRATION-PLAN.md).

QEMU guest-tools publisher-source recheck, 2026-10-27 15:08 UTC: the official
SPICE index lists x64 WebDAV 2.4 plus `.sha256` and `.sig` sidecars, but the
web reader refuses the MSI/signature MIME types and the previous local request
failed DNS. Exact bytes and integrity remain unverified. Upstream confirms the
VirtIO bundle overlaps SPICE components; WebDAV stays separate and optional.
The later user decision supersedes pre-pinning: observe Debian/Ubuntu releases
and Boxes build when preparing the matching guest, keeping Fedora 44 selected.
No package or legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/qemu-guest-tools-source-and-validation-decision-recheck-2026-10-27-1508.json)
and the [migration plan](../MIGRATION-PLAN.md).

Sysinternals migration decision reaffirmed, 2026-10-27 15:05 UTC: the user reiterates that prior RIDE v2 license-specialist approval governs RIDE's direct download-and-install workflow. RIDE does not transfer or publish copies; no legal issue or further review blocks migration, and strict redistribution analysis is not a migration gate. Defender-blocked utilities remain separate security exclusions. No package outcome closed and estimates are unchanged. See [decision evidence](../archive/evidence/sysinternals-license-practical-administration-reaffirmation-2026-10-27-1505.json) and the [settled disposition](../package-licensing.md#sysinternals-settled-ride-v2-approval).

## Hyper-V Manager integrity and registered VM access recheck, 2026-10-27 14:56 UTC

PowerShell `Get-VM` access to the registered Windows 11 and Server 2025 VMs
continues to fail at host CIM. A read-only attempt to inspect the already-open
Hyper-V Manager window also failed: accessibility data reports that the
target has higher Windows integrity than the helper, and screenshot capture
returned black, so VM/checkpoint state was unreadable. No UI input, elevation
request, VM start/stop, checkpoint change or acceptance dispatch occurred.
Native acceptance remains deferred. Estimates remain settings **37-57**,
packages **38-53**, components **19-24**, files/assets **25-35**, maintenance
**8-12**, exact **127-181**, rounded **125-180/about 155**; no legacy outcome
changed. See [structured UI evidence](../archive/evidence/hyper-v-manager-integrity-access-recheck-2026-10-27-1456.json),
[CIM recheck](../archive/evidence/ride-vm-cim-access-recheck-2026-10-27-1454.json),
and the [migration plan](../MIGRATION-PLAN.md).

## OpenSSH independent firewall setting and VM access, 2026-10-27 11:03 UTC

Added windows.openssh-server-firewall as a separate pending setting for the exact local OpenSSH-Server-In-TCP rule. It requires the Server capability and validates inbound allow/TCP/22/local PersistentStore identity before changing only the enabled flag; it cannot create a rule, install the feature or start sshd. Full Catalog.Tests and NetworkAndSoundControls suites passed 108 tests, with 0 failures and 1 live-registry test not run. Repository validation passed for 432 operations, 8 groups, 5 profiles and 294 PowerShell files, and the CLI settings view reports the operation pending with no supported targets. Read-only VM and registered-task queries failed at CIM before inspection; no acceptance was dispatched and no state changed. Windows 11 and Server 2025 native acceptance and first-start server-data recovery remain deferred. No legacy outcome closed; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about 155. Sysinternals remains clear for direct download-and-install under the prior RIDE v2 specialist approval; licensing does not block migration and Defender exclusions remain separate. See [structured evidence](../archive/evidence/openssh-server-independent-firewall-setting-and-vm-block-2026-10-27-1103.json) and [component guide](../windows-component-inventory.md).

## OpenSSH Server preacceptance engine regression, 2026-10-27 10:38 UTC

Catalog/engine Pester checks passed 3/3 for discovery, state matching and fail-closed install planning; the three OpenSSH candidate suites passed 32/32 with mocked providers. `./ride.ps1 list components` displays the capability with CandidateTargets Windows 11/Windows Server 2025, PendingAcceptance true and no SupportedTargets. Invoke-RidePlan rejects it before invoking the installer because native acceptance is pending. Repository validation passed for 430 operations, 8 groups, 5 profiles and 294 PowerShell files. The 10:34 read-only VM/task check failed at CIM before inspection or dispatch; no guest, host, Defender or UAC state changed. No legacy outcome closed; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about 155. Sysinternals remains cleared under the prior RIDE v2 specialist approval for direct download-and-install; Defender exclusions are separate. See [structured evidence](../archive/evidence/openssh-server-preacceptance-engine-regression-2026-10-27-1038.json), [VM/task blocker](../archive/evidence/ride-win11-test-vm-and-task-cim-access-recheck-2026-10-27-1034.json), and [estimate table](../MIGRATION-PLAN.md).

## VM and registered-task CIM access recheck, 2026-10-27 10:34 UTC

Read-only `Get-VM -Name RIDE-Win11-Test` failed with `VirtualizationException: Access to a CIM resource was not available to the client`. The registered-task query failed with the same CIM access denial before enumeration. No VM/checkpoint/task was inspected, no acceptance was dispatched, and no guest, host, Defender or UAC state changed. Native acceptance remains deferred. No legacy outcomes were resolved, retired, excluded or closed; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about 155. See [structured evidence](../archive/evidence/ride-win11-test-vm-and-task-cim-access-recheck-2026-10-27-1034.json) and [migration estimates](../MIGRATION-PLAN.md).

## OpenSSH Server engine/catalog integration, 2026-10-27 10:31 UTC

Registered the guarded capability lifecycle as a pending `WindowsCapability` catalog operation and wired read-only state inspection, install, RIDE-owned removal and saved-run recovery through the engine. Added a `components` view, exposed pending/candidate target metadata in discovery, and kept the operation out of settings/packages views. Catalog validation and generated operation documentation now cover the operation. The 32/32 mocked OpenSSH candidate suites and 2/2 focused catalog projection tests passed; repository validation passed for 430 operations, 8 groups, 5 profiles and 294 PowerShell files. No capability, service, firewall, VM, Defender or host state changed, and no fresh UAC prompt was requested. Windows 11 and Windows Server 2025 remain candidate targets with no support declaration; native acceptance is blocked by the existing VM/controller access failure. Activation and inbound firewall exposure remain independent choices and are not included in this installer. Sysinternals remains cleared by the prior RIDE v2 specialist approval for RIDE direct download-and-install; Defender-blocked tools remain separate. No whole legacy outcome closed; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about 155. See [structured evidence](../archive/evidence/openssh-server-engine-catalog-integration-2026-10-27-1031.json), [component guide](../windows-component-inventory.md), and [latest VM/task access evidence](../archive/evidence/ride-win11-test-cim-and-task-access-recheck-2026-10-27-0856.json).

## Sysinternals current-source package and license-planning regression, 2026-10-27 10:12 UTC

The focused current-source Pester run passed **104/104** across the independent Sysinternals product suite, whole-Suite lifecycle, and LicenseReviews. TestRegistry and TestResult plugins were disabled and TEMP/TMP were redirected to .local/pester-sysinternals-current-20261027. The initial TestRegistry setup failure occurred before assertions; the sandbox-TEMP attempt was interrupted after access-denied atomic file moves. The corrected workspace-local run passed all tests in 735.29 seconds. All ten Sysinternals install plans remain available. The prior RIDE v2 specialist approval settles direct download-and-install; there is no license or migration gate. Defender-alerted tools remain separate exclusions. No executable, publisher request, VM request, or Windows/Defender state change occurred. No legacy outcome closed; estimates remain **37-57 / 38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/sysinternals-license-plan-current-source-regression-2026-10-27-1012.json), [package disposition](../package-licensing.md#sysinternals-settled-ride-v2-approval), and [migration estimate](../MIGRATION-PLAN.md).
Sysinternals catalog, lifecycle and licensing disposition audit, 2026-10-27 09:49 UTC: verified all ten current package records are Reviewed, supported on Windows 11 and not pending acceptance. Existing Windows 11 lifecycle acceptance passed for the suite and nine independent products; no utility was executed. Prior RIDE v2 specialist approval settles RIDE's direct-download-and-install workflow, with no license or migration gate. Defender exclusions remain independent. A fresh read-only VM/task check failed at CIM and the registered task query returned an invalid network address; no request or system change. No legacy outcome or estimate changed (127-181 exact; 125-180/about 155 rounded). See [structured audit](../archive/evidence/sysinternals-current-catalog-and-license-disposition-audit-2026-10-27-0949.json) and [package licensing disposition](../package-licensing.md#sysinternals-settled-ride-v2-approval).

WFN Nightly current-source complete 531-member lifecycle, 2026-10-27 09:40 UTC:
`WfnPackage.Tests.ps1` passed **4/4**, including the pinned retained-archive
inventory and complete synthetic 531-member repeat/install/snapshot/uninstall/
restore lifecycle (1299.14s). The earlier stopped current-source rerun is
superseded. WFN and the installer were not launched; firewall/Defender/VM state
was untouched. Windows lifecycle/runtime acceptance remains blocked before
VM/task inspection/dispatch. No legacy outcome or estimate changed (**127-181**
exact; **125-180/about 155** rounded). See [structured evidence](../archive/evidence/wfn-current-source-full-531-member-lifecycle-regression-2026-10-27-0940.json).
Cookie Cruncher current-source real-archive lifecycle, 2026-10-27 08:23 UTC: the retained 2.0.0.1 archive matched the catalog pin; the complete focused suite passed 4/4, including staging only the three declared files, repeat installation, snapshot/uninstall/restore, and operator-output preservation. GUI was not launched; SQLite/browser profiles/cookie data were not accessed. Repository validation passed 429 operations, 8 groups, 5 profiles and 294 PowerShell files. NeedsReview/Unassigned is administrative; bundled notice permits redistribution, so no license gate applies. Windows runtime/GUI acceptance remains pending. No VM/Windows/Defender/UAC change, supported target, legacy closure or estimate change. See docs/archive/evidence/cookie-cruncher-current-source-real-archive-lifecycle-2026-10-27-0823.json.

WinHTTP host command-availability diagnostic, 2026-10-27 08:21 UTC: read-only `netsh winhttp show advproxy` on local build 26300 exits 1 with “The following command was not found”; no proxy values were exposed. This is not VM acceptance. Registered VM inspection remains blocked at CIM. Exact capture, guarded write, recovery and catalog integration remain open. No settings/VM/Defender state change, UAC or legacy closure; estimates unchanged. See docs/archive/evidence/winhttp-netsh-advproxy-host-capability-check-2026-10-27-0821.json.

OpenSSH Client and Telnet LabSources recursive source check, 2026-10-27 08:18 UTC: a read-only recursive filename scan of Z:\LabSources found no OpenSSH-Client-Package CAB, Languages and Optional Features source, or FOD-named file; the four ISO list is unchanged and servicing repositories have README files only. OpenSSH Client matching CAB, dependencies, fallback boundary, recovery and Windows acceptance remain open; Telnet package/source identity remains unknown, so LocalSource stays blocked. OpenSSH Server is independent of FOD source. VM and task inspection again failed at CIM. No dispatch/elevation/state change, or legacy closure. Estimates unchanged at 127-181 exact and 125-180/about 155 rounded. See docs/archive/evidence/b06-labsources-recursive-fod-source-recheck-and-vm-access-2026-10-27-0818.json.

RawCopy current-source retained-archive lifecycle, 2026-10-27 09:11 UTC: added and passed an opt-in real-archive `ApplicationPackages.Tests.ps1` case (1/1) against pinned RawCopy 1.0.0.22 hashes. It staged only the x64 executable and three notices, repeated install, omitted x86/AutoIt source, and restored saved state with an operator note preserved. Repository validation passed 429 operations, 8 groups, 5 profiles and 294 PowerShell files. No product ran. Fresh Win11/Server2025 VM queries and task inspection failed at CIM; `schtasks` reports invalid network address. No dispatch, elevation, state change or Defender action. Windows lifecycle and synthetic NTFS behavior remain deferred. No legacy outcome/estimate changed (127-181 exact; 125-180/about 155 rounded). See docs/archive/evidence/rawcopy-current-source-real-archive-lifecycle-and-vm-access-2026-10-27-0911.json.

MiTeC SQLite Query retained-archive lifecycle regression, 2026-10-27 08:09 UTC: `MiTeCSqliteQuery.Tests.ps1` passed 3/3 against the exact catalog-pinned 3.2.0 archive. Offline staging/repeat/member health/snapshot/note-preservation/uninstall/restore passed for only the three declared files; no executable launched, database opened or SQL ran. Repository validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell files. Exact-version license marker remains NeedsReview/Unassigned and is administrative only, not a migration gate. Native Windows behavior remains pending. PSScriptTools queue staging was denied before enqueue; VM/task inspection failed at CIM. No UAC or system/Defender state change. Defender-blocked tools excluded. No legacy outcome or estimate changed (127-181 exact; 125-180/about 155 rounded). See docs/archive/evidence/mitec-sqlite-query-real-archive-current-source-lifecycle-2026-10-27-0809.json.

## PSScriptTools real-archive current-source lifecycle and VM controller queue block, 2026-10-27 08:04 UTC

The retained PSScriptTools 3.2.0 archive matched its catalog pin and
`PSScriptToolsPackage.Tests.ps1` passed **7/7** on PowerShell 7.6.5/Pester 5.7.1.
The inert 360-member lifecycle passed staging/repeat/removal and exact saved-state
recovery, including operator-content preservation and drift/collision refusal.
No upstream module was imported or executed.

The authorized registered `PSScriptTools` Windows 11 batch was attempted with
the existing controller, checkpoint and focused-portable capability. Protected
queue staging failed before enqueue because its temporary request file was
denied; no task started, result exists, or elevation prompt appeared. Fresh
read-only VM/task queries also failed at CIM before inspection. No VM, Windows,
or Defender state changed. Windows package lifecycle/runtime/dependency
acceptance remains deferred. No legacy outcome closes; estimates remain
**37-57 / 38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**, rounded
**125-180/about 155**. See [structured evidence](../archive/evidence/psscripttools-real-archive-current-source-lifecycle-and-controller-queue-block-2026-10-27-0804.json)
and the [package ledger](application-migration-review.md).

## Telnet Client official identity and source-boundary recheck, 2026-10-27 07:48 UTC

Microsoft's current OptionalFeatureList example confirms `TelnetClient` as the
exact optional-feature name with `NotPresent` and `Installed` states. The
current non-language Features on Demand list does not identify Telnet Client
as a capability or give a matching CAB/package identity. Keep `LocalSource`
blocked until matching media, package identity, architecture/build/language
fit, complete dependencies, policy source precedence, recovery and native
acceptance are verified. No servicing, VM, Windows or Defender state changed.
No legacy outcome closed; estimates remain settings **37-57**, packages
**38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**,
exact **127-181**, rounded **125-180/about 155**. See [structured evidence]
(../archive/evidence/telnetclient-official-optional-feature-identity-current-review-2026-10-27-0748.json),
the [component guide](../windows-component-inventory.md) and [current
migration estimate](../MIGRATION-PLAN.md).

## OpenSSH Server current-source regression and repository validation, 2026-10-27 07:44 UTC

The install/remove, observation and activation suites passed **30/30** on
PowerShell 7.6.5/Pester 5.7.1 with TestRegistry and TestResult disabled.
Repository validation passed for 429 operations, 8 groups, 5 profiles and 294
PowerShell files. Native providers were mocked; no VM, Windows, service,
firewall, capability or Defender state changed. The candidate remains
unregistered; catalog integration and Windows 11/Server 2025 acceptance remain
open. The latest VM/task access check failed at CIM before inspection or
dispatch. No legacy outcome closed; estimates remain settings **37-57**,
packages **38-53**, components **19-24**, files/assets **25-35**, maintenance
**8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured
evidence](../archive/evidence/openssh-server-current-source-regression-and-repository-validation-2026-10-27-0744.json)
and the [current migration estimate](../MIGRATION-PLAN.md).

## OpenSSH conditional install removal lifecycle, 2026-10-27 06:50 UTC

The unregistered capability candidate now saves a completed post-install snapshot
and exports Remove-RideOpenSshServerCapability. It removes only a matching run
that began with no sshd service, firewall rule or server data; the current service,
firewall and data observations must match the completed snapshot. If DISM leaves
the exact TCP/22 rule created by that saved install, RIDE removes it only when it
is still disabled and its identity matches. Removal writes an idempotence record
only after verifying the capability, service, firewall and server data returned
to the captured absence state. This preserves a deliberate fail-closed boundary
for pre-existing server state and any post-install drift.

The combined capability-install, observer and activation suites passed **30/30**
on both PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711/Pester 5.7.1.
Repository validation passed for 429 operations, 8 groups, 5 profiles and 294
PowerShell files. All native calls were mocked; no Windows, VM, service, firewall
or Defender state changed. Catalog integration and native Windows 11/Server 2025
acceptance remain open; prior service/firewall/data also require a separate
recovery design. No legacy outcome closed; estimates remain settings **37-57**,
packages **38-53**, components **19-24**, files/assets **25-35**, maintenance
**8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured
OpenSSH evidence](../archive/evidence/openssh-server-capability-install-candidate-2026-10-27.json),
[component guide](../windows-component-inventory.md) and [current estimate](../MIGRATION-PLAN.md).
## RIDE-Win11-Test read-only access recheck, 2026-10-27 06:43 UTC

Get-VM/Get-VMSnapshot and Get-ScheduledTask both failed before inspection with
CIM access denied. No elevation was requested; no VM, checkpoint, task, guest,
host service, Windows or Defender state changed. Keep native Windows acceptance
deferred and continue local source and mocked-test work. No legacy outcome
closed; estimates remain settings **37-57**, packages **38-53**, components
**19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**,
rounded **125-180/about 155**. See [read-only access evidence](../archive/evidence/ride-vm-access-recheck-2026-10-27-0643.json)
and the [current migration estimate](../MIGRATION-PLAN.md).
## OpenSSH cross-shell regression, 2026-10-27 06:42 UTC

The combined capability-install, observer and activation suites passed 24/24
under both PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711/Pester 5.7.1,
with all native providers mocked. Repository validation passed for 429
operations, 8 groups, 5 profiles and 294 PowerShell files. No Windows, VM or
Defender state changed. No legacy outcome closed; exact capability
removal/recovery, catalog integration, and Windows 11/Server 2025 acceptance
remain open. Estimates remain settings **37-57**, packages **38-53**,
components **19-24**, files/assets **25-35**, maintenance **8-12**, exact
**127-181**, rounded **125-180/about 155**. See [structured
candidate evidence](../archive/evidence/openssh-server-capability-install-candidate-2026-10-27.json)
and [current migration estimate](../MIGRATION-PLAN.md).
## OpenSSH combined regression and repository validation, 2026-10-27 06:39 UTC

The capability-install suite passed 6/6, and the combined capability-install,
observer and activation suites passed 24/24 on PowerShell 7.6.5/Pester 5.7.1
with the optional TestRegistry and TestResult plugins disabled. Repository
validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell
files. All native servicing, service and firewall calls were mocked. No Windows,
VM or Defender state changed. The candidate remains unregistered and does not
support exact removal/recovery. No legacy outcome closed; estimates remain
settings **37-57**, packages **38-53**, components **19-24**, files/assets
**25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about
155**. See [candidate evidence](../archive/evidence/openssh-server-capability-install-candidate-2026-10-27.json)
and [current estimate](../MIGRATION-PLAN.md).
## OpenSSH Server unattended capability installation candidate, 2026-10-27 06:37 UTC

Added an unregistered source candidate for installing only the
OpenSSH.Server~~~~0.0.1.0 capability. It uses the exact local target identity,
requires an already elevated process, checks pending servicing and captured
server surfaces, supports a local source with LimitAccess, and never starts
sshd. Microsoft documents that capability installation creates and enables its
TCP/22 allow rule; the candidate restores an absent or previously disabled
rule to disabled, preserves a pre-existing enabled rule, and verifies service
and server-data postconditions. The focused mocked Pester suite passed **6/6**
on PowerShell 7.6.5/Pester 5.7.1 after disabling optional TestRegistry and
TestResult plugins. No Windows or VM state changed.

Exact capability removal/recovery, catalog integration, and native Windows 11
and Server 2025 acceptance remain open. The latest recorded VM access failed
at CIM before inspection and registered-task lookup returned an invalid
network address. No legacy outcome closed; estimates remain settings **37-57**,
packages **38-53**, components **19-24**, files/assets **25-35**, maintenance
**8-12**, exact **127-181**, rounded **125-180/about 155**. See [candidate
evidence](../archive/evidence/openssh-server-capability-install-candidate-2026-10-27.json),
[component guide](../windows-component-inventory.md) and
[migration estimate](../MIGRATION-PLAN.md).
## BitLocker drive-type policy implementation, 2026-10-27 06:30 UTC

Implemented three Windows 11 local Group Policy values for future encryption:
OS, fixed-data and removable-data drives. The historical
`windows.bitlocker-encryption-method` remains unchanged; the default profile
carries AES-CBC 256-bit intent forward as XTS-AES 256-bit across all three
drive types. The focused catalog/planning suite passed **3/3** and repository
validation passed for 429 operations, 8 groups, 5 profiles and 292 PowerShell
files. This closes no legacy outcome and does not establish live policy
precedence or volume conversion. Native Windows policy acceptance remains
blocked by current VM/controller access. Estimates remain settings **37-57**,
packages **38-53**, components **19-24**, files/assets **25-35**, maintenance
**8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured
evidence](../archive/evidence/bitlocker-drive-method-policy-source-review-2026-10-27.json)
and [current estimate](../MIGRATION-PLAN.md).

## NirSoft full-member lifecycle and portable recovery regression, 2026-10-27 06:22 UTC

Both filtered candidates passed synthetic, inert full-member lifecycle in
`tests/NirsoftCollectionPackages.Tests.ps1` (**4/4**): the 660 selected NirLauncher
paths and 47 selected x64 paths installed, repeated, removed and restored from
saved snapshots while preserving an operator note. The full candidate suite
took 17m40s. `ApplicationPackages.Tests.ps1` passed **124/124** in 74.1s. The
large-set run exposed and prompted an indexed lookup in
`Restore-RidePortableSnapshot`, replacing a repeated full ownership scan per
snapshot file without changing conflict checks. No publisher archive, alert
binary, utility, Windows or Defender state was touched. The VM target lifecycle,
real archive extraction, Defender scans and launcher/tool behavior remain
pending; no legacy outcome closes. Estimates stay settings **37-57**, packages
**38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**,
exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/nirsoft-filtered-portable-candidates-2026-10-27.json)
and [current estimate](../MIGRATION-PLAN.md).

## Scope decision and estimate refresh, 2026-10-27 05:41 UTC

The user retired two legacy outcomes: the Neo4j/APOC stack bound to the old
BloodHound deployment and Arsenal's MEGAcmd download helper. Preserve existing
installations, databases, configuration, service state and user data; Arsenal
product migration continues without MEGAcmd. Validate the current reviewed
Store app selection; dynamic discovery remains deferred and closes no outcome.
Packages decrease from **40-55** to **38-53**; other group ranges are unchanged.
The exact total is **127-181**, rounded to **125-180/about 155**. See the
[decision record](decision-session-2026-10-17.md#legacy-bloodhound-stack-and-megacmd-helper-retired-store-validation-retained-2026-10-27)
and [structured evidence](../archive/evidence/legacy-bloodhound-megacmd-store-scope-decision-2026-10-27.json).

## Registered Windows VM/task access recheck, 2026-10-27 05:34 UTC

Read-only `Get-VM` and checkpoint queries again stopped before inspection for
both `RIDE-Win11-Test` and `RIDE-S25-Test`: `Access to a CIM resource was not
available to the client.` The registered `\\RIDE\\RIDEWin11Test` task query
stopped before task inspection or dispatch with `The network address is
invalid.` No guest request, elevation prompt, VM/checkpoint/host/Windows or
Defender state change occurred. Keep native acceptance deferred and continue
independent package, settings and component work. No legacy outcome closed;
estimates remain settings **37-57**, packages **40-55**, components **19-24**,
files/assets **25-35**, maintenance **8-12** (exact **129-183**, rounded
**130-185/about 155**). Sysinternals licensing remains settled under the prior
RIDE v2 license-specialist approval for direct download-and-install; no legal
or redistribution gate applies. See [structured access evidence](../archive/evidence/ride-vm-access-recheck-2026-10-27-0534.json).

## Current-source settings cross-shell regression and VM access recheck, 2026-10-26 19:11 UTC

`RemainingSettings.Tests.ps1` and `SixtySettings.Tests.ps1` passed **207/207** in both PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711. ProfileSettings passed 37/37; presentation passed 14/14; Catalog/ProfileValidation passed 95 runnable checks with one WindowsIntegration case excluded. Tests used mocks/WhatIf and did not change host settings. Current VM and registered task queries failed at CIM before inspection/dispatch; schtasks returned an invalid network address. No guest request or elevation prompt occurred. No setting legacy outcome closes. Estimates unchanged. See [structured cross-shell and VM evidence](../archive/evidence/settings-remaining-sixty-current-source-cross-shell-2026-10-26-1911.json).

## NTCore PE Detective, CFF Explorer and 4GB Patch real-archive lifecycle, 2026-10-26 18:54 UTC

Three retained publisher archives matched their catalog hashes and passed offline install/repeat/uninstall and present/absence snapshot recovery across 14 selected files. The focused `NtcorePackages.Tests.ps1` suite passed 16/16. 4GB Patch version 1.0.0.1 has an exact-version NeedsReview/Unassigned marker that does not block planning; no legal grant is inferred. No executable or Windows/Defender state changed. Windows acceptance and remaining NTCore behavior remain deferred. No legacy outcome closes; estimates are unchanged. See [package evidence](../archive/evidence/ntcore-pe-cff-4gb-real-archive-lifecycle-2026-10-26-1854.json) and [current VM access evidence](../archive/evidence/ride-vm-access-recheck-2026-10-26-1856.json).

## NTCore PE Detective, CFF Explorer and 4GB Patch real-archive lifecycle, 2026-10-26 18:54 UTC

Three retained, hash-pinned publisher archives passed current-source offline lifecycle: PE Detective 7/7 files, CFF Explorer 6/6 and 4GB Patch 1/1. Install/repeat/uninstall, present-snapshot restore and prior-absence restore passed for each while preserving operator content. `NtcorePackages.Tests.ps1` passed 16/16 on PowerShell 7.6.5/Pester 5.7.1. No utility or Windows/Defender state changed. The 4GB Patch exact-version NeedsReview/Unassigned marker is informational and does not gate package planning; owner review remains open. Windows acceptance and remaining product behavior remain deferred. No legacy outcome closes; estimates unchanged. See [structured evidence](../archive/evidence/ntcore-pe-cff-4gb-real-archive-lifecycle-2026-10-26-1854.json).

## RegRipper 3.0 real-archive lifecycle and focused regression, 2026-10-26 18:50 UTC

The retained pinned archive matched the catalog SHA-256 and passed local offline install/repeat/uninstall, present-snapshot restoration and prior-absence restoration across **282** managed files. Required files were present and operator content was preserved. `RegRipperPackage.Tests.ps1` passed **4/4** on PowerShell 7.6.5/Pester 5.7.1 with optional TestRegistry/TestResult plugins disabled. No executable ran and no hive was parsed. Windows lifecycle and synthetic-hive parser behavior remain deferred because VM and registered-task queries fail at CIM; native schtasks returns an invalid network address. No legacy outcome closes; estimates unchanged. See [structured evidence](../archive/evidence/regripper-real-archive-lifecycle-and-focused-regression-2026-10-26-1850.json).

## Sysinternals package and license-planning regression, 2026-10-26 18:36 UTC

`SysinternalsProductPackages.Tests.ps1`, `SysinternalsSuitePackage.Tests.ps1` and `LicenseReviews.Tests.ps1` passed **104/104** on PowerShell 7.6.5/Pester 5.7.1 with optional TestRegistry/TestResult plugins disabled. All ten prior-v2-approved Sysinternals package plans remain available without a licensing gate. Prior specialist approval and user clarification settle licensing for RIDE direct download-and-install; Defender-blocked tools remain separately excluded. No utility or Windows/Defender state changed, and no legacy outcome closed. VM-target acceptance remains deferred because controller access fails before inspection/dispatch. Estimates unchanged. See [structured regression evidence](../archive/evidence/sysinternals-and-license-planning-focused-current-source-regression-2026-10-26-1836.json).

## Registered VM/controller access recheck, 2026-10-26 18:25 UTC

Read-only `Get-VM` queries for `RIDE-Win11-Test` and `RIDE-S25-Test`, and the registered `\RIDE\RIDEWin11Test` task query, failed at CIM before inspection or dispatch. Native `schtasks.exe` returned `ERROR: The network address is invalid.` No guest request, VM/checkpoint, host service, Windows or Defender state changed; no elevation prompt occurred. Keep native acceptance deferred and continue independent migration work. No legacy outcome or estimate changed; ranges remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured access evidence](../archive/evidence/ride-vm-and-runner-access-recheck-2026-10-26-1825.json).

## WFN real-archive local lifecycle, 2026-10-26 18:11 UTC

The retained, pinned `20250719-ac02df` ZIP passed the current-source local lifecycle across all **531** selected members: exact required-file presence, repeat install, uninstall, present-snapshot restore, prior-absence restore and operator-content preservation. No firewall notifier executable ran. An initial runner assertion incorrectly compared 531 managed files against three required checks; read-only verification found the staged package healthy and the corrected continuation passed all steps. `tests/WfnPackage.Tests.ps1` also passed **3/3** on PowerShell 7.6.5/Pester 5.7.1, covering catalog/inventory metadata and synthetic 531-member presence/absence recovery. The exact-version local license record is **NeedsReview / Unassigned** and remains informational; it does not block package planning. Windows 11 install/recovery and notification/settings behavior remain deferred. No legacy outcome closes; estimates stay **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured evidence](../archive/evidence/wfn-real-archive-lifecycle-regression-2026-10-26-1811.json) and [VM access evidence](../archive/evidence/ride-vm-and-runner-access-recheck-2026-10-26-1749.json).

## Registered VM/controller access recheck, 2026-10-26 17:49 UTC

Read-only `Get-VM` queries for `RIDE-Win11-Test` and `RIDE-S25-Test`, plus the registered `\RIDE\RIDEWin11Test` task query, again failed at CIM before inspection or dispatch. Native `schtasks.exe` returned `ERROR: The network address is invalid.` No guest request, VM/checkpoint, host service, Windows or Defender state changed, and no elevation prompt occurred. Keep native acceptance deferred and continue independent migration work. No legacy outcome or estimate changed; ranges remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured access evidence](../archive/evidence/ride-vm-and-runner-access-recheck-2026-10-26-1749.json).

## ImageMagick real-archive lifecycle, 2026-10-26 17:47 UTC

The retained 7.1.2-34 Q16 x64 7z archive matched its catalog digest and passed current-source local staging, repeat, uninstall and present/absence snapshot recovery across 23 managed files. `magick.exe` was present and healthy; no ImageMagick code ran and no user image was opened. The existing Windows 11 package/PNG acceptance remains authoritative. Activation remains pending; Server 2025 is outside the reviewed target scope. Repository validation passed 424 operations, 8 groups, 5 profiles and 286 PowerShell files. No legacy outcome closes; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured evidence](../archive/evidence/imagemagick-real-archive-lifecycle-regression-2026-10-26-1747.json), [Windows 11 acceptance](../archive/evidence/imagemagick-win11-v14-prerequisite-and-lifecycle-acceptance-2026-10-25-0228.json), and [Server target guard](../archive/evidence/imagemagick-server2025-target-guard-2026-10-25-0221.json).

## ETL2PCAPNG real-file lifecycle, 2026-10-26 17:43 UTC

The retained, hash-pinned ETL2PCAPNG 1.11.0 executable and repository-staged MIT notice both matched their catalog digests; Authenticode was valid. The offline file lifecycle passed install/repeat/remove and both snapshot recovery checks for the two declared files, preserving operator content. No trace was read and the converter did not run. Windows 11 lifecycle and synthetic ETL conversion behavior remain deferred. No legacy outcome closes; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured evidence](../archive/evidence/etl2pcapng-real-file-lifecycle-regression-2026-10-26-1743.json).

## RawCopy real-archive lifecycle regression, 2026-10-26 17:41 UTC

The retained, hash-pinned RawCopy 1.0.0.22 ZIP passed local exact-file install/repeat/remove and both present/absence snapshot recovery checks for its four selected members. The x64 executable was staged but not run; operator content was preserved. Windows 11 lifecycle and synthetic NTFS read-only behavior remain deferred. No legacy outcome closes; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured evidence](../archive/evidence/rawcopy-real-archive-lifecycle-regression-2026-10-26-1741.json).

## Registered VM/controller access recheck, 2026-10-26 17:38 UTC

Read-only `Get-VM` queries for `RIDE-Win11-Test` and `RIDE-S25-Test`, plus the registered `\RIDE\RIDEWin11Test` task query, failed at CIM before inspection or dispatch. Native `schtasks.exe` returned `ERROR: The network address is invalid.` No guest request, VM/checkpoint, host service, Windows or Defender state changed, and no elevation prompt occurred. Repository validation passed for 424 operations, 8 groups, 5 profiles and 286 PowerShell files. Keep native acceptance deferred and continue independent work. No legacy outcome or estimate changed; ranges remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured access evidence](../archive/evidence/ride-vm-and-runner-access-recheck-2026-10-26-1738.json).

## ThreadJob real-archive lifecycle, 2026-10-26 17:34 UTC

The retained ThreadJob 2.2.0 nupkg matched its catalog SHA-256 and passed local exact-file install, repeat, uninstall, present-snapshot restore and prior-absence restore checks for all 10 required files. Operator content was preserved. The run used offline mode and did not import or execute package code. Windows runtime acceptance remains deferred; no legacy outcome closes and all estimates remain unchanged. See [structured evidence](../archive/evidence/threadjob-real-archive-lifecycle-regression-2026-10-26-1734.json).

## PSScriptTools real-archive regression, 2026-10-26 17:34 UTC

The pinned 3.2.0 PSScriptTools archive passed all **7/7** focused lifecycle tests on PowerShell 7.6.5/Pester 5.7.1, including staging all 360 reviewed members, repeat install, exact saved-state restore and preservation/refusal boundaries. The run used `.local` scratch and did not import or execute upstream code. Windows 11 file acceptance and runtime verification with the separately selected ThreadJob prerequisite remain deferred. No legacy outcome closes; estimates are unchanged at **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured evidence](../archive/evidence/psscripttools-real-archive-lifecycle-regression-2026-10-26-1734.json).

## Windows 11 and Server VM/controller access recheck, 2026-10-26 17:19 UTC

Read-only `Get-VM` queries for `RIDE-Win11-Test` and `RIDE-S25-Test` both failed at CIM before VM/checkpoint inspection. `Get-ScheduledTask` for `\RIDE\RIDEWin11Test` also failed at CIM; native `schtasks.exe` returned `ERROR: The network address is invalid.` No guest request, controller/VM/checkpoint/host service/Defender change or elevation occurred. Keep Windows 11 and Server 2025 acceptance deferred and continue independent local/source work. No legacy outcome or estimate changed. See [structured access evidence](../archive/evidence/ride-vm-and-runner-access-recheck-2026-10-26-1719.json).
## B06 client component current-source regression, 2026-10-26 17:15 UTC

`ClientComponentLifecycle.Tests.ps1`, `ClientComponentPreparation.Tests.ps1`, and `ComponentInventory.Tests.ps1` passed **67/67** on PowerShell 7.6.5/Pester 5.7.1 with Pester's TestRegistry and TestResult plugins disabled. The initial default invocation was denied when TestRegistry attempted to create an HKCU key before assertions; the successful rerun used mocks and synthetic fixtures. No DISM servicing, component change, result-file write, VM request, Defender change, elevation, or target-support promotion occurred. The 17:11 `Get-VM` query remains denied at CIM before inspection. B06 remains source-ready only; exact LocalSource completeness/dependencies, policy source behavior, recovery and native Windows acceptance remain deferred. No legacy outcome closes and estimates remain settings **37-57**, packages **40-55**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured regression evidence](../archive/evidence/client-component-current-source-regression-2026-10-26-1715.json) and [VM access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-26-1711.json).
## RIDE-Win11-Test CIM access recheck, 2026-10-26 17:11 UTC

The read-only Hyper-V query failed before inspection with Access to a CIM resource was not available to the client; checkpoint inspection was not reached. No guest dispatch, VM/checkpoint, host service, Defender state, or elevation change occurred. Keep VM acceptance deferred while advancing independent source work. No legacy outcome or estimate changed. See [structured access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-26-1711.json).
## RIDE-Win11-Test access blocker, 2026-10-26 16:47 UTC

Hyper-V and ScheduledTasks CIM queries both fail before inspection; native
`schtasks.exe` query also returns an invalid network address. No task was
launched. Keep VM acceptance deferred and continue independent source work.
See [latest access evidence](../archive/evidence/ride-win11-test-cim-and-task-scheduler-access-recheck-2026-10-26-1647.json).
## Zimmerman collection source checkpoint, 2026-10-26 16:43 UTC

The publisher's live index reconfirms the 26 selected versions and recommended
.NET 10 route. Exact archive acquisition remains blocked at DNS; no ZIP bytes
were received. VM/CIM and registered-task access remain unavailable. Do not run
the publisher updater/helper. Continue when the official archive host resolves;
keep per-tool packages, notices and acceptance pending. See [current evidence](../archive/evidence/zimmerman-current-index-and-payload-dns-recheck-2026-10-26-1643.json).
## CCleaner family source recheck, 2026-10-26 16:39 UTC

Official pages now show full CCleaner 7.13.1573 and the Portable route
`ccsetup641.zip` at version 6.41.11567; Recuva 1.55.133 and Speccy 1.34.84
remain standard-installer-only. The publisher URL could not resolve locally, so
no exact payload or digest was acquired. Keep the selected products in scope;
no license gate or estimate change. See the [current source evidence](../archive/evidence/ccleaner-family-official-source-recheck-and-dns-block-2026-10-26-1639.json).
# Remaining migration analysis and decisions
# E08 local password complexity explicit-value recovery preparation, 2026-10-26 19:36 UTC

The inert E08 candidate now prepares recovery for explicit local
`Enabled`/`Disabled` values when supplied current state matches the expected
applied value. It refuses undefined/merged/malformed observations and drift;
matching prior/current values return a no-op without acquiring ownership.
`LocalPasswordComplexityCandidate.Tests.ps1` passed 11/11 on PowerShell 7.6.5
and Windows PowerShell 5.1.26100.9711. No secedit, registry, Windows, Defender
or VM state changed. RIDE-Win11-Test/RIDE-S25-Test and registered task access
failed at CIM before inspection or dispatch; no guest request or elevation
occurred. Effective policy, NotDefined recovery, durable lifecycle, guarded
mutation and Windows 11/Server acceptance remain deferred. No legacy outcome
closed; estimates remain settings **37-57**, packages **40-55**, components
**19-24**, files/assets **25-35**, maintenance **8-12**, exact **129-183**,
rounded **130-185/about 155**. See the [structured evidence](../archive/evidence/local-password-complexity-explicit-recovery-preparation-2026-10-26-1936.json)
and [active E08 plan](remaining-settings-plan.md#current-implementation-and-validation).

## B06 Features on Demand source inventory recheck, 2026-10-26 16:15 UTC

Read-only inventory of the existing `Z:\LabSources` share found the four
previously reviewed setup ISOs and no separate Languages and Optional Features
ISO. The `OSUpdates` and `SoftwarePackages` roots contain only their README
files. No matching source is available locally to verify OpenSSH Client's CAB,
Telnet Client's payload, complete dependencies, configured-source fallback or
exact recovery. No ISO was mounted, no VM or Windows servicing operation ran,
and no Defender or host state changed. Both client components remain deferred
for source/dependency/recovery and disposable-Windows acceptance. No legacy
outcome closed; estimates remain settings **37-57**, packages **40-55**,
components **19-24**, files/assets **25-35**, maintenance **8-12**, exact
**129-183**, rounded **130-185/about 155**. See the [structured media
inventory](../archive/evidence/b06-labsources-fod-media-recheck-2026-10-26-1615.json).

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
| B04 proxy | The `windows.proxy-auto-detect` candidate is engine-integrated with a create-new pre-change snapshot, saved-run restore and completion tracking. The lifecycle compares current values, verifies readback, preserves unowned values and attempts compensation after verified partial writes. | Effective-policy coverage, snapshot authenticity and cross-process limits, controlled PAC-consumer behavior, visible GUI effect and disposable Windows acceptance. No target is supported until acceptance; RAS and WinHTTP remain distinct. |
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
| 1: B03 startup user-bin | Current-source lifecycle suite now passes 21/21 in PowerShell 7.6.5 and 21/21 in Windows PowerShell 5.1; the `UserBinPath` Windows 11 scenario is prepared. Native execution is blocked before inspection by current CIM/task access. | When VM access returns, prove intended-user ConsoleHost startup, duplicate/missing-bin behavior, repeat apply, exact prior-profile restore and refusal of unowned legacy snippets. Preserve bin contents and unrelated profile bytes. Only close the startup slice; persistent PATH, directory provisioning and WindowsApps repair stay separate. Until then, record the blocker and advance to the next independent item. Evidence: [2026-10-26 regression and access check](../archive/evidence/user-bin-current-source-regression-and-vm-access-2026-10-26-1601.json). |
| 2: B08 / application R06 PSScriptTools | Current-source local lifecycle and portable runner suites pass 46/46; no source fixture work remains. Windows request was rejected before guest staging by protected-controller prerequisite metadata, and VM/CIM access is currently unavailable. | When the controller and VM are available, verify complete files, repeat deployment, owned removal, modified-file preservation and recovery on the declared target. Do not auto-import scripts, install dependencies or infer runtime function compatibility. Reconcile the original legacy outcome before claiming closure; any required functional evidence stays open. Rufus is an additional requested tool with hardware acceptance, not the first legacy-count win. |
| 3: B10 offline deployment gate | Current source already connects byte-bound selected-profile coverage and whole-plan preflight to `install`/`apply`; five focused suites passed 234/234 on both PowerShell 7.6.5 and Windows PowerShell 5.1. Engine integration is not an open implementation task. | Remains open for a minimal reviewed disposable offline deployment, real supported-package compatibility and servicing behavior. Preserve failed staging, old bundles and saved runs. The current VM/CIM/task blocker is documented; proceed to another independent source-ready item until guest acceptance can run. See [2026-10-26 regression](../archive/evidence/offline-deployment-gate-current-source-regression-2026-10-26-1605.json). |

Next independent work: continue R05 source pinning and extraction/ownership from
official publisher evidence. The MiTeC page/version recheck now covers all 17
pending package identities; exact archives remain blocked for the shared
`www.mitec.cz` host by DNS. Do not loop on that same failed host; advance to
another independent source-ready family and return to MiTeC payload acquisition
when name resolution works. B01 presentation review is complete at 279/279;
GUI/native behavior acceptance remains separate. B03/B08 and B10 native guest
acceptance remain blocked by current VM/controller access. B06 selected client
components remain available for source/dependency work. Broader B02/B04/B07/B09
work remains backlog, not completed or abandoned because it is outside the
active queue.

### Decisions, deferrals and retained technical knowledge

The [decision ledger](decision-session-2026-10-17.md) is authoritative for Q01-Q31
and later refinements. The broad policy pass is complete. Ask only a concrete
exception supported by technical evidence, not the same general scope again.
Shared artifacts use one package; licence/activation changes remain optional and
separate. The durable rule now also lives in the [deployment model](package-deployment-decisions.md#shared-installers-and-licence-tiers).

Explicitly deferred: new deployment-profile composition/default selections;
BitLocker/recovery TPM/boot/backup/retrieval setup; optional BloodHound CE backend
deployment; standalone Neo4j/APOC is retired as an old BloodHound-bound outcome;
the MEGAcmd helper is retired; dynamic Store lists remain deferred after the
decision to validate the existing reviewed selection. Controller/default-branch certification stays at v3 RC. Entitlements,
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
| App R03 / 9 | ADReplStatus; RSAT; OpenJDK; Neo4j/APOC; BloodHound; SharpHound; AzureHound; ImproHound; PingCastle | RSAT is component-owned. CE backend is separately managed; optional deployment deferred. Standalone OpenJDK remains deferred pending an independent use case. The user retired the old BloodHound-bound Neo4j/APOC outcome on 2026-10-27; preserve existing installations/data. Planned ImproHound remains retired. The historical Neo4j contract is retained for traceability, not as a standalone v3 requirement. Q05/Q19/Q20. |
| App R04 / 6 | Office deployment; bundled Teams actions; Teams startup; Store Teams cleanup; classic machine-wide Teams cleanup; Visio | Independent product/channel/license/configuration and destructive cleanup scopes. Installing Office authorizes none of the cleanup actions. Q21. |
| App R05 / 8 | Sysinternals; JoeWare; MiTeC; NTCore; Zimmerman; Nirsoft launcher, x64 tools and package/config files | Freeze reviewed membership and file ownership; separate launch/configuration and restricted tools. No mutable collection crawl or implicit Defender exclusion. Q13/Q14. JoeWare is the latest user-selected next collection for focused review; its existing 41-name membership remains fixed. |
| App R06 / 4 | PSScriptTools; PartDiagParser; GglCookieCruncher; Sigma | Pinned release/source snapshot versus editable checkout; dependencies, import/execution and rule application are independent actions. Q15/Q18. |
| App R07 / 4 | OneDrive package; OneDrive sync policy; WinGet; WinGet AutoUpdate | Data and sync account ownership separate from uninstall. WinGet app presence does not implement a package provider. Scheduler/services/configuration and updater policy require separate ownership. Q22. |
| App R08 / 8 | VMware; its home/Documents directory choices; AutomatedLab; VirtIO; SPICE guest tools; SPICE WebDAV; Lenovo Vantage | User wants VirtIO and SPICE integrations when required for a full GNOME Boxes experience, and selected SPICE WebDAV as an optional guest-folder-sharing component on 2026-10-23. Verify devices, exact artifact and lifecycle on a matching QEMU guest; Hyper-V does not validate these. No default installation; configuration is separate from package installation. Q16/Q23. |
| App R09 / 5 | VeraCrypt installed/portable; Arsenal products; MEGAcmd helper; WinPmem | Coexistence, drivers, mount/encryption ownership and vendor access/license remain. Q24/R09 includes publisher products with a free-use scenario; licensed-only products are excluded. The user retired the separate MEGAcmd helper outcome on 2026-10-27; Arsenal product migration continues without it. Q01/Q16/Q24. |
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
| Adobe Flash and standalone Internet Explorer | User chose to keep these discovery-gated and conditional. Check actual component and supported release meaning; consider retirement only with source/applicability evidence. Existing IE ESC/IE-mode requirements remain separate. |
| Edge preload/shortcut, first run/logon, media sharing/online, developer/fullscreen controls | Reconcile earlier registry implementations with the complete legacy bundle. These are settings/consumer acceptance, not optional-feature installer work. |
| Optional Windows Media Player | Keep discovery-gated and conditional per user decision. Discover native feature versus Store Media Player; separate from radio/WMDRM consumer and multimedia group. |
| Work Folders | Keep discovery-gated and conditional per user decision. Feature/role and configured sync data/credentials have separate lifecycle. Removing the feature does not recover deleted or unsynced files. |
| Windows Hello Face | Keep discovery-gated and conditional per user decision. Capability, camera/hardware and enrollment are separate; no deletion of existing biometric enrollment through generic recovery. |
| Math Recognizer | Keep discovery-gated and conditional per user decision. Enumerate availability per build; absent capability stays not applicable. Do not fetch old payloads to emulate an obsolete component. |
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
| Supplemental README tools | User included capa/FLOSS, Detect It Easy, x64dbg, peStudio, browser utilities, HxD, Volatility Workbench and OfficeMalScanner in v3 review unless a product is end-of-life or does not work. Keep each optional and separately selectable; verify current source, product status, artifact, rights and lifecycle before support. Hash Suite Free, Ophcrack and steghide were already accepted. ThumbcacheViewer maps to App R13. No silent substitution of oletools for OfficeMalScanner. |
| SwitchyOmega / HashCalc aggregator route | Preserve disregarded original routes; a maintained proxy extension or native hashing outcome would be a separate reviewed requirement. |
| Requested v3 additions | Rufus has a [pending source candidate](application-migration-review.md#b08-rufus-portable-source-candidate-2026-10-16); idrassi HashCheck [completed Windows 11 acceptance](../archive/evidence/hashcheck-windows11-acceptance-complete-2026-10-30.json) on 2026-10-30 for the intended signed-in administrator; the two hash-context-menu options remain queued. These additions are separate from legacy estimates. No automatic media writing; attribution/algorithm/quoting/GUI and shell lifecycle need evidence. |
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
| Q08 | Answered 2026-10-27: user-bin scope | Migrate the legacy PowerShell startup-only block. Persistent user PATH remains a separate outcome; preserve directory contents on removal. |
| Q09 | Answered 2026-10-27: Terminal default profile | Discover and select an existing profile identity; own only root defaultProfile. No guessed executable/path or Terminal installation. |
| Q10 | Answered 2026-10-27: browser preference boundary | Keep user-file preference fields distinct from managed policies. Import no blanket legacy preference file; preview owned fields per existing profile. |
| Q11 | Answered 2026-10-27: asset source and scope | Use a user-supplied reviewed manifest and official license/source; start per-user where supported. Machine/default-user changes remain separate and collision-refusing. |
| Q12 | Answered 2026-10-27: Wi-Fi scope and connection behavior | Use an explicit current-user profile and interface; import without connecting. Machine/all-user provisioning remains separate. Secure credential entry and recoverable existing profile are prerequisites. |
| Q13 | Accepted: reviewed collections and later membership decisions | Follow the later Sysinternals, Zimmerman, NirSoft, JoeWare, MiTeC and NTCore scopes in the decision ledger. Pin exact member inventories; new upstream members need review. The prior RIDE v2 specialist approval covers Sysinternals in RIDE; the current package migration is not blocked by licensing. |
| Q14 | Accepted: separate local review, installation and publication | Pending local review alone does not block unattended installation. Keep exact product/version/owner assessments local; publication omits members lacking applicable redistribution review. No catalog approval default. |
| Q15 | Pinned source snapshot or editable development checkout? | Pinned inert snapshot for deployment; explicitly separate clone/update/import/execute workflows for development tools and rules. |
| Q16 | Answered 2026-10-27: driver/nested-installer integrations | Use minimum product-specific reviewed integrations; keep service, driver and reboot requirements explicit. Do not enable optional integrations by default. Preserve earlier Gpg4win/ImageMagick/Npcap decisions and collect only unresolved installer flags. |
| Q17 | Accepted: retire planned Volatility 2 deployment | Preserve selector history and all existing installations/data. Continue separately selected Volatility 3; do not claim every historical workflow is replaced. |
| Q18 | Answered 2026-10-27: rules/plugins and dependencies | Use pinned core deployment with separate explicit rule/plugin update actions; broader analyst extras selectable, with no arbitrary network execution during install. |
| Q19 | Answered 2026-10-27: BloodHound CE backend | Use Docker Desktop on a dedicated Windows 11 machine; no Windows Server backend support in v3. Keep workstation collectors/client separate. Backend provisioning, data migration, service/network activation, and native acceptance remain distinct work. |
| Q20 | Updated 2026-10-27: retire old BloodHound-bound Neo4j/APOC; planned ImproHound retirement remains | Neo4j/APOC is no longer a standalone v3 migration outcome. Preserve existing installations and data; do not remove them. The separately managed BloodHound CE 9.8.0 choice remains, with collector compatibility as technical work. |
| Q21 | Office/Visio choices accepted; technical acceptance open | Microsoft 365 Apps enterprise, Monthly Enterprise default/Current option; fresh x64/existing match/explicit x86; standard sign-in with activation-pending continuation. Separate 2016 Retail/Plan 2 Visio, en-US/da-DK exception, optional Teams and separate startup/cleanup. Extra-language compatibility and native recovery remain open. [Record](application-migration-review.md#b10-inert-office-configuration-review-2026-10-17). |
| Q22 | Accepted: OneDrive preservation and opt-in updater | Preserve accounts/sync/files. Updater defaults to an explicit package list; broad eligible-except-exclusions mode is explicit. Approved sources/pins, separate schedule, no automatic reboot or forced app closure. Eligibility, identity and upstream behavior still require implementation. |
| Q23 | Accepted priority: VMware workstation installation first; GNOME Boxes guest integrations include VirtIO and SPICE when needed for full experience | Preserve VMs/preferences; directory configuration separate with no relocation. Verify which VirtIO drivers, SPICE agent and SPICE WebDAV are required on a matching QEMU guest. Edition/source, hardware/GPU roles and native acceptance remain open; Hyper-V cannot establish QEMU guest behavior. Decision 2026-10-22. |
| Q24 | Accepted: FTK Imager, then KAPE; Arsenal products selected | Later Arsenal/KAPE entries settle scope. MEGAcmd helper is retired by the 2026-10-27 decision and is not required for Arsenal migration. Artifacts, terms, drivers and functional evidence remain. FTK source inspection found CodeMeter; no installer was executed. |
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

[Local assembly](application-migration-review.md#b10-explicit-local-offline-bundle-assembly-2026-10-17) now copies and verifies explicit sources into a new directory, retaining failed staging and old versions. Automatic planning, complete dependency/source packaging and install integration remain. Arsenal/Sysinternals scope is recorded; MEGAcmd is retired and exact CE collector compatibility remains technical work. The 2026-10-27 scope decision retires two legacy outcomes and reduces the package estimate by two; see the [current estimate](../MIGRATION-PLAN.md#estimated-remaining-migration-work).

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

## B06 Telnet setup-ISO UDF source recheck, 2026-10-26 06:03 UTC

The registered Windows 11 setup ISO was listed read-only with 7-Zip, which traversed the UDF tree without mounting or extracting the image. The 1,072 listed entries contain no Telnet-named path. `sources\sxs` exposes two Internet Explorer optional-package CABs and one NetFx3 CAB, none matching Telnet. Microsoft documents Windows 11 Features on Demand as CABs on matching Languages and Optional Features media; the inspected artifact is a setup ISO and does not establish the TelnetClient source identity. Keep the Telnet `LocalSource` gate. Next source step: locate matching Languages and Optional Features media/repository, then inspect its exact package identity, completeness and architecture/build/language fit without servicing a target. No code, catalog, VM, Windows or Defender state changed. Resolved: the registered setup ISO is not demonstrated to contain a Telnet source. Deferred: matching FOD media/repository, dependency and policy/source-order validation, exact payload recovery and Windows acceptance. No legacy outcome or estimate changed; see [structured listing evidence](../archive/evidence/telnet-fod-iso-udf-listing-recheck-2026-10-26-0603.json), [Microsoft Features on Demand media guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11), and the [component preparation guide](../windows-component-inventory.md#local-transition-runner-candidate).
## B06 Telnet registered LabSources FOD-media inventory, 2026-10-26 06:06 UTC

Read-only 7-Zip listings of all four registered LabSources ISOs (Windows 11 26100 LTSC, Windows Server 2025, and two Windows 11 26300 images) found no Telnet-named archive entry. Each ISO has only three CABs under `sources\sxs`: two Internet Explorer optional-package files and NetFx3. The `SoftwarePackages` and `OSUpdates` roots contain only README files; no separate matching Languages and Optional Features media/repository is registered in these checked roots. This inventory does not prove that no source exists elsewhere. Microsoft documents Windows 11 FOD CABs on matching Languages and Optional Features media. Keep Telnet `LocalSource` blocked until matching media is available and the exact package identity, architecture/build/language fit, repository completeness, dependencies, source policy and recovery are verified. No code/catalog or Windows/VM/Defender state changed. Resolved: available media inventory in the inspected roots. Deferred: matching FOD media and Telnet package/source lifecycle acceptance. No legacy outcome or estimate changed. See [structured inventory evidence](../archive/evidence/telnet-labsource-fod-media-inventory-2026-10-26-0606.json), [Microsoft FOD media guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11), and [component preparation guide](../windows-component-inventory.md#local-transition-runner-candidate).
## Registered VM acceptance access recheck, 2026-10-26 06:19 UTC

Read-only access to both registered targets was rechecked. `Get-VM` failed before VM or checkpoint inspection with `Access to a CIM resource was not available to the client`; the registered `RIDEWin11Test` task query returned `ERROR: The network address is invalid`. No acceptance request, guest inspection, elevation prompt or state change occurred. Keep package, setting, component and user-context acceptance deferred. Continue independent implementation, source work and local regression; do not request fresh UAC. The prior RIDE v2 specialist approval remains settled for Sysinternals direct download-and-install, and its license-planning regression passed 24/24; Defender-blocked utilities remain separate exclusions. No legacy outcome closed and all five ranges remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured VM access evidence](../archive/evidence/ride-vm-access-recheck-2026-10-26-0619.json), [Sysinternals decision/regression](../archive/evidence/sysinternals-license-disposition-reaffirmation-2026-10-26-0613.json) and [current migration estimate](../MIGRATION-PLAN.md).
## Registered VM and host WinRM access recheck, 2026-10-26 06:23 UTC

The current non-elevated session still cannot inspect the registered test environments: `Get-VM` for RIDE-Win11-Test and RIDE-Srv2025Test failed before VM/checkpoint inspection with CIM access denied, and the task query returned `ERROR: The network address is invalid`. The previously authorized `Start-Service WinRM` attempt could not find an addressable WinRM service; `sc.exe query` for WinRM, vmms and vmcompute returned access denied, so service state could not be established. No guest request or elevation prompt was made, and no host, VM, checkpoint, Defender or service state changed. Save host service and VM setup for a later elevated session; continue independent local work. No legacy outcomes closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured access evidence](../archive/evidence/ride-vm-winrm-access-recheck-2026-10-26-0623.json) and [current estimate](../MIGRATION-PLAN.md).

## ArsenalRecon source pins and release metadata via connected API, 2026-10-26 07:49 UTC

The connected GitHub API resolved immutable commit IDs for all six selected ArsenalRecon repositories and exposed their complete source-tree names. Three repositories have no GitHub releases; three list exact official ZIP names, sizes, release tags and URLs. Publisher license files identify MIT terms across all six. NetWire Log Decoder and Sdba Parser documentation calls for temporarily relaxing PowerShell execution policy; do not automate that change. The NwStacks repository tree includes unrelated sample snapshots, uploaded files and decrypted payload data, which stay excluded from automatic package membership.

The connected API did not return binary release bytes, so no ZIP hash or member inventory is verified and no package artifact is ready to declare. The source refs are resolved; exact acquisition, static archive review, implementation and inert lifecycle checks remain. No legacy outcome closed, and all five estimate ranges remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured source evidence](../archive/evidence/arsenal-open-source-github-api-pin-resolution-2026-10-26-0749.json).

## Google Analytic Cookie Cruncher artifact and local package lifecycle, 2026-10-26 07:59 UTC

Acquired the exact versioned ZIP from the immutable publisher GitHub commit via the connected Contents API. The 533,817-byte payload hash is `5a27c94887b25cb159f8f3477cb3cf73658dbcd1f77acba5643a88a1127b3922`; its three members are the managed x86 GUI, the upstream freeware/re-distribution notice, and bundled SQLite. Added a pending portable package declaration pinned to that revision and digest. Focused package Pester passed 3/3; real-artifact repeat install, exact owned-file checks, preservation of unowned output during removal, and saved-state restore passed locally without executing the app.

Resolved: exact source/archive identity and digest, file inventory, embedded version/architecture/license notice, and local portable lifecycle. Deferred: disposable Windows 11 acceptance, runtime prerequisites, and GUI behavior. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured evidence](../archive/evidence/cookie-cruncher-exact-artifact-static-review-2026-10-26-0755.json), [package operation guidance](../application-packages.md#google-analytic-cookie-cruncher-pending-package-candidate), and [current migration estimate](../MIGRATION-PLAN.md).


## ArsenalRecon Python source behavior review, 2026-10-26 08:02 UTC

At their exact pinned commits, Backstage Parser, CyberGate Log Decrypt and Gmail URL Decoder use Python standard-library modules only. Their input/output boundaries are recorded: Office cache files to selected structured outputs/logs; user-selected ciphertext to a sibling decrypted-plaintext file; and user-selected plaintext/raw data to JSON. RIDE does not inspect those files or run the utilities. The three repositories have no published release ZIPs and their exact source archives, hashes and complete member inventories remain unresolved. Preserve the MIT notices when package candidates are developed; license review is not a migration gate.

Resolved: pinned source behavior and dependency profile. Deferred: exact publisher archives/hashes, package declarations, inert lifecycle, and native acceptance. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured review evidence](../archive/evidence/arsenal-open-source-script-source-review-2026-10-26-0802.json).


## ArsenalRecon native-source behavior review, 2026-10-26 08:06 UTC

Reviewed pinned NetWire Log Decoder, Sdba Parser and NwStacks source without execution. NetWire requires elevation at runtime and reads raw volumes/devices; Sdba reads user-selected files and writes selected CSV/log output; NwStacks scans raw-device paths and logs findings. Do not automate PowerShell execution-policy changes. NwStacks repository samples, snapshots, decrypted payloads and research data remain excluded pending release member inspection. No input data was opened.

Resolved: static source behavior for all six selected ArsenalRecon tools. Deferred: exact release/source archives, SHA-256 and member inventories, package lifecycle, and Windows acceptance. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured evidence](../archive/evidence/arsenal-open-source-native-source-review-2026-10-26-0806.json).


## Component current-source regression and registered VM access, 2026-10-26 08:09 UTC

The five focused component suites passed **85/85** on PowerShell 7.6.5/Pester 5.7.1 with TestRegistry and TestResult plugins disabled and scratch files under .local/pester-temp. Windows PowerShell 5.1 parsed all 279 repository PowerShell files with zero syntax errors. The suites cover read-only inventory, OpenSSH/Telnet preparation, exact-source/recovery guards, and OpenSSH Server observation/lifecycle through mocks and ShouldProcess previews. No DISM or Server Manager provider, Windows service, firewall, VM, or guest operation ran.

A fresh read-only Get-VM request for RIDE-Win11-Test and RIDE-Srv2025Test failed before inspection with CIM access denied; the registered RIDEWin11Test task query still returns ERROR: The network address is invalid. No guest request, UAC prompt or host/VM/Windows/Defender change occurred. Resolved: current-source mocked component regression. Deferred: native Windows 11/Server 2025 integration; Telnet matching FOD media, exact source identity, dependencies, recovery and source-precedence verification. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured regression and access evidence](../archive/evidence/components-current-regression-and-vm-access-2026-10-26-0809.json).


## Cookie Cruncher runtime framework metadata, 2026-10-26 08:14 UTC

A Windows PowerShell 5.1 reflection-only metadata read confirms the pinned x86 GUI targets .NET Framework 4.0 and references the bundled System.Data.SQLite 1.0.89. No program code ran. Catalog and operator guidance record the target framework, while Windows compatibility and runtime acceptance remain pending. Focused package Pester passed 3/3.

No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured artifact evidence](../archive/evidence/cookie-cruncher-exact-artifact-static-review-2026-10-26-0755.json).
## Package planning and license-administration regression, 2026-10-26 08:23 UTC

`ApplicationPackages.Tests.ps1` and `LicenseReviews.Tests.ps1` passed **148/148** on PowerShell 7.6.5/Pester 5.7.1 with TestRegistry and TestResult disabled; the suites took 125.37 and 81.14 seconds. Repository validation passed for 416 operations, 8 groups, 5 profiles and 279 PowerShell files. These checks cover package planning and local owner/version review administration; Sysinternals stays eligible under the settled RIDE v2 specialist approval, and review markers remain informational. No installer or utility ran. Read-only `Get-VM` remains CIM-denied before inspection and the registered task query remains invalid, so guest acceptance is deferred. No legacy outcome closed. Estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured evidence](../archive/evidence/package-planning-license-regression-and-vm-access-2026-10-26-0823.json).
## Cookie Cruncher exact-version marker and pending-package coverage, 2026-10-26 08:31 UTC

Added `package.google-analytic-cookie-cruncher` version `2.0.0.1` as `NeedsReview` / `Unassigned` in the workspace-local review store. Its bundled notice permits redistribution; the reminder records owner/deployment context only and does not gate migration. A fresh exact-version join found review markers for all **34/34** currently pending package operations, with no missing or wrong-status records. The 148/148 package-planning/license regression remains current. No package or utility ran, no legacy outcome closed, and estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. VM/controller acceptance remains blocked before guest inspection. See [structured evidence](../archive/evidence/cookie-cruncher-license-marker-and-pending-package-audit-2026-10-26-0831.json).
## Registered VM/controller access recheck, 2026-10-26 08:33 UTC

Read-only `Get-VM` for RIDE-Win11-Test and RIDE-Srv2025Test again failed at CIM before VM/checkpoint inspection. The registered `\RIDE\RIDEWin11Test` task query returned `ERROR: The network address is invalid`. No guest request, checkpoint inspection/change, host service change, Defender change or elevation prompt occurred. Keep native acceptance deferred and continue local/source work. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured access evidence](../archive/evidence/registered-vm-access-recheck-2026-10-26-0833.json).
## ArsenalRecon NetWire exact release acquisition retry, 2026-10-26 08:36 UTC

The direct official v1.0.0.1 release-asset HEAD request failed before response because `github.com` did not resolve on this host. No binary bytes, digest, archive inventory, or local artifact advanced. Keep the selected package pending exact artifact review and lifecycle; no license gate or legacy outcome changed. Estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured source evidence](../archive/evidence/arsenal-netwire-release-acquisition-dns-block-2026-10-26-0836.json).
## Zimmerman immutable helper source review, 2026-10-26 08:49 UTC

Used the connected GitHub API to resolve `EricZimmerman/Get-ZimmermanTools` `master` to immutable commit `6e57e22030aee1c4e4369a87ed0f7f6ca0d76c73`, then read `Get-ZimmermanTools.ps1` and `LICENSE` at that exact ref. GitHub reports the commit signature as unverified (`unknown_key`). The source blob is `3defabe82b5ebd4ac7c365c22b41adf94c4ec788`; the license blob is `d6106bfbed0026d5f36c38b0ba56f21b1496c7c1` and says MIT, with a 2027 copyright year. Preserve that notice if adapting the helper; the year observation is not a legal or migration gate.

The source defaults to .NET 10 and accepts 9 as an alias; `-NoUpdate` suppresses its default self-update, while a sibling `.git` directory also prevents replacement. It discovers ZIP/TXT URLs from the live `https://tools.ericzimmermanstools.com` page, excludes KAPE and `All` archives, and performs up to six conditional GETs. Its CSV `SHA1` field stores HTTP ETags rather than payload digests. ZIP extraction includes a zip-slip destination check but overwrites existing files and has no selected-member allowlist, archive digest or signature verification. `-Sync` recursively executes matching EvtxECmd, SQLECmd and RECmd binaries. No script, helper, product, archive or `--sync` command was run.

A read-only HEAD request to the official `AmcacheParser` x64/.NET 10 archive route failed before response because `download.ericzimmermanstools.com` did not resolve. No product bytes, digest, archive inventory or package lifecycle advanced. The immutable helper source pin resolves the former source-identity gap only; it does not pin the selected 26 product archives or make the helper appropriate as a managed RIDE updater. No legacy outcome closed. Repository validation passed at 08:52 UTC for 416 operations, 8 groups, 5 profiles and 279 PowerShell files, and `git diff --check` passed for the focused documentation/evidence files. Estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See the [structured source review](../archive/evidence/zimmerman-helper-immutable-source-review-2026-10-26-0849.json) and the [prior 26-product version map](../archive/evidence/zimmerman-current-source-version-and-helper-recheck-2026-10-25-1446.json).
## Zimmerman current publisher-index reconciliation, 2026-10-26 08:55 UTC

Fetched the publisher's current `docs/index.md` at immutable repository commit `f3947d47f72070c2b7695859d4f746a48aca2845` (blob `38d71093176767ec50922d6f70f4351914119e82`; GitHub reports its signature unverified). The page lists 29 product tools. Every product in the accepted 26-member collection is present and its current page version exactly matches the 2026-10-25 observed map. Three page entries—`iisGeoLocate`, `TimeApp`, and `XWFIM`—are outside the accepted selection and remain unselected; the mutable page does not expand the approved scope. Its current framework guidance sets .NET 10 as the default and identifies four CLI tools as .NET-10-only. The Hasher page/route inconsistency remains: the index points to `net/hasher.zip` and the current product page reports version 2026.10.0, while the prior detail-page observation labeled the variant .NET 4.7.2. Keep Hasher's framework decision open pending exact bytes or publisher clarification.

The exact official AmcacheParser .NET 10 archive HEAD request again failed before response because `download.ericzimmermanstools.com` did not resolve. No binaries or lifecycle ran. Resolved: immutable publisher-index source pin, accepted member presence/version reconciliation, and the three out-of-selection entries. Partial: product ZIP artifacts remain unverified. Deferred: exact payloads, hashes, notices/signatures, member inventories, Hasher framework resolution and package lifecycle. No legacy outcome closed. Repository validation passed at 08:57 UTC for 416 operations, 8 groups, 5 profiles and 279 PowerShell files; the focused diff check passed. Estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See the [structured page reconciliation](../archive/evidence/zimmerman-publisher-page-revision-reconciliation-2026-10-26-0855.json), the [pinned helper review](../archive/evidence/zimmerman-helper-immutable-source-review-2026-10-26-0849.json), and the [prior 26-product version map](../archive/evidence/zimmerman-current-source-version-and-helper-recheck-2026-10-25-1446.json).
## Zimmerman Hasher framework clarified by publisher index, 2026-10-26 09:00 UTC

The latest pinned official publisher index resolves the earlier Hasher framework discrepancy: the `🖥️ Hasher` row lists no .NET 4.7.2 build and places version `2026.10.0` only in the .NET 10 column, linked to `https://download.ericzimmermanstools.com/net/hasher.zip`. The same index says GUI tools are .NET 10 only except TimeApp, which is also available for .NET 4. This is the publisher clarification allowed by the 2026-10-24 decision; set the Hasher candidate's selected framework to .NET 10 when exact artifact review proceeds.

The official Hasher archive HEAD request still fails before response because `download.ericzimmermanstools.com` does not resolve. No ZIP bytes, hash, members, notice, signature, implementation or lifecycle were obtained. Resolved: framework mapping only. Deferred: exact official archive, artifact integrity, package implementation, and target acceptance. Repository validation passed at 09:04 UTC for 416 operations, 8 groups, 5 profiles and 279 PowerShell files; `git diff --check` passed. No product legacy outcome closed and no estimate is deducted. Estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See the [framework resolution evidence](../archive/evidence/zimmerman-hasher-framework-resolution-2026-10-26-0900.json) and the [immutable publisher-page reconciliation](../archive/evidence/zimmerman-publisher-page-revision-reconciliation-2026-10-26-0855.json).
## Registered VM acceptance access recheck, 2026-10-26 09:02 UTC

Read-only `Get-VM` checks for `RIDE-Win11-Test` and `RIDE-Srv2025Test` again failed before VM/checkpoint inspection because CIM access was unavailable. The registered `\RIDE\RIDEWin11Test` task query failed before dispatch with `The network address is invalid`. No guest request, VM/checkpoint or host service change, Windows/Defender change, or elevation prompt occurred. Keep all pending native settings, package and component acceptance deferred until existing VM/controller access is available. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See the [structured current access evidence](../archive/evidence/registered-vm-access-recheck-2026-10-26-0902.json).
## Zimmerman accepted-collection framework map, 2026-10-26 09:05 UTC

At the publisher's immutable `docs/index.md` revision `f3947d47f72070c2b7695859d4f746a48aca2845`, mapped all 26 accepted collection members to the current .NET 10 download route and exact page version. Every version matches the 2026-10-25 version map. Fourteen members also publish a .NET 4.7.2 route; twelve are .NET 10 only. Select the publisher-recommended .NET 10 default consistently, including Hasher, whose current row has no .NET 4.7.2 build. Keep the three unselected current-page tools—iisGeoLocate, TimeApp and XWFIM—out of the approved selection.

This resolves framework and source-route mapping only. The official product ZIP host still fails DNS, so no archive bytes, hashes, notices, signatures or members are available; no catalog operations or package lifecycle are implemented. Repository validation passed at 09:07 UTC for 416 operations, 8 groups, 5 profiles and 279 PowerShell files; the 26-member version/framework join and focused diff check passed. No legacy product outcome closed and no estimate is deducted. Estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See the [26-product .NET 10 mapping](../archive/evidence/zimmerman-accepted-26-dotnet10-source-map-2026-10-26-0905.json), [current page reconciliation](../archive/evidence/zimmerman-publisher-page-revision-reconciliation-2026-10-26-0855.json), and [latest VM access blocker](../archive/evidence/registered-vm-access-recheck-2026-10-26-0902.json).
## Registered VM/controller blocker refresh, 2026-10-26 09:11 UTC

The latest read-only `Get-VM` check for both registered targets was denied at CIM before inspection; the registered RIDEWin11Test task query failed with an invalid network address before dispatch. No elevation, guest request, checkpoint/service/Windows/Defender change occurred. Continue independent local/source work and defer native acceptance. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured blocker evidence](../archive/evidence/registered-vm-access-recheck-2026-10-26-0911.json).
## NTCore WIM Installer candidate and estimate refresh, 2026-10-26 09:25 UTC

The retained NTCore WIM Installer archive is now represented by a pinned, one-member staging candidate. Focused package and license-review tests passed **40/40**; repository validation passed with **417 operations, 8 groups, 5 profiles and 279 PowerShell files**. The exact-version local `NeedsReview` reminder is informational and is not a package migration gate. The utility and all WIM/disk behavior remain unexecuted. Windows lifecycle/compatibility and synthetic-image behavior acceptance remain deferred because registered VM/controller access fails before inspection or dispatch. See [candidate evidence](../archive/evidence/ntcore-wim-installer-package-candidate-2026-10-26.json) and [VM/controller evidence](../archive/evidence/registered-vm-access-recheck-2026-10-26-0911.json).

No legacy outcome closed, so estimates are unchanged: settings **37-57**, packages **40-55**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **129-183**, rounded **130-185/about 155**. The rounded ranges are unchanged because the candidate adds tracked migration implementation and acceptance work without resolving a legacy product outcome.
## Current component regression and VM/controller blocker, 2026-10-26 09:30 UTC

The current `ClientComponentPreparation`, `ClientComponentLifecycle`, `ComponentInventory`, `OpenSshServerLifecycle`, `OpenSshServerObservation` and `F1Help` suites passed **92/92** on Pester 5.7.1. Registry and test-result output were disabled and scratch data stayed under `.local`. Repository validation passed for **417 operations, 8 groups, 5 profiles and 279 PowerShell files**. This is local/mock evidence only; no Windows component behavior was observed or changed.

Fresh read-only checks for `RIDE-Win11-Test` and `RIDE-Srv2025Test` again failed before VM inspection because CIM access was denied. The registered `\RIDE\RIDEWin11Test` query failed before dispatch with `The network address is invalid`. No guest request, checkpoint inspection/change, host service, Windows or Defender change, or elevation prompt occurred. Keep native component acceptance deferred while continuing independent migration work. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured regression and blocker evidence](../archive/evidence/component-focused-regression-and-vm-access-2026-10-26-0930.json) and [VM access evidence](../archive/evidence/registered-vm-access-recheck-2026-10-26-0930.json).
## Current settings regression, 2026-10-26 09:53 UTC

Current `SettingPresentation`, `RemainingSettings`, `SixtySettings`, `ProfileSettings` and `CatalogProfileValidation` Pester suites cover 266 distinct cases. The combined run passed **265/266**: the profile-file preservation/restore case encountered an exclusive-file-lock error in the combined run. Rerunning the full 37-case `ProfileSettings.Tests.ps1` suite in isolation passed **37/37**, including that case. No implementation change was made; record the combined lock as transient environment contention, not a feature acceptance failure. The lengthy `RemainingSettings` and `SixtySettings` files passed.

Pester ran with `TestRegistry` and `TestResult` disabled and scratch files under `.local`; no live Windows settings changed. Repository validation passed at 417 operations, 8 groups, 5 profiles and 279 PowerShell files after the subsequent evidence updates. These checks establish local mocked lifecycle coverage only; native user-visible behavior, exact Windows restore, policy precedence and target-specific behavior remain deferred pending disposable-VM access. No legacy setting outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured regression evidence](../archive/evidence/settings-focused-local-regression-2026-10-26-0953.json).
## Registered VM/controller access recheck, 2026-10-26 09:56 UTC

Read-only `Get-VM` for `RIDE-Win11-Test` and `RIDE-Srv2025Test` again failed before VM/checkpoint inspection with `Access to a CIM resource was not available to the client`. The registered `\RIDE\RIDEWin11Test` task query returned `ERROR: The network address is invalid` before dispatch. No guest request, checkpoint or host-service change, Windows/Defender change, or elevation prompt occurred. Keep native settings, package and component acceptance deferred and continue independent local/source work. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured access evidence](../archive/evidence/registered-vm-access-recheck-2026-10-26-0956.json).
## Exact-version marker audit for pending packages, 2026-10-26 09:59 UTC

The workspace review store now contains **72** records and exact-version `NeedsReview` entries for all **35/35** Package operations marked `PendingAcceptance`. The new record covers `package.ntcore-wim-installer` version `1.0.0.1` with owner `Unassigned`; it is informational administration and does not block package planning. No package or utility was executed and no legacy outcome closed. Estimates remain settings **37-57**, packages **40-55**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured marker audit](../archive/evidence/pending-package-license-marker-audit-2026-10-26-0959.json).
## Current package planning and license-review regression, 2026-10-26 10:05 UTC

`ApplicationPackages.Tests.ps1` and `LicenseReviews.Tests.ps1` passed **148/148** on Pester 5.7.1 with `TestRegistry` and `TestResult` disabled. These tests exercise package planning and local license-review behavior with mocked handlers/providers; no installer or utility ran. The exact-version workspace marker audit remains **35/35** with zero missing or wrong-status pending-package records. Windows installation, uninstall, recovery and product behavior remain deferred to disposable targets. No legacy outcome closed; estimates remain **37-57 / 40-55 / 19-24 / 25-35 / 8-12**, exact **129-183**, rounded **130-185/about 155**. See [structured test evidence](../archive/evidence/package-planning-license-regression-2026-10-26-1005.json) and [marker audit](../archive/evidence/pending-package-license-marker-audit-2026-10-26-0959.json).

## OpenSSH Server capability candidate current-source regression, 2026-10-27 06:55 UTC

The focused capability install/remove, observation and activation suites passed **30/30** on PowerShell 7.6.5/Pester 5.7.1 when the optional TestRegistry and TestResult plugins were disabled. The first default-plugin invocation failed before discovery because the sandbox denies access to Pester's HKCU test fixture; the configured rerun completed the suite. `tools/validate.ps1` passed for **429 operations, 8 groups, 5 profiles and 294 PowerShell files**. All native providers were mocked; no VM or Windows state changed. No legacy outcome closes. The capability candidate remains unregistered pending catalog integration and Windows 11/Server 2025 acceptance. Estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12** (exact **127-181**, rounded **125-180/about 155**). The refreshed overview and run record are in [MIGRATION-PLAN.md](../MIGRATION-PLAN.md); see also [structured evidence](../archive/evidence/openssh-server-capability-current-regression-2026-10-27-0655.json) and [current component guide](../windows-component-inventory.md#openssh-server-component-boundary).

## Registered VM/checkpoint/task access recheck, 2026-10-27 06:57 UTC

Read-only `Get-VM` and checkpoint queries for the three registered Windows targets and a query for `\RIDE\RIDEWin11Test` all failed with CIM access denied before inspection. No runner request, guest action, elevation prompt or machine/checkpoint/Defender change occurred. Keep Windows acceptance deferred and continue independent source implementation. No legacy outcome closed and all five ranges remain **37-57 / 38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured access evidence](../archive/evidence/ride-vm-access-recheck-2026-10-27-0657.json) and refreshed [migration estimates](../MIGRATION-PLAN.md).


## OpenSSH candidate cross-shell regression and VM access recheck, 2026-10-27 07:14 UTC

The three existing OpenSSH capability install/remove, observation and activation suites passed **30/30** under PowerShell 7.6.5/Pester 5.7.1 and Windows PowerShell 5.1.26100.9711/Pester 5.7.1. Repository validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell files. All providers were mocked. Fresh VM and registered-task inspection failed at host CIM before inspection or dispatch; no elevation or Windows state change occurred. The candidate remains unregistered with no supported targets. Windows 11/Server 2025 acceptance and pre-existing service/firewall/data recovery design remain open. No legacy outcome closed; estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/openssh-candidate-cross-shell-regression-and-vm-access-2026-10-27-0714.json).
## WinHTTP incomplete-state preparation refusal, 2026-10-27 07:31 UTC

E07's separate WinHTTP preparation now refuses to build a full configuration
payload if `show advproxy` omitted any of its three strings, and refuses recovery
from incomplete current state or snapshots. The focused suite passed **9/9** on
Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5/Pester 5.7.1, and
repository validation passed for 429 operations, 8 groups, 5 profiles and 294
PowerShell files. This is source-side safety progress only;
no native setter, exact literal capture, durable state, catalog integration or
Windows acceptance is claimed. VM/task inspection again failed at CIM before
inspection or dispatch. No legacy outcome closed; all five ranges remain **37-57
/ 38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**, rounded
**125-180/about 155**. See [structured evidence](../archive/evidence/winhttp-proxy-preparation-incomplete-state-guard-and-vm-access-2026-10-27-0731.json).

## WFN Nightly current-source source inventory and lifecycle status, 2026-10-27 08:49 UTC

The retained WFN archive matched the catalog pin and all 531 declared members; its focused Pester case passed 1/1. Repository validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell files. A full synthetic lifecycle rerun did not return within the bounded interactive run window and was stopped, so no result is claimed; current-source synthetic lifecycle remains open. The earlier real-archive lifecycle record remains valid for that prior run. WFN was not launched and firewall, Defender and VM state did not change. Native Windows 11 acceptance remains deferred by VM/task access failure before inspection. No legacy outcome closed; estimates stay settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/wfn-pinned-archive-current-source-inventory-2026-10-27-0849.json).

## RIDE-Win11-Test access preflight, 2026-10-27 08:56 UTC

The read-only preflight again failed before inspecting the registered VM, checkpoint or task: `Get-VM` and `Get-ScheduledTask` returned CIM access denied and `schtasks` reported “The network address is invalid.” No request, guest action, elevation or host/Windows/Defender state change occurred. Native acceptance remains deferred; continue independent source implementation and local mocked validation. No legacy outcome closed. Estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/ride-win11-test-cim-and-task-access-recheck-2026-10-27-0856.json).

## HashCheck publisher download retry and VM access, 2026-10-27 08:58 UTC

The exact catalog-declared HashCheck 2.6.3 installer request failed before transfer because the publisher hostname could not be resolved; no partial file or installer execution occurred. Its BSD-3-Clause license and NeedsReview/Unassigned reminder are informational, not migration gates. Exact artifact/signature and RIDE/Windows lifecycle remain open. The same turn's read-only VM/task preflight again failed before inspection/dispatch. No legacy outcome or estimate changed. See [HashCheck evidence](../archive/evidence/hashcheck-publisher-acquisition-dns-block-2026-10-27-0858.json), [VM access evidence](../archive/evidence/ride-win11-test-cim-and-task-access-recheck-2026-10-27-0856.json), and [migration estimates](../MIGRATION-PLAN.md).

### OpenSSH Server caller-owned run ID adapter, 2026-10-27 09:01 UTC

The guarded capability installer now accepts a caller-owned RIDE run ID and uses it for both prepared and completed snapshots. This is a recovery-contract prerequisite for engine integration; it does not register or expose the operation. The combined install/remove, observation and activation candidate suites passed **31/31** on PowerShell 7.6.5/Pester 5.7.1 with native providers mocked and optional TestRegistry/TestResult plugins disabled. No capability, service, firewall, VM, Windows or Defender state changed. The candidate remains unregistered: the engine has no Windows capability lifecycle kind yet, its current-state/apply/generic-restore paths still need adapter wiring, and activation and inbound firewall access must become separately selectable. Keep supported targets empty pending native Windows 11 and Server 2025 acceptance. No legacy outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/openssh-server-caller-runid-adapter-regression-2026-10-27-0901.json) and [latest VM/task access evidence](../archive/evidence/ride-win11-test-cim-and-task-access-recheck-2026-10-27-0856.json).

## OpenSSH service catalog projection and VM access, 2026-10-27 10:47 UTC

windows.openssh-server-service now represents sshd activation separately from installing the OpenSSH Server capability; the operation remains pending with no supported targets. The focused catalog/engine projection tests passed 4/4, generated operation documentation is current, and repository validation passed for 431 operations, 8 groups, 5 profiles and 294 PowerShell files. Read-only VM and registered-task checks for RIDE-Win11-Test failed at CIM before inspection; no request was dispatched and no guest or host state changed. Keep native Windows 11 and Windows Server 2025 acceptance deferred until VM/controller access works without fresh UAC. Firewall exposure remains independent work. No legacy outcome closed; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about 155. The user's Sysinternals disposition is also reaffirmed in this turn: RIDE v2 specialist approval settles direct download-and-install use; licensing does not block migration, while Defender exclusions remain separate. See [structured evidence](../archive/evidence/openssh-server-service-component-catalog-current-regression-and-vm-block-2026-10-27-1047.json) and [Sysinternals disposition](../archive/evidence/sysinternals-license-practical-administration-reaffirmation-2026-10-27.json).

## OpenSSH Server partial-removal recovery and VM access, 2026-10-27 11:47 UTC

Added a guarded saved-run retry for the partial state where RIDE removed the OpenSSH Server capability and service but failed to delete its own disabled TCP/22 firewall rule. It requires unchanged pre-install server data and the exact disabled rule from the completed removable run; an added test proves that an operator-reenabled rule is preserved and blocks cleanup. The capability lifecycle suite passed 16/16 under PowerShell 7 and Windows PowerShell 5.1, and all three current OpenSSH candidate suites passed 34/34 under PowerShell 7. Repository validation passed for 432 operations, 8 groups, 5 profiles and 296 PowerShell files. A fresh `Get-VM` query failed at CIM before VM inspection; no acceptance request, capability, firewall, Windows, Defender or elevation state changed. Supported targets remain empty pending native Windows 11 and Server 2025 evidence. No legacy outcome closed; estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. Sysinternals licensing remains settled with no migration gate; Defender-blocked tools remain separate exclusions. See [structured recovery/VM evidence](../archive/evidence/openssh-server-partial-removal-recovery-and-vm-block-2026-10-27-1147.json).
## Filtered NirSoft lifecycle regression and VM acceptance blocker, 2026-10-27 12:20 UTC

Both filtered collection candidates passed synthetic package install/repeat/remove/saved-run recovery on PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711 (4/4 per shell). Final-source PowerShell 7 fast metadata, Defender-exclusion and non-gating license checks passed 3/3; its long lifecycle case was not rerun after the fixture-only compression-assembly load was added. The four Defender-alerted executables remain omitted from selections and were not read or extracted. No publisher source or NirSoft executable/installer was accessed or launched. A new read-only VM query failed before inspection with host CIM access unavailable, so Windows 11 acceptance remains deferred. The exact-version NeedsReview/Unassigned entries are informational. NK2Edit's company-use note is specific to that product and use; it does not block migration of either collection. No legacy outcome or estimate changed (127-181 exact; 125-180/about 155 rounded). Sysinternals license approval remains settled from the RIDE v2 specialist review for RIDE's direct download-and-install workflow; do not reopen a distribution analysis or impose a new legal gate. See [structured NirSoft evidence](../archive/evidence/nirsoft-filtered-package-lifecycle-regression-and-vm-block-2026-10-27-1220.json), [current estimate table](../MIGRATION-PLAN.md), and [settled Sysinternals decision](../package-licensing.md#sysinternals-settled-ride-v2-approval).
## Pinned Python-source retained-archive lifecycle and VM access, 2026-10-27 12:29 UTC

Hex2text and ChromeSyncParser each passed current-source staging/repeat/saved-state recovery from their exact catalog-pinned retained archive. The combined suite passed 10/10 on PowerShell 7.6.5/Pester 5.7.1 and 10/10 on Windows PowerShell 5.1.26100.9711/Pester 5.7.1. It checked the exact hash and three-file inventory and preserved operator output through uninstall and restore; no Python code, browser database, profile, or forensic evidence was opened. Fresh read-only RIDE-Win11-Test inspection again failed at host CIM before inspection/dispatch. Windows 11 target behavior remains deferred and SupportedTargets stays empty. No legacy outcome or estimate changed (**127-181** exact; **125-180/about 155** rounded). Sysinternals' prior specialist approval remains settled for RIDE's direct-download-and-install workflow without a license gate; Defender exclusions remain separate. See [structured evidence](../archive/evidence/python-source-current-artifact-lifecycle-and-vm-block-2026-10-27-1229.json) and the [current estimate table](../MIGRATION-PLAN.md).
## BitLocker policy candidate target correction and VM access, 2026-10-27 12:40 UTC

The three modern future-encryption registry operations keep the XTS-AES 256
default-profile intent and all four AES/XTS values, but now correctly declare
Windows 11 only as a candidate with no supported target until native policy
acceptance. Focused settings tests passed 3/3 in PowerShell 7.6.5 and 3/3 in
Windows PowerShell 5.1.26100.9711; the targeted legacy-selector catalog case
passed 1/1. The broader 98-test run had 97 passes and one unrelated sandbox
denial on direct registry security-descriptor access. Repository validation
passed for 432 operations, 8 groups, 5 profiles and 296 PowerShell files;
generated operation documentation is current. `Get-VM` again failed at CIM
before target inspection or dispatch. No setting, drive, VM, Defender or
elevation state changed. No legacy outcome or estimate changed. See
[structured evidence](../archive/evidence/bitlocker-policy-target-candidate-correction-and-acceptance-regression-2026-10-27-1240.json)
and the [current estimate table](../MIGRATION-PLAN.md).

## BitLocker target guard cross-shell regression, 2026-10-27 12:48 UTC

The three modern BitLocker drive-type policy operations remain Windows 11 candidates with no supported targets pending native policy acceptance. Added an engine-level fail-closed regression: with the platform mocked as Windows 11, Invoke-RidePlan -WhatIf rejects all three XtsAes256 requests as unsupported before reaching the registry handler. The focused policy suite passed 4/4 in PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711; the targeted legacy selector identity case passed 1/1. Repository validation passed for 432 operations, 8 groups, 5 profiles and 296 PowerShell files. A broader 98-test catalog/policy invocation had 97 passes and one unrelated sandbox denial reading a registry security descriptor. Generated operation documentation is current. Fresh VM access remains blocked before inspection by host CIM, so Group Policy precedence, native behavior and saved-state restoration remain pending. No Windows, drive, host or Defender state changed and no elevation was requested. No legacy outcome closed; estimates remain unchanged. See [structured evidence](../archive/evidence/bitlocker-policy-apply-guard-and-cross-shell-regression-2026-10-27-1246.json).
## RIDE-Win11-Test CIM access recheck, 2026-10-27 12:51 UTC

Read-only `Get-VM -Name RIDE-Win11-Test` again failed before VM/checkpoint inspection with `Access to a CIM resource was not available to the client.` No task query, acceptance dispatch, elevation request, or host/guest/Defender state change occurred. Pester 5.7.1 is available locally for focused suites, so local/source batches can continue while native acceptance waits for host CIM access. No legacy outcome changed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured access evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-27-1251.json) and [migration plan](../MIGRATION-PLAN.md).

## B06 OpenSSH Client/Telnet current-source cross-shell regression, 2026-10-27 12:58 UTC

The focused component preparation, lifecycle and inventory suites passed 67/67 in PowerShell 7.6.5 and 67/67 in Windows PowerShell 5.1.26100.9711. DISM was mocked; no target state changed. Current Microsoft references confirm the OpenSSH Client non-satellite CAB and release-matched media boundary. Telnet LocalSource remains refused. The candidate remains unregistered, unsupported and pending native source/dependency/recovery acceptance. Host CIM still blocks VM inspection/dispatch. No legacy outcome or estimates changed (127-181 exact; 125-180/about 155 rounded). See [structured evidence](../archive/evidence/b06-client-component-cross-shell-current-source-regression-and-vm-block-2026-10-27-1258.json) and [VM blocker](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-27-1251.json).

## Hyper-V Manager read-only UI access recheck, 2026-10-27 13:02 UTC

Hyper-V Manager was listed as a running `mmc.exe` window, but the Computer Use helper reported limited accessibility because the target window has higher Windows integrity. Its screenshot capture was blank, with no readable VM or checkpoint state. No window activation, input, VM selection, checkpoint inspection, request dispatch, elevation or system-state change occurred. This UI path does not resolve the existing `Get-VM` CIM access denial. Native acceptance remains deferred; local/source work can continue. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [UI access evidence](../archive/evidence/ride-hyperv-manager-ui-integrity-access-recheck-2026-10-27-1302.json) and [host CIM evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-27-1251.json).

## Filtered NirSoft current-source cross-shell regression, 2026-10-27 13:45 UTC

The filtered NirLauncher and x64-tools package candidates passed their full
current-source suites, 4/4 on PowerShell 7.6.5 and 4/4 on Windows PowerShell
5.1.26100.9711. Tests revalidated both member inventories, the four Defender
exclusions and synthetic repeat/saved-state/uninstall/restore behavior. No
alerted executable, retained publisher archive, utility, VM, or Windows state
was accessed. Both candidates remain pending native Windows acceptance with
SupportedTargets empty; host CIM continues to block VM inspection and
dispatch. No legacy outcome or estimate changed (**127-181** exact;
**125-180/about 155** rounded). See [structured evidence](../archive/evidence/nirsoft-filtered-current-source-cross-shell-regression-2026-10-27-1345.json).

## NTCore WIM Installer retained-archive cross-shell lifecycle, 2026-10-27 13:50 UTC

The exact retained WIM Installer archive passed the focused staging and
recovery tests **2/2** on PowerShell 7.6.5 and **2/2** on Windows PowerShell
5.1.26100.9711. Only its selected executable was staged under isolated test
directories; the executable, WIM and disk were not accessed. SupportedTargets
remains empty and native acceptance remains deferred behind the existing VM
access blocker. No legacy outcome or estimate changed (**127-181** exact;
**125-180/about 155** rounded). See [structured evidence](../archive/evidence/ntcore-wim-installer-retained-archive-cross-shell-regression-2026-10-27-1350.json).
## NTCore Unpacker/DynLogger package preparation, 2026-10-27 14:10 UTC

Added pinned x86/x64 portable candidates for .NET Generic Unpacker and
DynLogger. The focused retained-archive lifecycle passed **8/8** in Windows
PowerShell 5.1.26100.9711 and **8/8** in PowerShell 7.6.5 after redirecting
Pester scratch to repository `.local` and disabling registry/result plugins.
The tests checked all four exact archive hashes/member lists and exercised
repeat staging and saved-state restore. No utility or target process was run.
Version-specific license-review markers are informational, not migration
gates. Windows 11 target acceptance remains pending and `SupportedTargets` is
empty. No legacy outcome closed; estimates remain settings **37-57**, packages
**38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**,
exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/ntcore-unpacker-dynlogger-portable-candidate-regression-2026-10-27-1410.json).

## NTCore SNSRemover stage-only candidate, 2026-10-27 14:15 UTC

Added a pinned x86 package candidate for SNSRemover that selects only
`SNSRemover.exe`; the nested `PE_Detective.zip` has a different, older hash
and remains excluded. The catalog version key is the publisher's 2005-11-29
listing date because the executable has no file/product version. The retained
archive lifecycle suite passed **10/10** on Windows PowerShell 5.1.26100.9711
and **10/10** on PowerShell 7.6.5. No utility ran and no assembly was opened or
modified. A fresh read-only VM query failed at CIM before inspection; target
acceptance remains pending. The exact-version license-review marker is
informational and does not gate migration. No legacy outcome closed and
estimates remain unchanged. See [structured evidence](../archive/evidence/ntcore-snsremover-portable-candidate-regression-2026-10-27-1415.json).
## Pending-package license marker coverage refresh, 2026-10-27 14:20 UTC

A read-only join across all pending package operations and their declared
variants found **41 pending operations / 50 exact-version selections**. The
workspace-local review store has a matching `NeedsReview` entry for every
selection (**50/50**, zero missing, duplicate or wrong-status matches). These
markers are administrative; no license entitlement was inferred and none
blocks package migration. `Catalog.Tests.ps1` plus
`LicenseReviews.Tests.ps1` passed **118/118** with one registry-only
WindowsIntegration case excluded because this sandbox denies registry access.
Repository validation passed for **435 operations, 8 groups, 5 profiles and
297 PowerShell files**. No store/catalog data, Windows state or Defender state
changed and no legacy outcome closed. See [structured audit](../archive/evidence/pending-package-license-marker-audit-2026-10-27-1420.json).
## NTCore NoDel stage-only candidate, 2026-10-27 14:25 UTC

Added a pinned x86 portable candidate that stages only `NoDel.exe` and
`nodel.sys`; source/project files remain excluded. The archive hash and full
inventory were checked. Its focused package lifecycle passed **12/12** on
Windows PowerShell 5.1.26100.9711 and **12/12** on PowerShell 7.6.5, without
running the utility, loading the driver, creating a service or attempting a
file-operation hook. The publisher listing date is used as the catalog version
key because binary version metadata is not verified. The exact-version
`NeedsReview` marker does not gate migration. Windows 11 remains a candidate
only; driver compatibility and functional behavior remain pending a separately
attended disposable-VM scenario. A fresh VM query failed at CIM before
inspection. No legacy outcome closed and estimates remain unchanged. See
[structured evidence](../archive/evidence/ntcore-nodel-portable-candidate-regression-2026-10-27-1425.json).
## Pending-package license marker coverage refresh, 2026-10-27 14:25 UTC

After adding NoDel, a read-only join across all pending package operations and
their declared variants found **42 pending operations / 51 exact-version
selections**. The workspace-local review store has a matching `NeedsReview`
entry for every selection (**51/51**, zero missing, duplicate or wrong-status
matches). The markers are administrative and do not block package migration.
The focused catalog/license regression passed **118** tests with one registry-only
WindowsIntegration case excluded because sandbox registry access is denied.
Repository validation passed for **436 operations, 8 groups, 5 profiles and
297 PowerShell files**. No review-store or Windows state changed and no legacy
outcome closed. See [structured audit](../archive/evidence/pending-package-license-marker-audit-2026-10-27-1425.json).

## MiTeC EXE Explorer and HexEdit focused route regression, 2026-10-27 15:54 UTC

Prepared the `MiTeCAnalysisTools` portable route for the pinned EXE Explorer
3.7.5 and HexEdit 7.1.0 candidates. It selects the exact archive members and
checks only repeat staging/removal, saved-state recovery, and owned-file
preservation. It launches neither program and does not exercise EXE analysis,
VirusTotal/network behavior, process memory or raw disks. The guest target
guard remains Windows 11; both catalog entries keep empty `SupportedTargets`
and `PendingAcceptance = true` until native acceptance and their separate
synthetic-file feature checks are complete.

The focused portable-selection and automation suites passed **183/183** with
**2 skipped**, Pester 5.7.1; `WindowsIntegration` and optional TestRegistry /
TestResult plugins were disabled and temporary files stayed in `.local`. The
first run exposed one missing capability in a forwarding-test fixture; after
correcting that fixture, the final run passed. PowerShell parsing and both
runner version commands passed. A fresh read-only `Get-VM -Name RIDE-Win11-Test`
check failed with CIM access denied before VM/checkpoint inspection.
`MiTeCAnalysisToolsV1` must be added by the deferred protected-controller
refresh before dispatch. No request, archive download, install, utility launch,
Defender change, or UAC prompt occurred. No legacy outcome closed; estimates
remain settings **37-57**, packages **38-53**, components **19-24**,
files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded
**125-180/about 155**. See [structured evidence](../archive/evidence/mitec-analysis-tools-focused-route-regression-2026-10-27-1554.json)
and the [Sysinternals license clarification](../archive/evidence/sysinternals-license-practical-administration-reaffirmation-2026-10-27-1554.json).

## MiTeC System Information eXtra and TAPI Monitor focused route regression, 2026-10-27 16:04 UTC

Prepared `MiTeCSystemAndTelephony` for `package.mitec-system-information`
16.0.0 and `package.mitec-tapi-monitor` 1.2.0. The fixed portable route
selects the catalog-pinned archive and package files, then checks repeat
staging/removal, saved-state recovery, and preservation of unrelated or modified
files. It does not launch either program, generate or retain system reports,
query host inventory, access a TAPI provider, inspect calls, or make/alter calls.
The exact local archives were rehashed at **10,635,839 bytes** and **2,015,874
bytes**; both match their catalog pins. Created the ignored local input
`.local/acceptance-input/MiTeCSystemAndTelephony.json`; the route resolver
accepted exactly the two selected IDs and hashes.

The runner, controller automation, candidate staging and license-planning
regression passed **215/215** with **2 skipped**, Pester 5.7.1. The
`WindowsIntegration` tag and optional TestRegistry / TestResult plugins were
disabled; temporary files stayed under `.local`. PowerShell parsing, all four
runner/registration version commands, and focused diff checks passed. A fresh
read-only `Get-VM -Name RIDE-Win11-Test` failed with CIM access denied before
VM/checkpoint inspection. The registered controller must receive
`MiTeCSystemAndTelephonyV1` in the deferred elevated refresh before dispatch.
No task was queued, archive downloaded, package installed, utility launched,
report created, TAPI provider accessed, Defender setting changed, or UAC prompt
requested. Resolved: exact source pins and local route preparation. Retired:
none. Excluded: none in this batch. Partial: no whole legacy package outcome is
accepted. Deferred: Windows 11 package lifecycle and recovery, System Information
report-field/redaction review, simulated TAPI provider behavior, and protected
controller refresh. No legacy outcome closed; estimates remain settings
**37-57**, packages **38-53**, components **19-24**, files/assets **25-35**,
maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See
[structured evidence](../archive/evidence/mitec-system-information-tapi-focused-route-regression-2026-10-27-1604.json)
and the [pinned candidate evidence](../archive/evidence/mitec-system-information-tapi-package-candidates-2026-10-23-1218.json).

## MiTeC System Information eXtra and TAPI Monitor real-archive lifecycle, 2026-10-27 16:07 UTC

Extended the candidate test with an explicit retained-archive path for each
product. The actual catalog-pinned archives passed ZIP member-inventory and
SHA-256 checks, repeat offline staging, owned-file removal and saved snapshot
restore; a synthetic operator note survived removal and restoration. The focused
`MiTeCSystemInformationTapiMonitor.Tests.ps1` run passed **6/6**, Pester 5.7.1,
with both retained archives explicitly supplied. This supplements the synthetic
fixture and controller-route regression. It does not launch either utility,
query the host inventory, create a system report, contact a TAPI provider, or
access a phone line/call.

Windows 11 lifecycle remains pending because `RIDE-Win11-Test` is inaccessible
at CIM before VM/checkpoint inspection. The controller capability refresh stays
for a later elevated session. No legacy outcome closed; the exact ranges remain
**37-57 / 38-53 / 19-24 / 25-35 / 8-12**, total **127-181**, rounded
**125-180/about 155**. See [real-archive evidence](../archive/evidence/mitec-system-information-tapi-real-archive-lifecycle-2026-10-27-1607.json),
[route and controller regression](../archive/evidence/mitec-system-information-tapi-focused-route-regression-2026-10-27-1604.json),
and [source/member review](../archive/evidence/mitec-system-information-tapi-static-review-2026-10-20.json).

## MiTeC Windows File Analyzer and Icon Explorer retained-archive lifecycle, 2026-10-27 16:14 UTC

The retained WFA 2.10.0 and Icon Explorer 5.3.0 archives passed exact archive
and selected-member hash checks, repeated offline staging, removal, and saved
state restore in both PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711.
Each focused run passed **6/6** tests with Pester 5.7.1. The default optional
TestRegistry fixture initially failed before discovery due to sandbox registry
access; the reruns disabled TestRegistry and TestResult and passed.

No executable ran, no host forensic artifact was opened, and no icon was
extracted. The current read-only RIDE-Win11-Test check failed at CIM before VM
inspection. Windows lifecycle acceptance and the separate synthetic behavior
checks remain pending. No legacy outcome closed; estimates remain **37-57 /
38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**, rounded **125-180/about
155**. See [evidence](../archive/evidence/mitec-historical-file-tools-real-archive-lifecycle-2026-10-27-1614.json).

## MiTeC OLE/COM Explorer, Registry Recovery and SMBIOS real-archive lifecycle, 2026-10-27 16:16 UTC

OLExp 1.4.0.0, WRR 3.1.3 and SMBE 1.8.0 passed retained-archive hash and
member verification, repeated offline staging, removal and saved-state restore
in PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711. The focused Pester
run passed **9/9** in each edition. No COM server, registry hive, firmware
source or utility was accessed. Fresh VM access remains blocked at CIM before
inspection; Windows acceptance and the separate synthetic behavior cases are
pending. No legacy outcome closed; estimates remain **37-57 / 38-53 / 19-24 /
25-35 / 8-12**, exact **127-181**, rounded **125-180/about 155**. See
[evidence](../archive/evidence/mitec-review-data-tools-real-archive-lifecycle-2026-10-27-1616.json).

## MiTeC Network Scanner and Interbase Query real-archive lifecycle, 2026-10-27 16:20 UTC

NetScanner 6.1.0 and IBQ 9.5.0 passed retained archive hash and member
verification plus x86/x64 repeat staging, uninstall and recovery. The focused
tests passed **6/6** on PowerShell 7.6.5 and **6/6** on Windows PowerShell
5.1.26100.9711. No utility launched, no scan traffic was sent and no database
was contacted. VM access is still blocked at CIM before inspection. Windows
acceptance and the separate isolated-network/synthetic-database behavior tests
remain pending. No legacy outcome closed; estimates remain **37-57 / 38-53 /
19-24 / 25-35 / 8-12**, exact **127-181**, rounded **125-180/about 155**. See
[evidence](../archive/evidence/mitec-network-interbase-real-archive-lifecycle-2026-10-27-1620.json).

## MiTeC Task Manager DeLuxe real-archive lifecycle, 2026-10-27 16:23 UTC

TMX 5.1.1 passed retained archive/member hash checks and x64/x86 repeat
staging, removal and saved-state restore. The focused test passed **3/3** in
PowerShell 7.6.5 and **3/3** in Windows PowerShell 5.1.26100.9711. No program
ran and no live process/service data or sensitive information was accessed.
VM access remains blocked at CIM before inspection; Windows and synthetic UI
acceptance remain pending. No legacy outcome closed; estimates remain
**37-57 / 38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**, rounded
**125-180/about 155**. See [evidence](../archive/evidence/mitec-task-manager-deluxe-real-archive-lifecycle-2026-10-27-1623.json).

## MiTeC DFM Editor Delphi variants real-archive lifecycle, 2026-10-27 16:26 UTC

DFMEdit.zip passed its archive and 18-member hash checks. Both actual nine-file
Delphi variants passed repeat staging, uninstall and recovery in PowerShell
7.6.5 and Windows PowerShell 5.1.26100.9711: 7/7 tests per shell. Runtime
families 280 and 290 remained isolated; no executable or BPL was loaded.
Windows acceptance and synthetic DFM/PE behavior remain pending because VM
access fails at CIM before inspection. No legacy outcome closed; estimates
remain **37-57 / 38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**, rounded
**125-180/about 155**. See [evidence](../archive/evidence/mitec-dfm-editor-real-archive-lifecycle-2026-10-27-1626.json).

## MiTeC EXE Explorer and HexEdit real-archive lifecycle, 2026-10-27 16:29 UTC

EXE Explorer 3.7.5 and HexEdit 7.1.0 passed real archive/member hash checks and
repeat staging, removal and saved-state restore in both PowerShell editions.
The focused suite passed **10/10** in PowerShell 7.6.5 and Windows PowerShell
5.1.26100.9711. Neither program ran and no PE, network, process memory or raw
disk was accessed. VM access remains blocked at CIM before inspection; Windows
and synthetic feature acceptance remain pending. No legacy outcome closed;
estimates remain **37-57 / 38-53 / 19-24 / 25-35 / 8-12**, exact **127-181**,
rounded **125-180/about 155**. See [evidence](../archive/evidence/mitec-analysis-tools-real-archive-lifecycle-2026-10-27-1629.json).

## MiTeC SQLite Query real-archive cross-shell lifecycle, 2026-10-27 16:31 UTC

SQLite Query 3.2.0 passed the retained archive SHA-256 and selected-member
hash/length checks. `MiTeCSqliteQuery.Tests.ps1` passed **3/3** in PowerShell
7.6.5 and **3/3** in Windows PowerShell 5.1.26100.9711. The exact three-file
package passed repeat staging, removal and saved-state recovery while
preserving an operator note. No utility launched and no database, SQL or user
data was accessed. `Get-VM -Name RIDE-Win11-Test` remains blocked at CIM before
inspection. Windows lifecycle and synthetic database behavior/provenance
remain pending; `SupportedTargets` stays empty. No legacy outcome closed and
estimates remain settings **37-57**, packages **38-53**, components **19-24**,
files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded
**125-180/about 155**. Sysinternals licensing is settled by prior RIDE v2
specialist approval for direct download-and-install; Defender exclusions stay
separate. See [evidence](../archive/evidence/mitec-sqlite-query-real-archive-cross-shell-2026-10-27-1631.json)
and [Sysinternals decision](../archive/evidence/sysinternals-license-practical-administration-reaffirmation-2026-10-27-1554.json).

## Hyper-V UI integrity and VM access recheck, 2026-10-27 16:36 UTC

Read-only VM queries for both registered targets failed before inspection at
CIM. Hyper-V Manager's target window reports higher Windows integrity than the
computer-use helper, so its VM/checkpoint content could not be read; activation
failed. No VM/checkpoint, Windows or Defender state changed and no elevation
was requested. Windows acceptance and protected-controller dispatch remain
deferred; local work remains available. See [structured evidence](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json).

## License planning and Sysinternals cross-shell regression, 2026-10-27 16:45 UTC

The current-source `LicenseReviews.Tests.ps1` suite passed **24/24** in
PowerShell 7.6.5. In Windows PowerShell 5.1.26100.9711, the full suite passed
**23/24**; the sole failure was an intermittent `File.Replace` error in the
synthetic review-store case for pending-package planning. That case passed
**1/1** on a focused rerun. All ten prior-v2-approved Sysinternals install
plans passed in both shells with no license gate. No install, utility,
publisher request or Windows/Defender change occurred. No legacy outcome
closed and estimates remain **127-181** exact, **125-180/about 155** rounded.
See [evidence](../archive/evidence/license-review-plan-current-source-cross-shell-2026-10-27-1645.json),
[Sysinternals decision](../archive/evidence/sysinternals-license-practical-administration-reaffirmation-2026-10-27-1554.json),
and [VM/UI blocker](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json).

## User scope decisions, 2026-10-27

The user chose to keep `DisableWSUS`/`EnableWSUS`, `InstallEntraConnect`, and
`InstallNucleusKernelFATNTFS` in future review rather than add them to v3 scope.
The Nucleus preset spelling reconciliation remains as recorded above; this
decision covers scope only.

The user included capa/FLOSS, Detect It Easy, x64dbg, peStudio, browser
utilities, HxD, Volatility Workbench and OfficeMalScanner in v3 review unless
the product is end-of-life or does not work. Each remains optional and
individually selectable. This scope decision does not waive product-specific
source, artifact, rights, lifecycle or Windows acceptance requirements, and
does not authorize automatic execution. Already accepted Hash Suite Free,
Ophcrack and steghide remain settled. The user also chose to keep Flash and
standalone IE toggles, optional Windows Media Player, Work Folders, Windows
Hello Face and Math Recognizer discovery-gated and conditional pending
component/build applicability evidence.

No function or component was implemented or activated, and no legacy outcome
or estimate changed. See the [custom RIDE dispositions](custom-ride-dispositions.md#readme-only-candidate-reconciliation)
for product-level review notes.
## NirSoft PasswordScan temporary-workspace Defender alert, 2026-10-27 19:35 UTC

The user reported a Microsoft Defender block alert for
`NirSoft/x64/passwordscan.exe` under the temporary filtered Pester workspace
`.local/nirsoft-encrypted-launcher-filtered-pester-tmp`. The alert did not
include a detection name. Both PasswordScan architecture paths were already
omitted from the NirLauncher `PortableMembers` candidate. The current Pester
source asserts that blocked names are absent from `PortableMembers`, and the
encrypted-ZIP handler selects those exact members. Keep both names excluded;
do not restore, extract, inspect, run, allow, or add a Defender exclusion for
the reported file. This does not establish the alert's cause or classify the file.

Source trace, 2026-10-27 21:26 UTC: the `RIDE-Portable-<guid>` path segment
matches the stage directory created by `Install-RidePortablePayload` under the
process TEMP directory. Current encrypted-ZIP extraction requests only the
catalog's exact `PortableMembers`, and current NirLauncher metadata excludes
both PasswordScan paths. The reported file was absent in a metadata-only path
check. This identifies the staging mechanism, but not the creating run or the
catalog revision it used; stale metadata or an earlier run remains possible.
Keep real-archive lifecycle deferred and use synthetic fixtures until run
provenance is established. No file contents/hash, process identity, Defender
history, or alert classification was obtained.

No VM, Windows, or Defender setting changed; no package was committed and no
legacy outcome closed. All estimates remain 37-57 / 38-53 / 19-24 / 25-35 /
8-12, exact 127-181, rounded 125-180/about 155. See [alert evidence](../archive/evidence/nirsoft-passwordscan-temp-defender-alert-2026-10-27-1935.json).
## NirSoft package-scoped filter regression, 2026-10-27 19:54 UTC

The user repeated the exact x64 PasswordScan temporary-path alert already
recorded at 18:35 UTC; no detection name was supplied. The repeated notification
does not establish a new file or how the previous temporary output was created.
The reported path remains a blocker for retained NirLauncher archive lifecycle.

The first focused Pester attempts were not accepted as validation: the optional
TestRegistry plugin hit the sandbox's HKCU denial, and a shared blocked-name test
set incorrectly treated x64 NetPass as excluded even though the x64 candidate's
source evidence omits only ProduKey.exe and WirelessKeyView.exe. The test now
checks exclusions per package and asserts before staging; its synthetic lifecycle
uses RequiredFiles plus one safe representative, while the catalog test still
checks the complete selected inventory. With TestRegistry and TestResult plugins
disabled and workspace-local TEMP/TMP, the focused suite passed **4**, failed **0**,
and skipped **1** (retained publisher archives were not enabled). Repository validation passed for 438 operations, 8 groups, 5 profiles and 297 PowerShell files. No publisher
archive, utility, VM, Defender setting or Windows state was accessed or changed.

Resolved: package-scoped test expectations and pre-staging guard. Deferred:
reconcile the origin of the repeated PasswordScan temp path before another retained
NirLauncher archive lifecycle run; disposable Windows acceptance remains blocked
at host CIM before VM inspection. No legacy package outcome closed; estimates remain
37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about 155.
See [regression evidence](../archive/evidence/nirsoft-package-scoped-filter-regression-2026-10-27-1954.json),
[repeated alert evidence](../archive/evidence/nirsoft-passwordscan-temp-defender-alert-2026-10-27-1935.json),
and [prior path record](../archive/evidence/nirsoft-defender-filtered-retry-incomplete-2026-10-27-1835.json).

## B06 OpenSSH Client LocalSource removal guard, 2026-10-27 21:15 UTC

Extended the unregistered OpenSSH Client candidate so removal is refused in Online
mode and requires a validated native-architecture CAB whose CBS identity matches
the target Windows build. The saved machine-state record includes the source mode,
source path, package identity, architecture and SHA-256; restore revalidates those
values before restoring either a present or absent prior state. Added focused cases
for LocalSource removal and restore, Online refusal, and wrong-build refusal. No
servicing command, CAB acquisition, VM, Defender state or elevation was used.

Repository validation passed for 438 operations, 8 groups, 5 profiles and 297
PowerShell files. The focused Pester suite was not run: this shell has Pester 3.4.0,
while the repository's component suite requires Pester 5.7.1. No legacy outcome
closed, retired or excluded. Partial: LocalSource CAB identity/build recovery is
implemented but not regression-executed in this environment. Deferred: repository
completeness and dependencies, policy-configured source fallback, exact payload/version
recovery, and Windows 11/Server acceptance. The candidate remains unregistered and
has no supported targets. Estimates remain settings **37-57**, packages **38-53**,
components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**,
rounded **125-180/about 155**. See [component operator guidance](../windows-component-inventory.md)
and [cross-shell baseline](../archive/evidence/b06-client-component-cross-shell-current-source-regression-and-vm-block-2026-10-27-1258.json).

## JoeWare AdMod current publisher source recheck, 2026-10-27 21:30 UTC

The official AdMod page and publisher version list both identify version
1.29.00 dated June 8, 2026. The version-list header's 2023 date is a file-level
header, not the date of the AdMod row. Publisher documentation confirms that
AdMod changes Active Directory/ADAM/LDAP objects, including security descriptors,
passwords and recursive tree operations; it warns that these operations can be
dangerous and recommends a test lab. This behavior review adds no RIDE target
support and does not authorize use against a live directory.

No ZIP was acquired, no download form was submitted, and no local hash or member
inventory was verified; the known publisher DNS acquisition blocker was not
retried. Exact artifact identity, catalog lifecycle/recovery, and synthetic
directory behavior in a disposable AD/AD LDS lab remain open. The commercial-
packager note remains informational owner administration if an exact catalog
identity is later admitted; it is not a migration or install-planning gate.
AdFind remains excluded while Defender-blocked. No legacy outcome closed and
estimates are unchanged at 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact
127-181, rounded 125-180/about 155. See [source evidence](../archive/evidence/joeware-admod-current-publisher-source-recheck-2026-10-27-2130.json),
[earlier focused AdMod review](../archive/evidence/joeware-admod-focused-source-review-2026-10-25-0907.json)
and [acquisition policy](../../tools/joeware-acquisition-policy.json).

## JoeWare UserDump, DNSSrvRec and ELDLLEx source recheck, 2026-10-27 21:32 UTC

The UserDump publisher page now exposes its purpose and legacy platform list.
Its Current Version section says 1.01.00, while Version History says 2.02.00
on the same date; the publisher version-list row agrees with 1.01.00. Preserve
the discrepancy until exact archive contents can be reviewed. No UserDump data
or directory was accessed.

The web reader returned cache misses for the DNSSrvRec and ELDLLEx pages; this
does not prove a publisher outage or changed page. The frozen inventory records
DNSSrvRec as 1.00.00 in both the product-page and version-list fields, and
ELDLLEx as `1.00.0` versus `01.00.00`, with no publisher digest values for
ELDLLEx. Exact ZIP identity remains required. No downloads, extraction, payload
execution, VM/Windows state change or Defender change occurred. AdFind remains
excluded while Defender-blocked. No legacy outcome closed; estimates remain
37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about
155. See [source evidence](../archive/evidence/joeware-userdump-dnssrvrec-eldllex-source-recheck-2026-10-27-2132.json)
and [version-discrepancy register](../joeware-version-discrepancies.md).

## B06 Client components Windows PowerShell current-source regression, 2026-10-28 03:53 UTC

The focused `ClientComponentPreparation`, `ClientComponentLifecycle` and
`ComponentInventory` suites passed **70/70** in Windows PowerShell
5.1.26100.9711 with Pester 5.7.1. Pester's TestRegistry and TestResult plugins
were disabled and temporary output used `.local`. Coverage includes OpenSSH
Client LocalSource CAB validation/removal/restore, refusal of unsafe Telnet
source/removal paths, and mocked read-only inventory. No DISM command ran and
no VM, checkpoint, Windows/Defender state, elevation or supported-target
declaration was involved.

Resolved: current-source mocked regression execution. Partial: OpenSSH Client
LocalSource recovery guards and component inventory are implemented and now
regression-tested in Windows PowerShell; the PowerShell 7 current-source run
remains at the prior 67/67 because Pester 5.7.1 is unavailable in that shell.
Deferred: complete matching FoD source/dependency proof, servicing-policy
fallback and offline-boundary verification, exact payload/version recovery,
and Windows 11/Server acceptance. VM/CIM access remains blocked at the last
recorded host query, before inspection or dispatch. No legacy outcome closed;
estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded
125-180/about 155. See [run evidence](../archive/evidence/b06-client-component-windows-powershell-local-regression-2026-10-28-0353.json),
[component guidance](../windows-component-inventory.md) and [VM blocker](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-27-1929.json).

## JoeWare UserDump, DNSSrvRec and ELDLLEx behavior and version detail, 2026-10-28 03:50 UTC

Official publisher documentation now establishes the UserDump account-status
fields, DNSSrvRec's ordered SRV-record clear/replace/delete/add actions, and
ELDLLExInstall's event-source add/remove behavior with two DLLs. It also
surfaces unresolved version metadata: UserDump Current Version 1.01.00 versus
Version History 2.02.00; DNSSrvRec product page January 2005 versus the version
list and usage label January 2006; and ELDLLEx product version `1.00.0` versus
`01.00.00`, with no digest in the list row. The observations are from official
cached page/usage snapshots, not archive bytes; no version is silently
normalized or assigned to a payload.

No download, extraction, program execution, account/directory/DNS access,
event-source registration, VM, Windows or Defender change occurred. Exact
archives and SHA-256/member inventories remain open. Functional behavior must
be checked only against synthetic data in isolated disposable Windows/AD/DNS
targets; UserDump must not be pointed at real account inventories. AdFind
remains excluded while Defender-blocked. No legacy outcome closed and estimates
remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded
125-180/about 155. See [source detail evidence](../archive/evidence/joeware-administration-tools-source-review-2026-10-28-0350.json)
and [version-discrepancy register](../joeware-version-discrepancies.md).

Disposition: resolved source behavior only; no legacy outcome retired or
closed. Partial: JoeWare collection source mapping. Excluded: AdFind remains
Defender-blocked. Deferred: exact artifacts, catalog lifecycle/recovery and
isolated functional acceptance.

## NirSoft PasswordScan renewed Defender alert, 2026-10-28 03:58 UTC

The user reported the same `NirSoft\x64\passwordscan.exe` temporary-stage path already recorded on 2026-10-27. No new detection name or creating-run provenance was supplied. Keep both PasswordScan architecture paths excluded and do not inspect, extract, run, restore, allow, or add a Defender exclusion for the file. The retained NirLauncher archive lifecycle remains deferred because the temporary-stage origin is unresolved; independent synthetic/static work that does not select PasswordScan can continue. No file contents/hash, Defender history, VM or Windows state was accessed or changed, and no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-0358.json) and [prior source trace](../archive/evidence/nirsoft-passwordscan-temp-defender-alert-2026-10-27-1935.json).
## OpenSSH Server local current-source regression, 2026-10-28 03:58 UTC

Windows PowerShell 5.1.26100.9711 with Pester 5.7.1 passed the capability lifecycle, observation and guarded lifecycle suites 34/34. Catalog and network-control suites discovered 109 tests: 108 passed, none failed or skipped, and one WindowsIntegration test was not run. Optional Pester TestRegistry/TestResult plugins were disabled; native providers were mocked. The capability, service and firewall operations are registered but still have empty `SupportedTargets`; no DISM, live registry, VM, Windows state or Defender state changed. Native Windows 11/Server 2025 lifecycle, first-start data recovery and network exposure acceptance remain deferred; the prior VM query failed at CIM before inspection. No legacy outcome closed; estimates unchanged at 37-57 / 38-53 / 19-24 / 25-35 / 8-12 (exact 127-181; rounded 125-180/about 155). See [structured regression evidence](../archive/evidence/openssh-server-current-winps51-regression-2026-10-28-0358.json) and [component guide](../windows-component-inventory.md).
## RIDE-Win11-Test CIM access recheck, 2026-10-28 04:04 UTC

A read-only `Get-VM -Name RIDE-Win11-Test` from PowerShell 7.6.5 failed before VM/checkpoint inspection with `Access to a CIM resource was not available to the client.` No task query, acceptance dispatch, UAC request, host/guest change or Defender action occurred. The prepared ApplicationsBatch11 HashCheck route and other native package/component acceptance remain deferred until host CIM access returns. Continue source/static work that does not use the VM. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured access evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-0404.json) and [prepared HashCheck route](../archive/evidence/hashcheck-batch11-route-regression-and-cim-block-2026-10-27-1851.json).
## WinHTTP candidate runner availability recheck, 2026-10-28 04:07 UTC

A current-source focused rerun was attempted for the WinHTTP inventory, preparation and lifecycle suites. PowerShell 7.6.5 has no available Pester 5.7.1 module. Windows PowerShell 5.1.26100.9711 found Pester 5.7.1 under the user Documents module path, but import stopped with `AuthorizationManager check failed` before test discovery. No assertions ran. The last successful current-source mocked result remains 22/22 in each shell from 2026-10-27. No execution policy, elevation, native WinHTTP command, Windows state or Defender state changed. WinHTTP remains an unintegrated candidate pending a usable runner, verified native observation/recovery, a setter contract and disposable Windows acceptance. No legacy outcome closed; estimates unchanged at 37-57 / 38-53 / 19-24 / 25-35 / 8-12 (exact 127-181; rounded 125-180/about 155). See [structured attempt evidence](../archive/evidence/winhttp-current-runner-pester-unavailable-2026-10-28-0407.json) and [last successful candidate regression](../archive/evidence/winhttp-proxy-current-source-cross-shell-regression-and-access-2026-10-27-1648.json).
## WinHTTP parser and recovery synthetic checks, 2026-10-28 04:08 UTC

To keep source work moving while Pester import is unavailable, direct calls to the pure inventory/parser and preparation functions passed 8/8 synthetic checks in PowerShell 7.6.5: machine scope, reported-empty versus omitted strings, preserving unselected fields, machine mutation gates, prior-value preparation and refusal on drift. This did not execute native WinHTTP commands or change Windows state. WinHTTP remains unintegrated pending supported native observation, exact underlying-state recovery and setter semantics, plus disposable Windows acceptance; no legacy setting outcome closed. Estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12 (exact 127-181; rounded 125-180/about 155). See [direct synthetic evidence](../archive/evidence/winhttp-direct-synthetic-parser-recovery-checks-2026-10-28-0408.json), [Pester runner blocker](../archive/evidence/winhttp-current-runner-pester-unavailable-2026-10-28-0407.json) and [last Pester pass](../archive/evidence/winhttp-proxy-current-source-cross-shell-regression-and-access-2026-10-27-1648.json).
## WinHTTP Windows PowerShell direct-check authorization block, 2026-10-28 04:10 UTC

A Windows PowerShell 5.1.26100.9711 runner for the pure WinHTTP synthetic checks failed with `AuthorizationManager check failed` before importing the candidate modules or executing assertions. A read-only `Get-ExecutionPolicy -List` query was also denied registry access. No execution policy was changed and no elevation was requested. The only current direct synthetic result is 8/8 in PowerShell 7.6.5; cross-shell/Pester validation is unavailable in this session. No native WinHTTP command or state change occurred, and no legacy setting outcome closed. Estimates unchanged. See [structured authorization-block evidence](../archive/evidence/winhttp-winps51-authorization-block-2026-10-28-0410.json).

## NirSoft PasswordScan repeated Defender block alert, 2026-10-28 04:13 UTC

The user reported another Defender block alert for the same x64 temporary-stage path recorded at 03:58 UTC and 2026-10-27. No new detection name or creating-run provenance was supplied. Both PasswordScan architecture paths remain excluded; do not inspect, extract, restore, open, run, allow or add a Defender exclusion for the file. Retained NirLauncher archive lifecycle stays deferred because the stage origin remains unresolved. No file contents/hash, Defender history, VM or Windows state was accessed or changed; no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0413.json) and [prior repeat evidence](../archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-0358.json).

## JoeWare AdMod acquisition retry and DNS block, 2026-10-28 04:16 UTC

The official `Download-JoeWareCollection.ps1` retry for AdMod 1.29.00 failed before it could retrieve `https://www.joeware.net/freetools/versions.txt`: the host reported `No such host is known.` No publisher product form was submitted and no payload bytes were received. The downloader had created an empty destination before the request; after verifying it held no files, the generated directory was removed. AdMod remains selected for direct-download/install migration when JoeWare DNS resolves. The publisher's freeware/commercial-packaging note is retained as product information and is not a migration gate. AdFind remains separately excluded under its Defender policy; this AdMod attempt was not Defender-blocked. No elevation, VM, Windows or Defender state change occurred; no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180). See [structured acquisition evidence](../archive/evidence/joeware-admod-acquisition-dns-block-2026-10-28-0416.json).

## PSScriptTools ThreadJob runtime-probe path correction, 2026-10-28 04:25 UTC

Review of the updated Windows 11 runtime probe exposed a module-discovery error: adding the RIDE package leaf directory (`microsoft-powershell-threadjob`) to `PSModulePath` does not resolve a consumer manifest's `RequiredModules` entry. Reproduced the failure with synthetic manifests only. The 0.1.5 probe now imports `Microsoft.PowerShell.ThreadJob.psd1` by exact path inside the present-mode child process, verifies module identity/version 2.2.0 and the exact loaded manifest path, then imports PSScriptTools without changing persistent `PSModulePath`. Added a Pester regression using synthetic manifests. PowerShell 7 and Windows PowerShell 5.1 parsers and the synthetic dependency/consumer import passed in both shells. Pester was unavailable in this session (PowerShell 7 exposes only 3.4.0; the Windows PowerShell 5.1 Pester 5 import remains AuthorizationManager-blocked). A fresh read-only `Get-VM` again failed at host CIM before inspecting RIDE-Win11-Test or its checkpoint; runtime acceptance remains deferred. No upstream PSScriptTools code ran, no Windows/VM/Defender state changed and no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured harness-fix evidence](../archive/evidence/psscripttools-runtime-dependency-path-fix-2026-10-28-0422.json) and [current runtime runner](../../tests/integration/Invoke-RidePSScriptToolsRuntimeAcceptance.ps1).
## NirSoft PasswordScan Defender alert report, 2026-10-28 04:30 UTC

The user reported another Defender alert for `NirSoft/x64/passwordscan.exe` in the existing encrypted-launcher filtered Pester temporary stage. The detection name and alert timestamp were not included. The file was not inspected, opened, extracted, restored or run; Defender was not queried or changed. Keep both PasswordScan architecture paths excluded, and defer retained NirLauncher archive lifecycle while the staging run/catalog revision that produced the path is unknown. No VM, Windows or Defender state changed and no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0430.json).

## BitLocker wizard DesktopShortcut resolver metadata fix, 2026-10-28 04:30 UTC

The user-current DesktopShortcut resolver previously expanded environment variables by assigning resolved paths back into the catalog operation. It now returns a resolved descriptor consumed by state inspection and shortcut creation. Synthetic checks and parsers passed in PowerShell 7 and Windows PowerShell 5.1; the resolver preserved the original catalog metadata. Pester was not run: PowerShell 7 exposes Pester 3.4.0, and the Windows PowerShell Pester 5.7.1 import is AuthorizationManager-blocked. No COM access, desktop file enumeration/change, BitLocker state access/change or VM operation occurred. RIDE-Win11-Test access remains blocked at host CIM. Shortcut ownership and native create/inspect/remove/recovery acceptance remain pending; no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured resolver evidence](../archive/evidence/desktop-shortcut-metadata-resolution-2026-10-28-0430.json).

## BitLocker wizard DesktopShortcut collision guard, 2026-10-28 04:34 UTC

modules/RIDE-DesktopShortcuts.psm1 v0.1.2 now inspects path attributes before COM access and refuses directory/reparse-point collisions. Both PowerShell parsers passed, and synthetic missing-path, ordinary-file and directory-collision checks passed. The focused Pester test file now covers those cases; Pester 5 was unavailable, so it was not run. No COM, desktop file, BitLocker, VM, Defender or elevation interaction occurred. The read-only VM recheck remains blocked by host CIM. Shortcut ownership and native create/inspect/remove/recovery acceptance remain pending; no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured guard evidence](../archive/evidence/desktop-shortcut-path-collision-guard-2026-10-28-0434.json).


## NirSoft PasswordScan renewed Defender block alert, 2026-10-28 04:46 UTC

The user reported the same x64 NirSoft/x64/passwordscan.exe path under .local/nirsoft-encrypted-launcher-filtered-pester-tmp already reported at 04:30 UTC. No new detection name or alert timestamp was supplied. No executable contents/hash were read, and the executable was not opened, restored, extracted or run. Defender was not queried or changed. Keep both PasswordScan architecture paths excluded; defer retained NirLauncher archive lifecycle until the temporary-stage creating run and catalog revision are understood. No VM or Windows state changed; no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0446.json).


## JoeWare AdMod 1.29.00 acquisition and candidate registration, 2026-10-28 04:50 UTC

After the 04:16 DNS-blocked retry, the official AdMod product form acquisition completed at 04:40. The retained AdMod.zip is 811,771 bytes, SHA-256 45cf050eec76d7f1c736b613616bcbf4c3dea872d3d5f7398fd276b1fc369235, with only AdMod.exe. In-memory PE inspection recorded x86 (0x014C), length 1,975,296 and SHA-256 86c922fc98c115ea21c2053739938234fd90ce626ed227b2c3c122c2484e4d79; the executable was not extracted to disk or run. The product page and publisher versions list agree on 1.29.00 dated 2026-06-08. The package candidate, pinned provider resolver and operator guidance are now in the catalog and docs. PowerShell 7.6.5 parsed six focused source/test files; catalog validation returned zero errors, resolver pinning passed and a modified product URI was refused. Export-RideCatalog regenerated docs/OPERATIONS.md and its read-only check passed. Pester 5 and Save-RidePackageArtifact end-to-end were not run. The package remains unsupported pending RIDE-managed install/repeat/uninstall/exact restore and Windows 11 acceptance; it requires machine elevation when applied, and no VM/UAC prompt was requested. The terms note is not a migration gate for RIDE direct download-and-install; exact owner review is administrative/local. AdFind stays separately excluded by Defender policy. No Defender, utility, VM or Windows state changed; no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/joeware-admod-package-candidate-2026-10-28-0450.json), [operator guidance](../application-packages.md#joeware-admod-portable-package-candidate), and [verification matrix](../package-verification-matrix.md#joeware-admod-12900-retained-archive-and-package-candidate-2026-10-28-0450-utc).


## RIDE-Win11-Test acceptance access recheck, 2026-10-28 04:53 UTC

A read-only Get-VM -Name RIDE-Win11-Test query failed before VM or checkpoint inspection with Access to a CIM resource was not available to the client. No task was dispatched; no VM/host state changed and no UAC prompt was requested. AdMod managed install/repeat/uninstall/exact restore and Windows 11 acceptance remain deferred. Continue source/static work that does not depend on the VM. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured access evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-0453.json) and [AdMod candidate evidence](../archive/evidence/joeware-admod-package-candidate-2026-10-28-0450.json).


## OpenSSH Client and Telnet DISM source-order review, 2026-10-28 04:55 UTC

Current Microsoft documentation clarifies that capability servicing checks explicit Source locations first, Group Policy-configured sources after an explicit-source miss, then Windows Update only when LimitAccess is absent. LimitAccess blocks Windows Update/WSUS but does not disable policy-configured fallback. Updated docs/windows-component-inventory.md to distinguish documented source order from the effective target policy, which RIDE has not inspected. This clarifies that the candidate local-source outline does not guarantee network isolation. No code/catalog registration, native DISM, VM, Defender or Windows state changed. OpenSSH Client and Telnet candidates remain unregistered/unsupported pending effective target policy, media completeness, dependency coverage, exact recovery and native acceptance. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured source-order evidence](../archive/evidence/open-ssh-client-dism-source-order-review-2026-10-28-0455.json) and [Microsoft DISM documentation](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-capabilities-package-servicing-command-line-options).


## JoeWare AdMod focused Windows PowerShell regression, 2026-10-28 05:00 UTC

Windows PowerShell 5.1.26100.9711 with Pester 5.7.1 passed 3/3 selected AdMod resolver/catalog tests from ApplicationPackages.Tests.ps1 and 7/7 Download-JoeWareCollection.Tests.ps1. TestRegistry and TestResult plugins were disabled; scratch used .local/pester-joeware-admod-winps51. The first default ApplicationPackages invocation failed before test bodies because TestRegistry could not create HKCU\Software\Pester; the configured rerun passed. The downloader tests used mock/WhatIf paths; no publisher request or payload was made. Its AdFind cases verify default and explicit-selection exclusion only; no blocked utility or PasswordScan file was selected/staged. No utility, Defender, VM, Windows state or elevation was used. Save-RidePackageArtifact end-to-end and managed AdMod install/repeat/uninstall/restore/Windows 11 acceptance remain pending. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured regression evidence](../archive/evidence/joeware-admod-focused-winps51-regression-2026-10-28-0500.json), [candidate evidence](../archive/evidence/joeware-admod-package-candidate-2026-10-28-0450.json), and [VM access evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-0453.json).


## OpenSSH Client/Telnet and component-inventory current-source regression, 2026-10-28 05:01 UTC

Windows PowerShell 5.1.26100.9711/Pester 5.7.1 passed 70/70 current-source tests: ClientComponentPreparation 28/28, ClientComponentLifecycle 23/23 and ComponentInventory 19/19. TestRegistry and TestResult plugins were disabled; scratch used .local/pester-client-components-winps51. The candidate suites mocked servicing/providers and used synthetic CAB fixtures; no native DISM, Windows component query, registry, VM, Defender or Windows state changed and no elevation was requested. OpenSSH Client and Telnet remain unregistered and unsupported pending actual media/source completeness, dependencies, effective target policy, exact payload recovery and native Windows acceptance. The read-only RIDE-Win11-Test check at 04:53 UTC remains blocked at host CIM. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured regression evidence](../archive/evidence/client-components-current-source-winps51-regression-2026-10-28-0501.json), [source-order review](../archive/evidence/open-ssh-client-dism-source-order-review-2026-10-28-0455.json), and [VM access evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-0453.json).


## NirSoft PasswordScan repeated Defender block report, 2026-10-28 05:04 UTC

The user reports another Defender block for the same x64 `NirSoft/x64/passwordscan.exe` path in `.local/nirsoft-encrypted-launcher-filtered-pester-tmp` previously recorded at 04:46 UTC. No detection name, alert timestamp, creating run or catalog revision was supplied. The file was not inspected, opened, extracted, restored or run; Defender was not queried or changed, and no path metadata check was made. Keep both PasswordScan architecture paths excluded, and defer retained NirLauncher archive lifecycle until the stage provenance is understood. No VM, Windows or Defender state changed; no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0504.json) and [prior report](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0446.json).


## JoeWare AdMod cache validation and package review-marker audit, 2026-10-28 05:11 UTC

The fresh `Save-RidePackageArtifact` acquisition attempt stopped before a publisher response because `www.joeware.net` did not resolve. Using the previously acquired official 1.29.00 archive, the cached-artifact path validated its 811,771-byte ZIP against the current catalog SHA-256 and retained a versioned RIDE cache copy. Static ZIP inspection found only `AdMod.exe` (1,975,296 bytes), whose streamed member SHA-256 matches the previously recorded pin. The utility was not extracted to an executable path or run. Added an exact 1.29.00 `NeedsReview` / `Unassigned` record to `.local/license-reviews.json`; the user-specific terms reminder does not gate RIDE direct-download/install migration. Current-catalog audit now finds exact `NeedsReview` / `Unassigned` version matches for all 45/45 pending packages, with no missing or wrong-status rows. Phoenix Protector 1.7.1 and NTCore 4GB Patch 1.0.0.1 markers were also confirmed in the workspace-local store; the default LocalAppData store is separate and was not changed. Windows PowerShell 5.1.26100.9711/Pester 5.7.1 passed `LicenseReviews.Tests.ps1` 24/24 after disabling optional TestRegistry/TestResult plugins. No install, VM, registry, Defender, Windows state or elevation interaction occurred. AdMod install/repeat/remove/recovery/Windows acceptance remains pending; fresh publisher acquisition and VM access remain blocked. No legacy outcome closed; estimates unchanged at settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/joeware-admod-cache-validation-license-audit-2026-10-28-0511.json), [AdMod candidate evidence](../archive/evidence/joeware-admod-package-candidate-2026-10-28-0450.json), and [package licensing guide](../package-licensing.md).


## WinHTTP inventory, preparation and lifecycle cross-shell regression, 2026-10-28 05:17 UTC

The current-source Pester suites passed 22/22 in both Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 using Pester 5.7.1. PowerShell 7 imported the existing Pester 5.7.1 installation by exact module path; Windows PowerShell used process-only `ExecutionPolicy Bypass`. Optional TestRegistry and TestResult plugins were disabled. Inventory and lifecycle commands/providers were mocked, and the preparation/recovery tests used synthetic observations only. No native `netsh`, live proxy state, VM, Defender, Windows state or persistent execution policy was touched; no UAC was requested. This resolves the local Pester availability/import blocker, not native validation: WinHTTP remains outside catalog/engine integration, host build 26300 lacks the `netsh winhttp advproxy` command used by the candidate, and exact target capture/set/restore support and Windows acceptance remain unverified. The registered VM host CIM access block remains. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured cross-shell evidence](../archive/evidence/winhttp-cross-shell-pester-regression-2026-10-28-0517.json) and [earlier native command availability check](../archive/evidence/winhttp-netsh-advproxy-host-capability-check-2026-10-27-0821.json).


## NirSoft PasswordScan renewed Defender block alert, 2026-10-28 05:20 UTC

The user reported another Defender block for the same x64 `NirSoft/x64/passwordscan.exe` path under `.local/nirsoft-encrypted-launcher-filtered-pester-tmp`. No alert timestamp, detection name, creating run or catalog revision was supplied. The file was not inspected, opened, extracted, restored or run; Defender was not queried or changed, and no path metadata check was made. Keep both PasswordScan architecture paths excluded and defer retained NirLauncher archive lifecycle until the temporary-stage provenance is understood. No VM, Windows or Defender state changed; no legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0520.json).


## WinHTTP machine automatic-detection catalog/engine integration, 2026-10-28 05:29 UTC

Registered `windows.winhttp-automatic-proxy-detection` as a machine-scope, elevation-requiring candidate with explicit Boolean Enabled/Disabled states, empty `SupportedTargets`, and pending native acceptance. Added catalog invariants and prevented profile selection while pending. The engine now routes read-only status and state matching, saves a preparation snapshot under the run ID, dispatches the guarded durable WinHTTP lifecycle candidate, and uses its conflict-checked restore. A user-scope observation is reported unavailable by this machine-only operation. Generated `docs/OPERATIONS.md` includes the candidate.

Focused catalog/engine Pester coverage passed 5/5 in PowerShell 7.6.5/Pester 5.7.1 with optional TestRegistry/TestResult disabled. It verifies the pending target gate, read-only state, machine-scope refusal, saved snapshot and shared engine/lifecycle run ID. A broader 96-test catalog attempt exposed one presentation-count assertion (292, corrected to 293) and two `Save-RidePackageArtifact` fixture write denials before those package tests completed; that broad run was not repeated. No publisher payload, native WinHTTP command, VM, Defender state, Windows state, or elevation was accessed.

This is catalog and engine integration, not supported Windows behavior: `SupportedTargets` remains empty; build 26300 lacks the candidate `netsh winhttp show advproxy` command; RIDE-Win11-Test remains blocked at host CIM before inspection. Native capture/set/restore, policy and consumer behavior and Windows acceptance remain open. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured integration evidence](../archive/evidence/winhttp-engine-catalog-integration-regression-2026-10-28-0529.json), [current cross-shell candidate evidence](../archive/evidence/winhttp-cross-shell-pester-regression-2026-10-28-0517.json), and [VM access blocker](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-0453.json).


## WinHTTP machine automatic-detection post-integration regression, 2026-10-28 05:33 UTC

After aligning the durable lifecycle record with the registered catalog operation ID and adding a check for that identity, the inventory/preparation/lifecycle suites passed 22/22 in Windows PowerShell 5.1.26100.9711 and 22/22 in PowerShell 7.6.5, both with Pester 5.7.1. Five focused catalog/engine tests passed in both Windows PowerShell 5.1 and PowerShell 7; `tools/Export-RideCatalog.ps1 -Check` confirmed generated operation documentation is current, and `tools/validate.ps1 -Root .` passed for 440 operations, 8 groups, 5 profiles and 298 PowerShell files. Optional TestRegistry/TestResult plugins were disabled. Providers and native command boundaries were mocked, and the WinHTTP integration assertions use synthetic observations. No Defender-blocked payload, native `netsh`, live proxy state, VM, Windows state or elevation was accessed.

One broad catalog test attempt discovered 96 tests but did not produce a complete result summary. It reported the presentation-count expectation as 292 while actual catalog count was 293; the expectation was corrected and the focused presentation test passed. Two package-artifact fixture tests were denied file access before completing; they were not rerun. The remaining acceptance blockers are unchanged: the local host lacks `netsh winhttp show advproxy`, the registered VM fails at host CIM before inspection, and native capture/set/restore plus policy and consumer behavior remain unverified. The setting remains pending with no supported targets. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured post-integration evidence](../archive/evidence/winhttp-machine-autodetect-postintegration-regression-2026-10-28-0531.json).


## JoeWare UserDump, DNSSrvRec and ELDLLEx publisher version-list recheck, 2026-10-28 05:34 UTC

The publisher's official `versions.txt` reports UserDump `01.01.00` dated 2001-01-28 and includes MD5/SHA-1; this agrees with the UserDump product page's Current Version field, while its Version History still says `2.02.00` on that date. The page describes its account-status enumeration and lists Windows NT through XP/Server 2003 only; this is source detail, not RIDE support evidence. `versions.txt` reports DNSSrvRec `01.00.00` dated 2006-01-15 with MD5/SHA-1, and ELDLLEx `01.00.00` dated 2002-02-17 without digests. The official free-tools index describes their purposes, but direct DNSSrvRec/ELDLLEx product-page re-reads returned cache misses. No download form was submitted and no payload was acquired, extracted or run. These publisher version-list hashes do not verify a ZIP or RIDE artifact. Exact archive/member identity, Windows lifecycle and support remain open; no package outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/joeware-version-list-administration-tools-recheck-2026-10-28-0534.json) and [discrepancy register](../joeware-version-discrepancies.md).


## NirSoft PasswordScan Defender block alert, 2026-10-28 05:37 UTC

The user reports a new Defender block alert for the x64 `NirSoft/x64/passwordscan.exe` executable in the same `.local/nirsoft-encrypted-launcher-filtered-pester-tmp` staging tree reported at 05:20 UTC. The alert's detection name, alert timestamp, creating run and catalog revision were not supplied. Read-only source review traces `RIDE-Portable-<guid>` to `Install-RidePortablePayload`, which stages under the process temp directory and extracts exact-selected ZIP members. Current catalog and focused Pester assertions exclude both PasswordScan architecture paths, so the path is not explained by the current selection alone; an earlier/different catalog snapshot, another caller or leftover output remains possible. The process temp-root override explains the `.local` parent, but the creating run is still unidentified. No file content/hash or path metadata was read; the file was not opened, extracted, restored or run. Defender was not queried or changed; no allow rule or exclusion was added. Keep both PasswordScan architecture paths excluded and defer retained NirLauncher archive lifecycle until the creating execution is reconciled. No VM, Windows state or elevation interaction occurred. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0537.json), [portable staging implementation](../../modules/RIDE-PortablePackages.psm1), and [current candidate selection](../../catalog/operations.psd1).


## JoeWare AdMod pinned archive host-local file lifecycle, 2026-10-28 05:42 UTC

Verified the cached JoeWare AdMod 1.29.00 archive against its pinned SHA-256, then used the portable package module directly with `InstallDirectory` and process `TEMP`/`TMP` confined to a fresh workspace-local case directory. The actual selected `AdMod.exe` was staged with the expected publisher-member SHA-256, repeat staging remained healthy, managed removal succeeded, a snapshot restored the exact pinned bytes and healthy state, and a separate snapshot restored prior absence. A later diagnostic also passed recovery from a synthetic previously installed version to the current pinned archive and back, with restored manifest state `Installed` and exact prior bytes. The unique temporary case directories were removed after each run. AdMod was never launched; no VM, registry or Windows state, Defender settings, or elevation were involved. One initial harness attempt failed its recovery-health assertion and lacked post-restore diagnostics; the cause is unresolved, it was not counted, and the corrected current-pin and diagnostic scenarios passed. This is host-local file-lifecycle evidence only: machine-scope engine dispatch, fresh publisher acquisition (DNS failure), guest ACL behavior, and Windows 11 acceptance remain open. No legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured evidence](../archive/evidence/joeware-admod-pinned-archive-host-file-lifecycle-2026-10-28-0542.json) and [AdMod package candidate](../archive/evidence/joeware-admod-package-candidate-2026-10-28-0450.json).


## JoeWare rdp-sec-check publisher acquisition retry, 2026-10-28 05:43 UTC

The official product and usage pages reconfirm the offered `0.9-beta / JoeWare V02.00.00`, dated 2014-11-17. The older `versions.txt` V01.00.00 row and its MD5/SHA-1 are not attributable to V02.00.00 without inspecting the archive. The bounded publisher acquisition attempt stopped at DNS resolution for `versions.txt`; the script did not fetch the product page or submit the optional-email download form. A read-only resolver check for both `joeware.net` and `www.joeware.net` returned `Access is denied`, indicating a local DNS-access block rather than proving publisher unavailability. The newly created empty workspace-local destination was removed. The product page identifies GPLv2 source in the ZIP and credits Portcullis Labs / Mark Lowe; owner-specific review remains informational for RIDE's direct download/install workflow. No archive, executable, endpoint, Defender, VM or Windows state was accessed; no UAC was requested. Package registration remains deferred until the exact V02.00.00 archive inventory and source/notices can be reviewed. No legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured acquisition/source evidence](../archive/evidence/joeware-rdp-sec-check-acquisition-dns-block-2026-10-28-0543.json), [version discrepancy register](../joeware-version-discrepancies.md), and [publisher product page](https://joeware.net/freetools/tools/rdp-sec-check/index.htm).


## Registered disposable VM host-CIM access recheck, 2026-10-28 05:47 UTC

Read-only `Get-VM` queries for `RIDE-Win11-Test` and `RIDE-Server2025-Test` both failed before VM inspection with `Access to a CIM resource was not available to the client`. No checkpoint or registered test task was inspected or dispatched, and neither VM nor host WinRM was changed. No elevation was requested. Disposable Windows 11 and Server 2025 acceptance remains deferred; continue independent source, mocked and local file-lifecycle work. No legacy outcome closed; estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-28-0547.json).


## Current repository validation and VM/task access blocker, 2026-10-28 05:51 UTC

The read-only `tools/validate.ps1 -Root .` validator passed on the current working tree: 440 operations, 8 groups, 5 profiles, 298 PowerShell files, generated operation documentation current. No handler or installer ran. The paired read-only `Get-VM` recheck for RIDE-Win11-Test and RIDE-Server2025-Test failed before inspection at host CIM. Alternate read-only access paths also failed before task metadata was returned: `schtasks /Query` reported an invalid network address for both tasks, and local `Schedule.Service` COM connection returned access denied. No task was dispatched; VM acceptance remains pending. No legacy outcome closed. Estimates remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [validator and access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-28-0547.json).

## NirSoft PasswordScan repeated Defender block alert, 2026-10-28 05:57 UTC

The user reported another Defender block alert for the same x64
`NirSoft/x64/passwordscan.exe` temporary-stage path recorded at 05:37 UTC. No
detection name, alert timestamp, creating process or catalog revision was
provided. Current repository source and focused assertions still exclude both
PasswordScan architecture paths; the latest focused Pester run in this session
was for AdMod, and no NirSoft test was run in response. Do not inspect, open,
hash, restore, extract, run, allow or add a Defender exclusion for the flagged
file. Keep both PasswordScan paths excluded and defer the retained NirLauncher
archive lifecycle until the creating run and catalog revision are understood.
No Defender, VM, Windows state or elevation was accessed or changed. No legacy
outcome closed; estimates remain settings 37-57, packages 38-53, components
19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded
125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0557.json)
and [prior alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0537.json).

## JoeWare AdMod retained-archive current-source Pester regression, 2026-10-28 05:59 UTC

Windows PowerShell 5.1.26100.9711/Pester 5.7.1 passed the focused
`ApplicationPackages.Tests.ps1` AdMod retained-archive lifecycle case (1/1;
131 tests discovered in the file, one selected). The test verified the exact
1.29.00 archive and `AdMod.exe` member digests, repeat staging, removal, exact
current-version restore, synthetic prior-version restore, and prior absence
restore. The utility did not run. An initial Pester `TestDrive` attempt failed
while replacing its manifest in the app-container temporary path; the final
test uses a unique workspace-local `.local/application-package-tests` folder
and passed. The reported temporary manifest was not inspected or cleaned by
hand. This adds durable host-local module regression coverage, not machine-scope
engine, ACL, or Windows 11 acceptance. No Defender, VM, registry or Windows
state changed and no elevation was requested. No legacy outcome closed; the
estimates remain settings 37-57, packages 38-53, components 19-24, files/assets
25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See
[structured Pester evidence](../archive/evidence/joeware-admod-retained-archive-pester-regression-2026-10-28-0556.json)
and [host-local lifecycle evidence](../archive/evidence/joeware-admod-pinned-archive-host-file-lifecycle-2026-10-28-0542.json).

## Repository validation and registered VM CIM access recheck, 2026-10-28 06:01 UTC

The current `tools/validate.ps1 -Root .` run passed: 440 operations, 8 groups,
5 profiles, 298 PowerShell files, and generated operation documentation current.
The paired read-only `Get-VM` recheck for `RIDE-Win11-Test` and
`RIDE-Server2025-Test` again failed before returning state or identity with
`Access to a CIM resource was not available to the client`; no checkpoints were
inspected or tasks dispatched. No host, guest, Windows state or elevation was
changed. Windows 11 and Server 2025 acceptance remain blocked before
inspection. No legacy outcome closed; estimates remain settings 37-57,
packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12 (exact
127-181; rounded 125-180/about 155). See [structured validation and VM access
evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-28-0601.json).

## PSScriptTools dependency-path current-source Pester regression, 2026-10-28 06:03 UTC

Windows PowerShell 5.1.26100.9711/Pester 5.7.1 passed two focused selections
from `PortableAcceptanceAutomation.Tests.ps1`: 4/4 synthetic ThreadJob exact
manifest/dependency cases and 5/5 version-discovery cases, including the current
PSScriptTools runtime probe version `0.1.5`. This found and corrected a stale
`0.1.4` test expectation. The synthetic test does not import or execute upstream
PSScriptTools code. The initial Pester configuration attempt used invalid config
property paths; the default TestRegistry plugin then failed before test bodies
because it could not create its HKCU fixture. No registry change occurred. The
corrected run used `Filter.FullName`, with TestRegistry and TestResult plugins
disabled. No VM, Windows or Defender state changed and no UAC was requested.
Guest runtime and Windows 11 acceptance remain deferred. No legacy outcome
closed; estimates remain settings 37-57, packages 38-53, components 19-24,
files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about
155). See [structured regression evidence](../archive/evidence/psscripttools-runtime-dependency-current-winps51-pester-regression-2026-10-28-0603.json)
and [runtime dependency path correction](../archive/evidence/psscripttools-runtime-dependency-path-fix-2026-10-28-0422.json).

## BitLocker wizard DesktopShortcut WinPS 5.1 Pester regression, 2026-10-28 06:05 UTC

Windows PowerShell 5.1.26100.9711/Pester 5.7.1 passed all 5 tests in
`DesktopShortcuts.Tests.ps1`: path normalization, unsupported metadata, missing
path, directory collision and ordinary-file behavior. The tests did not open
shortcut COM or change the desktop, BitLocker, Defender, VM or Windows state.
This resolves the earlier local Pester-execution gap; native Windows 11
shortcut ownership, create/inspect/remove and saved-state recovery remain
deferred, and RIDE-Win11-Test is still blocked before inspection by CIM access.
No legacy outcome closed; estimates remain settings 37-57, packages 38-53,
components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded
125-180/about 155). See [structured Pester evidence](../archive/evidence/desktop-shortcut-winps51-pester-regression-2026-10-28-0605.json)
and [path collision guard evidence](../archive/evidence/desktop-shortcut-path-collision-guard-2026-10-28-0434.json).

## WinHTTP current-source PowerShell 7 Pester regression, 2026-10-28 06:06 UTC

PowerShell 7.6.5/Pester 5.7.1 passed the inventory, preparation and lifecycle
test files 22/22 with the TestRegistry and TestResult plugins disabled. The
tests exercise fixed-observer parsing and mocked identity/command handling,
explicit-scope preparation, conflict-aware recovery, and preview guards. No
native `netsh` or WinHTTP command ran and no Windows proxy state was read or
changed. This resolves the current-source PowerShell 7 Pester-discovery gap;
the Windows PowerShell 5.1 current-source rerun and native VM apply/restore
acceptance remain open. The latest read-only VM checks remain blocked at host
CIM before inspection. No legacy outcome closed; estimates remain settings
37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12
(exact 127-181; rounded 125-180/about 155). See [structured WinHTTP regression
evidence](../archive/evidence/winhttp-current-source-pester-regression-2026-10-28-0606.json)
and [latest VM access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-28-0601.json).

## WinHTTP current-source cross-shell regression, 2026-10-28 06:07 UTC

The inventory, preparation and lifecycle Pester suites passed 22/22 in both
PowerShell 7.6.5/Pester 5.7.1 and Windows PowerShell 5.1.26100.9711/Pester
5.7.1. TestRegistry and TestResult plugins were disabled. The WinPS run used
process-only ExecutionPolicy Bypass to import Pester; persistent policy was
not changed. Native command interactions are mocked. No `netsh`/WinHTTP
command, registry, proxy state, Defender, VM, Windows state or elevation was
accessed or changed. Current-source cross-shell regression is resolved; native
WinHTTP acceptance on RIDE-Win11-Test and Server 2025 remains blocked before VM
inspection at host CIM. No legacy outcome closed; estimates remain settings
37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12
(exact 127-181; rounded 125-180/about 155). See [cross-shell evidence](../archive/evidence/winhttp-current-source-cross-shell-pester-regression-2026-10-28-0607.json)
and [VM access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-28-0601.json).

## Disposable VM access recheck, 2026-10-28 06:08 UTC

Read-only `Get-VM` again failed before returning state or identity for both
`RIDE-Win11-Test` and `RIDE-Server2025-Test` with
`Access to a CIM resource was not available to the client`. No checkpoint was
inspected and no task was dispatched. No VM, host, Defender or Windows state
changed; no elevation was requested. Native Windows 11 and Server 2025
acceptance remains deferred before inspection. No legacy outcome closed;
estimates remain settings 37-57, packages 38-53, components 19-24, files/assets
25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See
[current access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-28-0608.json).

## JoeWare administration-tool publisher version reconciliation, 2026-10-28 06:10 UTC

Read-only official publisher snapshots sharpened three version-history
discrepancies. UserDump's current-version section and `versions.txt` agree on
1.01.00/January 28, 2001, while its version history lists 2.02.00 for that date.
DNSSrvRec's product page dates 1.00.00 to January 2005, while the publisher
version list and usage page identify January 2006. ELDLLEx's current-version
section and version list agree on February 2002 after numeric formatting, but
its history and usage page identify July 2004. The discrepancy register and
structured evidence now preserve the separate observations. No archive was
downloaded or opened; no utility, account, DNS, event source, VM, Defender,
Windows state or elevation was accessed. Exact archives and byte identities
remain open, but these are source-identity questions, not licensing gates. No
legacy outcome closed; estimates remain settings 37-57, packages 38-53,
components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded
125-180/about 155). See [structured publisher reconciliation](../archive/evidence/joeware-administration-version-source-reconciliation-2026-10-28-0610.json)
and the [version discrepancy register](../joeware-version-discrepancies.md).

## JoeWare UserDump official acquisition DNS block, 2026-10-28 06:13 UTC

The authorized acquisition script failed on its first request to
`www.joeware.net` with a name-resolution error while requesting the official
`versions.txt`. It did not request the UserDump product page, submit the
optional-email form, or acquire a payload. The newly created destination was
confirmed empty and removed. No archive or utility was inspected or run; no
account data, Defender, VM, Windows state or elevation was accessed. Exact
archive identity remains deferred until local DNS works or an approved
publisher-acquisition route is available. No legacy outcome closed; estimates
remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
acquisition evidence](../archive/evidence/joeware-userdump-official-acquisition-dns-block-2026-10-28-0613.json)
and [version-source reconciliation](../archive/evidence/joeware-administration-version-source-reconciliation-2026-10-28-0610.json).

## JoeWare AdMod current-source cross-shell package regression, 2026-10-28 06:14 UTC

PowerShell 7.6.5/Pester 5.7.1 passed 11/11 focused cases from
`ApplicationPackages.Tests.ps1` and `Download-JoeWareCollection.Tests.ps1`.
The selected tests cover the pinned form provider, catalog metadata, actual
archive lifecycle/recovery, downloader version/URI guards, no-request `WhatIf`
and the AdFind exclusion. Earlier Windows PowerShell 5.1/Pester 5.7.1 runs
passed 10/10 provider/catalog/downloader cases and 1/1 actual-archive lifecycle
case, so current-source package tests and actual file lifecycle pass in both
editions. The fixture archive/member digests match the recorded 1.29.00 pins.
No publisher request occurred in preview tests; AdMod was not executed. No
Defender-blocked tool, VM, registry, Windows or Defender state was touched and
no elevation was requested. The machine-scope RIDE engine route, guest ACLs and
Windows 11 acceptance remain open. No legacy outcome closed; estimates remain
settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
cross-shell evidence](../archive/evidence/joeware-admod-cross-shell-current-source-regression-2026-10-28-0614.json),
[Windows PowerShell 5.1 evidence](../archive/evidence/joeware-admod-focused-winps51-regression-2026-10-28-0500.json)
and [actual-archive lifecycle evidence](../archive/evidence/joeware-admod-pinned-archive-host-file-lifecycle-2026-10-28-0542.json).

## PSScriptTools runtime dependency cross-shell Pester regression, 2026-10-28 06:16 UTC

PowerShell 7.6.5/Pester 5.7.1 passed the same 9 focused synthetic cases that
passed in Windows PowerShell 5.1: five runner-version checks, runtime-probe
parser coverage, exact-path ThreadJob manifest import, pinned package selection
and `.nupkg` guard. The current `0.1.5` runner version is verified in both
editions. No upstream PSScriptTools code was imported or executed, and
`PSModulePath`, registry, VM, Windows or Defender state was not changed. This
resolves the current-source cross-shell Pester gap; exact retained-archive
runtime and Windows 11 guest acceptance remain deferred by host CIM access. No
legacy outcome closed; estimates remain settings 37-57, packages 38-53,
components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181; rounded
125-180/about 155). See [cross-shell evidence](../archive/evidence/psscripttools-runtime-dependency-cross-shell-pester-regression-2026-10-28-0616.json)
and [Windows PowerShell 5.1 regression evidence](../archive/evidence/psscripttools-runtime-dependency-current-winps51-pester-regression-2026-10-28-0603.json).

## Disposable VM access recheck, 2026-10-28 06:16 UTC

Read-only `Get-VM` again failed before returning state or identity for both
`RIDE-Win11-Test` and `RIDE-Server2025-Test` with
`Access to a CIM resource was not available to the client`. No checkpoint was
inspected and no task was dispatched. No VM, host, Defender or Windows state
changed; no elevation was requested. Native Windows 11 and Server 2025
acceptance remains deferred before inspection. No legacy outcome closed;
estimates remain settings 37-57, packages 38-53, components 19-24, files/assets
25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See
[current access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-28-0616.json).

## NirSoft PasswordScan repeat Defender alert, 2026-10-28 06:18 UTC

The user reported another Defender block for the same x64 PasswordScan path in
the filtered Pester temporary staging tree. The report did not include a
detection name or alert event time. The prior read-only source review remains
applicable: current catalog and tests exclude both PasswordScan architectures,
so the creating process/run and catalog snapshot are unresolved. Keep both
architectures excluded and defer retained NirLauncher archive lifecycle until
staging provenance is established. No file was opened, hashed, restored or
executed; Defender and VM state were not queried or changed, and no elevation
was requested. No legacy outcome closed; estimates remain settings 37-57,
packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12
(exact 127-181; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0618.json)
and [previous alert evidence](../archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0557.json).
## B06 component cross-shell regression, 2026-10-28 06:19 UTC

The current-source client component preparation, guarded lifecycle and
read-only inventory suites passed 70/70 in PowerShell 7.6.5/Pester 5.7.1.
The same three suites passed 70/70 in Windows PowerShell 5.1/Pester 5.7.1
earlier today. Pester registry/result plugins were disabled. Native DISM,
Server Manager and Windows inventory were not called; no VM, checkpoint,
Windows or Defender state changed, and no elevation was requested. The
PasswordScan file from the separate Defender report was not accessed.
Matching OpenSSH source/dependency proof, offline-source behavior, exact
recovery, catalog disposition and disposable-VM acceptance remain open.
No legacy outcome closed; estimates remain settings 37-57, packages 38-53,
components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181;
rounded 125-180/about 155). See [structured evidence](../archive/evidence/b06-client-components-cross-shell-current-source-regression-2026-10-28-0619.json)
and [Windows PowerShell 5.1 evidence](../archive/evidence/b06-client-component-windows-powershell-local-regression-2026-10-28-0353.json).
## HashCheck candidate cross-shell regression and VM access, 2026-10-28 06:26 UTC

Added a focused ApplicationPackages.Tests.ps1 regression for the HashCheck
2.6.3 candidate pin and ApplicationsBatch11 route. PowerShell 7.6.5/Pester
5.7.1 and Windows PowerShell 5.1.26100.9711/Pester 5.7.1 both passed the
selected case 1/1 with TestRegistry/TestResult disabled. Windows PowerShell
needed a process-scoped ExecutionPolicy Bypass to load Pester's format files;
the persistent policy was not changed. Two initial test attempts exposed only
a version expectation error (the current application runner is 0.17.0) and a
malformed regex; both were corrected before the cross-shell pass. The installer
was not executed. A read-only recheck of RIDE-Win11-Test and
RIDE-Server2025-Test again failed at host CIM before inspection; no
checkpoint/task was inspected or dispatched. No elevation or Defender/Windows
state change occurred. Package and Explorer acceptance remain VM-blocked. No
legacy outcome closed; estimates remain settings 37-57, packages 38-53,
components 19-24, files/assets 25-35, maintenance 8-12 (exact 127-181;
rounded 125-180/about 155). See [structured evidence](../archive/evidence/hashcheck-candidate-declaration-regression-and-vm-block-2026-10-28-0624.json)
and [current VM access evidence](../archive/evidence/ride-vm-cim-access-recheck-2026-10-28-0623.json).
## NTCore current-source staging regression, 2026-10-28 06:28 UTC

The current-source NtcorePackages.Tests.ps1 suite passed 16/16 in PowerShell
7.6.5/Pester 5.7.1 and 16/16 in Windows PowerShell 5.1.26100.9711/Pester
5.7.1. The retained-archive fixture variable was unset, so tests used inert
generated ZIP members in TestDrive. TestRegistry/TestResult plugins were
disabled, and scratch was isolated under .local. No upstream binary was read,
launched or loaded; no driver service, VM, Defender or Windows state changed,
and no elevation was requested. This validates synthetic staging, repeat,
removal and saved-file recovery boundaries; it does not add Windows target or
functional acceptance. No legacy outcome closed; estimates remain settings
37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance
8-12 (exact 127-181; rounded 125-180/about 155). See [structured
cross-shell evidence](../archive/evidence/ntcore-package-current-source-cross-shell-regression-2026-10-28-0628.json)
and [prior current-source regression](../archive/evidence/ntcore-packages-focused-current-source-regression-2026-10-26-1442.json).
## Power-plan menu source review and VM access, 2026-10-28 06:31 UTC

The legacy SetPwrSchemeDesktopMenu source writes through merged HKCR, enumerates
four English display names from powercfg output and places direct
powercfg.exe -setactive GUID commands in shell entries. RemovePwrSchemeDesktopMenu
recursively deletes the entire named subtree without prior-state capture or an
ownership check. This confirms the old path is not a safe intended-user contract
and bypasses RIDE's saved-state/reporting workflow. Keep the v3 native Power
Options handoff separate; its intended-user path, ownership/recovery and UI
acceptance remain open. A fresh read-only Get-VM check at 06:31 again failed for
both registered VMs at host CIM before inspection; no checkpoint or task was
inspected or dispatched. No registry, power, VM, Windows or Defender state
changed and no elevation was requested. No legacy outcome closed; estimates
remain settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
evidence](../archive/evidence/power-plan-menu-source-review-and-vm-block-2026-10-28-0631.json).
## Power Options current-user shortcut candidate, 2026-10-28 06:37 UTC

Added pending operation windows.power-options-shortcut for the accepted
native Power Options handoff. It owns only the exact current-user desktop link
Power Options.lnk, targeting System32 control.exe with
/name Microsoft.PowerOptions; removal refuses modified or unrelated files.
The operation has no SupportedTargets, candidate target Windows 11, and is
excluded from profiles. PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711
both passed the focused shortcut resolver/catalog suite 7/7. Repository
validation passed (441 operations, 8 groups, 5 profiles, 298 PowerShell files);
generated operation docs are current. No COM, shortcut, Control Panel, registry,
power, VM or Defender state changed. Get-VM at 06:37 again failed for both
registered targets at host CIM before inspection or dispatch. Current Windows
11 UI/launch, intended interactive session, lifecycle/recovery, and Server
behavior remain deferred. No legacy outcome closed; estimates remain settings
37-57, packages 38-53, components 19-24, files/assets 25-35, maintenance 8-12
(exact 127-181; rounded 125-180/about 155). See [structured cross-shell
evidence](../archive/evidence/power-options-shortcut-candidate-cross-shell-regression-and-vm-block-2026-10-28-0637.json),
[generated operation reference](../OPERATIONS.md) and the [Microsoft launch
reference](https://learn.microsoft.com/en-us/windows/win32/shell/executing-control-panel-items).
## Repeated PasswordScan Defender report, 2026-10-28 06:57 UTC

The user reported the same x64 `passwordscan.exe` temporary-stage path again.
This path was already recorded in the 06:39 UTC alert evidence and the
2026-10-27 filtered-retry record. No new detection name, Defender event time or
creating-run identity was supplied. Keep both PasswordScan architectures
excluded and the retained NirLauncher archive lifecycle deferred until stage
provenance is understood. Current catalog and extraction-source review exclude
the selected PasswordScan members but do not identify this file's creator. No
file, Defender, VM or Windows state was accessed or changed. No legacy outcome
closed; estimates remain settings 37-57, packages 38-53, components 19-24,
files/assets 25-35, maintenance 8-12 (exact 127-181; rounded 125-180/about
155). See [repeat-report evidence](../archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-0657.json),
[earlier alert evidence](../archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-0639.json)
and the [current source trace](../archive/evidence/nirsoft-encrypted-stager-current-source-trace-2026-10-28-0646.json).

## PasswordScan Defender report, 2026-10-28 15:49 UTC

The user reports a Defender block for x64 PasswordScan in the same encrypted-launcher filtered-Pester temporary workspace and GUID recorded at 15:20 UTC. This report does not establish whether the Defender event is distinct or repeated; the detection name, event time and creating-run provenance remain unknown. Do not inspect, open, restore, extract, execute, allow or add an exclusion for the reported file. Keep both PasswordScan architectures excluded and pause NirSoft staging/Pester lifecycle reruns that could materialize the blocked member until stage provenance and the creating catalog revision are reconciled. Continue independent migration batches. No VM, Defender or Windows state was queried or changed; no elevation was requested. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured alert evidence](../archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1549.json) and [prior report](../archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1520.json).

## Storage Sense machine policy candidate, 2026-10-28 15:56 UTC

Added windows.storage-sense-global-policy as a separate, unsupported machine-policy candidate with no declared supported targets. Catalog export and repository validation passed (447 operations, 8 groups, 5 profiles, 301 PowerShell files). The isolated focused Pester invocation returned no summary after a FileSystem InitializeDefaultDrives provider error; no assertion count is claimed. UI enforcement, edition, policy precedence, exact restore and cleanup-boundary acceptance remain pending. No legacy outcome closed; estimates remain unchanged. See the [settings review and evidence](settings-post-migration-review.md) and [structured run record](../archive/evidence/storage-sense-machine-policy-candidate-validation-2026-10-28-1556.json).

## Storage Sense focused test environment block, 2026-10-28 15:59 UTC

Windows PowerShell 5.1 denied Pester 5.7.1 format files during module import under AuthorizationManager, so the focused assertions did not run; no policy bypass was attempted. A PowerShell 7 attempt returned no summary after a FileSystem provider error. No test count is claimed. No registry, VM, Defender or Windows state changed. See [test-block evidence](../archive/evidence/storage-sense-focused-test-environment-block-2026-10-28-1559.json).

## Explorer Suite VM access recheck, 2026-10-28 16:03 UTC

Get-VM -Name RIDE-Win11-Test failed before returning VM state; no checkpoint or guest acceptance runner was inspected or dispatched. Version source is reconciled to publisher III-2012-11-18, but Windows lifecycle/recovery remains blocked. No state or elevation changed. See [VM access evidence](../archive/evidence/ntcore-explorer-suite-vm-access-recheck-2026-10-28-1603.json).

## Phoenix Protector publisher route recheck, 2026-10-28 16:04 UTC

The official page still labels Phoenix Protector 1.8.0.1; the official MSI fetch yielded no bytes. Keep the retained MSI ProductVersion 1.7.1, its SHA-256 pin and contained executable version 1.9.0.1 distinct. The NeedsReview marker remains informational, not a migration gate. Windows lifecycle acceptance remains open. No legacy outcome closed; estimate unchanged. See [source evidence](../archive/evidence/phoenix-current-publisher-route-recheck-2026-10-28-1604.json).

## PSScriptTools preregistered dispatch blocked before enqueue, 2026-10-28 16:07 UTC

The existing registered client could not write the request temporary file under the protected pending queue. Pending and running queues were empty afterward; no request was dispatched, and no VM/checkpoint was inspected or changed. The manifest selects only PSScriptTools and ThreadJob. No queue permission change or elevation was attempted. See [structured evidence](../archive/evidence/psscripttools-preregistered-task-pending-queue-access-block-2026-10-28-1607.json).

## Storage Sense engine state probe, 2026-10-28 16:09 UTC

Direct current-source synthetic state checks passed in PowerShell 7.6.5; the same module could not be imported in Windows PowerShell 5.1 because AuthorizationManager denied it. No registry or Windows state was touched; no Pester count is claimed. See [structured evidence](../archive/evidence/storage-sense-engine-state-probe-2026-10-28-1609.json).
# NirSoft retained encrypted archive test safety guard, 2026-10-28 16:42 UTC

The retained encrypted archive Pester case now stops at archive metadata/member inventory and exact catalog-selection checks; it no longer calls staging, snapshot or restore on retained publisher archives. The synthetic inert archive lifecycle case still covers those code paths. The updated test source parses in Windows PowerShell; assertions remain unrun. No retained archive bytes, reported executable, temp stage, Defender state, VM or Windows state were accessed or changed. Both PasswordScan architectures remain excluded and retained NirSoft lifecycle remains deferred pending independent extraction validation and stage provenance. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/nirsoft-retained-archive-inventory-only-test-guard-2026-10-28-1642.json).
# NirSoft exact-member inert ZIP argument probe, 2026-10-28 16:46 UTC

Windows inbox `tar.exe` selected one requested inert text entry from a two-entry unencrypted ZIP and left the unselected text entry absent. This matches the argument form used by the encrypted-ZIP helper but does not validate encryption/password handling or real archive member filtering. The unique probe directory was removed after its resolved path was checked to be inside the repository. No retained publisher archive, reported executable, Defender, VM or Windows configuration was accessed or changed. PasswordScan x86/x64 remain excluded; retained NirSoft lifecycle and alert provenance remain deferred. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/nirsoft-tar-exact-member-inert-probe-2026-10-28-1646.json).
# RIDE-Win11-Test Hyper-V UI inventory and acceptance preflight, 2026-10-28 16:48 UTC

Hyper-V Manager visibly lists `RIDE-Win11-Test` as Off. The console runs at higher Windows integrity than the Computer Use helper, so the target could not be selected and its checkpoint association could not be inspected. The only visible checkpoint tree belonged to `RIDE-S25-Test`. No VM start/stop, checkpoint operation, guest dispatch, Windows/Defender change or elevation occurred. Native acceptance remains deferred until target and checkpoint access is available. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/ride-win11-test-hyperv-ui-off-and-selection-access-block-2026-10-28-1648.json).

# NTCore full Explorer Suite candidate catalog reconciliation, 2026-10-28 16:51 UTC

The current catalog contains a separate pinned full Explorer Suite candidate at III-2012-11-18, distinct from CFF Explorer, with no supported target and Windows lifecycle acceptance pending. Filter Monitor, Vista4Experts and AntiMida remain unpinned pending exact artifacts. No source artifact, installer, VM, Windows or Defender state changed. No legacy outcome closed; estimates unchanged. See [catalog evidence](../archive/evidence/ntcore-full-suite-candidate-current-catalog-recheck-2026-10-28-1651.json).

# PasswordScan Defender repeat alert, 2026-10-28 19:33 UTC

The user reports a Defender block for x64 PasswordScan in the same filtered-Pester temporary-stage path/GUID recorded earlier. The reported stage root was absent at the time of a metadata-free existence check; no detection name or event timestamp was provided, and the report does not establish a distinct Defender event. Keep both PasswordScan architectures excluded. Pause NirSoft staging/Pester lifecycle reruns that could materialize PasswordScan until the creating run and catalog/source revision are reconciled. The flagged executable was not opened, read, restored, extracted or run; Defender, VM and Windows state were not queried or changed; no elevation was requested. No legacy outcome closed. Estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1933.json).

## PSScriptTools Windows PowerShell 5.1 full inert lifecycle regression and VM access recheck, 2026-10-28 19:41 UTC

Windows PowerShell 5.1/Pester 5.7.1 passed all 7/7 focused assertions, including the full inert 360-member install, repeat, state snapshot, removal, restore and unowned-output preservation lifecycle. The fixture was generated locally and contained inert text; no retained archive, upstream PSScriptTools code, Defender-blocked utility or installer was loaded or executed. The first test attempt stopped before test bodies because Pester's default TestRegistry plugin could not create a temporary registry key; the successful retry disabled TestRegistry without changing registry permissions or user registry state. PowerShell 7.6.5 previously emitted a 7/7 pass summary, while its wrapper exit code was 1 because it omitted `-PassThru`; the two shell results are recorded separately. A fresh read-only `Get-VM -Name RIDE-Win11-Test` query again failed before state retrieval with `Access to a CIM resource was not available to the client`; no checkpoint was inspected and no guest request was dispatched. No legacy package outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/psscripttools-inert-360-member-winps51-regression-and-vm-block-2026-10-28-1941.json) and [PowerShell 7 evidence](../archive/evidence/psscripttools-inert-360-member-full-local-regression-2026-10-28-1543.json).

## MiTeC Mail and History Viewer current-source Windows PowerShell regression, 2026-10-28 19:44 UTC

`tests/MiTeCMailHistoryViewers.Tests.ps1` passed 16/16 in Windows PowerShell 5.1/Pester 5.7.1. The suite checked all four package metadata/archive/member pins against current evidence, checked their previously accepted Windows 11 lifecycle cases, and used only inert synthetic fixtures for repeat staging, uninstall, snapshot recovery and user-file preservation. No utility was run and no mail, browser profile, messaging database, Defender state, VM or Windows state was accessed or changed. The earlier RIDE-Win11-Test package lifecycle/recovery run passed all four cases; this is a current-source local regression, not a new VM run. Functional and activation evidence remains open; no legacy outcome closed. Estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/mitec-mail-history-viewers-current-source-winps51-regression-2026-10-28-1944.json), [Windows 11 lifecycle evidence](../archive/evidence/mitec-mail-history-viewers-win11-lifecycle-acceptance-2026-10-25-0409.json) and [acceptance-scope reconciliation](../archive/evidence/mitec-mail-history-acceptance-scope-reconciliation-2026-10-28-1136.json).

## NTCore current-source Windows PowerShell regression, 2026-10-28 19:47 UTC

`tests/NtcorePackages.Tests.ps1` passed 20/21 in Windows PowerShell 5.1/Pester 5.7.1, with no failures. One retained ScreenWriter MSI digest case was skipped because no retained archive directory was supplied; its digest check had passed in the earlier 14:41 run. The other cases used synthetic inert archives and verified current catalog/review bindings and file ownership lifecycle. No utility or Windows Installer ran, and no VM/Windows/Defender state changed. No legacy outcome closed. Estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/ntcore-packages-current-winps51-synthetic-regression-2026-10-28-1947.json) and [prior retained-MSI evidence](../archive/evidence/ntcore-packages-winps51-pester-retained-candidate-regression-2026-10-28-1441.json).

## NTCore retained-source Windows PowerShell regression, 2026-10-28 19:49 UTC

After the 19:47 no-cache run identified one skipped ScreenWriter MSI digest check, the reviewed local source directory was located and supplied to the same suite. `tests/NtcorePackages.Tests.ps1` then passed 21/21 in Windows PowerShell 5.1/Pester 5.7.1 with no failures or skips. The ScreenWriter MSI digest and VirtualReg Manager retained archive/lifecycle checks passed; other package lifecycle cases used inert synthetic fixtures. No utility, MSI, VM, Defender or Windows state was changed or activated. The remaining NTCore package-list scope and pending-candidate Windows acceptance are open; no legacy outcome closed. Estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [complete run evidence](../archive/evidence/ntcore-packages-retained-winps51-regression-2026-10-28-1949.json) and [preceding no-cache observation](../archive/evidence/ntcore-packages-current-winps51-synthetic-regression-2026-10-28-1947.json).

## B04 UserProxy current-source Windows PowerShell regression and VM access, 2026-10-28 19:50 UTC

`UserProxyInventory.Tests.ps1`, `UserProxyPreparation.Tests.ps1` and `UserProxyLifecycle.Tests.ps1` passed 103/103 in Windows PowerShell 5.1/Pester 5.7.1 with TestRegistry disabled. WinINet and registry calls were mocked. A fresh read-only `Get-VM -Name RIDE-Win11-Test` query failed at host CIM before returning state; no checkpoint inspection or guest dispatch occurred. Native Windows apply/repeat/status/restore, effective policy, visible GUI and controlled PAC-consumer behavior remain deferred, and catalog target support remains empty. No legacy setting outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/b04-userproxy-inventory-preparation-lifecycle-winps51-and-vm-block-2026-10-28-1950.json).

## E07 WinHTTP advanced proxy post-reconciliation Windows PowerShell regression, 2026-10-28 19:52 UTC

The current inventory, preparation and lifecycle suites passed 22/22 in Windows PowerShell 5.1/Pester 5.7.1 after the 16:30 source reconciliation. No `netsh`, WinHTTP, registry or network calls were made. The candidate remains unsupported; native command availability, exact behavior, effective policy, GUI/consumer behavior and disposable-VM acceptance remain open. Host CIM denied the latest `Get-VM` query before VM state was returned. No legacy outcome closed. Estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/winhttp-proxy-current-source-postreconciliation-winps51-regression-2026-10-28-1952.json) and [VM blocker evidence](../archive/evidence/b04-userproxy-inventory-preparation-lifecycle-winps51-and-vm-block-2026-10-28-1950.json).

## JoeWare download-only preview and source discrepancy recheck, 2026-10-28 19:54 UTC

`tests/Download-JoeWareCollection.Tests.ps1` passed 8/8 in Windows PowerShell 5.1/Pester 5.7.1. The tests verify no publisher request/output-directory creation under WhatIf and that Defender-blocked AdFind is omitted or rejected before acquisition. No package bytes were downloaded or run. Official current-available version/page snapshots still show the recorded UserDump and DNSSrvRec discrepancies; ELDLLEx's product page was unavailable in this recheck, and its archive/version identity remains open. Exact publisher acquisitions remain blocked by local DNS; RIDE-Win11-Test inspection remains blocked by host CIM. AdFind remains excluded. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/joeware-download-preview-winps51-and-version-source-recheck-2026-10-28-1954.json) and [version discrepancy register](../joeware-version-discrepancies.md).

## JoeWare selected-product publisher DNS preflight, 2026-10-28 19:55 UTC

A read-only `Resolve-DnsName -Name www.joeware.net -Type A` preflight returned `Access is denied.` No download was attempted and no bytes or files were received for UserDump, DNSSrvRec or ELDLLEx. AdFind remains excluded. Exact publisher artifacts, package lifecycle and Windows acceptance remain deferred; no legacy outcome closed. Estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/joeware-selected-source-dns-preflight-block-2026-10-28-1955.json) and [source/version register](../joeware-version-discrepancies.md).

## JoeWare AdMod retained-artifact offline engine route, 2026-10-28 19:57 UTC

`tests/JoeWareAdModEngineRoute.Tests.ps1` passed 2/2 in Windows PowerShell 5.1/Pester 5.7.1 using the retained AdMod ZIP. The archive length (811,771 bytes) and SHA-256 matched the catalog pin; the offline package route staged the declared member through the real portable handler. Network acquisition and machine execution-context checks were mocked; AdMod was not run and the disposable test fixture was cleaned. Publisher DNS still denies selected product acquisition, AdFind remains excluded, and native VM lifecycle acceptance remains deferred by host CIM. No legacy outcome closed. Estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/joeware-admod-retained-engine-route-winps51-regression-2026-10-28-1957.json), [DNS blocker](../archive/evidence/joeware-selected-source-dns-preflight-block-2026-10-28-1955.json) and [VM access evidence](../archive/evidence/b04-userproxy-inventory-preparation-lifecycle-winps51-and-vm-block-2026-10-28-1950.json).


## Artcraft current-source validation and VM access recheck, 2026-10-28 20:29 UTC

Repository validation passed for 447 operations, 8 groups, 5 profiles and 301 PowerShell files. The focused Artcraft Pester suite did not run because Pester 5.7.1 is unavailable; the available module is 3.4.0. RIDE-Win11-Test access again failed before state retrieval at host CIM, so no native acceptance was dispatched. Resolved: repository validation only. Retired/excluded: none. Deferred: focused Artcraft regression pending Pester 5.7.1 availability and any Windows acceptance requiring the VM. Partial: no Artcraft legacy outcome closed. Estimates remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). Sysinternals license approval remains settled under the prior RIDE v2 specialist review and is not a migration gate; Defender exclusions remain separate. See [structured evidence](../archive/evidence/artcraft-current-source-validation-and-access-block-2026-10-28-2029.json).
## Legacy feedback selector component traceability, 2026-10-28 20:35 UTC

The v2 `DisableFeedback` selector writes `NumberOfSIUFInPeriod=0` (REG_DWORD), writes `DoNotShowFeedbackNotifications=1` (REG_DWORD), and disables DmClient plus DmClientOnScenarioDownload. Its reverse removes the SIUF count and policy override and enables both tasks. Neither selector writes `PeriodInNanoSeconds`. Added migration batch and selector metadata to `windows.feedback-notifications-policy`; both task operations already carry the selector pair. Repository export and validation passed for 447 operations, 8 groups, 5 profiles and 301 PowerShell files. No focused Pester run was possible because Pester 5.7.1 is unavailable. Get-VM failed at host CIM before state retrieval; no guest work ran.

Resolved: policy-operation legacy traceability metadata. Retired/excluded: none. Deferred: R04 GUI/value-kind/managed-precedence/pair-recovery acceptance and remaining guest tests. Partial: the SIUF pair overlap and full legacy feedback bundle remain open. The Learn page's REG_DWORD declaration conflicts with daily/weekly period values outside the DWORD range; no guessed state was added. Estimates remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). See [evidence](../archive/evidence/legacy-feedback-selector-catalog-traceability-2026-10-28-2035.json).
## NTCore Filter Monitor, Vista4Experts and AntiMida official-page review, 2026-10-28 20:40 UTC

Publisher pages reconfirm Filter Monitor 1.1.0 supports only Vista RTM through Windows 7 RTM and requires boot-time disabling of driver-signature enforcement for its unsigned x64 driver; Vista4Experts 1.2.0.1 advertises changing UAC, Defender scanning and automatic updates; AntiMida 1.0 documents process injection and kernel-driver/kernel-patching techniques. No tool/driver ran. Publisher ZIPs could not be fetched by the web reader; no archive bytes, digest, member inventory, package candidate or Windows target was added. The products remain selected under the user's full NTCore publisher-list decision. Resolved: current official-page facts for these three products. Retired/excluded: none. Deferred: archive identity, member review, candidate preparation and acceptance. Partial: no legacy outcome closed. Estimates remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). No license gate. See [source evidence](../archive/evidence/ntcore-filter-vista-antimida-official-page-review-2026-10-28-2040.json).
## Artcraft source regression and VM access recheck, 2026-10-28 20:42 UTC

The read-only Artcraft package metadata suite passed 6/6 in PowerShell 7.6.5 and 6/6 in Windows PowerShell 5.1/Pester 5.7.1. The Windows PowerShell invocation used process-only ExecutionPolicy Bypass; the initial default invocation failed before discovery. TestRegistry/TestResult were disabled. No installer/network/Windows state was touched. Fresh RIDE-Win11-Test Get-VM failed at host CIM before state retrieval. Resolved: source regression. Retired/excluded: none. Deferred: Windows package acceptance. Partial: no legacy outcome closed. Estimates remain 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). See [evidence](../archive/evidence/artcraft-current-source-pester-cross-shell-and-vm-block-2026-10-28-2042.json).
## RIDE-Win11-Test non-elevated read-only access recheck, 2026-10-28 22:56 UTC

`Get-VM -Name 'RIDE-Win11-Test'` failed before state retrieval with “Access to a CIM resource was not available to the client.” No checkpoint or Task Scheduler state was queried, and no guest request was dispatched. No VM, checkpoint, Windows, Defender or elevation state changed. Keep Windows acceptance deferred pending restored host CIM access and confirmed checkpoint/task readiness; continue independent source work. No legacy outcome closed; estimates unchanged at Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-2256.json).
## steghide 0.5.1 current publisher route and access recheck, 2026-10-28 23:00 UTC

The official [download page](https://steghide.sourceforge.net/download.php) still lists 0.5.1 and links the Windows ZIP through SourceForge. The web reader redirected to a mirror it could not access; local DNS for both `prdownloads.sourceforge.net` and `sourceforge.net` returned `Access is denied`. No archive bytes, hash, inventory, catalog candidate, extraction or execution. Keep the selected package optional; GPL review status is administrative and does not gate migration. Archive acquisition and Windows acceptance remain open. No legacy outcome closed; estimates unchanged. See [evidence](../archive/evidence/steghide-0.5.1-current-publisher-route-and-access-block-2026-10-28-2300.json).
## RIDE-S25-Test non-elevated read-only access recheck, 2026-10-28 23:02 UTC

`Get-VM -Name 'RIDE-S25-Test'` failed before state retrieval with “Access to a CIM resource was not available to the client.” No checkpoint or Task Scheduler state was queried, and no guest request was dispatched. No VM, checkpoint, Windows, Defender or elevation state changed. Keep Windows Server 2025 acceptance deferred pending restored host CIM access and confirmed checkpoint/task readiness; continue independent source work. No legacy outcome closed; estimates unchanged at Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/ride-s25-test-cim-access-recheck-2026-10-28-2302.json).

## B06 OpenSSH Client and Telnet Client current-source regression, 2026-10-28 23:14 UTC

	ests/ClientComponentLifecycle.Tests.ps1 passed 26/26 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1. Inventory, pending-reboot, source-path/architecture, and native transition boundaries were mocked; lifecycle state files were confined to Pester TestDrive. No DISM or Windows component transition ran. This verifies current local lifecycle guards only. Disposable Windows 11 and declared Windows Server target acceptance, native source/media behavior and recovery remain open; current host VM/checkpoint/task access is still blocked at CIM. No legacy component outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/b06-client-component-current-source-winps51-regression-2026-10-28-2314.json).

## Repository static validation after current migration batches, 2026-10-28 23:19 UTC

Windows PowerShell 5.1 	ools/validate.ps1 -Root . passed for 447 operations, 8 groups, 5 profiles and 301 PowerShell files; generated operation documentation is current. This read-only validation invokes no handlers/installers and does not establish native Windows acceptance. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/repository-static-validation-after-current-migration-batches-2026-10-28-2319.json).

## RIDE-Win11-Test and RIDE-S25-Test current CIM access blocker, 2026-10-28 23:19 UTC

Fresh non-elevated Get-VM calls for both existing disposable targets failed before state retrieval with Access to a CIM resource was not available to the client. No checkpoint/task/queue query was made and no guest request was submitted. Defer native acceptance until host CIM access and existing checkpoint/task readiness can be confirmed. Continue independent local source preparation and regression. No VM, Windows, Defender or elevation state changed; no legacy outcome closed and estimates unchanged. See [structured evidence](../archive/evidence/ride-win11-and-s25-test-current-cim-access-block-2026-10-28-2319.json).

## OpenSSH Server capability catalog/engine integration current-source regression, 2026-10-28 23:25 UTC

Corrected the catalog AcceptanceNotes: the component.openssh-server-capability operation is now catalog-discoverable and wired through engine planning, state capture, guarded apply/remove and saved-run restore; service activation and TCP/22 firewall control remain separate operations. The four focused Catalog, NetworkAndSoundControls, OpenSshServerCapabilityLifecycle and OpenSshServerObservation suites discovered 136 tests; 135 passed and the one WindowsIntegration registry test was excluded. Pester 5.7.1 TestRegistry/TestResult plugins were disabled. 	ools/Export-RideCatalog.ps1 regenerated docs/OPERATIONS.md; 	ools/validate.ps1 -Root . passed for 447 operations, 8 groups, 5 profiles and 301 PowerShell files. All capability/service/firewall/DISM boundaries were mocked or synthetic. No VM, Defender or Windows state changed. SupportedTargets remains empty; native Windows 11 and Server 2025 servicing, repeat, exact restore, first-start data preservation and partial-failure recovery remain pending host CIM and guest access. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/openssh-server-capability-current-catalog-engine-regression-2026-10-28-2325.json).


## Gpg4win source regression and PasswordScan Defender blocker update, 2026-10-28 23:28 UTC

The focused Gpg4win suite passed 12/12 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1. All installer, key/configuration, network and registry effects were mocked or synthetic; no installer or real user key data was touched. A newly received user report identifies x64 PasswordScan at the already known NirSoft filtered-Pester temporary-stage path/GUID. Event details and creating run remain unknown. Keep x86 and x64 PasswordScan excluded and pause only NirSoft staging/Pester runs that could materialize the file. Gpg4win native Windows 11 acceptance remains deferred. No migration outcome closed; estimates remain unchanged. See [Gpg4win regression evidence](../archive/evidence/gpg4win-current-source-winps51-regression-and-passwordscan-defender-block-2026-10-28-2328.json) and [Defender alert evidence](../archive/evidence/nirsoft-passwordscan-user-defender-block-2026-10-28-2328.json).

## RIDE-Win11-Test and RIDE-S25-Test host CIM access recheck, 2026-10-28 23:30 UTC

The read-only Get-VM query for both disposable targets failed before returning VM state with Access to a CIM resource was not available to the client. No checkpoint/task/queue state was inspected, no guest work was dispatched, and no UAC or system state was changed. Keep native acceptance deferred; continue independent source and mocked regression work. No legacy outcome closed; estimates unchanged at 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/ride-win11-and-s25-test-cim-access-recheck-2026-10-28-2330.json).

## Offline bundle integrity and execution current-source regression, 2026-10-28 23:32 UTC

	ests/OfflineExecution.Tests.ps1 and 	ests/OfflineBundle.Tests.ps1 passed 81/81 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1 on repeat. The initial 80/81 run had one synthetic portable-manifest replacement failure; no source changed before the passing retry. The test's mocked acquisition, Authenticode and installer boundaries prevented network or real installer activity. Test-generated .local fixtures were cleaned. Mandatory install/apply gating is already implemented in the engine. Reviewed-bundle disconnected Windows deployment, full dependency/provenance coverage and native servicing behavior remain deferred; both VM CIM checks failed before state retrieval. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/offline-bundle-integrity-execution-current-source-regression-and-cim-block-2026-10-28-2332.json).

## NirSoft PasswordScan current-catalog and stage-source text audit, 2026-10-28 23:36 UTC

A metadata-only catalog parse found zero passwordscan.exe selections in either current NirSoft package (647 launcher members and 47 x64-tool members). The current filtered Pester source includes PasswordScan in blocked basenames, and the reported temporary-parent name does not appear in current tests, modules, tools or catalog source. The creating run/source revision is still unknown. No archive, binary, .local stage, alert path or Defender state was accessed; no NirSoft staging/test ran. Maintain both architecture exclusions and pause only tests that could materialize PasswordScan. No outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/nirsoft-current-catalog-passwordscan-exclusion-and-stage-source-audit-2026-10-28-2336.json).

## RIDE-Win11-Test and RIDE-S25-Test host CIM access recheck, 2026-10-28 23:38 UTC

A fresh read-only Get-VM query for both registered disposable targets failed with Access to a CIM resource was not available to the client before state retrieval. Checkpoint/task/queue state was not queried and no guest request or elevation occurred. Keep all native Windows 11/Server 2025 acceptance deferred; continue source implementation and local regressions that do not need these VMs. No legacy outcome closed; estimates unchanged at 37-57 / 37-52 / 19-24 / 25-35 / 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/ride-win11-and-s25-test-cim-access-recheck-2026-10-28-2338.json).

## E08 Secedit source-contract recheck, 2026-10-28 23:40 UTC

Official Microsoft Learn pages confirm secedit /import, /configure, /generaterollback and /validate apply to Windows 11 and Server 2025, and document rollback preparation/validation plus the broad account-policy scope of securitypolicy. They do not prove isolated one-setting behavior or exact restoration of local NotDefined; E08 remains unregistered pending disposable-VM acceptance. No native Secedit or Windows state changed; estimates unchanged. See [structured evidence](../archive/evidence/local-password-complexity-secedit-import-isolation-source-recheck-2026-10-28-2340.json).
