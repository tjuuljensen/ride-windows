## HashCheck Windows 11 acceptance complete, 2026-10-30

HashCheck 2.6.3 (installed version 2.6.3.0) is complete for the intended signed-in Windows 11 administrator workflow. The pinned official installer, publisher checksum and valid signature were verified. Maintained ApplicationsBatch11 run 77f50d48b54c4f5c9b5393208f54987e passed all eight install/remove/repeat and saved-state presence recovery checks, with 428 Pester tests passed, zero failed and four skipped. Recovery reinstalls the declared version, not an arbitrary historical version.

Feature run 4b1d874246f44009b360753c6a64ad78 passed matching-manifest verification, deliberately changed-file mismatch detection and SHA-256 manifest creation. Explorer observations are operator-reported; the exported generated manifest and installation records were independently verified. Ten guest evidence files passed transfer hash comparison and host rehashing. The retained recovery receipt records checkpoint 91369e82-5ff2-49ef-87c4-c4518a77ae7b restored at 2026-10-30 06:05:05 UTC, VM Off, controller Ready and ten verified files. The operator also confirmed this final state.

The catalog now declares Windows 11 support and clears PendingAcceptance. Installation and removal require the intended user's elevated interactive session. Session 0, SYSTEM, another intended user and Windows Server remain unsupported. No further HashCheck acceptance retry is required for this scope. Broader controller certification remains NotValidated and other Windows acceptance work remains separate.

One requested v3 addition is completed. HashCheck was tracked separately from legacy estimates, so no legacy outcome is resolved, retired or newly excluded by this closure. Other partial and deferred scope is unchanged. All five ranges remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35 and maintenance 8-12: exact 126-180, rounded 125-180/about 155. Two focused Windows PowerShell 5.1 metadata tests passed, one each in Catalog and ApplicationPackages; unrelated tests were not selected.

Evidence: [completed acceptance](archive/evidence/hashcheck-windows11-acceptance-complete-2026-10-30.json).

## NTCore package current-source synthetic regression, 2026-10-29 03:02 UTC

`NtcorePackages.Tests.ps1` passed **22**, failed **0**, skipped **1** in Windows PowerShell 5.1/Pester 5.7.1. The retained-archive fixture environment was unset, so only current-source metadata and synthetic package lifecycle tests ran; the retained ScreenWriter MSI case skipped. Explorer Suite III’s publisher pin and administrative, non-gating `NeedsReview` status were verified. No product ran. Windows target acceptance remains pending. See [structured evidence](archive/evidence/ntcore-packages-current-source-synthetic-regression-and-cim-block-2026-10-29-0302.json).

## Sysinternals Suite current-source package lifecycle regression, 2026-10-29 03:01 UTC

The full Suite package test passed **8/8** with inert synthetic ZIP members for all 164 required files. It verified the pin, immutable network boundary, complete-member guard, collision-safe ownership, repeat lifecycle, and recovery. No product or driver ran and no payload was downloaded. This adds no new Windows acceptance; the prior RIDE v2 specialist approval remains settled without a license gate. See [structured evidence](archive/evidence/sysinternals-suite-current-source-regression-and-cim-block-2026-10-29-0301.json).

## Sysinternals independent product current-source regression, 2026-10-29 02:57 UTC

`SysinternalsProductPackages.Tests.ps1` passed **72/72** across nine products in Windows PowerShell 5.1/Pester 5.7.1. Inert synthetic archives and mocks covered package pins, managed-member lifecycle, and signature/network boundaries; no product utility or driver ran and no payload was downloaded. Native acceptance was not performed. The prior RIDE v2 specialist approval remains settled and non-gating. See [structured evidence](archive/evidence/sysinternals-products-current-source-winps51-regression-and-cim-block-2026-10-29-0257.json).

## MiTeC DirList current-source synthetic lifecycle regression, 2026-10-29 02:35 UTC

The focused suite passed **2/2** in Windows PowerShell 5.1/Pester 5.7.1 with TestRegistry and TestResult disabled. Using an inert synthetic ZIP, it verified the selected member is staged and repeated idempotently, the unselected member is omitted, and snapshot recovery preserves operator content. No utility or live directory was accessed. DirList remains a pending candidate; Windows lifecycle acceptance remains open. See [structured evidence](archive/evidence/mitec-dirlist-current-source-synthetic-lifecycle-and-cim-block-2026-10-29-0235.json).

## MiTeC Task Manager DeLuxe current-source synthetic lifecycle regression, 2026-10-29 02:33 UTC

The focused suite passed **2/2** in Windows PowerShell 5.1/Pester 5.7.1; the retained publisher archive case was skipped because no explicit archive fixture was supplied. After adding the missing `System.IO.Compression.FileSystem` assembly reference, the inert fixture verified x86/x64 variant selection, repeat staging, exact managed-member removal, snapshot restore, and operator-note preservation. No utility ran. The product remains a pending candidate without Windows target acceptance. See [structured evidence](archive/evidence/mitec-task-manager-deluxe-current-source-synthetic-lifecycle-and-cim-block-2026-10-29-0233.json).

## MiTeC Network Meter current-source synthetic lifecycle regression, 2026-10-29 02:29 UTC

`MiTeCNetworkMeter.Tests.ps1` passed **2/2** in Windows PowerShell 5.1/Pester 5.7.1. It verifies current candidate metadata, then installs/repeats/removes/restores an inert synthetic ZIP using only `NetMet.exe`; it preserves an operator note and confirms the unselected member is absent. The exact local-version `NeedsReview` marker is present and non-gating. No publisher archive was reacquired or rehashed, and Network Meter did not run or inspect live adapters. Windows 11 lifecycle/product behavior remains pending. No legacy outcome closed; estimates are unchanged. See [structured evidence](archive/evidence/mitec-network-meter-source-lifecycle-regression-2026-10-29-0229.json).

## MiTeC Network Meter 2.5.0 package review coverage, 2026-10-29 00:09 UTC

The new package.mitec-network-meter candidate has an exact-version NeedsReview / Unassigned local marker. The workspace-local store contains 92 records, and the coverage audit confirms all 51 pending package versions have exact operation-ID/version markers. Review remains administrative and does not gate package planning or acceptance. See [candidate evidence](archive/evidence/mitec-network-meter-v3-portable-candidate-regression-2026-10-29-0009.json).
## MiTeC DirList 1.3.0 package review coverage, 2026-10-29 00:06 UTC

The new package.mitec-dirlist candidate has an exact-version NeedsReview / Unassigned local marker. The workspace-local store contains 91 records after the update; a read-only audit confirms all 50/50 pending package versions have exact operation-ID/version markers. Review remains administrative and does not gate package planning or acceptance. See [candidate evidence](archive/evidence/mitec-dirlist-v3-portable-candidate-regression-2026-10-29-0006.json).
## BloodHound CE 9.8.0 collector release metadata and SharpHound license, 2026-10-28 23:18 UTC

The publisher's v2.17.0 and v3.1.1 release API metadata reconfirms the exact selected Windows ZIP names, sizes and SHA-256 digests. BloodHound CE v9.8.0's tagged Dockerfile pins that pair. Retained SharpHound LICENSE text matches the v2.17.0 Git blob SHA; the tag root has no separate NOTICE file. The ZIPs and sidecars are still absent locally: a previous exact-source DNS preflight was denied before resolution, and the available GitHub connector cannot download binary release assets. No collector or backend ran. Do not create a package candidate before obtaining and inventorying the exact ZIPs. GPL review remains administrative, not a migration gate. See [structured evidence](archive/evidence/bloodhound-collectors-exact-release-api-digests-and-sharphound-license-2026-10-28-2318.json) and [publisher CE Dockerfile](https://raw.githubusercontent.com/SpecterOps/BloodHound/v9.8.0/dockerfiles/bloodhound.Dockerfile).

## Independent Sysinternals product current-source regression, 2026-10-28 23:15 UTC

	ests/SysinternalsProductPackages.Tests.ps1 passed 72/72 with zero skips in Windows PowerShell 5.1.26100.9818/Pester 5.7.1 across Process Explorer, Autoruns, TCPView, Process Monitor, RAMMap, Disk2vhd, Sigcheck, Strings and Handle. Product file staging used inert synthetic ZIP members in TestDrive; network/signature calls and product execution were mocked. No Sysinternals utility, driver, EULA, startup setting or Windows state was touched. The user's prior RIDE v2 license-specialist approval governs RIDE's direct Microsoft download/install model; no license gate is reopened. Defender-blocked tools remain separately excluded. This regression adds no native acceptance or legacy outcome closure. See [structured evidence](archive/evidence/sysinternals-independent-product-current-source-winps51-regression-2026-10-28-2315.json).

## BloodHound CE 9.8.0 selected AzureHound 3.1.1 license/notice retention, 2026-10-28 23:09 UTC

Retained exact-tag upstream LICENSE.md and NOTICE.md for AzureHound v3.1.1 at catalog/notices/azurehound-v3.1.1-license.md and catalog/notices/azurehound-v3.1.1-notice.md; byte lengths and SHA-256 digests are recorded in the linked evidence. The notice files match the retained 3.1.2 text. This does not supply the selected 3.1.1 ZIP, establish compatibility with BloodHound CE 9.8.0, or close a package outcome. No binary/payload ran and no VM, Defender, Windows or elevation state changed. The selected pair remains AzureHound 3.1.1 plus SharpHound 2.17.0. See [structured evidence](archive/evidence/bloodhound-azurehound-v3.1.1-license-notice-retained-2026-10-28-2309.json).

## NirSoft PasswordScan user-reported Defender block, 2026-10-28 23:08 UTC

The user reports another Defender block alert for x64 passwordscan.exe at the previously reported filtered-Pester temporary-stage path and GUID. The report did not include a detection name, event timestamp, or creating-run identity; a distinct event is unconfirmed. Keep PasswordScan x86 and x64 excluded and pause NirSoft staging/Pester runs that could materialize the file pending provenance reconciliation. Unrelated NirSoft source review may continue when isolated from PasswordScan materialization. No alert file or Defender state was accessed or changed; no legacy outcome closed and estimates unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-user-defender-alert-2026-10-28-2308.json).

## NTCore Unpacker/DynLogger retained archive full regression, 2026-10-28 22:53 UTC

`tests/NtcoreUnpackerDynLogger.Tests.ps1` passed all 18/18 tests with zero skips in Windows PowerShell 5.1.26100.9818/Pester 5.7.1 using the reviewed `.local/remaining-collections-20261017` archive directory. All six retained publisher archives matched declared SHA-256 pins and selected-member inventories; repeat staging, removal, snapshot restore and operator-note preservation passed in TestDrive. No executable or DLL was launched/loaded, no target process was inspected, and the NoDel driver was not loaded. TestRegistry/TestResult were disabled; process-only `ExecutionPolicy Bypass` made no persistent change. No VM, queue, Defender, PasswordScan alert path, Windows state or elevation was accessed. Native Windows acceptance remains deferred; no legacy outcome closed and estimates unchanged. See [structured evidence](archive/evidence/ntcore-unpacker-dynlogger-retained-archives-full-regression-2026-10-28-2253.json).
## Phoenix Protector retained MSI exact-pin recheck, 2026-10-28 22:50 UTC

The reviewed local artifact `.local/remaining-collections-20261017/Phoenix_Protector.msi` is present at 1,357,312 bytes and still hashes to the catalog SHA-256 `15a7dbbf90ce66fb302a322c6809fafd897808096069dfecededf78e51b16369` for version 1.7.1. This confirms the retained candidate pin, not the current bytes behind the publisher's mutable URL. The page/MSI/contained-executable versions remain 1.8.0.1/1.7.1/1.9.0.1. No file content was extracted; no installer, VM, Defender, Windows or elevation state was touched. No legacy outcome closed; estimates unchanged. See [structured hash evidence](archive/evidence/phoenix-retained-msi-hash-current-recheck-2026-10-28-2250.json) and [fetch blocker](archive/evidence/phoenix-protector-publisher-msi-byte-recheck-web-decode-block-2026-10-28-2249.json).
## Phoenix Protector official MSI byte-fetch recheck, 2026-10-28 22:49 UTC

The official product page lists version 1.8.0.1 and links the existing `Phoenix_Protector.msi` URL. A direct fetch of that publisher MSI through the available web source failed with a Unicode decoding error before any artifact bytes were available; no file was written or hashed. Preserve the catalog's exact 1.7.1 / SHA-256 pin and the distinct embedded executable version 1.9.0.1 until the bytes can be inspected. The NeedsReview marker remains administrative and does not gate migration. No VM, installer, Defender, Windows or elevation state changed. No legacy outcome closed; estimates unchanged. See [structured fetch evidence](archive/evidence/phoenix-protector-publisher-msi-byte-recheck-web-decode-block-2026-10-28-2249.json) and the [official publisher page](https://ntcore.com/phoenix-protector/).
## Phoenix Protector current pin/prerequisite regression, 2026-10-28 22:48 UTC

`tests/PhoenixPackage.Tests.ps1` passed 4/4 with no skips in Windows PowerShell 5.1.26100.9818/Pester 5.7.1. Coverage confirms the exact 1.7.1 MSI hash pin, machine-wide quiet arguments, .NET Framework 3.5 prerequisite fail-closed behavior, and the mocked msiexec argument path. The product page currently lists 1.8.0.1, while the pinned MSI is 1.7.1 and the contained executable 1.9.0.1; this regression does not resolve that identity mismatch. The exact-version NeedsReview marker remains administrative, not a migration gate. TestRegistry/TestResult were disabled; process-only ExecutionPolicy Bypass did not change persistent policy. No MSI, installer, publisher network, VM, Defender, Windows state or elevation was accessed. Native acceptance and exact current MSI identity remain deferred. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/phoenix-protector-pinned-package-regression-2026-10-28-2248.json) and [current NTCore product page](https://ntcore.com/phoenix-protector/).
## NTCore package retained-source full regression, 2026-10-28 22:47 UTC

`tests/NtcorePackages.Tests.ps1` passed all 23/23 tests with no skips in Windows PowerShell 5.1.26100.9818/Pester 5.7.1 after setting `RIDE_NTCORE_FIXTURE_DIRECTORY` to the previously reviewed workspace-local `source-review-batches2-20261017` directory. The retained ScreenWriter MSI digest case ran and passed; other retained-source and synthetic lifecycle cases passed. Optional TestRegistry/TestResult were disabled and process-only `ExecutionPolicy Bypass` made no persistent change. No installer, utility, network, VM, Defender, PasswordScan alert path or Windows state was accessed. Native Explorer Suite lifecycle acceptance remains deferred pending controller capability refresh and host VM access. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/ntcore-packages-retained-source-full-regression-2026-10-28-2247.json).
## NTCore package full regression with one retained-source skip, 2026-10-28 22:46 UTC

`tests/NtcorePackages.Tests.ps1` discovered 23 tests and passed 22, failed 0, skipped 1 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1. The skipped check is retained ScreenWriter MSI identity because `RIDE_NTCORE_FIXTURE_DIRECTORY` was not configured; prior retained-source verification remains linked in earlier ledger entries. Synthetic portable file lifecycles, candidate metadata and the new ApplicationsBatch12 runner test passed. TestRegistry/TestResult were disabled, and `ExecutionPolicy Bypass` applied only to the test process. No installer or utility ran; no retained artifact, VM, queue, Defender, PasswordScan path, Windows state or elevation was accessed. Native Explorer Suite acceptance remains deferred. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/ntcore-packages-full-current-source-regression-with-screenwriter-skip-2026-10-28-2246.json).
## NTCore Explorer Suite focused runner Pester regression, 2026-10-28 22:45 UTC

Windows PowerShell 5.1.26100.9818/Pester 5.7.1 passed 42 focused tests: the exact-package ApplicationsBatch12 route assertion (1/1), registered-controller capability guard (1/1), VM task forwarding/correlation (26/26), and guest dispatcher scenario mapping (14/14). Optional TestRegistry/TestResult integrations were disabled. This run used `-ExecutionPolicy Bypass` for the test process only; no persistent policy or elevation change occurred. A preliminary filter matched no tests and ran none; corrected filters produced the passing results above. These tests prove runner orchestration only, not guest lifecycle behavior. No VM/checkpoint/queue request, installer, suite utility, publisher network, Defender, alert file or Windows state was touched. Controller capability refresh and host VM access remain the acceptance blockers. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/ntcore-explorer-suite-pester5-focused-runner-tests-2026-10-28-2245.json).
## NTCore Explorer Suite acceptance-route assertion follow-up, 2026-10-28 22:42 UTC

Corrected the focused Pester source assertion to verify the actual task-client guard call and the controller module's capability token. Seven direct source assertions now pass. Windows PowerShell 5.1.26100.9818 parser validation accepted all eight changed scripts; the PowerShell 7.6.5 repository validator passed 447 operations, 8 groups, 5 profiles and 301 PowerShell files. Pester tests remain unrun: Pester 5.7.1 import is blocked by AuthorizationManager in Windows PowerShell and PowerShell 7 only has Pester 3.4.0. No policy bypass, VM, installer, utility, network, Defender or elevation action occurred. No legacy outcome closed; estimates unchanged. See [structured follow-up evidence](archive/evidence/ntcore-explorer-suite-runner-source-assertion-and-validation-followup-2026-10-28-2242.json).
## NTCore Explorer Suite runner parser/repository validation follow-up, 2026-10-28 22:41 UTC

The guarded ApplicationsBatch12 route was parser-checked under Windows PowerShell 5.1.26100.9818 across all eight changed scripts. The PowerShell 7.6.5 repository validator passed for 447 operations, 8 groups, 5 profiles and 301 PowerShell files, and catalog documentation is current. Direct exact-package and stale-controller guards and all five script-version checks passed in PowerShell 7.6.5. Pester did not run: PS7 provides Pester 3.4.0, while the installed Windows PowerShell 5.1 Pester 5.7.1 import fails on AuthorizationManager loading its format file. Repository-script execution under Windows PowerShell is likewise blocked; no execution-policy bypass was used. VM/controller/elevation and installer acceptance remain deferred. No legacy outcome closed; estimates unchanged. See [structured validation evidence](archive/evidence/ntcore-explorer-suite-runner-cross-shell-parser-and-repository-validation-2026-10-28-2241.json).

## NTCore Explorer Suite focused Windows acceptance route, 2026-10-28 22:36 UTC

The guarded `ApplicationsBatch12` runner now selects only `package.ntcore-explorer-suite`, targets Windows 11, and covers installer file identity, install/repeat, remove/repeat, and saved-state recovery without launching suite utilities. It requires the new protected-controller capability. Local parser and exact-selector/capability checks passed; Pester tests were not run: PowerShell 7 has Pester 3.4.0, and the Windows PowerShell 5.1 Pester 5.7.1 import is blocked by AuthorizationManager; no VM request was submitted. Controller refresh requires the saved elevated step; host VM/CIM access remains blocked. The candidate remains pending native acceptance; no target support is declared. Its license marker remains administrative, not a migration gate. See [structured evidence](archive/evidence/ntcore-explorer-suite-focused-acceptance-runner-preparation-and-local-guard-regression-2026-10-28-2236.json).
## NTCore Explorer Suite candidate-boundary test and Phoenix DNS recheck, 2026-10-28 22:29 UTC

Added a focused package test for package.ntcore-explorer-suite. It passed 1/1 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1 with TestRegistry and TestResult disabled. It asserts the exact publisher version/digest, EXE machine-scope candidate metadata, quiet install/uninstall arguments, compensating rollback, pending Windows support, and NeedsReview/Unassigned as non-gating owner administration. No installer or utility ran. This improves candidate coverage only; the full-suite install, installed component/shortcut scope, registered uninstaller, repeat/remove/recovery and Windows acceptance remain pending.

The exact-version NeedsReview/Unassigned marker is present in the local review store and does not delay technical completion. Phoenix DNS preflight for ntcore.com and www.ntcore.com returned Access is denied, so no current publisher MSI bytes were received; retain the 1.7.1 pin and its separate 1.8.0.1 page / 1.9.0.1 executable identities. No VM, Windows, Defender or elevation state changed. No outcome closed; estimates unchanged. See [structured evidence](archive/evidence/ntcore-explorer-suite-candidate-acceptance-boundary-and-phoenix-dns-recheck-2026-10-28-2229.json).

## NTCore Explorer Suite current publisher/version regression and Phoenix DNS block, 2026-10-28 22:26 UTC

The current NTCore Explorer Suite publisher page labels the exact artifact III (18/11/2012) and publishes SHA-256 94f4348ec573b05990b1e19542986e46dc30a87870739f5d5430b60072d5144d. The 3,613,174-byte retained installer hash matches. The focused NtcorePackages.Tests.ps1 publisher-version identity assertion passed 1/1 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1, with TestRegistry and TestResult disabled. The internal IV label remains separate. The full-suite candidate is still unsupported pending install/repeat/remove/recovery acceptance on the disposable VM; its NeedsReview marker is administrative and is not a migration gate.

The current Phoenix Protector page lists 1.8.0.1 but links to the same Phoenix_Protector.msi URL. The retained pinned MSI remains 1.7.1 (SHA-256 15a7dbbf90ce66fb302a322c6809fafd897808096069dfecededf78e51b16369), and its contained executable remains 1.9.0.1. A Windows PowerShell fetch to the publisher URL failed before receiving bytes because DNS resolution of ntcore.com failed; no partial file was retained. Keep the exact pin and version labels distinct until the artifact is obtainable; its NeedsReview marker does not block technical work. No package or utility was installed or run, and no VM/Windows/Defender/elevation state changed. No outcome closed; estimates unchanged. See [batch evidence](archive/evidence/ntcore-explorer-suite-current-publisher-regression-and-phoenix-dns-block-2026-10-28-2226.json) and [current NTCore Explorer Suite publisher page](https://ntcore.com/explorer-suite/) and [Phoenix Protector publisher page](https://ntcore.com/phoenix-protector/).

## NirSoft PasswordScan Defender repeat report, 2026-10-28 18:56 UTC

The user reports a newly received block alert for x64 PasswordScan at the same temporary-stage path/GUID recorded earlier. The reported stage root did not exist when checked; that does not establish the Defender event identity or creating run. The current NirSoft staging test uses synthetic archives, while the retained publisher-archive case is inventory-only. Keep both PasswordScan architectures excluded and affected staging/Pester lifecycle checks paused pending provenance reconciliation. No executable, file metadata, contents, hash or Defender state was inspected; no test rerun or Windows change occurred. No legacy outcome closed; estimates remain Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1856.json).

## PasswordScan temporary-stage provenance text audit, 2026-10-28 18:45 UTC

A text-only search found no exact reported GUID in local source/log text, and the reported parent temp-directory name does not appear in current runner source. The portable handler generates `RIDE-Portable-<GUID>` under the process temp root; the current NirSoft test source excludes 13 blocked executable names including PasswordScan, uses synthetic inert archives for staging tests, and keeps the retained encrypted-archive review inventory-only. The creator and source revision for the reported stage remain unknown. No reported executable, metadata or hash was accessed; no staging/test rerun, Defender query/change, VM action, Windows change or elevation occurred. Keep PasswordScan x86/x64 excluded and pause NirSoft lifecycle runs that could materialize it pending provenance reconciliation. No legacy outcome closed; estimates remain Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured provenance evidence](archive/evidence/nirsoft-passwordscan-stage-provenance-text-audit-2026-10-28-1845.json).
## Sysinternals independent products current-source regression, 2026-10-28 18:38 UTC

`tests/SysinternalsProductPackages.Tests.ps1` passed 72/72 across process explorer, Autoruns, TCPView, Process Monitor, RAMMap, Disk2vhd, Sigcheck, Strings and Handle in PowerShell 7.6.5/Pester 5.7.1 (139.36 seconds). Each test container used synthetic inert archive members; TestRegistry and TestResult were disabled. No network discovery, payload download, product executable, installer, Defender-blocked tool, VM, Windows state or elevation was used. Together with the separately recorded Suite regression, all 80 focused assertions pass. These are local source/lifecycle regressions, not new native acceptance and not a legacy-outcome closure. Estimates remain Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). Prior RIDE v2 specialist approval clears Sysinternals direct download/install; Defender exclusions remain separate. See [structured evidence](archive/evidence/sysinternals-products-current-source-pester-regression-2026-10-28-1838.json) and [Suite regression](archive/evidence/sysinternals-suite-current-source-pester-regression-2026-10-28-1834.json).
## Sysinternals Suite current-source regression, 2026-10-28 18:34 UTC

`tests/SysinternalsSuitePackage.Tests.ps1` passed 8/8 in PowerShell 7.6.5/Pester 5.7.1 (368.29 seconds), with TestRegistry and TestResult disabled. Synthetic inert ZIP members exercised pinned acquisition boundaries, archive validation, repeat staging, owned-file uninstall/restore and collision handling. No network discovery, payload download, product executable, installer, Defender-blocked tool, VM, Windows state or elevation was used. An initial combined invocation failed before discovery due an invalid Pester configuration property; the corrected combined 80-test invocation remained silent and was interrupted without an aggregate result. Only the isolated 8/8 run is counted. This adds no native acceptance and closes no legacy outcome; estimates remain Settings 37-57, Packages 37-52, Components 19-24, Files/assets 25-35, Maintenance 8-12 (exact 126-180; rounded 125-180/about 155). Sysinternals direct download/install remains cleared under prior RIDE v2 specialist approval; Defender exclusions remain separate. See [structured evidence](archive/evidence/sysinternals-suite-current-source-pester-regression-2026-10-28-1834.json).
## NirSoft PasswordScan Defender notification repeat report, 2026-10-28 18:18 UTC

The user reports another Defender block alert for x64 `passwordscan.exe` at the same filtered-Pester temporary-stage path/GUID reported earlier today. This does not establish a distinct Defender event or provide its detection name, event timestamp, or creating process/catalog revision. Keep both PasswordScan architectures excluded and pause NirSoft staging/Pester lifecycle runs that could materialize the member pending temporary-stage provenance and catalog/source revision reconciliation. No file, metadata, hash, Defender state, test or staging was accessed or changed. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1818.json).

## RIDE-Win11-Test read-only CIM access recheck, 2026-10-28 18:16 UTC

`Get-VM -Name RIDE-Win11-Test` failed before state retrieval because host CIM access was denied. No checkpoint or guest task was inspected; no guest request or VM/Windows/Defender change occurred. The target had been shown running in Hyper-V Manager at 17:43, but checkpoint membership remains unconfirmed. Keep Windows package acceptance deferred. Estimates unchanged. See [structured evidence](archive/evidence/ride-win11-test-vm-cim-access-block-2026-10-28-1816.json).
## steghide 0.5.1 official archive acquisition retry, 2026-10-28 17:46 UTC

The official page still lists 0.5.1 and links the Windows ZIP through SourceForge. Metadata-only HEAD requests to both official download hosts failed DNS before transfer. No archive bytes, hash, member inventory or catalog candidate were added; no utility was extracted or run. Keep it selected and optional. GPL review metadata is administrative and does not gate migration. Exact archive inventory and Windows acceptance remain open; estimates unchanged. See [structured evidence](archive/evidence/steghide-official-download-dns-retry-2026-10-28-1746.json).
## RIDE-Win11-Test VM access recheck, 2026-10-28 17:43 UTC

Hyper-V Manager shows RIDE-Win11-Test running, but the visible `RIDE-clean-test-base` checkpoint belongs to selected RIDE-S25-Test; target checkpoint membership remains unconfirmed. The elevated console does not expose its VM/checkpoint list to read-only accessibility inspection, and host CIM had denied `Get-VM`. No guest request was dispatched and no VM/checkpoint changed. Keep Windows acceptance deferred until target checkpoint membership and task readiness are confirmed. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/ride-win11-test-hyperv-running-checkpoint-unconfirmed-2026-10-28-1743.json).
## NirSoft PasswordScan Defender alert report, 2026-10-28 17:41 UTC

The user reports a newly received Defender block alert for x64 `passwordscan.exe` at the same filtered-Pester temporary-stage path/GUID recorded in earlier reports. The notification does not provide a detection name, Defender event timestamp or creator; it does not establish whether the underlying event is distinct. Keep both PasswordScan architectures excluded and pause NirSoft staging/Pester lifecycle runs that could materialize the member until temporary-stage provenance and catalog/source revision are reconciled. The file, path metadata, hash and Defender state were not accessed; no test or staging ran. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](archive/evidence/nirsoft-passwordscan-user-defender-alert-2026-10-28-1741.json).
## Ophcrack and steghide current-source review, 2026-10-28 17:37 UTC

The Ophcrack publisher lists portable 3.8.0, a Windows ZIP, support through Windows 10, and MD5; its linked SourceForge file page lists SHA-256. Local DNS prevented exact ZIP acquisition before transfer, so there are no local bytes/hash/member inventory and no candidate yet. Steghide's official site lists 0.5.1, a 1.8 MB Windows ZIP and bundled dependencies; the project is GPL, but its download page does not publish SHA-256. It has no local artifact inventory or Windows 11 acceptance. Keep both optional and unsupported pending exact archive inventory and target acceptance. Mark exact-version GPL review as `NeedsReview` / `Unassigned` local owner administration once each candidate ID exists; this does not gate migration. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/ophcrack-steghide-current-source-review-and-acquisition-2026-10-28-1737.json).
## Hash Suite Free current-source recheck, 2026-10-28 17:34 UTC

The official publisher lists Free 4.1 (2026-10-17), a 28.3 MB ZIP, published SHA-256 `72c215e7c6a5da0941d73cd7a474af9565b7823017d29e400e5a4ef9892165fe`, and Windows 10 64-bit minimum. The exact publisher URL could not be acquired because local DNS failed before transfer; no local hash or member inventory exists, so no package candidate was added. The source page describes Free as allowed for any legal use while the separate license page presents paid commercial terms; add an exact-version `NeedsReview` / `Unassigned` local owner marker when a candidate ID exists. This is administrative and does not gate direct-download migration. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/hash-suite-free-4.1-publisher-source-review-and-dns-block-2026-10-28-1734.json).
## NirSoft current-source staging safety audit, 2026-10-28 17:30 UTC

The current catalog loaded through `Get-RideCatalog` selects 647 NirLauncher members and 47 x64-tools members, with zero PasswordScan paths in either selection; both candidates remain PendingAcceptance with no supported targets. `tests/NirsoftCollectionPackages.Tests.ps1` parses with zero errors. Its two portable staging calls use a test-created synthetic inert ZIP after checking the blocked names are absent; its retained encrypted-archive case is inventory-only and does not extract or stage. No tests or staging ran. This tracked source does not explain the reported temporary file; an older catalog, another caller or prior output remains possible, and the creating run is unresolved. Keep PasswordScan x86/x64 excluded and pause any NirSoft staging/Pester lifecycle run that could materialize the member. No legacy outcome closed; estimates remain unchanged. See [structured evidence](archive/evidence/nirsoft-current-source-staging-safety-audit-2026-10-28-1730.json).
## NirSoft PasswordScan Defender alert report, 2026-10-28 17:26 UTC

The user reports a Defender block for x64 `passwordscan.exe` at `C:\Users\tjuuljensen\git\ride-windows\.local\nirsoft-encrypted-launcher-filtered-pester-tmp\RIDE-Portable-dd1c11ff272241dab6884a3f14a78f50\NirSoft\x64\passwordscan.exe`. This is the same path/GUID as the earlier 17:12 report; the new message does not establish a distinct Defender event or provide a detection name, event timestamp, or creating-run/catalog revision. Keep both PasswordScan architectures excluded and pause NirSoft staging/Pester runs that could materialize the member pending temporary-stage provenance and catalog/source revision reconciliation. The alert path was not opened, hashed, restored or executed; Defender and Windows state were not queried or changed. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). Unrelated migration batches remain available. See [structured evidence](archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1726.json).
## NirSoft PasswordScan Defender repeat report, 2026-10-28 17:12 UTC

The user reports a Defender block for x64 `passwordscan.exe` at the same filtered-Pester temporary path/GUID reported earlier. This report does not confirm a distinct Defender event or provide the detection name, event time, or creating process/catalog revision. Keep both PasswordScan architectures excluded and pause NirSoft staging/Pester runs that could materialize the member; the retained encrypted-archive case remains inventory-only, with the actual lifecycle deferred. No alert path was opened, hashed, restored or executed; Defender and Windows state were not queried or changed. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). Unrelated migration batches remain available. See [structured evidence](archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1712.json).

## NTCore Filter Monitor, Vista4Experts and AntiMida source recheck, 2026-10-28 17:03 UTC

The current official pages still list Filter Monitor 1.1.0, Vista4Experts 1.2.0.1 and AntiMida 1.0. Filter Monitor is documented only through Windows 7 RTM and requires boot-time disabling of driver-signature enforcement for its unsigned driver. Vista4Experts describes changing UAC, Defender scanning and automatic updates, says changes can be reversed, but gives no per-setting map. AntiMida's official article describes process-memory/DLL injection and companion kernel-driver behavior, calls its methods obsolete, and says PAE is unsupported. These are technical compatibility and recovery questions; all three remain selected under the full NTCore collection decision, and licensing is not an exclusion or package-planning gate. The official ZIP URLs are identified, but the web reader could not return any archive bytes; no hash or member inventory is available. No code, utility or driver ran and no Windows/Defender state changed. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](archive/evidence/ntcore-filter-vista-antimida-current-page-recheck-2026-10-28-1703.json), [Filter Monitor](https://ntcore.com/filter-monitor/), [Vista4Experts](https://ntcore.com/vista4experts/), [AntiMida](https://ntcore.com/files/antimida_1.0.htm), and the [official Download catalog](https://ntcore.com/download/).

## PSScriptTools full inert 360-member local lifecycle regression, 2026-10-28 15:43 UTC

The complete `tests/PSScriptToolsPackage.Tests.ps1` suite passed 7/7 in PowerShell 7.6.5/Pester 5.7.1 in 652.06 seconds; the full inert 360-member file lifecycle and six compact boundary cases passed. No upstream module code ran and no VM, Windows or Defender state changed. The wrapper exited 1 because it checked the result variable without enabling the supported `-PassThru` option; Pester's emitted summary reports 7 passed, 0 failed, 0 skipped. A read-only `Get-VM` query in both PowerShell editions failed before returning VM state with a null-name Hyper-V exception, so package acceptance remains deferred. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/psscripttools-inert-360-member-full-local-regression-2026-10-28-1543.json).

## NTCore Vista4Experts and AntiMida current source/acquisition, 2026-10-28 15:24 UTC

The official Vista4Experts page still lists version 1.2.0.1 and describes changing UAC, Defender scanning, automatic updates and other Vista settings; it claims reversibility but does not give per-setting effects or restoration mappings. The AntiMida article describes process-memory/dumping and file/registry monitoring via an injected DLL and companion kernel driver, and warns the old project is obsolete and does not work with PAE. Both products remain selected under the full NTCore collection migration; compatibility and package behavior are technical acceptance questions, not license exclusions. The official ZIP links were identified, but web retrieval cannot return ZIP content and direct requests failed DNS. No archive bytes, hashes or member inventories were obtained; no code, utility or driver ran. No legacy outcome closed; estimates remain unchanged. See [structured evidence](archive/evidence/ntcore-vista4experts-antimida-current-source-and-acquisition-block-2026-10-28-1524.json), [Vista4Experts page](https://ntcore.com/vista4experts/), [AntiMida article](https://ntcore.com/files/antimida_1.0.htm), and [NTCore download index](https://ntcore.com/download/).

## NirSoft PasswordScan repeat Defender report, 2026-10-28 15:20 UTC

The user again reports the exact x64 `passwordscan.exe` path recorded at 14:54 UTC under the encrypted-launcher filtered-Pester temporary workspace. The message does not establish a distinct Defender event, event time, or creating run. Keep both PasswordScan architectures excluded. Pause NirSoft archive-staging and Pester lifecycle reruns that could materialize the blocked member until stage provenance and the catalog revision are reconciled; retained NirLauncher lifecycle remains deferred. No file, hash, Defender state, VM, or Windows state was accessed or changed. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). Unrelated migration batches remain available. See [structured evidence](archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1520.json).

## Package dependency/evidence regression and PSScriptTools partial acceptance, 2026-10-28 15:15 UTC

PackageDependencyPlanning.Tests.ps1 passed 11/11. PackageAdoptionReview.Tests.ps1 and PackageEvidence.Tests.ps1 passed 54/54 in PowerShell 7.6.5/Pester 5.7.1 with TestRegistry and TestResult disabled. The package evidence fixture now sets ProgramFiles to a per-test synthetic directory and restores the prior process value; this fixed two environment-dependent test failures caused by this session having no ProgramFiles value. Six focused PSScriptTools metadata, collision and recovery cases passed. Its 360-file repeat/install/uninstall/snapshot-recovery case did not return a result after the 180-second child timeout and a separate 300-second orchestration wait, so leave the full case deferred. No installer or upstream code ran; no VM, Defender or Windows state changed. Repository validation passed for 446 operations, 8 groups, 5 profiles and 301 PowerShell files. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/package-planning-evidence-and-psscripttools-partial-regression-2026-10-28-1515.json).

## NirSoft current catalog blocked-member selection audit, 2026-10-28 14:59 UTC

PowerShell 7.6.5 read the current catalog through the RIDE data-only reader and compared PortableMembers with frozen JSON inventory metadata after applying the documented blocked-name filters. package.nirsoft-launcher matched 647/647 expected members; package.nirsoft-x64-tools matched 47/47. Neither selection contains a blocked basename, and both have zero supported targets and remain PendingAcceptance. No archive, executable payload, temporary stage or Defender state was accessed. This verifies catalog selection only; it does not identify the repeated alert creating run or prove encrypted tar.exe extraction. Keep both architectures excluded and defer retained archive lifecycle pending provenance. No legacy outcome closed; estimates unchanged. See [structured evidence](../archive/evidence/nirsoft-current-catalog-blocked-member-selection-audit-2026-10-28-1459.json).

## Repository validation and PSScriptTools regression deferral, 2026-10-28 14:57 UTC

`tools/validate.ps1 -Root .` passed in PowerShell 7.6.5: 446 operations, 8 groups, 5 profiles and 301 PowerShell files; generated operation documentation is current. The next `PSScriptToolsPackage.Tests.ps1` attempt did not reach assertions. Windows PowerShell 5.1.26100.9711 discovers Pester 5.7.1 but import fails while loading its format files with `AuthorizationManager check failed`; PowerShell 7.6.5 has no discoverable Pester. No policy bypass was attempted. Defer this local regression until Pester can be loaded normally. No installer, utility, VM or Windows/Defender state changed and no legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](../archive/evidence/repository-validation-and-psscripttools-pester-import-block-2026-10-28-1457.json).

## NirSoft PasswordScan Defender block, 2026-10-28 14:54 UTC

The user reports another Defender block for x64 `NirSoft/x64/passwordscan.exe` at the same filtered-Pester temporary-stage path, now at 14:54 UTC. No detection name, Defender event time or creating-run identity was supplied. Keep both PasswordScan architectures excluded from selection and acceptance; defer retained NirLauncher lifecycle pending temporary-stage provenance and catalog-revision reconciliation. The reported file, its contents and hash, Defender state, VM and Windows state were not accessed or changed. This does not block unrelated migration batches. No legacy outcome closed; estimates remain settings 37-57, packages 37-52, components 19-24, files/assets 25-35, maintenance 8-12 (exact 126-180; rounded 125-180/about 155). See [structured evidence](archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1454.json).

## NTCore package retained-file regression, 2026-10-28 14:41 UTC

`tests/NtcorePackages.Tests.ps1` passed 20/20 in Windows PowerShell 5.1/Pester 5.7.1 with TestRegistry and TestResult disabled and workspace-local TEMP/TMP. It covered retained archive staging/repeat/removal/recovery guards plus pending VirtualReg Manager, ScreenWriter and WIM Installer candidate checks. The retained ScreenWriter MSI digest matched its reviewed/catalog digest; Windows Installer was not started. No utility, VM, Windows or Defender state changed. Native candidate acceptance remains pending; no legacy outcome closed and estimates are unchanged. See [structured evidence](archive/evidence/ntcore-packages-winps51-pester-retained-candidate-regression-2026-10-28-1441.json).

## Raspberry Pi Imager current publisher release recheck, 2026-10-28 14:39 UTC

The official release page marks v2.0.12 as latest and lists the Windows x64 `imager-v2.0.12.exe` asset at 21.3 MB with SHA-256 `98bff90afe23339d0768915f6f68d35ac254740ec1eac2082ebeaa9ba41bc8e3`; the current catalog pin matches. The local bytes and Authenticode were not checked, and no installer or image writer ran. The candidate remains unsupported pending disposable Windows lifecycle and checkpoint recovery. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/raspberry-pi-imager-current-release-recheck-2026-10-28-1439.json) and the [official release page](https://github.com/raspberrypi/rpi-imager/releases).

## Raspberry Pi Imager focused candidate regression, 2026-10-28 14:34 UTC

The focused Windows PowerShell 5.1/Pester 5.7.1 suite passed 2/2 with TestRegistry and TestResult disabled and workspace-local TEMP/TMP. It checks the pinned v2.0.12 metadata, pending Windows 11 candidate status, Compensating rollback and metadata-only selection. The test wording now reflects the accepted publisher uninstall lifecycle; this is static evidence only. No installer, image writer, removable media, VM, Defender or Windows state was accessed or changed. Native install/repeat/uninstall and checkpoint restoration remain pending; no legacy outcome closed and estimates unchanged. See [structured evidence](archive/evidence/raspberry-pi-imager-focused-pester-winps51-2026-10-28-1434.json).

## NirSoft PasswordScan Defender repeat alert, 2026-10-28 14:31 UTC

The user reports the same x64 `passwordscan.exe` temporary-stage path again, after the 13:58 UTC report. No detection name, Defender event time or creating run was supplied. Keep both PasswordScan architectures excluded; retained NirLauncher archive lifecycle remains deferred pending temporary-stage provenance and catalog-revision reconciliation. No file, hash, Defender state, VM or Windows state was accessed or changed; no legacy outcome closed and estimates unchanged. See [repeat alert evidence](archive/evidence/nirsoft-passwordscan-user-defender-repeat-2026-10-28-1431.json).

## NTCore Explorer Suite exact artifact/signature recheck, 2026-10-28 14:15 UTC

The retained 3,613,174-byte ExplorerSuite.exe still matches the publisher page's exact SHA-256, 94f4348ec573b05990b1e19542986e46dc30a87870739f5d5430b60072d5144d. Get-AuthenticodeSignature reports NotSigned. The digest match and absent Authenticode signature are separate observations; neither is a Defender detection or license gate. The candidate remains unsupported pending disposable Windows 11 installer lifecycle and checkpoint recovery; read-only Get-VM access failed at host CIM at 14:12 UTC. The page still labels the release III (18/11/2012), while the installer internally says IV. No installer or utility ran, no Defender/Windows/VM state changed, and no legacy outcome closed; estimates unchanged. See [artifact evidence](archive/evidence/ntcore-explorer-suite-exact-artifact-signature-current-recheck-2026-10-28-1415.json), [publisher page](https://ntcore.com/explorer-suite/), and [VM access evidence](archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-1412.json).

## NirSoft PasswordScan Defender alert, 2026-10-28 13:58 UTC

The user reports a Defender block for x64 `passwordscan.exe` at the same filtered-Pester temporary-stage path named in the 13:39 UTC report. No detection name, Defender event time or creating run was supplied. Keep both PasswordScan architectures excluded; retained NirLauncher archive lifecycle remains deferred pending temporary-stage provenance and catalog-revision reconciliation. No file, hash, Defender state, VM or Windows state was accessed or changed. No legacy outcome closed; estimates unchanged. See [alert evidence](archive/evidence/nirsoft-passwordscan-user-defender-block-2026-10-28-1358.json).

## PSScriptTools / ThreadJob source and dependency reconciliation, 2026-10-28 13:52 UTC

PSScriptTools 3.2.0-549fa3e3d769's retained 360-file source archive passed its
current-source local staging/repeat/remove/snapshot suite 7/7 on 2026-10-27;
the upstream module was not imported or executed. Its ThreadJob 2.2.0 dependency
is pinned to the exact 49,678-byte `.nupkg`, whose nuspec and manifest versions
agree; the direct portable handler install/repeat/10-file health/uninstall and
snapshot recovery passed in isolated scratch with the operator sentinel
preserved. Current planning orders the dependency first, and the removal guard
refuses removing ThreadJob while PSScriptTools is installed. Pester 5 is
unavailable in the current shell, controller metadata is stale, and current
host CIM blocks VM/checkpoint inspection. Runtime behavior and Windows 11/Server
2025 acceptance remain deferred. No legacy outcome closed; estimates remain
unchanged. See [structured reconciliation evidence](archive/evidence/psscripttools-threadjob-current-dependency-status-reconciliation-2026-10-28-1352.json).

## NTCore Vista4Experts pinned-endpoint GET retry, 2026-10-28 13:37 UTC

The official Vista4Experts ZIP HEAD returned HTTP 200, Content-Length 295338 and remote IP 172.104.252.30. Local DNS lookup failed with Access denied; forcing the verified IP for the official HTTPS host still failed to connect (curl exit 7). No ZIP or partial file was retained. Vista4Experts remains selected but cannot yet receive a hash-pinned candidate; this is an acquisition blocker, not a license exclusion. No utility ran and no Windows/Defender state changed. No legacy outcome closed; estimates unchanged. See [route evidence](archive/evidence/ntcore-vista4experts-pinned-endpoint-get-retry-2026-10-28-1337.json).

## NTCore Vista4Experts and AntiMida download-route check, 2026-10-28 13:31 UTC

HEAD requests to the publisher's Vista4Experts ZIP returned HTTP 200, 295,338 bytes, and Last-Modified 2020-10-17; GET requests failed DNS resolution on both publisher host forms. The AntiMida ZIP HEAD returned HTTP 200 and 272,481 bytes, while the web reader returned Cache miss and no shell GET was attempted. No archive bytes, digest or member inventory were obtained; both remain selected for migration preparation, with no legal exclusion. No utility/driver ran and no partial file was retained. See [route evidence](archive/evidence/ntcore-vista4experts-antimida-download-route-recheck-2026-10-28-1331.json).

## NTCore Vista4Experts and AntiMida publisher-source recheck, 2026-10-28 13:28 UTC

Both products remain selected for the full NTCore collection migration; previous page-only dispositions are not exclusions under the 2026-10-27 decision, and license status is not a migration gate. The current Vista4Experts page lists 1.2.0.1 and describes changes to UAC, Defender scanning and automatic updates but gives no per-setting map or recovery details. The AntiMida article describes a process-injection and kernel-driver project and the publisher index says its ZIP includes source files and a compiled executable. The official ZIP requests returned Cache miss through the web reader, so no archive bytes or hashes were obtained and no catalog package can yet be pinned. No code/driver ran and no Defender file or Windows state was touched. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/ntcore-vista4experts-antimida-source-recheck-2026-10-28-1328.json).

## NTCore full Explorer Suite candidate, 2026-10-28 13:18 UTC

The exact 3,613,174-byte Inno Setup installer is retained and its SHA-256 matches the publisher's current Explorer Suite download. Added `package.ntcore-explorer-suite` as a pinned Windows 11 candidate, separate from standalone CFF Explorer; the candidate records the publisher's III (2012-11-18) label and the installer's internal IV label without reconciling them. Static inventory lists 27 members. No installer or utility ran. A 13:26 UTC read-only Get-VM query for RIDE-Win11-Test failed with `Access to a CIM resource was not available to the client`; installed scope, shortcuts, uninstaller identity, repeat lifecycle and exact recovery remain pending checkpoint access. See [VM access evidence](archive/evidence/ntcore-explorer-suite-vm-access-block-2026-10-28-1326.json). Its exact-version NeedsReview marker is administrative and does not block migration. No legacy outcome closed; estimates unchanged. See [candidate evidence](archive/evidence/ntcore-explorer-suite-candidate-preparation-2026-10-28-1318.json).

## NTCore full-list candidate preparation and VirtualReg Manager lifecycle, 2026-10-28 13:11 UTC

The current official NTCore Download index lists 16 utility entries. Two retained items absent from the catalog are now pinned candidates: VirtualReg Manager 1.0.0.1 and ScreenWriter MSI ProductVersion 1.0.0 (publisher page/executable version 1.1.0.1). Both have exact-version NeedsReview/Unassigned records in the workspace-local review store; these are administrative and do not gate migration. VirtualReg's current PowerShell 7.6.5 portable-handler lifecycle passed 1/1 for repeat staging, selected-file health, uninstall, snapshot restore and operator-note preservation; the utility was not launched and the registry was not changed. ScreenWriter remains static-only; its CLR, custom actions, scope, shortcuts and uninstall require disposable Windows acceptance. Filter Monitor, Vista4Experts, AntiMida 1.0 and the full Explorer Suite remain in the selected scope for further package/source reconciliation; current CFF coverage is partial. No legacy outcome closed; estimate ranges unchanged. See [structured evidence](archive/evidence/ntcore-screenwriter-virtualreg-candidate-preparation-and-virtualreg-lifecycle-2026-10-28-1311.json) and the [official publisher list](https://ntcore.com/download/).
## NTCore retained archive current-handler regression, 2026-10-28 12:56 UTC

Current PowerShell 7.6.5 portable-handler calls passed 6/6 retained archive variants: .NET Generic Unpacker x86/x64, DynLogger x86/x64, SNSRemover and WIM Installer. The run verified each pinned archive hash, repeat staging, selected-member health, uninstall, snapshot restore and operator-note preservation. No utility or driver ran; NoDel's driver archive was not touched. Pester 5.7.1 is unavailable in the installed shells, so this was a direct handler probe, not a Pester run or Windows acceptance. All four catalog candidates remain pending Windows 11 acceptance; no legacy outcome closed and estimates remain unchanged. See [structured evidence](archive/evidence/ntcore-current-portable-handler-retained-archive-regression-2026-10-28-1256.json).

## NirSoft PasswordScan Defender repeat alert, 2026-10-28 12:50 UTC

The user reports another Defender block for the same x64 passwordscan.exe temporary filtered-Pester stage path recorded at 12:28 UTC. No detection name, Defender event time, current file state, or creating-run identity was supplied. Keep both architecture paths excluded; retained NirLauncher archive lifecycle remains deferred pending stage provenance and catalog-revision reconciliation. No file, hash, Defender state, VM, or Windows state was accessed or changed; no legacy outcome closed and estimates remain unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-1250.json).

## NTCore Filter Monitor current-source compatibility gate, 2026-10-28 12:42 UTC

The publisher still lists Filter Monitor v1.1.0, but its own page only claims Windows Vista RTM through Windows 7 RTM, disclaims later compatibility and requires boot-time disabling of driver-signature enforcement to load its unsigned driver. Keep it in the selected collection review, with no Windows 11 support or utility execution claim. The official ZIP route resolves, but the web reader returned Cache miss; no artifact or members were retrieved. This is a compatibility gate, not an EOL/license exclusion. No legacy outcome closed; estimates unchanged. See [source evidence](archive/evidence/ntcore-filter-monitor-publisher-current-source-recheck-2026-10-28-1242.json).
## NTCore Windows 11 package support reconciliation, 2026-10-28 12:39 UTC

Current catalog metadata and registered guest evidence agree: PE Detective, CFF Explorer, guarded 4GB Patch, Driver List and Rebel.NET have Windows 11 package-staging support. Two runs on build 26300 passed 3/3 each; Driver List x64/x86 are one product outcome. No general payload was launched; the one bounded 4GB Patch action used an owned synthetic x86 PE. Activation/feature behavior and remaining publisher-listed products stay open. No additional legacy outcome closed; estimates unchanged. See [reconciliation evidence](archive/evidence/ntcore-win11-package-support-disposition-reconciliation-2026-10-28-1239.json).
## Hyper-V Manager read-only test-VM inventory, 2026-10-28 12:37 UTC

A screenshot from the existing Hyper-V Manager window shows `RIDE-Win11-Test`, `RIDE-S25-Test`, `RIDE-Store-W11` and `Windows 11 Pro` all Off. The visible `RIDE-clean-test-base` checkpoint is associated with selected `RIDE-S25-Test`; the target checkpoint for `RIDE-Win11-Test` was not confirmed. Direct `Get-VM` and `Get-ScheduledTask` remain blocked by host CIM, and the higher-integrity manager does not expose UI Automation to the helper. No VM/checkpoint was changed and no runner was dispatched. See [structured evidence](archive/evidence/hyperv-manager-read-only-test-vm-inventory-2026-10-28-1237.json).
## R04 feedback-frequency Microsoft-source recheck, 2026-10-28 12:32 UTC

Microsoft Support confirms the Windows 11 Feedback frequency location and user-prompt purpose; Microsoft Learn section 18.16 lists five paired values and labels both REG_DWORD, although its daily/weekly period numbers exceed the unsigned DWORD maximum. Preserve the mapping as source evidence only. Do not write or coerce values until exact current-build UI and registry types are observed on a disposable target. Read-only host CIM access to both test VMs and registered tasks remains unavailable, so no runner was dispatched. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/feedback-frequency-current-microsoft-source-recheck-2026-10-28-1232.json), [Microsoft Support](https://support.microsoft.com/en-us/windows/privacy/diagnostics-feedback-and-privacy-in-windows) and [Microsoft Learn](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services).
## NirSoft PasswordScan Defender repeat alert, 2026-10-28 12:28 UTC

The user reports another Defender block for the same x64 `passwordscan.exe` temporary filtered-Pester stage path. No detection name, Defender event time, current file state or creating-run identity was supplied. Keep both architecture paths excluded; retained NirLauncher archive lifecycle remains deferred pending stage provenance and catalog-revision reconciliation. No file, hash, Defender state, VM or Windows state was accessed or changed; no legacy outcome closed and estimates remain unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-1228.json).
## Sysinternals Windows 11 package migration scope reconciliation, 2026-10-28 11:14 UTC

The prior RIDE v2 license-specialist approval settles RIDE's direct Microsoft download-and-install workflow; licensing is not a gate. Existing acceptance passed the pinned Suite file lifecycle 1/1 and the nine independently selectable product lifecycles 9/9 on RIDE-Win11-Test, Windows 11 build 26300. This verifies RIDE's package file lifecycle; utility feature execution is outside that acceptance boundary. One legacy Sysinternals Suite download/install outcome is closed for Windows 11. Server support remains undeclared, and Defender-blocked utilities remain excluded. See [scope reconciliation](archive/evidence/sysinternals-windows11-package-migration-scope-reconciliation-2026-10-28-1114.json), [Suite evidence](archive/evidence/sysinternals-suite-win11-current-lifecycle-acceptance-2026-10-25-0201.json) and [product evidence](archive/evidence/sysinternals-products-runner-path-fix-and-win11-acceptance-2026-10-25-1017.json).

## NirSoft PasswordScan Defender alert, 2026-10-28 11:09 UTC

The user reports a Defender block for x64 `passwordscan.exe` at the same filtered temporary-stage path and GUID reported previously. The alert's detection name, event time and creating-run provenance were not supplied. A metadata-only check found the path absent; no contents/hash or Defender state were accessed. Keep both architectures excluded and defer retained NirLauncher archive lifecycle pending stage provenance and catalog-revision identity. No legacy outcome closed; estimates remain unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-1109.json), [prior alert](archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-1048.json) and [incomplete retry evidence](archive/evidence/nirsoft-defender-filtered-retry-incomplete-2026-10-27-1835.json).

## NirSoft unselected synthetic archive-entry regression, 2026-10-28 11:03 UTC

Strengthened `tests/NirsoftCollectionPackages.Tests.ps1`: its synthetic lifecycle archive now contains an extra inert unselected text entry and asserts it is not staged. The edited test parses with zero errors in PowerShell 7.6.5 and Windows PowerShell 5.1. Direct PowerShell 7.6.5 portable-handler probes passed repeat install, exact selected-file health, omission of the unselected entry and uninstall for both candidates (3 NirLauncher files, 1 x64-tools file) using inert text only; scratch was cleaned. Pester 5 is unavailable. The Windows PowerShell 5.1 script probe was blocked by AuthorizationManager before execution; no policy bypass was attempted. No publisher archive, Defender-blocked payload, VM, Windows state or elevation was used. Repository validation passed for 441 operations, 8 groups, 5 profiles and 299 PowerShell files; generated operation docs are current. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/nirsoft-filtered-unselected-synthetic-entry-handler-probe-2026-10-28-1103.json).

## Defraggler displayed-version and EOL reconciliation, 2026-10-28 11:00 UTC

The official-domain indexed download/release page displays Defraggler 2.22.995 dated 2018-05-21, but opening it redirects to a JavaScript-only product page with no artifact or digest. The publisher's 2026-09-11 EOL notice says its last build shipped in August 2020 and the product is no longer distributed or supported, without identifying that build's exact version. The two sources do not establish whether the 2020 build was a same-version reissue or another artifact. No matching local artifact was found. Keep the user-selected legacy outcome open and defer implementation pending an authorized retained payload/source or user disposition. This is an upstream availability issue, not a license gate; estimates remain unchanged. See [structured evidence](archive/evidence/ccleaner-defraggler-version-route-eol-reconcile-2026-10-28-1100.json), [indexed publisher release page](https://www.ccleaner.com/defraggler/download/portable) and [publisher EOL notice](https://community.ccleaner.com/t/defraggler-end-of-life/166405).

## Migration VM and Pester prerequisite recheck, 2026-10-28 10:54 UTC

Fresh read-only `Get-VM` calls for RIDE-Win11-Test and RIDE-Server2025-Test both failed before inspection because host CIM access was denied. Only Pester 3.4.0 is discoverable in the current shell; Pester 5 regressions were not run. Defraggler's publisher EOL status is confirmed, and a recursive PowerShell search including hidden files found no matching artifact in `.local`; its selected legacy outcome remains open. PasswordScan remains excluded after the repeat Defender alert. No elevation, test, VM dispatch or Windows/Defender change occurred; no legacy outcome closed and estimates remain unchanged. See [structured evidence](archive/evidence/migration-prerequisites-recheck-and-defraggler-source-batch-2026-10-28-1054.json).

## Defraggler publisher end-of-life source confirmation, 2026-10-28 10:51 UTC

The official 2026-09-11 announcement confirms Defraggler reached end of life: its last build shipped in August 2020, its product/download/support pages were removed, and the publisher will no longer distribute, sell or support it. A recursive PowerShell search including hidden files found no matching Defraggler installer/archive in `.local`. This resolves lifecycle status, not the user's retained legacy selection. Keep that outcome open; no candidate is added and acquisition remains deferred pending disposition or a publisher-authorized retained artifact/source. This is an upstream source-availability blocker, not a legal/license migration gate. No package or Windows state changed; estimates remain unchanged. See [structured evidence](archive/evidence/ccleaner-defraggler-eol-confirmation-2026-10-28-1051.json) and the [publisher announcement](https://community.ccleaner.com/t/defraggler-end-of-life/166405).

## NirSoft PasswordScan Defender repeat alert, 2026-10-28 10:48 UTC

The user reports another Defender block for x64 `passwordscan.exe` at the same filtered temporary-stage path. A source-record correlation found this exact path/GUID in the incomplete filtered archive retry report from 2026-10-27 18:35 UTC; that report has no final Pester result and does not prove the retry created the file. A metadata-only existence check found the path absent; no file contents/hash or Defender state were accessed. Keep both architectures excluded and defer retained NirLauncher archive lifecycle pending run and catalog-revision provenance. The detection name and event time remain unknown. No legacy outcome closed; estimates remain unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-1048.json) and [incomplete retry evidence](archive/evidence/nirsoft-defender-filtered-retry-incomplete-2026-10-27-1835.json).

## CCleaner family current official versions and license-review notes, 2026-10-28 10:46 UTC

Official version pages identify CCleaner 7.13.1573 (2026-10-21), Recuva 1.55.133 (2026-06-22) and Speccy 1.34.84 (2026-06-22); the CCleaner portable ZIP is separately pinned by its release history at 6.41.11567. The CCleaner builds page still labels 7.12.1526 and calls its advanced builds not for distribution or mirroring. Recuva and Speccy say their Free and Professional products are for home use only. Carry these publisher notices into local, exact-version license-review markers when candidates are added; they are informational review items, not migration gates under the user direction. No exact candidates or review-store entries are created until artifacts are acquired and pinned. DNS to the CCleaner payload hosts is denied and Recuva/Speccy download buttons expose JavaScript-only pages; no binaries, hashes or signatures are available. Defraggler's current exact version/source remains unresolved. No package or Windows state changed; no legacy outcome closed and estimates remain unchanged. See [structured evidence](archive/evidence/ccleaner-family-current-official-source-and-artifact-acquisition-recheck-2026-10-28-1046.json), [CCleaner history](https://www.ccleaner.com/ccleaner/version-history/), [Recuva download](https://www.ccleaner.com/recuva/download) and [Speccy download](https://www.ccleaner.com/speccy/download).
## CCleaner current official versions and artifact acquisition recheck, 2026-10-28 10:45 UTC

The official homepage reports CCleaner v7.13; the official version history identifies 7.13.1573 dated 2026-10-21 and portable 6.41.11567 dated 2026-06-23. The official builds page still labels v7.12.1526, while exposing generic full-installer and direct portable-ZIP routes; it also says those advanced builds are not for distribution or mirroring. RIDE remains a direct download-and-install tool; preserve that publisher wording as an informational local license-review note when exact candidates are cataloged, not a technical migration gate. DNS for both official payload hosts was denied before HTTP, and the web reader cannot return binary payloads. No bytes, hashes or signatures were verified; no candidate was cataloged. No Defender, Windows or VM state changed. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/ccleaner-current-official-version-source-and-artifact-acquisition-dns-block-2026-10-28-1045.json), [official version history](https://www.ccleaner.com/ccleaner/version-history/) and [official builds page](https://www.ccleaner.com/ccleaner/builds).
## PSScriptTools ThreadJob dependency removal guard, 2026-10-28 10:44 UTC

A direct in-module plan probe confirms an Install plan orders ThreadJob before PSScriptTools with the 2.2.0 minimum. A second read-only probe stubbed only the dependent package's installed state in memory; planning ThreadJob removal then refused with the expected PSScriptTools dependent-package guard. No registry, installer, package, VM, Defender or Windows state was queried or changed. These probes do not replace the unavailable Pester 5 regression or the attested disposable-VM runtime and lifecycle acceptance. No legacy package outcome closed; estimates unchanged. See [structured evidence](archive/evidence/psscripttools-threadjob-dependency-plan-and-removal-guard-probe-2026-10-28-1044.json).
## PSScriptTools ThreadJob 2.2.0 current-source and real-archive handler lifecycle, 2026-10-28 10:41 UTC

The PowerShell Gallery still lists Microsoft.PowerShell.ThreadJob 2.2.0 as its current version. The retained official `.nupkg` is 49,678 bytes and matches the catalog SHA-256; its nuspec and module manifest both report 2.2.0, with ten package files, a `.signature.p7s` entry, `LICENSE` and `ThirdPartyNotices.txt`. The signature entry was not cryptographically verified. RIDE's portable handler passed install, repeat, exact 10-file health, uninstall, installed-snapshot restore, prior-absence restore and operator-sentinel preservation from isolated workspace scratch, which was cleaned. The module was not imported or invoked, its DLL was not loaded, and no installer, VM, Defender or Windows state changed. Pester 5 regression, cryptographic signature verification, engine dispatch, dependency-removal guard, runtime use and Windows target acceptance remain open. No legacy package outcome closed; estimates unchanged. See [structured evidence](archive/evidence/psscripttools-threadjob-2.2.0-current-source-and-handler-lifecycle-2026-10-28-1041.json).
## PSScriptTools current-catalog prerequisite plan, 2026-10-28 10:38 UTC

A read-only `Get-RideSingleOperationPlan` for `package.psscripttools` expands `package.microsoft-powershell-threadjob` first, with the declared `Microsoft.PowerShell.ThreadJob` version 2.2.0 minimum and the resolved portable tools directory; `package.psscripttools` follows at its own portable directory. No handler, package, installer or network source was invoked. This confirms current-catalog plan expansion only; Pester regression, managed installation/removal/recovery, actual module health/version, dependent-removal guard and Windows acceptance remain open. No legacy package outcome closed; estimates remain unchanged. See [structured evidence](archive/evidence/psscripttools-current-catalog-prerequisite-plan-readonly-2026-10-28-1038.json).
## NirSoft PasswordScan Defender repeat alert, 2026-10-28 10:32 UTC

A new user-reported Defender block names the same x64 PasswordScan temporary-stage path. The detection name, event time and creating-run provenance were not supplied. A fresh metadata-only existence check found the path absent; no contents/hash or Defender state was accessed. Keep both architectures excluded and defer retained NirLauncher archive lifecycle pending stage provenance. No legacy outcome closed; estimates remain unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-1032.json).
## WinPmem focused runner regression and VM access recheck, 2026-10-28 10:30 UTC

The WinPmem selector/inert-payload tests passed 2/2 and the mocked fixed
controller dispatch matrix passed 10/10 in Windows PowerShell 5.1/Pester 5.7.1
with registry/result plugins disabled. No binary/driver ran. The protected
controller still needs an elevated refresh and Get-VM/Get-ScheduledTask are
blocked at host CIM before inspection. Publisher bytes and guest lifecycle remain
open. No legacy outcome closed; estimates unchanged. See [structured
evidence](archive/evidence/winpmem-runner-current-source-regression-and-vm-cim-block-2026-10-28-1030.json).
## Phoenix current-source package regression, 2026-10-28 10:25 UTC

PhoenixPackage.Tests.ps1 passed 4/4 on Windows PowerShell 5.1.26100.9711/Pester
5.7.1 with Pester registry/result plugins disabled. Metadata, prerequisite and
mocked MSI dispatch passed; no installer or feature ran. Version identities
remain unmapped and VM acceptance remains open. License review metadata is
informational. No legacy outcome closed; estimates unchanged. See [regression
evidence](archive/evidence/phoenix-current-source-package-regression-2026-10-28-1025.json).
## NTCore Phoenix/Explorer Suite current version/source recheck, 2026-10-28 10:21 UTC

Current official NTCore pages still list Phoenix Protector 1.8.0.1 and Explorer
Suite III (18/11/2012). Retained Explorer Suite bytes match the official page hash;
its internal product label remains IV. The publisher's standalone x86 CFF Explorer
hash matches both retained bytes and the catalog pin. Phoenix's retained 1.7.1 MSI
hash matches the catalog; its page version and contained 1.9.0.1 executable remain
unmapped. Exact-version NeedsReview/Unassigned markers are present and do not gate
planning. No binaries or installers ran. No legacy outcome closed; estimates
unchanged. See [source evidence](archive/evidence/ntcore-phoenix-explorer-current-version-source-recheck-2026-10-28-1021.json).
## Wireshark focused package regression and VM access recheck, 2026-10-28 10:17 UTC

WiresharkPackage.Tests.ps1 passed 8/8 in Windows PowerShell
5.1.26100.9711/Pester 5.7.1 with TestRegistry and TestResult disabled. The suite
used catalog metadata, inert MSI bytes and mocked installer/process boundaries;
no MSI, network, driver or Windows state was touched. The initial Pester plugin
setup was denied HKCU access; bundled PowerShell 7 lacks Pester 5. A fresh
read-only Get-VM failed at host CIM before VM/checkpoint inspection. Windows
lifecycle/recovery and publisher PGP verification remain open. No legacy outcome
closed; estimates unchanged at 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact
127-181, rounded 125-180/about 155. See [structured
evidence](archive/evidence/wireshark-package-focused-regression-and-vm-cim-block-2026-10-28-1017.json).
## NirSoft PasswordScan Defender repeat alert, 2026-10-28 10:12 UTC

The user reported another Defender block for the same x64 executable path under
.local/nirsoft-encrypted-launcher-filtered-pester-tmp. The alert did not
include a detection name or Defender event time. A metadata-only existence check
found the path absent; file contents/hash and Defender state were not accessed.
Keep both PasswordScan architectures excluded and defer the retained NirLauncher
archive lifecycle until stage provenance is understood. Estimates remain
settings 37-57, packages 38-53, components 19-24, files/assets 25-35,
maintenance 8-12 (exact 127-181; rounded 125-180/about 155). See [structured
evidence](archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-1012.json).## WinPmem inert single-file handler lifecycle, 2026-10-28 10:10 UTC

The actual RIDE portable file handler passed install, repeat, exact one-file
ownership, removal, installed-state snapshot restore, restoration to prior
absence, and preservation of an operator-owned sentinel. The payload was inert
text written to a `.exe` fixture and was never executed. Authenticode was
explicitly skipped; no publisher bytes, engine route or Windows behavior are
established. The isolated `.local` scratch was cleaned. No VM, Defender, driver
or Windows state changed. WinPmem remains unsupported pending the pinned
publisher artifact and the prepared guest lifecycle batch. See [structured
handler evidence](archive/evidence/winpmem-inert-single-file-handler-lifecycle-2026-10-28-1010.json)
and [runner preparation](archive/evidence/winpmem-focused-file-acceptance-runner-preparation-2026-10-28-1008.json).
## WinPmem focused file-lifecycle VM runner preparation, 2026-10-28 10:08 UTC

Added a fixed one-case `WinPmem` batch to the focused package acceptance route.
The case accepts only `package.winpmem` with its exact catalog-pinned `.exe`
asset and `PortableFormat=File`; all unrelated `.exe` payloads remain refused.
The guest route exercises RIDE-owned install/repeat/remove and saved-state
recovery without executing the binary or loading the driver. Local inert-payload
selection assertions, PowerShell parser checks (7 changed files), full
repository validation (441 operations, 8 groups, 5 profiles, 299 PowerShell
files) and generated-document checks pass. Pester 5 is unavailable here (only
3.4.0 is installed), so focused Pester tests were not run.

No retained binary is present. The protected registered controller needs a
one-time elevated refresh before queueing this new batch, and a fresh Get-VM
recheck failed at host CIM for both registered targets before inspection. No
VM/checkpoint, Windows, Defender, driver or executable state changed. The
candidate remains unsupported; actual artifact verification and Windows
lifecycle acceptance remain pending. No legacy outcome closed; estimates are
unchanged. See [structured evidence](archive/evidence/winpmem-focused-file-acceptance-runner-preparation-2026-10-28-1008.json)
and the [acceptance runbook](../tests/integration/README.md).
## WinPmem expanded release asset source recheck, 2026-10-28 10:00 UTC

The official [expanded release-assets page](https://github.com/Velocidex/WinPmem/releases/expanded_assets/v4.1.dev1) lists go-winpmem_amd64_1.0-rc2_signed.exe, uploaded 2025-09-03, size 5.01 MB, with SHA-256 86691bb4af2c17dd9ec4834c04a99ad51e04f780a07d1b05bc382a5d1892e0c4, matching the catalog pin. The release note designates it for production use. A direct asset fetch redirected to an expired signed URL, so local bytes and Authenticode remain unverified. No executable, driver, VM or Windows state was touched. Machine-scoped install/remove/recovery on Windows 11 and Server 2025, plus separate driver behavior, remain pending; no legacy outcome closed and estimates are unchanged. See [structured evidence](archive/evidence/winpmem-expanded-release-asset-source-recheck-2026-10-28-1000.json).

## Wireshark retained MSI current digest/signature recheck, 2026-10-28 09:52 UTC

The retained 80,433,152-byte Wireshark 4.6.9 x64 MSI still matches the
catalog pin and publisher checksum. Windows Authenticode reports Valid for
Wireshark Foundation with a Microsoft timestamp signature. The MSI was not
opened or run. Windows 11/Server lifecycle, shared runtime and existing-install
transitions remain open. No legacy outcome closed; estimates remain unchanged.
See [structured evidence](archive/evidence/wireshark-retained-msi-current-digest-signature-check-2026-10-28-0952.json).

## Wireshark 4.6.9 publisher checksum source recheck, 2026-10-28 09:51 UTC

The official [checksum file](https://www.wireshark.org/download/SIGNATURES-4.6.9.txt)
lists the 80,433,152-byte x64 MSI and the SHA-256 that matches the catalog
pin. The file is PGP-signed, but this review did not verify its signature or
local MSI bytes. Windows lifecycle acceptance remains open. No legacy outcome
closed; estimates remain unchanged. See [structured evidence]
(archive/evidence/wireshark-4.6.9-publisher-checksum-recheck-2026-10-28-0951.json).

## Wireshark stable release and MSI source recheck, 2026-10-28 09:50 UTC

The official download page continues to identify 4.6.9 as the stable release;
the x64 all-versions index lists Wireshark-4.6.9-x64.msi. This matches the
catalog pin. The recheck did not fetch or inspect new MSI bytes or a signature.
Windows install/repeat/remove/saved-state recovery and reporting remain open;
no legacy outcome closed and estimates are unchanged. See [structured evidence]
(archive/evidence/wireshark-stable-release-current-source-recheck-2026-10-28-0950.json).

## WinPmem current production-asset source recheck, 2026-10-28 09:45 UTC

The official Velocidex release page continues to designate the catalog-pinned
go-winpmem_amd64_1.0-rc2_signed.exe for production use. Its newer 4.1
pre-release driver is test-signed and the publisher's test flow requires
enabling test-signing mode and rebooting. GitHub's asset list did not render;
no bytes, hash, or Authenticode signature were refreshed. Machine lifecycle,
exact payload verification, driver and Windows acceptance remain deferred. Fresh
Get-VM failed at host CIM for both targets before inspection; PowerShell remoting
is unavailable and no WinRM service is exposed in this execution environment.
No legacy outcome closed; estimates are unchanged. See [structured
evidence](archive/evidence/winpmem-current-production-asset-source-recheck-2026-10-28-0945.json).

## NirSoft PasswordScan Defender repeat alert, 2026-10-28 09:39 UTC

The user reports a Defender block for x64 `passwordscan.exe` at the same
filtered NirLauncher temporary path reported earlier today. Detection name,
Defender event time, and stage-creating run are unknown. No file, Defender
state, VM, or Windows state was checked or changed. Keep both architectures
excluded and defer the retained archive lifecycle until temporary-stage
provenance is understood. No legacy outcome closed; estimates are unchanged.
See [structured evidence](archive/evidence/nirsoft-passwordscan-defender-repeat-alert-2026-10-28-0939.json).

## WFN Nightly actual-archive lifecycle, 2026-10-28 09:33 UTC

The pinned 118,745,388-byte WFN archive (`b7ecea5a…678378`, 531 members)
passed actual portable-handler install, repeat, uninstall, installed-snapshot
recovery and prior-absence recovery in PowerShell 7.6.5 and Windows PowerShell
5.1.26100.9711. The operator-owned sentinel survived every transition. The
utility was not launched; firewall, Defender, VM and Windows state were not
changed. This is module-level archive lifecycle evidence, not Windows runtime
acceptance or engine-route acceptance. VM access remains host-CIM-blocked; no
legacy product outcome closed and estimates are unchanged. See [structured
evidence](archive/evidence/wfn-actual-pinned-archive-cross-shell-lifecycle-2026-10-28-0933.json).
The official [release page](https://github.com/wokhan/WFN/releases) still
lists Nightlies/Unstable at commit `ac02df2`, matching the catalog revision
suffix. Its asset list failed to render, so this adds no byte verification.
See [source recheck evidence](archive/evidence/wfn-official-nightly-current-source-recheck-2026-10-28-0936.json).

## Repeated NirSoft PasswordScan Defender alert, 2026-10-28 09:04 UTC

The user reports another Defender block for x64 `passwordscan.exe` at the same
filtered NirLauncher temporary-stage path. No detection name, event time, or
creating-run provenance was supplied. A metadata-only existence check found
the file and parent directory absent; no content/hash or Defender state was
accessed. Keep both PasswordScan architectures excluded and defer retained
NirLauncher archive lifecycle pending stage provenance. No legacy outcome
closed; estimates remain unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0904.json).

## Gpg4win current-user switch source verification, 2026-10-28 09:07 UTC

The retained Gpg4win 5.1.1 NSIS source configures
`MULTIUSER_INSTALLMODE_COMMANDLINE`; the NSIS MultiUser source recognizes
`/CurrentUser` under that mode and selects current-user install context. This
supports the catalog switch but does not prove runtime behavior or explain the
prior Windows 11 `0xC0000005`. A read-only `Get-VM` preflight again failed at
host CIM before inspecting either target; native install/repeat/remove and
exact recovery remain blocked. No installer ran, no legacy outcome closed,
and estimates are unchanged. See [source evidence](archive/evidence/gpg4win-currentuser-multiuser-source-verification-2026-10-28-0907.json)
and [VM access evidence](archive/evidence/gpg4win-source-review-vm-access-block-2026-10-28-0909.json),
[Gpg4win source archive](https://files.gpg4win.org/gpg4win-5.1.1.tar.xz), and
[NSIS MultiUser source](https://github.com/NSIS-Dev/nsis/blob/master/Contrib/MultiUser/MultiUser.nsh).

The catalog's ten explicit configuration keys also match the ten
`config_fetch_bool` keys in retained Gpg4win 5.1.1 `inst-sections.nsi`. This
establishes key-name compatibility only; it does not prove resulting component
behavior or resolve the installer crash. See [key cross-check evidence](archive/evidence/gpg4win-config-keys-retained-source-cross-check-2026-10-28-0911.json).

## Phoenix Protector prerequisite gate current-source regression, 2026-10-28 09:00 UTC

`PhoenixPackage.Tests.ps1` passed 4/4 in Windows PowerShell 5.1.26100.9711
and 4/4 in PowerShell 7.6.5/Pester 5.7.1. The tests verify fail-closed
behavior before artifact/MSI when .NET Framework 3.5 is absent and catalog
arguments on a mocked MSI path when present. No feature query, DISM or installer
ran. Target acceptance remains blocked by host CIM, and the previous MSI 1603
failure still requires a prerequisite-enabled disposable target. License review
is informational. See [structured evidence](archive/evidence/phoenix-prerequisite-gate-current-source-cross-shell-2026-10-28-0900.json).

## Gpg4win current-source mocked regression, 2026-10-28 08:57 UTC

`Gpg4winPackage.Tests.ps1` passed 12/12 in Windows PowerShell 5.1.26100.9711
and 12/12 in PowerShell 7.6.5/Pester 5.7.1. Tests cover explicit current-user
component configuration, guarded installer config staging, nested GnuPG
ownership conflicts and synthetic user-data recovery; installer and real
registry calls were mocked. The earlier Windows 11 `0xC0000005` failure remains
unresolved and VM access is blocked at host CIM. The exact-version NeedsReview
marker is administrative, not a migration gate. See [structured evidence](archive/evidence/gpg4win-current-source-mocked-cross-shell-regression-2026-10-28-0857.json).

## Rufus official version and portable-asset source recheck, 2026-10-28 08:51 UTC

The official GitHub releases page and Rufus download index still list 4.15,
released 2026-06-30, including `rufus-4.15p.exe` for x64. The catalog version
and URL remain current. No new bytes were downloaded or hashed; prior exact-byte
and signature evidence remains dated. Windows 11 package lifecycle/recovery and
a separate application scenario remain open; no USB media was touched. See
[structured evidence](archive/evidence/rufus-latest-release-source-recheck-2026-10-28-0851.json).

## Repeated NirSoft PasswordScan Defender alert, 2026-10-28 08:46 UTC

The user reports another Defender block for the same x64 `passwordscan.exe`
temporary-stage path recorded at 07:55 UTC. No detection name, event time, or
creating-run provenance was supplied. A metadata-only path existence check
found no file there; no contents or Defender state were inspected. Keep both
PasswordScan architectures excluded and defer the retained NirLauncher archive
lifecycle until provenance is understood. No legacy outcome closed; estimates
remain unchanged. See [structured evidence](archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-0846.json).

## WFN Nightly pinned-archive current-source regression, 2026-10-28 08:45 UTC

`WfnPackage.Tests.ps1` passed 4/4 in Windows PowerShell 5.1.26100.9711 and
4/4 in PowerShell 7.6.5/Pester 5.7.1. Synthetic ZIPs exercised complete
531-member lifecycle/recovery; the retained publisher archive matched its
catalog SHA-256 and member inventory. No WFN executable or installer was
launched, and firewall state was not changed. VM inspection remained blocked
at host CIM for both targets. Actual archive staging, runtime behavior and
Windows acceptance remain open. See [structured evidence](archive/evidence/wfn-pinned-archive-cross-shell-synthetic-lifecycle-and-vm-block-2026-10-28-0845.json).

## Full package and portable regression with retained archives, 2026-10-28 08:23 UTC

`ApplicationPackages.Tests.ps1` and `PortableAcceptanceAutomation.Tests.ps1`
passed **179/179** in Windows PowerShell 5.1.26100.9711 and **179/179** in
PowerShell 7.6.5/Pester 5.7.1, with no skips or unrun cases. The RawCopy,
ETL2PCAPNG, and JoeWare AdMod archive-backed file lifecycle cases ran using
retained files whose SHA-256 matched their exact catalog pins. The tests did
not launch those utilities, invoke installers, or select Defender-blocked
collections.

Read-only `Get-VM` failed before inspection for both acceptance targets with
`Access to a CIM resource was not available to the client`; no task was
dispatched. Windows package lifecycle remains deferred. No legacy outcome
closed; estimates stay 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181,
rounded 125-180/about 155. See [structured evidence](archive/evidence/package-provider-portable-full-retained-archives-cross-shell-regression-and-vm-block-2026-10-28-0823.json).

## Pending package catalog and review-marker readiness audit, 2026-10-28 08:15 UTC

The current catalog has 115 package operations, 45 pending acceptance. All 45
pending entries have a package version, product page, license reference,
download URI/provider, and SHA-256 or immutable source pin. A read-only join to
the explicitly resolved user-local review store confirmed `NeedsReview` for
all 45 exact ID/version pairs; the store was not changed. This verifies
preparation only, not publisher bytes or Windows lifecycle. Review status does
not gate migration and Defender exclusions remain separate. No legacy outcome
closed; estimates are unchanged. See [structured audit evidence](archive/evidence/pending-package-catalog-and-license-review-readiness-audit-2026-10-28-0815.json).

## Exact pending-package review-marker coverage audit, 2026-10-28 08:12 UTC

Read-only comparison of the current catalog with the explicit user-local review
store confirmed exact `NeedsReview` markers for **45/45** pending package
versions. The store contains 60 records; no owner details or distribution notes
were exposed. The store was not modified. `NeedsReview` is administrative
metadata, not a migration gate; Defender exclusions remain separate. No legacy
outcome closed and estimates remain unchanged. See [structured audit evidence](archive/evidence/package-review-marker-exact-pending-coverage-audit-2026-10-28-0812.json).

## Package dependency planning cross-shell regression, 2026-10-28 08:03 UTC

`PackageDependencyPlanning.Tests.ps1` passed **11/11** in Windows PowerShell
5.1.26100.9711 and **11/11** in PowerShell 7.6.5/Pester 5.7.1. No tests were
skipped or left unrun. Tests did not invoke installers or utilities, select
Defender-blocked tools, or change Windows state.

This is source-level dependency-planning evidence only. Package lifecycle and
target acceptance remain deferred under the 08:01 host-CIM block for both
acceptance VMs. No legacy outcome closed; estimates remain 37-57 / 38-53 /
19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about 155. See
[structured evidence](archive/evidence/package-dependency-planning-cross-shell-regression-2026-10-28-0803.json)
and [VM access evidence](archive/evidence/package-provider-portable-full-cross-shell-regression-and-vm-block-2026-10-28-0801.json).

## Package provider and portable selection full cross-shell regression, 2026-10-28 08:01 UTC

The complete `ApplicationPackages.Tests.ps1` and
`PortableAcceptanceAutomation.Tests.ps1` suites passed **176/176** in Windows
PowerShell 5.1.26100.9711 and **176/176** in PowerShell 7.6.5/Pester 5.7.1.
Three retained-archive cases were skipped because their RawCopy, ETL2PCAPNG,
and AdMod fixtures were not supplied. No test was filtered or left unrun.
Repository validation passed for 441 operations, 8 groups, 5 profiles and 299
PowerShell files; generated operation documentation is current.

Read-only `Get-VM` failed for `RIDE-Win11-Test` and `RIDE-Server2025-Test`
before VM/checkpoint inspection with `Access to a CIM resource was not
available to the client`. No acceptance task was dispatched. No installer or
utility ran; Defender-blocked tools were not selected. Package lifecycle and
Windows acceptance remain deferred. No legacy outcome closed; estimates stay
37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about
155. See [structured evidence](archive/evidence/package-provider-portable-full-cross-shell-regression-and-vm-block-2026-10-28-0801.json).

## NirSoft PasswordScan Defender block alert, 2026-10-28 07:55 UTC

The user reports a Defender block for x64 `passwordscan.exe` in the filtered
NirLauncher temporary tree. No detection name, Defender event time, or
creating-run provenance was supplied. Keep both PasswordScan architectures
excluded and defer the retained NirLauncher archive lifecycle until staging
provenance is understood. No reported file or Defender state was inspected or
changed. No legacy outcome closed; estimates remain 37-57 / 38-53 / 19-24 /
25-35 / 8-12, exact 127-181, rounded 125-180/about 155. See [structured
evidence](archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0755.json).

## Package provider and portable selection regression, 2026-10-28 07:37 UTC

Filtered current-source Pester across `ApplicationPackages.Tests.ps1` and
`PortableAcceptanceAutomation.Tests.ps1` passed **62/62** in Windows PowerShell
5.1.26100.9711 and **62/62** in PowerShell 7.6.5/Pester 5.7.1. The filter covers
the RIDE-managed module prerequisite, OpenJDK checksum response parsing,
AdMod publisher-form resolution, NuGet ZIP-format selection, HashCheck metadata
and portable acceptance selection boundaries. Pester discovered 179 total
tests; 117 outside the focus filter were not run. Publisher calls were mocked;
no installer or utility ran and no real package lifecycle was exercised.

Repository validation passed for 441 operations, 8 groups, 5 profiles and 299
PowerShell files; generated operation documentation is current. Exact-name VM
checks for `RIDE-Win11-Test` and `RIDE-Server2025-Test` again failed at host CIM
before inspection. Installation, removal, saved-state recovery and Windows
acceptance remain deferred. No legacy outcome closed; estimates remain
37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about
155. See [structured evidence](archive/evidence/package-provider-and-portable-selection-focused-cross-shell-regression-2026-10-28-0737.json).

## NirSoft PasswordScan Defender block alert, 2026-10-28 07:22 UTC

The user reports another Defender block for the same x64 PasswordScan path in
the filtered NirLauncher temporary tree. No detection name, Defender event
time, or creating-run provenance was supplied. Keep both PasswordScan
architectures excluded and defer the retained NirLauncher archive lifecycle
until staging provenance is understood. No reported file or Defender state was
inspected or changed. No legacy outcome closed; estimates are unchanged at
37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded 125-180/about
155. See [structured evidence](archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-0722.json).

## Pending package review-marker coverage refresh, 2026-10-28 07:18 UTC

The current catalog has **45** pending package versions. Direct read-only
comparison against `%LOCALAPPDATA%/RIDE/license-reviews.json` found 17 exact
`NeedsReview` / `Unassigned` records and 28 missing exact-version markers. The
28 rows were merged through `Manage-RideLicenseReviews.ps1 Import` after a
same-directory backup; all 32 prior records were preserved. The store now has
60 records and direct verification confirms 45/45 pending package versions
have exact markers. `LicenseReviews.Tests.ps1` passed 24/24 in both
PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711. These markers are
administrative only and do not block package planning, RIDE direct-download /
install migration, or Sysinternals under its existing specialist approval.
No legacy outcome closed; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12
(exact 127-181; rounded 125-180/about 155). See [structured evidence](archive/evidence/package-license-review-pending-marker-coverage-2026-10-28-0718.json).
## JoeWare AdMod managed-cache handler-route regression, 2026-10-28 07:05 UTC

Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5/Pester 5.7.1 each
passed both focused AdMod route cases. The added case copied the retained pinned
1.29.00 ZIP into an isolated canonical cache fixture, used the real
`Save-RidePackageArtifact` cache-validation and observation path, then passed the
verified result through offline `Install-RidePackage` to the real portable
handler. Only the declared `AdMod.exe` member was staged; no utility ran and no
publisher request or Windows change occurred. VM acceptance remains blocked
before inspection at host CIM. No legacy outcome closed; estimates remain
37-57 / 38-53 / 19-24 / 25-35 / 8-12 (exact 127-181; rounded 125-180/about
155). See [structured evidence](archive/evidence/joeware-admod-managed-cache-route-cross-shell-and-vm-block-2026-10-28-0705.json)
and [focused test](../tests/JoeWareAdModEngineRoute.Tests.ps1).
## JoeWare AdMod cache validation and license-marker audit, 2026-10-28 05:11 UTC

The previously publisher-acquired AdMod 1.29.00 archive was placed at the
RIDE package cache's canonical ID/version path and passed
`Save-RidePackageArtifact` cached-artifact validation against the catalog SHA-256.
The ZIP contains only `AdMod.exe`; its streamed in-memory SHA-256 matches the
recorded member hash. A fresh call through the direct publisher acquisition
branch is blocked before response while `www.joeware.net` fails DNS resolution.
The utility was not extracted to an executable path or launched. The workspace
license store now has exact `NeedsReview` / `Unassigned` records for all 45
pending package versions; Windows PowerShell 5.1/Pester 5.7.1 passed
`LicenseReviews.Tests.ps1` 24/24. AdMod managed install, repeat, uninstall,
recovery and Windows 11 acceptance remain pending. No legacy outcome closed.
See [structured evidence](archive/evidence/joeware-admod-cache-validation-license-audit-2026-10-28-0511.json).

## JoeWare AdMod focused Windows PowerShell regression, 2026-10-28 05:00 UTC

Windows PowerShell 5.1.26100.9711/Pester 5.7.1 passed the three filtered AdMod provider/catalog cases and all seven downloader tests. The first default invocation stopped before assertions on Pester TestRegistry HKCU access; rerunning with TestRegistry and TestResult disabled passed. Tests used mocks/WhatIf, made no publisher request and did not stage or execute an AdMod, AdFind or PasswordScan payload. Pester 5 in PowerShell 7 and fresh direct Save-RidePackageArtifact acquisition remain unverified; the direct route currently fails before publisher response at DNS. The cached-artifact validation path now passes separately. Windows lifecycle remains unverified. See [structured evidence](archive/evidence/joeware-admod-focused-winps51-regression-2026-10-28-0500.json) and the [follow-up cache validation](archive/evidence/joeware-admod-cache-validation-license-audit-2026-10-28-0511.json).

## JoeWare AdMod 1.29.00 retained archive and package candidate, 2026-10-28 04:50 UTC

The official AdMod product page reports version 1.29.00, released June 8, 2026;
the publisher versions list reports the same version/date and MD5/SHA-1 values.
The retained ZIP is 811,771 bytes with local SHA-256
45cf050eec76d7f1c736b613616bcbf4c3dea872d3d5f7398fd276b1fc369235. Its exact
inventory is AdMod.exe only. In-memory PE inspection identified x86
(0x014C), with embedded-file SHA-256
86c922fc98c115ea21c2053739938234fd90ce626ed227b2c3c122c2484e4d79. No
executable was written out or launched. The catalog candidate resolves to this
pin and passes catalog validation with zero errors. The operation remains
unsupported pending RIDE-managed install, repeat, uninstall, exact restore and
Windows 11 acceptance. Pester and native acceptance were not run; no legacy
outcome closed. See [acquisition and static evidence](archive/evidence/joeware-admod-package-candidate-2026-10-28-0450.json),
[package guide](application-packages.md#joeware-admod-portable-package-candidate),
and the publisher's [product page](https://joeware.net/freetools/tools/admod/index.htm).

## HashCheck retained-artifact preflight, 2026-10-27 18:39 UTC

The official HashCheck 2.6.3 installer remains available locally at its pinned
version. Its 2,157,368 bytes match the publisher sidecar/release digest, and its
Authenticode signature is valid for IDRIX SARL. The focused catalog assertion
passed 1/1. The installer was not run; RIDE-managed install/remove/recovery,
Explorer and sparse-package behavior, intended-user registration and Windows 11
acceptance remain deferred. `SupportedTargets` stays empty. No license gate or
legacy outcome was added; estimates remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12,
exact 127-181, rounded 125-180/about 155. See [HashCheck evidence](archive/evidence/hashcheck-retained-artifact-catalog-preflight-2026-10-27-1839.json).

## NirSoft Defender-filtered retry, 2026-10-27 18:35 UTC

A repeated user-reported alert received 2026-10-28 06:39 UTC again names the filtered x64 PasswordScan temp path; its Defender detection name and event time are unknown. See [repeat alert evidence](archive/evidence/nirsoft-passwordscan-repeat-defender-alert-2026-10-28-0639.json). Both PasswordScan
architecture paths are now excluded. NirLauncher selects 647 of 668 archive
entries and excludes 21 entries, including the four reported alert basenames,
IEHistoryView, LANIPScanner, LSASecretsDump, OperaPassView, RouterPassView,
NetPass, WebBrowserBookmarksView, BrowserAutoFillView, and PasswordScan. The
filtered actual-archive retry produced no result and was stopped after the
temporary tree showed no progress; it is incomplete, not a pass. No utility
launched, package commit occurred, or Defender setting changed. `Get-VM`
remains blocked by host CIM access before VM/checkpoint inspection. Estimates
remain 37-57 / 38-53 / 19-24 / 25-35 / 8-12, exact 127-181, rounded
125-180/about 155. The isolated catalog-pin/exclusion Pester assertion passed
1/1; the real-archive retry remains incomplete. See [retry evidence](archive/evidence/nirsoft-defender-filtered-retry-incomplete-2026-10-27-1835.json).

## NirSoft encrypted-archive lifecycle and Defender exclusions, 2026-10-27 17:35 UTC

The portable handler now extracts password-protected ZIPs through the signed
Windows inbox `tar.exe`, passing exact `PortableMembers` selectors and checking
the extracted inventory, lengths, and reparse-point state before package
ownership changes. The actual x64 publisher archive passed install, repeat,
removal, saved-state restore and operator-note preservation **1/1** on
PowerShell 7.6.5 and **1/1** on Windows PowerShell 5.1.26100.9711. NirLauncher
staging stopped when Defender prevented `NirSoft/iehv.exe` and, after excluding
that path, `NirSoft/lanipscanner.exe`. Both are now omitted, along with the four
user-reported alert basenames. No NirLauncher package commit or utility launch
occurred; no Defender allow rule/exclusion was added. Fresh `Get-VM` again failed
at CIM before inspection. Resolved: x64 local publisher-archive file lifecycle.
Retired/excluded: six individual NirSoft basenames/paths from selected staging.
Deferred/partial: NirLauncher publisher-archive lifecycle and both Windows 11
acceptance decisions. No whole legacy outcome closed; estimates remain settings
**37-57**, packages **38-53**, components **19-24**, files/assets **25-35**,
maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**.
Sysinternals licensing remains settled under the prior RIDE v2 specialist
approval and is unrelated to these Defender exclusions. See [evidence](archive/evidence/nirsoft-encrypted-archive-lifecycle-defender-blocks-2026-10-27-1735.json),
[package guide](application-packages.md#nirsoft-collection-pending-portable-candidates),
[NirLauncher publisher page](https://www.nirsoft.net/launcher/downloads/),
[x64 publisher page](https://mail.nirsoft.net/x64_download_package.html), and
[latest VM access evidence](archive/evidence/nirsoft-encrypted-archive-lifecycle-defender-blocks-2026-10-27-1735.json).

## NirSoft retained-archive encryption diagnostic, 2026-10-27 17:13 UTC

The retained NirLauncher and x64 publisher ZIPs match their pinned size, SHA-256
and central-directory inventories. Both use Deflate with the ZIP encryption flag
set; the current `System.IO.Compression` handler cannot extract their encrypted
entries, so publisher-archive install/repeat/remove/recovery is not yet verified.
The filtered Pester case failed at extraction (**0/1 passed**). The catalog still
omits all four Defender-reported executable basenames; no such entry was opened
or extracted and no utility ran. The earlier synthetic inert-ZIP lifecycle pass
does not establish publisher archive support. No legacy outcome closed; exact
estimates remain **127-181**, rounded **125-180/about 155**. Sysinternals
licensing remains settled under the prior RIDE v2 specialist approval and is
unrelated to this technical blocker. See [structured evidence](archive/evidence/nirsoft-retained-archive-encryption-lifecycle-block-2026-10-27-1713.json),
[candidate handling](application-packages.md#nirsoft-collection-pending-portable-candidates),
[official NirLauncher download page](https://www.nirsoft.net/launcher/downloads/)
and [official x64 package page](https://mail.nirsoft.net/x64_download_package.html).

## MiTeC JSON/XML Viewer current-source retained-archive regression, 2026-10-27 17:02 UTC

`MitecViewerPackages.Tests.ps1` passed **16/16** on PowerShell 7.6.5 and **16/16** on Windows PowerShell 5.1.26100.9711 with the retained official JSONView and XMLView archives. The matrix covers both x64 and x86 variants. Exact archive length/hash and selected executable evidence matched; each case staged only its architecture-selected executable, repeated installation, verified package state, preserved synthetic user licence/configuration files across removal and restore, refused modified owned files, and refused collisions with unowned executables. No viewer launched, document opened, activation performed, updater checked or network behavior exercised. A fresh VM read-only probe in this turn failed at CIM before inspection, so current-source Windows 11 acceptance remains deferred and `SupportedTargets` stays empty. Resolved: current-source retained-archive file lifecycle for both viewer packages and architectures. Retired/excluded: none. Deferred: Windows 11 lifecycle and GUI/document/activation/updater behavior. Partial: no whole legacy outcome closes. Estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/mitec-json-xml-current-source-retained-archive-cross-shell-regression-2026-10-27-1702.json), [current-source package suite](../../tests/MitecViewerPackages.Tests.ps1), and [current VM access evidence](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json).
## MiTeC Structured Storage Viewer retained-archive lifecycle and VM access, 2026-10-27 16:58 UTC

The retained publisher `SSView.zip` matched its checked-in size and SHA-256, and its selected `SSView.exe` member matched the pinned member digest. The focused current-source Pester suite passed **3/3** on PowerShell 7.6.5 and **3/3** on Windows PowerShell 5.1.26100.9711. The real-archive case stages only the selected executable and verifies repeat install, health, snapshot, removal, saved-state recovery and preservation of an operator note; it does not launch the utility, load the codec, open a structured-storage file or access user documents. The optional ZLib codec, Delphi source and sample remain excluded from staging. A fresh read-only `Get-VM -Name RIDE-Win11-Test` failed before inspection with CIM access unavailable; no VM acceptance or UAC prompt occurred. `SupportedTargets` remains empty. No complete legacy outcome closed; estimates remain settings **37-57**, packages **38-53**, components **19-24**, files/assets **25-35**, maintenance **8-12**, exact **127-181**, rounded **125-180/about 155**. See [structured evidence](../archive/evidence/mitec-ssview-retained-archive-cross-shell-lifecycle-and-vm-access-2026-10-27-1658.json), [candidate contract](../application-packages.md#mitec-structured-storage-viewer-portable-candidate), and [current VM blocker](../archive/evidence/hyper-v-manager-read-only-ui-integrity-recheck-2026-10-27-1636.json).
## NTCore WIM Installer retained-archive cross-shell lifecycle, 2026-10-27

The exact retained WIM Installer archive passed its focused current-source
staging/recovery cases **2/2** on PowerShell 7.6.5 and **2/2** on Windows
PowerShell 5.1.26100.9711. The archive SHA-256 was rechecked; only the selected
file was staged in an isolated test directory. The executable, WIM and disk
were not accessed. Windows 11 and product image/disk acceptance remain pending.
See [structured evidence](archive/evidence/ntcore-wim-installer-retained-archive-cross-shell-regression-2026-10-27-1350.json).

## Filtered NirSoft current-source cross-shell regression, 2026-10-27

`NirsoftCollectionPackages.Tests.ps1` passed **4/4** on PowerShell 7.6.5 and
**4/4** on Windows PowerShell 5.1.26100.9711. The current source verifies both
filtered inventories and the four Defender-alerted executable exclusions,
then stages synthetic inert archives, repeats install, saves/removes/restores
state, and preserves operator content. No publisher archive or utility was
accessed or run. Both candidates remain pending Windows 11 acceptance. See
[structured evidence](archive/evidence/nirsoft-filtered-current-source-cross-shell-regression-2026-10-27-1345.json).

## Sysinternals package and license-planning regression, 2026-10-27

SysinternalsProductPackages.Tests.ps1, SysinternalsSuitePackage.Tests.ps1,
and LicenseReviews.Tests.ps1 passed **104/104** with Pester 5.7.1. TestRegistry
and TestResult were disabled; TEMP/TMP stayed under
.local/pester-sysinternals-current-20261027. All ten Sysinternals install plans
remain available under the settled RIDE v2 specialist approval for direct
download-and-install. No license gate applies. No utility or installer ran, and
no Windows, Defender or VM state changed. See [structured
evidence](archive/evidence/sysinternals-license-plan-current-source-regression-2026-10-27-1012.json).
# Package verification matrix

## Hex2text and ChromeSyncParser pinned-source lifecycle, 2026-10-27

Both exact catalog-pinned retained archives passed current-source file lifecycle
coverage: **10/10** combined on PowerShell 7.6.5 and **10/10** on Windows
PowerShell 5.1.26100.9711. Checks include archive hash/member inventory,
repeat staging, saved-state recovery and operator-note preservation. Neither
Python script ran and no browser data was accessed. Native Windows 11 behavior
remains pending VM access. See [structured evidence](archive/evidence/python-source-current-artifact-lifecycle-and-vm-block-2026-10-27-1229.json).

## Filtered NirSoft collection package candidates, 2026-10-27

The current-source synthetic lifecycle passed **4/4** on PowerShell 7.6.5 and
**4/4** on Windows PowerShell 5.1.26100.9711. A final-source PowerShell 7 run
passed the three fast metadata, Defender-exclusion and no-license-gate cases;
the long lifecycle case was not run in that check. The package selections omit
the four Defender-alerted executables. No NirSoft executable or installer was
launched, and no publisher archive was accessed. Native Windows 11 acceptance
remains pending VM access. See [structured evidence](archive/evidence/nirsoft-filtered-package-lifecycle-regression-and-vm-block-2026-10-27-1220.json).


## Windows Firewall Notifier Nightly current-source full lifecycle, 2026-10-27

Current-source `WfnPackage.Tests.ps1` passed 4/4. This includes the exact
retained archive hash/member inventory and full synthetic lifecycle over all
531 declared members (1299.14 seconds), with exact owned-file health and saved
state recovery. WFN and its installer were not executed, and firewall state was
not changed. Windows 11 runtime and lifecycle remain pending. See [structured
evidence](archive/evidence/wfn-current-source-full-531-member-lifecycle-regression-2026-10-27-0940.json).
## ETL2PCAPNG 1.11.0 current-source retained-artifact lifecycle, 2026-10-27

The opt-in Pester case passed 1/1 against the retained pinned executable and
tracked MIT notice. It tested repeat owned-file staging, exact saved-run restore,
and operator-note preservation; the converter and ETL traces remained untouched.
Windows 11 lifecycle and synthetic ETL conversion are still pending. See
[structured evidence](archive/evidence/etl2pcapng-current-source-retained-artifact-pester-lifecycle-2026-10-27-0915.json).
## ExifTool 13.59 synthetic command-copy lifecycle, 2026-10-27

One focused current-source Pester case passed 1/1 with TestRegistry disabled, using an inert synthetic ZIP
members, including saved-run recovery of the command copy and upstream launcher.
This does not verify the exact SourceForge archive: acquisition previously failed
before transfer at DNS resolution. No utility or real media was accessed. Exact
archive hash/member review, Windows 11 lifecycle, and synthetic-media behavior
remain pending. See [structured evidence](archive/evidence/exiftool-current-source-synthetic-command-copy-lifecycle-2026-10-27-0908.json).
The package handler validates available provider-pinned digests and publisher checksums,
declared archive members, and Authenticode hash integrity before recording a successful
acquisition. A validation failure moves the bytes from the reusable canonical cache path to a
unique `.rejected-<id>` sibling with a JSON sidecar recording the content hash, source and
rejection reason; any previous canonical observation sidecar moves with the rejected bytes.
The next attempt can reacquire into the canonical path. Rejected bytes are not automatically deleted. Authenticode statuses
other than `HashMismatch` remain recorded evidence; unsigned artifacts can still be used when
their source and any available digest checks pass. This is not a blanket requirement for a
publisher signature or checksum, and package-specific source limitations remain below.

## Evidence thresholds and rejected-artifact review, 2026-10-24

RIDE uses available evidence to describe what it establishes; it does not
require every publisher to provide the same checksum or signature format.
Acquisition can proceed to package-candidate and lifecycle review when the
artifact is tied to an identified publisher source and exact version or
immutable revision, RIDE records the observed SHA-256 and size, declared archive
members pass validation, and every available provider or publisher digest
matches. A direct source that does not publish a digest is recorded as an
observed pin, not as publisher verification. A hosting-provider digest is
labelled as hosting metadata. Authenticode `Valid` records signed-byte integrity
and the observed signer identity; it does not by itself establish that RIDE has
approved that identity. `NotSigned`, `NotTrusted`, and `UnknownError` remain
observations and do not create a blanket package-migration block.

Always reject an available digest mismatch, Authenticode `HashMismatch`, an
archive member/path violation, or a mismatch against RIDE's reviewed pin before
installer execution. Record the exact source, version, reason and hashes. A
publisher checksum/signature gap can limit confidence and require a focused
security decision for a sensitive install context, such as a driver, service,
administrator-level installer, or credential-handling utility. That review is
separate from license review and package lifecycle readiness. No evidence tier
or successful acquisition authorizes installation, activation, target support,
or a license conclusion; those are assessed separately.

Rejected artifacts are retained for investigation and are never automatically
copied back into the canonical cache or deleted. Review an exact rejected file
and its `.ride.json` sidecar; compare the sidecar's SHA-256 and size with the
file, read the recorded source/version/reason, and preserve any
`.previous.ride.json` observation. If the failure is understood and a retry is
appropriate, reacquire from the declared publisher source and run all current
checks against the new bytes. Do not bless the rejected file by copying or
renaming it into the canonical path.

An operator may clean up reviewed rejected bytes only after exporting the
sidecar, previous observation and disposition to the relevant evidence record.
Use the exact path reported for the reviewed item; do not use a wildcard or
delete a whole cache tree. Preview the exact file removal first, verify the
resolved file is still the same regular file with the recorded hash, and then
remove that file and its two specifically associated sidecars if they exist.
For example, replace the placeholder with one exact reviewed path:

```powershell
$rejectedPath = 'C:\RIDE\Cache\<package>\<version>\artifact.exe.rejected-<id>'
$resolvedPath = (Resolve-Path -LiteralPath $rejectedPath -ErrorAction Stop).Path
$item = Get-Item -LiteralPath $resolvedPath -Force -ErrorAction Stop
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The rejected artifact is not a regular file.'
}
$record = Get-Content -LiteralPath ($resolvedPath + '.ride.json') -Raw | ConvertFrom-Json
$actualHash = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -cne $record.Sha256 -or $item.Length -ne $record.FileSize) {
    throw 'Rejected artifact no longer matches its evidence sidecar.'
}
$record | Format-List Kind,PackageId,Version,Uri,Reason,Sha256,FileSize
Remove-Item -LiteralPath $resolvedPath -WhatIf
# After confirming the reviewed evidence and path, repeat without -WhatIf.
Remove-Item -LiteralPath $resolvedPath
```

Remove `.ride.json` and `.previous.ride.json` separately by exact literal path
only after their contents have been archived. Do not run cleanup as part of
acquisition or automatically after a successful retry.

## Per-package source observations

Sysinternals Suite source review, 2026-10-17: 374,742,194-byte official ZIP,
SHA-256 `e1e75de5cdb12116b0a4eca83725dc7c7a1645266196025cbe5ca6c167161aed`.
All 164 files were inventoried without execution; 151 PE executables had Valid
Microsoft Authenticode, with 79 x86 and 72 x64 PE machine fields. No publisher
archive digest is claimed. The [frozen inventory](archive/evidence/sysinternals-suite-source-review-2026-10-17.json)
and [candidate boundaries](application-packages.md#sysinternals-reviewed-suite-candidate)
retain notices and pending individual/native acceptance.

Wireshark MSI source review, 2026-10-17: official 4.6.9 x64 payload, 80,433,152
bytes, SHA-256 `1975dfc96581a9b674fda3f41ac1585963b4ba52ea9459f3b6d9cedfac3a7217`,
matches the exact publisher checksum and has Valid Wireshark Foundation Authenticode.
PGP verification was not performed. Read-only MSI tables bind the all-user and
no-association candidate arguments; no installer ran. See [source evidence](archive/evidence/wireshark-msi-source-review-2026-10-17.json)
and [pending acceptance](application-packages.md#wireshark-machine-msi-candidate).

Wireshark 4.6.9 MSI database recheck, 2026-10-25: the retained artifact was
opened read-only through the Windows Installer COM API. Its properties identify
Wireshark 4.6.9.0 and `ALLUSERS=1`; launch conditions state Windows 10 1809 or
Windows Server 2019 or later. The MSI file table has 983 rows and no Npcap or
USBPcap payload. It declares a `VCRedist` feature with AMD64 and ARM64 runtime
components mapped to `System64Folder`; the selected feature state and shared
runtime effects still require disposable Windows acceptance. The 2026-10-22
guest report records clean-absence install/repeat/remove/saved-run recovery
passing on Windows 11 build 26300 and Server 2025 build 26100; existing-install,
association/runtime preservation and broader recovery remain open. No MSI
action ran during the database inspection. See [database inspection evidence](archive/evidence/wireshark-4.6.9-msi-database-inspection-2026-10-25-1548.json)
and [guest acceptance evidence](archive/evidence/applications-batch1-acceptance-2026-10-22.json).

PSScriptTools source review, 2026-10-17: the official pinned 3.2.0 source archive
contains 360 files and 75 function scripts, with MIT notices retained. All 36
manifest/root reference paths were present; root manifest/module parsed on both
PowerShell editions without import. The observed SHA-256 is pinned, not a publisher
signature/checksum. No dependencies were installed. See the [source evidence](archive/evidence/psscripttools-source-review-2026-10-17.json)
and [pending deployment contract](application-packages.md#psscripttools-source-candidate).

Pinned Python source review, 2026-10-16: Hex2text and ChromeSyncParser complete archives match all three separately acquired commit-pinned raw files. Observed archive hashes are pinned, with upstream licenses retained; no publisher signature/checksum is claimed. Python 3.12.14 parsed both scripts without execution. ShimCacheParser retains a Python 2 blocker. See the [source evidence](archive/evidence/python-script-source-review-2026-10-16.json) and [candidate contract](application-packages.md#pinned-python-source-candidates). On 2026-10-25 both exact three-file archives passed current-source local staging, repeat, saved recovery and modified/unowned-content preservation; no script ran. Runtime and target acceptance remain open. See [current lifecycle evidence](archive/evidence/python-source-real-artifact-lifecycle-2026-10-25-1625.json).

RegRipper 3.0 source review, 2026-10-16: the [pinned archive observation](archive/evidence/regripper-source-review-2026-10-16.json) records 282 files and the complete distribution hash. Both executables and the bundled x86 runtime are NotSigned. The observed pin is not a publisher signature/checksum. No parser was run; native and forensic acceptance remain pending. See the [candidate contract](application-packages.md#regripper-30-portable-candidate) and [batch evidence](migrations/application-migration-review.md#b08-regripper-30-distribution-candidate-2026-10-16). The retained exact-hash archive also passed local owned-file install/repeat/uninstall/saved-restore checks across all 282 files; unowned and modified user content was preserved. No program ran. The inert fixture suite passed 4/4 and repository validation passed 415/8/5/278; Windows target and parser acceptance remain pending. See [consolidated current-source evidence](archive/evidence/regripper-3.0-current-source-regression-and-real-artifact-lifecycle-2026-10-25-1618.json).

Rufus source review, 2026-10-16: official x64 portable 4.15 acquisition retained
1,989,992 bytes, file/product version 4.15.2396, SHA-256
`84c8a437f8af89257524478489e5c85f1edf25f761d299e2bcde46ac0afbe106`, and a Valid
Akeo Consulting Authenticode signature. The catalog pins those observed bytes;
no publisher checksum is claimed. The [sanitized observation](archive/evidence/rufus-portable-source-review-2026-10-16.json)
retains source, certificate and acquisition time. Current-source local validation
reused the exact retained bytes as inert content: repeat staging and uninstall,
exact single-file ownership, user settings/log preservation, saved snapshot
recovery, post-capture operator-edit preservation, and modified-executable
warning/preservation all passed. `RufusPackage.Tests.ps1` passed 4/4. Rufus was
not launched and no USB/media, Windows or Defender state was accessed or changed.
This confirms local package ownership and recovery only; disposable Windows 11
acceptance remains pending. See [current real-artifact lifecycle evidence](archive/evidence/rufus-4.15-real-artifact-local-lifecycle-2026-10-26-0654.json),
[prior real-artifact evidence](archive/evidence/rufus-real-artifact-local-lifecycle-2026-10-25-1127.json),
and the [candidate guide](application-packages.md#rufus-portable-candidate).

GitHub release discovery now uses [bounded process-local metadata reuse and
shared rate-limit backoff](github-release-discovery.md). Freshness and source
observations accompany artifact evidence independently of payload cache use;
available digest and publisher-checksum checks still run on retained bytes.

Thunderbird follow-up, 2026-10-11: read-only acquisition of official Release
157.0.1, win64/en-GB, matched the exact publisher SHA256SUMS entry
`4b346e97e782cfc03f374ec1e132dcb639b7366f0e8830d56aa75214ef4eebca`.
The installer has a Valid Mozilla Corporation Authenticode signature; the
available detached checksum signature is recorded but not verified. Current-user
lifecycle and saved-selection recovery passed on Windows 11 and Server 2025
Desktop Experience, with non-elevated identity and profile preservation verified.
See [correlated acceptance](archive/migrations/application-thunderbird-follow-up-2026-10-11.md#accepted-migration-after-resumed-validation).

Application migration additions, 2026-10-11: VS Code's official feed supplies
SHA-256; Mozilla uses an exact release path; GitHub releases retain available
asset digests, checksum/signature references and observed hashes. PuTTY's
publisher page resolves to a versioned executable. Available Authenticode
`HashMismatch` results stop acquisition/deployment. Managed portable manifests
also record per-file hashes and available executable signatures, retain notices
and validate saved recovery bytes. Unsigned/not-trusted observations are not
converted into publisher verification or license approval. Target-specific
acceptance and acquisition blockers are tracked in the
[application ledger](migrations/application-migration-review.md).

This matrix records what each upstream source makes available for the current
release. It separates publisher evidence from hosting-provider metadata and
RIDE's own observed hashes. A local observation does not prove authenticity.
Source review date: 2026-10-08.

| Package | Latest source | Exact versioned artifact | Publisher checksum/signature | Hosting metadata | Authenticode | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 7-Zip x64 | Official `ip7z/7zip` release `26.04` | `7z2604-x64.exe` | No publisher checksum/detached signature identified on the official download page | GitHub SHA-256 digest matched | Windows 11 observation: `NotSigned` | Eligible under the 2026-10-24 decision; source/version and available digest checks still apply |
| Notepad++ x64 | Official release `v8.9.8.1` | `npp.8.9.8.1.Installer.x64.exe` | Exact release checksum and GPG sidecar URLs recorded; detached verification remains open | GitHub digest matched | `Valid`; subject/organization `NOTEPAD++`, email `don.h@free.fr` | Confirm publisher signer expectations/rotation and implement trusted-key GPG verification |
| Git for Windows x64 | Official release `v2.56.0.windows.2` | `Git-2.56.0.2-64-bit.exe`; four-part installer names supported | Exact installer SHA-256 published in release notes is now parsed and matched. No detached signature over that checksum identified | GitHub digest matched separately as provider metadata | `Valid`; subject/organization `Johannes Schindelin`, Bruehl, DE | Git functionality/lifecycle passed; publisher signer expectations remain a trust-policy investigation |
| Sysmon x64 archive | Microsoft page version `15.22`, direct `Sysmon.zip` | Versioned cache; source ZIP URL remains mutable | No publisher checksum/detached signature identified on download page | Microsoft direct download; no GitHub digest | Root `Sysmon64.exe` reports `Valid`, signer `Microsoft Windows Publisher`, issuer `Windows Production PCA 2023`; member evidence is bound to archive SHA-256 | Actual Windows signer captured; certificate rotation/trust policy remains separate |
| SwiftOnSecurity Sysmon XML | Latest commit history for the exact file path in `SwiftOnSecurity/sysmon-config` | Yes; the selected file is downloaded from the resolved immutable commit SHA | No detached signature or checksum identified | GitHub API reports commit identity; this does not authenticate the author or content | Not applicable to XML | Download-only artifact support added; application remains a separate explicit configuration action |
| Git LFS standalone | Official `git-lfs/git-lfs` release `v3.8.0` | `git-lfs-windows-v3.8.0.exe` | `sha256sums.asc` and signature assets inventoried; detached verification not implemented | GitHub digest checked when supplied | `Valid`; subject/organization `GitHub, Inc.`, San Francisco, US | Requires Git before install and during removal; verify publisher keys separately |
| Joplin | Official `laurent22/joplin` release `v3.7.21` | `Joplin-Setup-3.7.21.exe` | Sidecar URLs collected when present; no new mandatory gate | GitHub digest matched | `Valid`; subject/organization `Joplin`, Nancy, FR | Current-user NSIS lifecycle passed on Windows 11 |
| ShareX | Official `ShareX/ShareX` release `v21.0.0` | `ShareX-21.0.0-setup-x64.exe` | Sidecar URLs collected when present; no new mandatory gate | GitHub digest matched | `NotSigned` | Eligible under the 2026-10-24 decision; machine EXE lifecycle passed on Windows 11; portable form remains separate |
| WinDirStat | Official `windirstat/windirstat` release `release/v2.9.2` | `WinDirStat-x64.msi`, retained under exact version | Publisher `WinDirStat-Hashes.txt` identified; parsing/verification remains open | GitHub digest matched | `Valid`; signer `Open Source Developer Bryan Berns` | Quiet no-restart MSI lifecycle passed on Windows 11 |
| PowerShell 7 | Official `PowerShell/PowerShell` release `v7.6.6` | `PowerShell-7.6.6-win-x64.msi` | Publisher checksum assets collected when present; verification remains separate | GitHub digest matched | `Valid`; signer `Microsoft Corporation` | MSI lifecycle and executable/version check passed on Windows 11; preserve Windows PowerShell 5.1 |

The user's 2026-10-24 decision keeps 7-Zip and ShareX eligible when their
installers report `NotSigned`. `PackageEvidence.Tests.ps1` passed **28/28** in
the corresponding acquisition regression: a matching provider SHA-512 was
accepted with `NotSigned`, while altered bytes were rejected. This test uses
mocked payloads and does not establish new package or Windows acceptance. See
the [structured evidence](archive/evidence/unsigned-package-eligibility-acquisition-regression-2026-10-24-0838.json)
and [decision](migrations/decision-session-2026-10-17.md#unsigned-package-eligibility-decision-2026-10-24).

### Installed continuation observations, 2026-10-11

| Package | Exact acquisition selection | Publisher evidence and RIDE checks | Observed executable signature | Acceptance and limits |
| --- | --- | --- | --- | --- |
| Chrome enterprise x64 MSI | 155.0.8059.40, official mutable Google endpoint; versioned cache filename | Inspected SHA-256 pin `32ba438dea18f0fed1ec621bfb274a2669adec67be2aa91d96b3cc6c64779276` checked before deployment; not a publisher-published checksum | `Valid`, Google LLC | Machine lifecycle/profile preservation/compensating recovery passed on Windows 11 and Server 2025 Desktop Experience; source changes require reviewed repinning |
| Signal Desktop stable x64 | 8.30.0, official update feed and exact versioned EXE | Feed's release/file SHA-512 must agree and match downloaded/cached bytes; SHA-256 `fb5cb6742e355df52e4375ad01d18adb671941c5e040e8dc9a81db852cfb43dd` retained separately | `Valid`, Signal Messenger LLC | Current-user lifecycle/profile preservation/compensating recovery passed on both targets; linking/UI and exact previous-version recovery are separate |

Requests `0a58abbfedac42ab87e60c6a682b4968` and
`a68b43e9367148caba8f3fd173b5bdb6` passed six installed scenarios and 224 guest
checks each. Sixteen correlated observations were appended, preserving all 78
earlier records; the shared library then contained 94 observations. The two new
products have one direct acquisition and one retained-cache read per target.
These are same-origin observations, not independently routed verification.
Signal's checked SHA-512 is recorded in `ProviderDigest` with its official feed
in `ChecksumUris`; publisher-SHA-256 fields are unavailable, not an assertion
that the feed lacks integrity evidence. Certificate observations remain distinct
from permanent signer policy and local owner/company licence approval.
See the [installed acceptance record](archive/migrations/application-installed-follow-up-2026-10-11.md).

Sources: [Chrome enterprise](https://chromeenterprise.google/download/),
[Signal feed](https://updates.signal.org/desktop/latest.yml), and
[Signal licence](https://github.com/signalapp/Signal-Desktop/blob/v8.30.0/LICENSE).

### WinSCP portable observations, 2026-10-11

The official stable 6.5.7 x86 portable ZIP resolves from its durable publisher page
to a fresh version-matched HTTPS CDN URL. The published SHA-256 matched on both
targets: `cbe76fc80695ac34d14e4ba81f7ff564beeb3f2033dae7490092e269016d7959`.
`PublisherSha256`, `PublisherChecksumUri`, `PublisherChecksumResult=Matched`
and the SHA-256 provider digest are retained separately from local decisions.
The archive contains exactly four owned files and complete upstream notices;
WinSCP.exe and WinSCP.com both have Valid Martin Prikryl signatures.

Final requests `06e454c9dcba455e9d9d0e81259453b5` (Windows 11) and
`6103ffaecca64224ab61874726bb814b` (Server 2025 Desktop Experience) each passed
230 guest checks and twelve portable lifecycles. Twenty-four correlated final
observations preserve all 94 earlier entries, bringing the shared total to 118.
The two WinSCP direct acquisitions share the same publisher route; they are not
independent-source verification. ZIP signature status is separate from member
signatures. Exact owned-file recovery, session preservation and VM recovery are
recorded in the [acceptance record](archive/migrations/application-winscp-follow-up-2026-10-11.md#final-correlated-acceptance).

## Source notes

- 7-Zip official downloads: <https://www.7-zip.org/download.html>
- 7-Zip official release: <https://github.com/ip7z/7zip/releases>
- Git for Windows official site: <https://gitforwindows.org/>
- Git for Windows official update mechanism: <https://github.com/git-for-windows/build-extra/blob/main/git-extra/git-update-git-for-windows>
- Git for Windows releases: <https://github.com/git-for-windows/git/releases>
- Microsoft Sysmon download page: <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
- Microsoft Sysmon installation and configuration guidance: <https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon>
- Notepad++ official releases: <https://github.com/notepad-plus-plus/notepad-plus-plus/releases>
- Notepad++ official project README and GPG key fingerprint: <https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/README.md>
- Notepad++ public GPG key: <https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/nppGpgPub.asc>
- GitHub documents the release asset `digest` field as a hosting-provided digest: <https://docs.github.com/en/rest/releases/releases>

The Notepad++ signing key fingerprint published by the project is
`14BC E436 2749 B2B5 1F8C 7122 6C42 9F1D 8D84 F46E`. The project has used
GPG signatures for release verification, but signature sidecar availability
must be checked on the specific release rather than assumed. RIDE currently
records available checksum and signature sidecar URLs; it does not yet verify
detached signatures.

## Next research

1. Windows inspection completed for all package artifacts in this matrix.
   7-Zip and ShareX are unsigned and remain eligible under the recorded
   decision; Sysmon's executable and the other installers report valid
   signatures. Compare signed publishers' certificate identities and rotation
   expectations with official material before turning those observations into
   an enforcement policy.
2. Git's release-note checksum and the exact Mozilla/PuTTY SHA-256 sum entries
   are implemented and matched. Other publisher sidecar parsing and detached
   GPG verification remain open, including trusted
   key acquisition, expiration/revocation and mismatch tests.
3. Sysmon executable signer collection is completed. Microsoft Windows Publisher
   is the observed subject, with Microsoft Corporation organization and Windows
   Production PCA 2023 issuer. Establish accepted identities and rotation rules
   before turning observations into enforcement. The ZIP's `UnknownError`
   signature result does not describe the contained executable.
4. Obtain at least two demonstrably independently routed observations for the
   same immutable artifact. Repeated direct downloads and cache reads do not
   satisfy this requirement.
5. Recheck provider behavior when adapters/artifacts change. The agreed workflow
   is evidence-first; a future mandatory authenticity gate needs an explicit
   missing-evidence policy, accepted identities, rotation and recovery decision.
6. Add metadata-only fallback collection for cache sidecars if a VM cannot write
   its shared library. Current VM collection exports the library; the local
   sidecar survives a shared-write warning only until checkpoint reset. Preserve
   it manually before reset when investigating that failure mode.

## Retention and use workflow

Every acquisition has a new `ObservationId`, UTC time, package/artifact ID,
version, architecture, filename, product origin, resolved source/release URIs,
route, SHA-256 and size. `AcquisitionKind` distinguishes `Download` from `Cache`.
Records retain provider digest, publisher checksum/source/result, available
checksum/signature URLs, file/product versions, Authenticode status, subject,
issuer, certificate thumbprint and timestamp certificate details. New VM
observations also include the correlated `RunId`.

Sysmon `Contents` records `ArchivePath=Sysmon64.exe`, member SHA-256,
`ParentSha256` and executable signature/version evidence. ZIP and executable
hashes remain separate; XML has its own observation. Inspection never executes
a file; installation goes through the separate engine lifecycle.

1. Resolve the official source to an exact versioned artifact or immutable file
   revision. Retain bytes in the local version cache.
2. Check any supplied provider digest and supported publisher checksum before
   installation. Mismatch stops execution; failure logs and retained cache
   support investigation. Missing evidence is unavailable, not verified.
3. Write an observation and `.ride.json` sidecar alongside the artifact. The
   shared library uses an exclusive lock and atomic replacement. On shared-write
   failure, retain the sidecar and report a warning.
4. VM requests export metadata to `guest/artifact-observations.json` before
   checkpoint restore. Host results retain transcripts, source hashes, Pester
   output and state. Installer caches are excluded and vanish on checkpoint reset.
5. Review source/version/hash, signer status, archive linkage and request outcome,
   then merge metadata using the importer. A failed installation can still supply
   acquisition evidence; it does not establish lifecycle acceptance.

```powershell
.\tools\Import-RideArtifactObservations.ps1 `
    -Path 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results\<run-id>\guest\artifact-observations.json' `
    -WhatIf
# After review, repeat without -WhatIf.
```

The importer preserves existing observations, ignores identical repeated IDs
and rejects conflicting IDs or member/parent mismatch. Older schema-1 records
are preserved; records without acquisition IDs are not invented as new events.
Binaries, credentials, notebooks and tool configuration are not stored in this
version-controlled metadata library.

Compare exact version/source and content hash. A cache read is not an independent
download; repeated direct acquisitions from the same host/provider are not
independently routed evidence. Mutable Sysmon URLs require comparison of time,
archive/member versions and both hashes. Never silently replace old observations
when source bytes change.

### Reviewed Windows observations

Runs `a2a2539763bf43e4a2981404d33a39e2` and
`d1ce1d8e371241699e5d9d1d88f98c7c`, followed by passing full request
`9744844940fd4ca498ef6486092ac831`, supplied matching direct-route acquisitions.
The final request passed 128 guest tests and integration. The library now holds
30 observations; repeat imports add zero duplicates. Full records are in
`catalog/artifact-observations.json`.

| Artifact | SHA-256 | Observed Authenticode certificate thumbprint |
| --- | --- | --- |
| 7-Zip 26.04 x64 | `d54bf805f9f3704d1e8db2fa3498ae7ef2df0312b40b558e7c71c734430a665d` | None (`NotSigned`) |
| Notepad++ 8.9.8.1 x64 | `26f3bcced788fadbac4e7e577b430ea2ce6060cf3bcad993ef4612ecd7d743da` | `1E8E0D13B608BA908572C1A129FAEC5D228DF8A2` |
| Git 2.56.0.windows.2 x64 | `52188f917b378f00c70ec136bcf090005f30d44fbc4eba0bce759cc6592d60f6` | `C4BA1DE1C1B6049CF0E3FB393640685052199AEB` |
| Git LFS 3.8.0 | `aa2d69214905d6b348f1b038beb2d68e4828342f9b3fe47dae5a5f023823fe92` | `5F69F3A04D6E13E9C1C5AA26C69A7FD2878A9936` |
| Joplin 3.7.21 | `4222536c69360a30a566627b35c2e1cd8d38d0c79735ebde4e39edbcddd750cd` | `AF0C1B9451567F9AF077DD0646D2927153B05DAF` |
| ShareX 21.0.0 x64 | `f213aca04d30e0e2dc7c43bc79acae8622be291cee6014a90962ed87ea5f10cc` | None (`NotSigned`) |
| WinDirStat 2.9.2 x64 | `21fb47b7262bcd094506a14977de8db54264bd7a93db9ad2863f1eed206ba2a3` | `82802376D2DD840614CC00C6EC8AD763CEA6D33C` |
| PowerShell 7.6.6 x64 | `958838ff55091e1c8705d89efed0cc7e8245a3a6ef6c0ccfae20015227108ad8` | `AB172913A2960A224809EE8A0C371CD47A079B72` |
| Sysmon 15.22 ZIP | `00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54` | No executable-signature interpretation |
| Sysmon64.exe 15.22, inside that ZIP | `83d31f2478dc6716cfdbf69e5c384bf043072b5f0d8d7b2eea365f709fda4352` | `CDCC1456D261BC0EB00975F46DFFB2E24592EDAD` |

Thumbprints identify observed certificates; they are not permanent trust roots
or automatic approvals. Reassess rotations through the publisher.

Additional official references: [Git's exact release/checksums](https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.2),
[Git LFS releases](https://github.com/git-lfs/git-lfs/releases),
[Git LFS installer dependency behavior](https://github.com/git-lfs/git-lfs/blob/v3.8.0/script/windows-installer/inno-setup-git-lfs-installer.iss),
[Joplin releases](https://github.com/laurent22/joplin/releases),
[ShareX releases](https://github.com/ShareX/ShareX/releases),
[WinDirStat releases](https://github.com/windirstat/windirstat/releases), and
[PowerShell releases](https://github.com/PowerShell/PowerShell/releases).

Sysmon is deliberately called out separately from ordinary EXE packages:
Microsoft documents `sysmon64 -i`, `sysmon64 -c`, and `sysmon64 -u`; the
download is an archive whose contained executable installs a service and
driver. The active legacy selectors also fetch separate community XML files
from mutable branch URLs. The user selected a separate download-only XML
artifact that is applied only when explicitly chosen; Sysmon installation must
not pick a community configuration implicitly. Keep the binary and XML as
separate artifact observations, and treat configuration updates as potentially
behavior-changing policy inputs. The Microsoft page currently identifies
Sysmon v15.22 (published 2026-09-10), but its download path is mutable.
[Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
also lists Windows 11 and Windows Server 2019+ as supported by Sysmon.

### Independent Sysinternals products, 2026-10-17

Process Explorer 17.2, Autoruns 14.3 and TCPView 4.19 have individually pinned official
archives, complete member inventories and fifteen observed Valid Microsoft executable
signatures. Twenty-four inert lifecycle/acquisition checks passed per PowerShell
edition; native file/tool/driver/UI/architecture acceptance remains pending. See the
[application record](migrations/application-migration-review.md#b11-independent-sysinternals-products-2026-10-17).

### Sysinternals diagnostic/imaging candidates, 2026-10-17

Process Monitor 4.12, RAMMap 1.63 and Disk2vhd 2.02 have pinned complete official archives and nine observed Valid Microsoft executable signatures. Another 24 inert tests passed per edition (48 distinct across all six products); native driver, tracing, memory and imaging behavior remains unaccepted. See the [record](migrations/application-migration-review.md#b11-sysinternals-diagnostic-and-imaging-candidates-2026-10-17).

### Sysinternals command-line candidates, 2026-10-17

Sigcheck 2.93, Strings 2.54 and Handle 5.0 have three complete pinned official archives, twelve files and nine observed Valid Microsoft signatures. Another 24 inert checks passed per edition, giving 72 distinct cases across nine individual products. Native tool/driver/use acceptance remains pending; see the [record](migrations/application-migration-review.md#b11-sysinternals-command-line-candidates-2026-10-17).

RawCopy 1.0.0.22 real-artifact lifecycle, 2026-10-25: the pinned official source ZIP passed two local installs, selected-member checks, snapshot restore and final removal. Only RawCopy64.exe and its three retained notices were staged; x86 and AutoIt source were excluded. The utility did not run and no evidence/system data was accessed. Windows 11 VM and synthetic NTFS behavior acceptance remain pending. See the [structured evidence](archive/evidence/rawcopy-real-artifact-local-lifecycle-2026-10-25-1131.json).

RawCopy synthetic acceptance runner prepared, 2026-10-26: [Invoke-RideRawCopySyntheticAcceptance.ps1](../tests/integration/Invoke-RideRawCopySyntheticAcceptance.ps1) verifies the pinned executable digest and permits only one generated synthetic file to be read and copied. TCP sending, directory listing and volume metadata output are explicitly disabled. The runner checks exact output bytes and source preservation, and records JSON evidence without promoting package support. Its PowerShell syntax and repository validation passed (417 operations, 8 groups, 5 profiles, 280 PowerShell files). It has not run because registered VM/CIM access remains blocked before inspection and task dispatch.

RawCopy current-source real-archive regression, 2026-10-27: the retained official ZIP passed one focused current-source lifecycle case at the exact catalog pin. Only RawCopy64.exe and three upstream notices were staged; x86 and AutoIt source were excluded, and snapshot recovery preserved an operator note. No utility ran. Repository validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell files. Fresh VM/task inspection failed at CIM; native current-source lifecycle and the synthetic-only NTFS check remain pending. See [structured evidence](archive/evidence/rawcopy-current-source-real-archive-lifecycle-and-vm-access-2026-10-27-0911.json).


WFN Nightly 20250719-ac02df real-artifact local lifecycle, 2026-10-25: the pinned 118,745,388-byte official archive (SHA-256 `B7ECEA5A7C1CAC4DBB845522AFCF49BBB7D7EFA01D3A8266033D11CA88678378`) passed repeat install, ownership verification of all 531 members, snapshot capture, uninstall, exact restore and final removal. Both license notices were retained. WFN was not launched and firewall configuration did not change. Windows 11 VM staging and WFN behavior acceptance remain pending. See the [structured evidence](archive/evidence/wfn-nightly-real-artifact-local-lifecycle-2026-10-25-1153.json).

### Current-source Sysinternals inert lifecycle regression, 2026-10-26

The focused current-source batch passed **104/104** Pester tests on Windows PowerShell 7.6.5/Pester 5.7.1: 72 independent-product lifecycle/acquisition checks, 8 whole-Suite lifecycle checks, and 24 license-planning checks. All ten prior-v2-approved package plans remain available without a license gate. Tests used inert synthetic archives and did not launch a Sysinternals utility or installer. The 164-member Suite lifecycle case took 200.77 seconds; Windows behavior and target acceptance remain separate and pending VM/controller access. See [structured evidence](archive/evidence/sysinternals-104-case-current-source-regression-2026-10-26-0718.json) and the [migration record](migrations/application-migration-review.md#sysinternals-independent-product-local-lifecycle-regression-2026-10-26-0718).

Cookie Cruncher 2.0.0.1 current-source real-archive lifecycle, 2026-10-27: the exact retained archive passed four focused tests, including staging only the three catalog-declared files, repeating installation, and restoring saved state with operator output preserved. The GUI was not launched and browser/cookie data was not accessed. The NeedsReview/Unassigned marker is administrative; the bundled notice permits redistribution and no license gate applies. Windows runtime/GUI acceptance remains pending. See [structured evidence](archive/evidence/cookie-cruncher-current-source-real-archive-lifecycle-2026-10-27-0823.json).

WFN Nightly current-source archive check, 2026-10-27: the retained archive matched the exact catalog SHA-256 and all 531 declared members; the focused Pester case passed 1/1. Repository validation passed. A full synthetic lifecycle rerun was stopped after exceeding the interactive run window and is not counted as a result. Windows 11 lifecycle and current-source synthetic acceptance remain pending; WFN was not launched and firewall/Defender state did not change. See the [structured evidence](archive/evidence/wfn-pinned-archive-current-source-inventory-2026-10-27-0849.json).

HashCheck Shell Extension 2.6.3 source acquisition, 2026-10-27: the official publisher URL retry failed before transfer because local DNS could not resolve the host. No partial payload was created; official digest remains unverified against local bytes, Authenticode and RIDE lifecycle remain open. BSD-3-Clause / NeedsReview status is not a migration gate. See [structured evidence](archive/evidence/hashcheck-publisher-acquisition-dns-block-2026-10-27-0858.json).

### Current Sysinternals catalog and licensing disposition, 2026-10-27

A current-source audit confirms that all ten exact-version Sysinternals package operations are supported on Windows 11 and have local Reviewed status. The Windows 11 package lifecycle passed for the suite and nine individual products without executing any utility. Prior RIDE v2 specialist approval covers RIDE's direct download-and-install workflow; RIDE does not transfer or publish copies. Licensing is settled and must not block migration. Defender-blocked utilities remain separate security exclusions. See [structured evidence](archive/evidence/sysinternals-current-catalog-and-license-disposition-audit-2026-10-27-0949.json) and the [settled disposition](package-licensing.md#sysinternals-settled-ride-v2-approval).
## NTCore portable package candidates, 2026-10-27 14:25 UTC

The focused retained-archive suite now covers .NET Generic Unpacker and
DynLogger x86/x64, SNSRemover x86, and NoDel x86 stage-only candidates. It passed
**12/12** on Windows PowerShell 5.1.26100.9711 and **12/12** on PowerShell
7.6.5. Tests verified exact archive hashes and inventories, selected files,
repeat staging, uninstall, saved-state recovery and operator-file preservation.
They did not run a utility, modify an assembly, load a driver, create a service,
or inspect a target process. The nested PE Detective archive is excluded from
SNSRemover; NoDel source/project files are excluded. Windows 11 remains a
candidate target with `SupportedTargets` empty.

Catalog.Tests.ps1 plus LicenseReviews.Tests.ps1 passed 118/119 discovered
tests; one registry-only WindowsIntegration case was excluded due sandbox
registry denial. Repository validation passed for 436 operations, 8 groups, 5
profiles and 297 PowerShell files, and generated operation documentation is
current. The 42 pending package operations have 51 exact version/variant
selections, all matched by informational NeedsReview markers. No license gate
blocks migration. See [NoDel evidence](archive/evidence/ntcore-nodel-portable-candidate-regression-2026-10-27-1425.json),
[SNSRemover evidence](archive/evidence/ntcore-snsremover-portable-candidate-regression-2026-10-27-1415.json),
[marker audit](archive/evidence/pending-package-license-marker-audit-2026-10-27-1425.json),
and [Unpacker/DynLogger evidence](archive/evidence/ntcore-unpacker-dynlogger-portable-candidate-regression-2026-10-27-1410.json).
## Wireshark 4.6.9 retained MSI hash recheck, 2026-10-28 12:04 UTC

The retained 80,433,152-byte x64 MSI still matches its catalog sidecar and the
publisher's [SIGNATURES-4.6.9.txt](https://www.wireshark.org/download/SIGNATURES-4.6.9.txt)
checksum entry. Its SHA-256 is unchanged from the exact bytes with prior Valid
Authenticode evidence. The publisher checksum file is PGP-signed; the official
[download page](https://www.wireshark.org/download.html) identifies key
`0xE6FEAEEA`.
This shell has no GPG/OpenPGP verifier, so this recheck did not verify that PGP
signature. The installer and utility did not run. Windows 11 and Server
lifecycle/recovery remain open pending VM access. No legacy outcome closed and
estimates remain unchanged. See [structured evidence](archive/evidence/wireshark-retained-msi-hash-recheck-and-pgp-tool-availability-2026-10-28-1204.json).


### Raspberry Pi Imager v2.0.12 source review and candidate preparation, 2026-10-28

The publisher release pins the Windows x64 installer to SHA-256
`98bff90afe23339d0768915f6f68d35ac254740ec1eac2082ebeaa9ba41bc8e3`. The
installer source documents machine-scope Inno Setup, a pnputil-staged rpiboot
WinUSB driver and machine file associations. Uninstall removes that driver,
the current user's cached OS image and credential-bearing imagecustomization
registry data. The candidate remains unsupported until disposable Windows 11 install/repeat/uninstall confirms the documented effects and the existing checkpoint is restored. Local NeedsReview/Unassigned status is
administrative, not a license gate; the license file describes Apache 2.0 main
source and separate third-party terms. Repository validation passed; the
focused Pester 5 suite was not run because only Pester 3.4.0 is installed. No
payload was acquired or executed. See [structured evidence](archive/evidence/raspberry-pi-imager-v2.0.12-package-candidate-source-review-2026-10-28-1219.json).
### Raspberry Pi Imager lifecycle acceptance boundary, 2026-10-28

The publisher's driver and user-data cleanup are normal install/uninstall
behavior, not a RIDE preservation requirement. The `Compensating` package
lifecycle may be activated only after disposable Windows 11 install/repeat/
uninstall verifies those effects and the existing checkpoint is restored.
Current host CIM/controller access blocks inspection and dispatch; Pester 5 is
unavailable. No installer or image writer ran. See [scope reconciliation](archive/evidence/raspberry-pi-imager-package-lifecycle-scope-reconciliation-2026-10-28-1222.json).
### RIDE-Win11-Test access recheck, 2026-10-28 12:26 UTC

`Get-VM -Name RIDE-Win11-Test` failed at host CIM before checkpoint inspection;
no runner was dispatched. Raspberry Pi Imager install/repeat/uninstall and VM
checkpoint recovery remain pending. See [structured evidence](archive/evidence/ride-win11-test-cim-access-recheck-and-imager-acceptance-block-2026-10-28-1226.json).
## NirSoft PasswordScan Defender block alert, 2026-10-28 13:14 UTC

The user reports a Defender block for `NirSoft/x64/passwordscan.exe` at the same encrypted-launcher filtered-Pester temporary-stage path seen in prior alerts. The detection name, event time and creating-run identity are unknown. Keep both PasswordScan architectures excluded; do not inspect or execute the file or change Defender. Retained NirLauncher archive lifecycle remains deferred pending stage provenance and catalog-revision reconciliation. No legacy outcome closed and estimates are unchanged. See [alert evidence](archive/evidence/nirsoft-passwordscan-defender-alert-2026-10-28-1314.json).
## Current package license-review coverage, 2026-10-28 22:57 UTC

Read-only comparison of the authoritative parsed catalog and `.local/license-reviews.json` found exact operation-ID/version owner-review markers for all 49/49 packages pending acceptance (90 total review records; zero missing). The ten Sysinternals records remain `Reviewed` under the prior RIDE v2 specialist approval; RIDE's direct download-and-install use has no licensing gate. No metadata, package, installer, Windows or Defender state changed. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/package-license-review-current-catalog-coverage-2026-10-28-2257.json).
## steghide 0.5.1 current publisher route and access recheck, 2026-10-28 23:00 UTC

The official [download page](https://steghide.sourceforge.net/download.php) still lists 0.5.1 and links `steghide-0.5.1-win32.zip` on SourceForge. The web reader followed the publisher link to a SourceForge mirror but could not access it; a local metadata-only DNS preflight returned `Access is denied` for both publisher-linked hosts. No archive bytes, hash, member inventory, catalog candidate or utility execution. Keep it selected and optional; GPL review metadata is administrative, not a migration gate. Archive acquisition and Windows acceptance remain open; no legacy outcome closed and estimates are unchanged. See [structured evidence](archive/evidence/steghide-0.5.1-current-publisher-route-and-access-block-2026-10-28-2300.json).
## BloodHound AzureHound retained 3.1.2 archive integrity and selected-version reconciliation, 2026-10-28 23:04 UTC

The retained AzureHound 3.1.2 x64 ZIP in `.local/b08-azurehound` is 5,363,432 bytes and matches the official GitHub release SHA-256. Its only member, `azurehound.exe`, also matches the retained standalone executable; README, LICENSE and NOTICE are present. Neither binary ran. The selected BloodHound CE 9.8.0 collector remains AzureHound 3.1.1 plus SharpHound 2.17.0; the available 3.1.2 archive cannot substitute for that pin, and the official release list now shows 3.1.3. No catalog candidate added. Collector/backend compatibility remains tied to the selected pair; license status is non-gating. No legacy outcome closed; estimates unchanged. See [structured evidence](archive/evidence/bloodhound-azurehound-v3.1.2-retained-archive-integrity-and-version-mismatch-2026-10-28-2304.json), [CE 9.8.0 Dockerfile](https://raw.githubusercontent.com/SpecterOps/BloodHound/v9.8.0/dockerfiles/bloodhound.Dockerfile), and [AzureHound releases](https://github.com/SpecterOps/AzureHound/releases).
