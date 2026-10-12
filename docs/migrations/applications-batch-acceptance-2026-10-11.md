# Application batch acceptance, 2026-10-11

All four installed products and nine portable outcomes are accepted on Windows
11 and Windows Server 2025 Desktop Experience. ShareX keeps its previously published
installed default. Recommended profiles are unchanged.

## Product lifecycle evidence

| Batch | Product / variant | Windows 11 | Server 2025 | Recovery | Applicability |
| --- | --- | --- | --- | --- | --- |
| 1 | Visual Studio Code / installed | Passed | Passed | Passed | Desktop Experience required |
| 1 | Firefox / installed | Passed | Passed | Passed | Desktop Experience required |
| 1 | DB Browser for SQLite / installed | Passed | Passed | Passed | Desktop Experience required |
| 1 | Autopsy / installed | Passed | Passed | Passed | Desktop Experience required |
| 2 | Chainsaw / portable | Passed | Passed | Passed | File deployment; executable and LICENCE retained |
| 2 | Hindsight / portable | Passed | Passed | Passed | Legacy GUI retained; Desktop Experience required |
| 2 | CyberChef / portable | Passed | Passed | Passed | HTML/assets; browser execution separate |
| 2 | PuTTY / portable | Passed | Passed | Passed | Desktop Experience required |
| 2 | ShareX / portable | Passed | Passed | Passed | Desktop Experience required |
| 2 | SRUM Dump / portable | Passed | Passed | Passed | File deployment; legacy folder mismatch reconciled |
| 2 | SrumMonkey / portable | Passed | Passed | Passed | File deployment; collector execution separate |
| 2 | dejsonlz4 / portable | Passed | Passed | Passed | Legacy x86 distribution retained |
| 2 | CyLR / portable | Passed | Passed | Passed | Legacy x86 distribution retained; collection separate |

Passing file lifecycle scenarios do not establish parsing quality, application
UI behavior, collection results, service/driver behavior or application-data
backup. No application migration adds Defender exclusions.

## Native verification

Full regression before the final focused corrections: Windows PowerShell 5.1
passed 1,063 tests, zero failed, one
`WindowsIntegration` test excluded from the developer workstation (1,064 total).
PowerShell 7 full regression: 1,066 passed, zero failed, one excluded (1,067 total).
Focused checks after portable acceptance on both runtimes passed 234 tests with
zero failures and one excluded (235 total), including saved target/edition recovery, user scope,
interrupted portable restore and publisher checksum/signature evidence.
The excluded registry integration scenario runs only in the
disposable guests. Parser/catalog/profile validation and generated-reference
verification passed for 282 operations, two groups, four profiles and 85
maintained PowerShell files.

The final application-only checks passed all 57 tests on both runtimes,
including rejection of unsafe publisher version strings before acquisition.
After the Firefox removal correction, all 75 application/acquisition tests
passed on both runtimes, including native MSI command validation, wrapper EXE
removal and catalog validation of the override.
Final regression with accepted catalog metadata passed 237 tests on each
runtime, zero failed, one workstation integration test excluded (238 total).
Both final parser/catalog/profile and generated-document checks also passed.

Download-only smoke checks retained Firefox 157.0.1 and PuTTY 0.85 in the private
workspace evidence cache. Both matched their official SHA-256 values and both
reported valid Authenticode signatures. Firefox:
`19a7e33aaa79b4711c566c53ebf5779fb79efe1ec8adccff2c5cb659aa7fa8ec`;
PuTTY: `d01fdb5aae8f112526040a39b0bfb9e27d813003178645e65f8d1cfdb2a26c87`.
Detached signatures are recorded references, not a claim of GPG verification.
These acquisition observations do not establish VM installation acceptance.

## Correlated disposable-VM runs

| Target | Suite / source | Run ID |
| --- | --- | --- |
| Windows 11 | Batch 1 / initial full regression snapshot | `ffe19cde1ee34830b7084fe7e6266d5e` |
| Server 2025 | Batch 1 / initial full regression snapshot | `5d7f7a29630c4d009c6d2a93efee024a` |
| Windows 11 | Batch 2 / final focused snapshot | `b0f6896798c444e399951c9558118487` |
| Server 2025 | Batch 2 / final focused snapshot | `49d5a0c8ed6e4ed9830099c8d70a6dad` |
| Windows 11 | Batch 1 / focused snapshot before Firefox removal correction | `bfe6aad2c8c2437397219be2629f476b` |
| Server 2025 | Batch 1 / focused snapshot before Firefox removal correction | `f9ef7d7d2ed4428db06a4d6abdb42b8d` |
| Windows 11 | Batch 1 / Firefox removal correction | `068c9939123744c2af0d52f5d1671bad` |
| Server 2025 | Batch 1 / Firefox removal correction | `de3eb5b57af348fa9d88411e7801e787` |

Controller results live under
`C:\ProgramData\RIDE\TestAutomation\<controller>\results\<run-id>`.
Each completed result must correlate its guest summary, Pester XML, application
scenario JSON, acquisition observations and captured state. The controller
collects evidence before restoring the pinned checkpoint and turning the VM
off. Batch 2 completed with no collection or cleanup errors on both targets;
corrected batch 1 also completed with successful evidence export, checkpoint
recovery and VM shutdown on both targets.

The initial batch 1 runs timed out at 90 minutes on both targets. Partial evidence
collection also timed out at 60 seconds, so no guest acceptance is inferred.
Both controllers completed checkpoint recovery without a cleanup error and
recorded unchanged host UAC settings. Both corrected batch 2 runs passed all
nine deployment lifecycle scenarios and all 207 guest Pester checks. Server
completion was 02:51 and Windows 11 completion was 02:53 Europe/Copenhagen.
Evidence and captured state were exported before successful checkpoint recovery
and VM shutdown. Host UAC settings remained unchanged. Corrected focused batch 1
runs passed all four lifecycle scenarios and all 211 guest Pester checks per
target; host UAC settings remained unchanged.

The first focused batch 1 runs passed 208 Pester checks per guest and the VS Code,
DB Browser for SQLite and Autopsy lifecycles. Firefox installation passed, but
removal incorrectly required msiexec although Mozilla registers an EXE
uninstaller. Collected results report the exact failure; both controllers
completed checkpoint recovery and shutdown without collection/cleanup errors.
Firefox now declares `UninstallerType = 'Exe'` and retains `/S`, consistent with
[Mozilla's documented silent removal](https://support.mozilla.org/en-US/kb/silently-install-uninstall-firefox-enterprise).
The corrected runs above passed, including Firefox removal and restoration of
original absence; all four installed outcomes now declare both tested targets.

The actual Windows 11 guest was Enterprise Evaluation, build 26300, running
Windows PowerShell 5.1.26100.9444. The actual Server guest was Windows Server 2025
Standard Evaluation, build 26100, with Desktop Experience (`InstallationType =
Server`), running Windows PowerShell 5.1.26100.33438. Server Core was not tested.

Pinned VM identities: `RIDE-Win11-Test`, VM
`6a5c9f91-91f9-44c5-924a-d1b5f863e16f`, checkpoint
`a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9`; `RIDE-S25-Test`, VM
`06c2ae01-bf82-4634-9215-f240f3ea4147`, checkpoint
`4a5b49ba-0795-480a-8d01-6f4f670577c8`. Both protected controllers were registered
successfully before dispatch. Their installed staging code predates the new
`.local` exclusion; large task-owned private samples and baseline copies were
placed under the already excluded `results` directory. Refreshing protected
controller files requires an elevated process and idle controllers.

## Remaining decisions and estimates

The [individual review ledger](application-migration-review.md) accounts for
175 selector names and 109 outcomes/components: 45 in batch 1 and 64 in batch 2.
The ledger contains ten earlier migrations, thirteen newly accepted
installed/portable outcomes and 86 individual review items.
Unresolved editions, licensed/interactive downloads, dynamic repositories,
driver workflows and obsolete dependencies remain individual review items.
No HTTP 404 observation alone establishes retirement.

Batch 2 acceptance resolves nine product/distribution outcomes. Batch 1 acceptance
resolves four further product outcomes. Packages/artifacts now have approximately
65-80 remaining items; the rounded total is 160-215, about 190. See
[MIGRATION-PLAN](../MIGRATION-PLAN.md#estimated-remaining-migration-work).

Accepted batch 2 versions: package.sharex 21.0.0; package.chainsaw 2.16.5; package.hindsight 2026.06; package.cyberchef 11.5.0; package.putty 0.85; package.srum-dump 3.2; package.srum-monkey 1.0.0; package.dejsonlz4 1.1; package.cylr 2.2.0.

Accepted batch 1 versions: package.vscode 1.141.0; package.firefox 157.0.1; package.sqlitebrowser 3.13.1; package.autopsy 4.23.1.

Final batch 1 controller completion was 03:15:47 for Server and 03:19:36 for
Windows 11, Europe/Copenhagen. All thirteen new distributions now declare both
tested targets. The shared observation library retained its existing records
and imported 26 new correlated acquisitions: eighteen portable and eight
installed observations across the two guests.
Both scheduled controllers reported `Ready` after completion. Existing
profiles and unrelated baseline files remained byte-for-byte unchanged.

Operational follow-up: refresh both protected controllers from the source when
idle in an elevated Windows session. The unattended session could not satisfy
the operating system UAC consent requirement. Existing approved controllers
completed both application suites; their older staging filter excluded task-owned
large files under `results`. The source now also excludes `.local`.
