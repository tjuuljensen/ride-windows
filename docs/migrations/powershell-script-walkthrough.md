# PowerShell script walkthrough - 8 October 2026

## Outcome and scope

The one-time walkthrough scheduled for 13:00 Europe/Copenhagen reviewed all
42 repository `.ps1`, `.psm1`, and `.psd1` files present at its start, including
untracked integration work, development helpers, and `legacy/v2`.
38 files received maintained help or data-file ownership comments. Four
upstream/historical files remain byte-identical, with exceptions below.

Native comment-based help now covers 23 maintained script/test entry points
and all 59 exported commands in the ten maintained modules. The 21 standalone
scripts have safe `-Version` exits; 13 gained that interface and eight retained
their existing version interface. Existing runner and SSH quick help was
retained and updated. Pester fixtures and data files have no invented CLI.

Repository models belong in [docs/models](../models/script-repository-model.md).
`docs/repository-portfolio` is reserved for network-devices governance. The
authoritative shared script and documentation models were read from the local
network-devices checkout; their earlier corrections establish the same
directory and native PowerShell help conventions.

## Review method and preservation

The checkout is on the Windows filesystem. `AGENTS.md`, the local script model,
Git status, `.gitattributes`, and `git ls-files --eol` were inspected before
rewriting. The checkout already contained substantial tracked and untracked
work. Its exact file contents and status were captured as this walkthrough's
baseline; comparisons used that baseline, rather than attributing every
HEAD difference to this work. Nothing was committed, deployed, or reset.

Maintained implementations were inspected for declared parameters/defaults,
examples, dependencies, import-time behavior, pipeline inputs/outputs, host and
file inputs, side effects, recovery, support declarations, and provenance.
Historical files were classified from their source and architecture; the large
v2 library was not subjected to a new function-by-function support audit.

Headers use `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.INPUTS`,
`.OUTPUTS`, `.NOTES`, and `.LINK` where applicable. Function help describes
direct handler calls as internal: those calls bypass the engine's preview and
snapshot boundaries. No license notice or embedded upstream attribution was
removed. Headers distinguish declared compatibility from integration evidence.

The executable-token comparison passed for every inventoried file after
accounting for these explicit changes:

- Added help/version parameters, version constants, early exits, and
  `CmdletBinding` on older standalone helpers. These exits precede Windows,
  network, console, COM, profile, installer, or provisioning work.
- Moved caffeine's misplaced `param($sleep = 120)` declaration to the top-level
  parameter block. Its positive integer interval is now validated in the range
  1-2147483647; its keep-awake loop is unchanged. The former declaration followed
  executable console/COM code and was not a valid script parameter block.
- Added `WindowsIntegration` to the existing live-registry Pester test. Its
  assertions and implementation are unchanged. Workstation test guidance now
  excludes it and disables Pester's unused automatic registry fixture.
- Added version lines to the runner and SSH manual usage strings; corrected
  stale explanatory comments and development documentation.

New `0.1.0` versions identify the first recorded versioned help contract, not a
reconstructed release history. Existing module/integration versions and known
history are retained. Clean-Disk's recorded `1.0` and SSH copy-id's `1.0.3`
advance to `1.1.0` for their added CLI contract. Known author names are retained;
first-party maintenance ownership does not assert authorship of adapted code.

Original file encoding/BOM and body line endings were preserved. Repository
attributes require CRLF for `default.cmd`, which this walkthrough did not edit.
Other sources include LF, CRLF, and an existing mixed-ending deployment helper.
No global Git setting or broad normalization was applied.

## Per-file disposition

Validation abbreviations: **P** = native parsers passed in Windows PowerShell
5.1 and PowerShell 7; **H** = native script or exported-command help inspected;
**V** = safe version exit checked in both engines; **Q** = new/retained quick
help exit checked for the 13 updated CLI entry points; **D** = data-file import
passed in both engines. Runtime state-changing behavior was not exercised.

| File | Disposition and verified contract | Version; checks | Exception or remaining work |
| --- | --- | --- | --- |
| [ride.ps1](../../ride.ps1) | Native command/parameter help, planning/recovery limits, manual usage and early version exit. | 0.1.0; P H V Q | Windows support remains per catalog operation; exact prior package version recovery is not guaranteed. |
| [docs/bootstrap.ps1](../bootstrap.ps1) | Archive selectors, explicit run selection, download-only/elevation behavior, extraction and recovery documented. | 0.1.0; P H V Q | Child-process argument handling, mutable default branch, integrity, extraction overwrite, and absent preview need a separate tested correction. |
| [tools/Export-RideCatalog.ps1](../../tools/Export-RideCatalog.ps1) | Generator inputs/output, Check mode, native help and early exits. | 0.1.0; P H V Q | Generated OPERATIONS content remains unchanged and current. |
| [tools/validate.ps1](../../tools/validate.ps1) | Read-only catalog/profile/parser/generated-document checks, root default, early exits. | 0.1.0; P H V Q | Static checks do not establish Windows integration support. |
| [tools/Deploy-SSHCopyId.ps1](../../tools/Deploy-SSHCopyId.ps1) | Local destination/backup/overwrite behavior, native help and early exits. | 0.1.0; P H V Q | Existing mixed line endings retained; operational writes not run. |
| [components/scripts/ssh-copy-id.ps1](../../components/scripts/ssh-copy-id.ps1) | Key selection, port/defaults, POSIX remote dependency, DryRun/WhatIf and recovery documented. | 1.1.0; P H V Q | Remote authorization changes not executed; prior 1.0.3 and Torsten Juul-Jensen attribution retained. |
| [components/scripts/Clean-Disk.ps1](../../components/scripts/Clean-Disk.ps1) | Native help/version entry points before self-elevation; deletion/service/cleanmgr effects explicit. | 1.1.0; P H V Q | Historical operational code lacks preview, exact rollback, guaranteed cleanup, and consistent terminating errors. VM-only; prior 1.0/date/author retained. |
| [components/scripts/Create-HyperVDisk.ps1](../../components/scripts/Create-HyperVDisk.ps1) | Path resolution, 1GB default, elevation/Hyper-V, replacement and formatting/output documented. | 0.1.0; P H V Q | Existing-file/replacement branches, non-literal paths, terminating errors and ShouldProcess need VM-tested safety work. |
| [components/scripts/caffeine.ps1](../../components/scripts/caffeine.ps1) | Top-level interval binding fixed; console, COM, Scroll Lock and stop behavior documented. | 0.1.0; P H V Q | Interactive loop not run; RawUI and desktop behavior remain host-dependent. No invented upstream attribution. |
| [components/scripts/Get-WindowsProductKey.ps1](../../components/scripts/Get-WindowsProductKey.ps1) | Decoder/registry inputs and sensitive string output documented; old OS predicate comment corrected. | 0.1.0; P H V Q | Embedded mrpeardotnet/WinProdKeyFinder attribution retained; upstream license and OS-decoder branch require review. Product key was not read. |
| [components/scripts/Write-Profile-File.ps1](../../components/scripts/Write-Profile-File.ps1) | Current-user profile creation/marker append and PATH snippets documented. | 0.1.0; P H V Q | No preview or automatic backup; path and marker correctness/idempotence need isolated profile tests before operational refactoring. |
| [components/scripts/New-IsoFile.ps1](../../components/scripts/New-IsoFile.ps1) | Upstream sourced function; existing native function help and pipeline/COM/C# implementation inspected. | Existing upstream metadata; P | Byte-identical exception. Chris Wu, 2016-03-23 retained. No standalone CLI version. Source license, example typo (`c:Downloads`), and runtime compatibility remain unverified. |
| [components/wallpaper/make-wallpaper-files.ps1](../../components/wallpaper/make-wallpaper-files.ps1) | Input default, ImageMagick/System.Drawing, orientation-dependent resize bounds and output files documented. | 0.1.0; P H V Q | No exact crop, native exit-code handling or output overwrite protection; `.\` path prefix and bitmap disposal require focused tests. |
| [tools/development/openssh-preview/Install-OpenSSH.ps1](../../tools/development/openssh-preview/Install-OpenSSH.ps1) | Winget preview installation, client detection and profile modification documented. | 0.1.0; P H V Q | Development-only. No ShouldProcess or automatic profile backup; package exit-code handling and repeatability need isolated review. |
| [modules/RIDE.Engine.psm1](../../modules/RIDE.Engine.psm1) | Overview and all exported discovery/planning/lifecycle/state commands documented. | 0.1.0; P H | Declared target support and restore semantics do not replace disposable-VM evidence. |
| [modules/RIDE-Settings.psm1](../../modules/RIDE-Settings.psm1) | Registry inspect/set/restore commands, value types and missing-value behavior documented. | 0.1.0; P H | Direct writes bypass engine safety; live registry handler execution excluded. |
| [modules/RIDE-Packages.psm1](../../modules/RIDE-Packages.psm1) | Package presence/download/install/remove, artifact observation and return contracts documented. | 0.1.0; P H | Installer/source availability and exact version recovery not validated on this workstation. |
| [modules/RIDE-Services.psm1](../../modules/RIDE-Services.psm1) | Service startup/status capture, desired-state application and restore documented. | 0.1.0; P H | State-changing service calls tested only through mocks. |
| [modules/RIDE-BackgroundApps.psm1](../../modules/RIDE-BackgroundApps.psm1) | Per-app override capture/removal/restore and registry inputs documented. | 0.1.0; P H | Live application registry changes not executed. |
| [modules/RIDE-BootConfiguration.psm1](../../modules/RIDE-BootConfiguration.psm1) | bcdedit inspection, declared boot menu states and restore documented. | 0.1.0; P H | Boot configuration writes not executed; isolated tests mock bcdedit. |
| [modules/RIDE-Defender.psm1](../../modules/RIDE-Defender.psm1) | Path resolver, exclusion inspection/set/restore and output contracts documented. | 0.1.0; P H | Defender changes mocked; no workstation exclusions added. |
| [modules/RIDE-NetworkProfiles.psm1](../../modules/RIDE-NetworkProfiles.psm1) | Identity/category capture, domain exclusion, per-profile restore and partial failure documented. | Existing 0.1.0; P H | Pre-existing untracked implementation preserved; live category updates mocked. |
| [modules/RIDE-RegistryKeySet.psm1](../../modules/RIDE-RegistryKeySet.psm1) | Registry-tree values/types/ACL capture, deletion and exact restore documented. | Existing 0.1.0; P H | Pre-existing untracked implementation preserved. Real registry subtree test reserved for a disposable VM. |
| [tests/integration/RIDE.TestAutomation.psm1](../../tests/integration/RIDE.TestAutomation.psm1) | Queue/config/staging/controller/evidence/recovery helpers documented individually. | Existing 0.1.2; P H | Retains 0.1.0-0.1.2 history; operational controller requires its documented 64-bit Windows PowerShell host and disposable VM. |
| [tests/integration/Invoke-RideVmTest.ps1](../../tests/integration/Invoke-RideVmTest.ps1) | Transport, VM/snapshot credentials/inputs, staging, preview and evidence contracts documented. | Existing 0.3.0; P H V | Operational VM test runner not invoked; existing version history retained. |
| [tests/integration/Invoke-RideVmSuite.ps1](../../tests/integration/Invoke-RideVmSuite.ps1) | Guest-only integration targets, output and failure/recovery boundaries documented. | Existing 0.3.0; P H V | Must run inside an authorized disposable guest; no system integration executed. |
| [tests/integration/New-RideAutomatedLabVm.ps1](../../tests/integration/New-RideAutomatedLabVm.ps1) | Provisioning/preflight requirements, OS/CPU/memory/security/update parameters documented. | Existing 0.1.0; P H V | GuestRepositoryPath is currently report-only; staging hard-codes C:\RIDE\ride-windows. Do not override until fixed. No VM provisioned. |
| [tests/integration/Register-RideVmTestTask.ps1](../../tests/integration/Register-RideVmTestTask.ps1) | Explicit task registration/removal, configured resources, privilege and preview documented. | Existing 0.1.0; P H V | No scheduled task registered or removed. |
| [tests/integration/Invoke-RideVmTestTask.ps1](../../tests/integration/Invoke-RideVmTestTask.ps1) | Source selection, correlated queue request, timeout and result contracts documented. | Existing 0.1.0; P H V | No request submitted to a live controller. |
| [tests/integration/Invoke-RideVmTestTaskWorker.ps1](../../tests/integration/Invoke-RideVmTestTaskWorker.ps1) | Fixed worker configuration, lock/queue behavior, controller and recovery boundaries documented. | Existing 0.1.0; P H V | Worker not started against a live configuration. |
| [tests/integration/Export-RideVmTestEvidence.ps1](../../tests/integration/Export-RideVmTestEvidence.ps1) | Target transport, run correlation, copying/logging output and prerequisite contracts documented. | Existing 0.1.0; P H V | No remote evidence collection invoked. |
| [tests/integration/Watch-RideVmTests.ps1](../../tests/integration/Watch-RideVmTests.ps1) | Watch filtering, debounce/queue behavior, local source and shutdown documented. | Existing 0.1.0; P H V | No watcher or periodic maintenance started. |
| [tests/Catalog.Tests.ps1](../../tests/Catalog.Tests.ps1) | Fixture purpose/isolation documented; live HKCU test tagged WindowsIntegration. | Repository fixture; P H | No independent version/CLI. One live-registry case excluded locally; remaining catalog/handler tests use mocks or scratch files. |
| [tests/TestAutomation.Tests.ps1](../../tests/TestAutomation.Tests.ps1) | Mocked VM/process/task/queue/recovery coverage and TestDrive use documented. | Repository fixture; P H | No independent version/CLI. VM/process operations remain mocked. |
| [catalog/operations.psd1](../../catalog/operations.psd1) | Concise owner/purpose/source-of-truth comments added. | SchemaVersion 1; P D | Data values and pre-existing catalog edits unchanged; no script help/CLI. |
| [profiles/analyst-basics.psd1](../../profiles/analyst-basics.psd1) | Profile owner/purpose comments added. | SchemaVersion 1; P D | Desired selections unchanged; no script help/CLI. |
| [profiles/baseline.psd1](../../profiles/baseline.psd1) | Baseline selection and restore distinction documented in comments. | SchemaVersion 1; P D | Desired selections unchanged; no script help/CLI. |
| [profiles/default.psd1](../../profiles/default.psd1) | Profile owner/purpose comments added. | SchemaVersion 1; P D | Pre-existing desired selections preserved; no script help/CLI. |
| [tests/integration/automation.example.psd1](../../tests/integration/automation.example.psd1) | Administrative disposable-controller example purpose documented. | SchemaVersion 1; P D | Pre-existing untracked configuration values retained; not installed or run. |
| [legacy/v2/lib-windows.psm1](../../legacy/v2/lib-windows.psm1) | Historical v2 reference, declared old targets, embedded sources and architecture inspected. | Existing v2.6, 2024-02-11; P | Byte-identical historical exception. Torsten Juul-Jensen/source attribution retained. Broad old system behavior and copied-code licenses are not recertified; do not reconnect to the maintained engine. |
| [legacy/v2/modules/RIDE-DomainJoined.psm1](../../legacy/v2/modules/RIDE-DomainJoined.psm1) | Historical WSUS/domain/firewall/Entra-related helpers classified. | No recorded independent version; P | Byte-identical historical exception. Author/license provenance is not established by its banner; review before any extraction or reuse. |
| [legacy/v2/modules/RIDE-Tools.psm1](../../legacy/v2/modules/RIDE-Tools.psm1) | Historical environment/package/export helpers classified. | No recorded independent version; P | Byte-identical historical exception. Author/license provenance is not established; some helpers depend on the old layout. Review before extraction or reuse. |

## Validation results

- Native parser checks passed for all 42 inventoried files under Windows
  PowerShell **5.1.26100.9549** and PowerShell **7.6.5** on Windows.
- `Get-Help -Full` exposed descriptions, examples, notes, and every declared
  parameter for all 23 rewritten `.ps1` files and 59 exported module commands
  in both engines. Module imports were inspected as definition-only and run in
  isolated processes; no exported operational handler was invoked for help.
- All 21 standalone `-Version` calls and the 13 updated quick-help exits passed
  in both engines. All five data files imported successfully. Caffeine's invalid
  interval was rejected before its console/COM loop.
- `tools/validate.ps1` passed: **91 operations, one group, three profiles**;
  generated operation documentation remained current. Its recursive parser
  also encountered the explicitly temporary validation helpers, which were
  removed after use; the repository inventory remains 42 files.
  A final validation after cleanup passed for the 37 script/module files;
  the five data files account for the rest of the inventory.
- Pester **5.7.1**, Windows PowerShell 5.1: **102 passed, zero failed, one not
  run** out of 103 discovered tests. The not-run test is the newly tagged live
  HKCU integration case. Hyper-V, services, Defender, installers, network calls,
  and external controllers were mocked or previewed in the included tests.
- Validation used process-local execution-policy bypass for Windows PowerShell
  scripts only; no user/machine execution-policy setting changed. Initial
  Pester attempts encountered sandbox restrictions on its registry fixture and
  atomic replacement in sandbox temporary storage. Disabling the unused
  registry fixture and placing isolated test scratch under the writable
  checkout resolved those environmental failures.
- Final review checked 93 native-help/Markdown links, with no missing local
  target or malformed source URL. Documentation `git diff --check` passed.
  The complete diff check reports existing body whitespace and CRLF in files
  without text attributes; a baseline comparison confirmed no newly introduced
  trailing whitespace. Native parser/executable-token comparison passed again
  after final edits; the four preserved exceptions are still byte-identical.
  No network source or upstream license was revalidated by these local checks.

## Repository handoff

The durable conventions are owned by `AGENTS.md` and
[`docs/models/script-repository-model.md`](../models/script-repository-model.md).
The [migration plan](../MIGRATION-PLAN.md) links to this record's operational
follow-ups; README owns the workstation test invocation. Keep these instructions
and the per-file dispositions when reviewing the local changes.

Companion shared-policy updates from this work belong in the network-devices
repository: `AGENTS.md`,
`docs/repository-portfolio/repository-documentation-model.md`, and
`docs/repository-portfolio/script-repository-model.md`. They establish the
`docs/models/` default and native PowerShell help convention for the portfolio.
Review those changes with the RIDE-specific implementation to keep both models
consistent.

This work left changes local for review rather than committing or publishing
them. At the archive-preparation review, the RIDE model and this walkthrough
were still untracked and the script changes were uncommitted. Include the new
documents and intentional source changes in a reviewed commit; preserve the
unrelated migration and integration work already present in the checkout.

## Remaining operational work and exceptions

The safe help rewrite is complete; it does not certify the historical helpers
for production use. Follow-up implementation work should be focused and
validated independently:

1. Correct bootstrap child-process argument handling: the current non-elevated
   call passes a joined argument string to the PowerShell executable. Add tests
   for spaces/quoting, tagged download-only selection, preview/application
   boundaries, archive integrity, extraction overwrite, and recovery.
2. Harden VHD existing-file detection/replacement and Clean-Disk's service and
   cleanmgr cleanup paths. Add literal-path validation, preview and clear
   failure handling before VM integration; do not test these on a workstation.
3. Honor GuestRepositoryPath throughout AutomatedLab staging and test a
   nondefault path; the header now discloses the current hard-coded path.
4. Review product-key decoder OS branching and copied-code license provenance.
   Do not collect or log actual product keys to validate documentation.
5. Validate profile marker appends, native image conversion failures/paths,
   and the OpenSSH preview install/profile workflow using isolated fixtures or
   disposable VMs. Existing operational error policies remain a deliberate
   preservation exception in Clean-Disk, Create-HyperVDisk, caffeine,
   Get-WindowsProductKey, Write-Profile-File, and make-wallpaper-files: this
   walkthrough does not enable Stop globally or rewrite their failure flows.
   The catalog generator retains its existing read policy and explicit throws
   in Check mode; .NET output writes already throw on failure.
6. Run the excluded registry-tree integration case and applicable Windows 11 /
   Windows Server 2025 lifecycle scenarios in authorized disposable VMs.
   No new Windows target support is inferred from these parser/help checks.
7. If a consistent text policy is desired, propose a separate focused
   `.gitattributes`/normalization change after reviewing the existing LF/CRLF
   mix. This walkthrough did not alter global EOL settings or rewrite unrelated
   body whitespace.

Upstream and historical exceptions have no invented replacement date. Review
their provenance and compatibility when promoting or adapting them into a
maintained command; keep their current source notices until that review is
complete. No ongoing watcher or recurring maintenance was created by this
one-time walkthrough.
