# Windows VM integration test runbook (draft)

Optional public-release authentication has a dedicated
[`GitHubAuthentication` suite](../../docs/github-release-discovery.md#disposable-guest-authentication).
It supports explicit anonymous/PAT comparison and verified payload downloads without
installation. PAT requires a dedicated account-bound enrollment and upgraded protected
controller; broad suites and UnitOnly remain anonymous. Live PAT acceptance is pending.

This runbook is intended for an advanced first-time contributor setting up a disposable Windows 11 test VM with Hyper-V. Please use it as the first pilot and report any step that is unclear, stale, or fails on your host.

The VM is for integration tests that change Windows state. Routine validation and mocked Pester tests remain available through the repository's GitHub Actions workflow and do not require a VM.

For a controller that stalls before guest execution, use the
[bounded host-preparation probe](automatedlab-tasks.md#bounded-host-preparation).
It checks dependencies, lab identity and source copying within five minutes,
without starting or restoring the VM. Refresh protected registration after the
probe passes to activate the independent request watchdog.

## What this pilot covers

### Persistent user PATH candidate

`Invoke-RideProfileVmAcceptance.ps1 -Scenario PersistentUserPath` runs the
guarded Q08 lifecycle case on the existing registered Windows 11 disposable VM
and its configured checkpoint. In an attended host session, use the existing
controller configuration, guest administrator credential and a new output
directory. The guest case creates only a unique sentinel file and, if needed, an
empty `bin` directory under the current user's profile; it checks preview,
apply, repeat, registry value kind, exact saved-run restore and preservation of
the current process PATH. The outer runner captures evidence and restores the
pinned checkpoint.

This candidate has no published target support yet. Do not run it on a workstation.
The Q08 handler requires a native interactive user process. The host runner uses
PowerShell Direct to start a short-lived scheduled task with `RunLevel Limited` in
the same account's existing interactive session, verifies that worker SID against
the PowerShell Direct identity, collects its result, and removes only that task. A
different signed-in guest account is refused. This transport has only been prepared
and locally validated; no VM run is claimed. The current run is also deferred
because host `Get-VM` access is denied at CIM and the registered protected
controller does not contain the current runner module; controller refresh requires
a future elevated host session. Save the native run for that attended session. The
Q08 case does not request a guest UAC change or broadcast an environment change,
and makes no claim that existing processes see the new PATH. Effective PATH
behavior and Windows acceptance remain separate review items. Preserve the existing
user-bin startup scenario as a separate setting.

### Focused reviewed portable packages

`Invoke-RidePortableVmAcceptance.ps1` is the focused Windows 11 runner for
MiTeC JSON/XML Viewer and the reviewed NTCore portable candidates. `AllReviewed`
selects seven file-lifecycle cases: both viewer architectures and PE Detective,
CFF Explorer, and 4GB Patch. `MiTeCViewers` and `NTCore` select four and three
cases respectively. The NTCore suite runs 4GB Patch only against
a generated, non-runnable x86 PE in its correlated guest evidence folder. It
checks the large-address-aware flag, exact original backup, refusal of a
pre-existing backup by the guarded RIDE launcher, guarded patching and exact
synthetic-file recovery; no real executable is opened. Direct use of the
upstream utility is unsafe when its `.Backup` path is occupied. The older
`ApplicationsBatch1`/`ApplicationsBatch2` selectors do not include these candidates.
No NirSoft or other Defender-blocked collection member is selected.

`NTCoreAdditional` selects Driver List x64/x86 and Rebel.NET as three pinned file-
lifecycle cases. It verifies member ownership, repeat install/remove, saved-state
recovery and preservation of unrelated files. It does not launch Driver List, read
loaded-driver inventory, create a report, open an assembly or invoke Rebel.NET
rebuilding. Its exact retained archives are listed in
`.local/acceptance-input/NTCoreAdditional.json`; functional tests remain separately
scoped to sensitive or synthetic data.

`MiTeCMailHistoryViewers` selects the pinned MiTeC Mail Viewer, E-mail History
Browser, Internet History Browser and Instant Messaging History Browser. It
checks package file staging, repeat, removal, saved-state recovery and preservation
of unrelated files. It does not launch the viewers or open user mail, browser
history or messaging stores. The retained archives are listed in
`.local/acceptance-input/MiTeCMailHistoryViewers.json`; synthetic-store behavior
checks remain a separate acceptance step, and all four package targets remain
unsupported until acceptance is complete.

`SysinternalsSuite` is an explicit one-package batch for the pinned 2026-10-17
164-member snapshot. It checks portable file staging, repeat, removal, saved-run
restoration, collision refusal and preservation of unowned or modified files. It
does not execute a utility, accept an EULA, activate a driver/service, or approve
publication. Its exact retained archive manifest is
`.local/acceptance-input/SysinternalsSuite.json`.

`SysinternalsProducts` is a separate nine-package batch for the pinned Process
Explorer, Autoruns, TCPView, Process Monitor, RAMMap, Disk2vhd, Sigcheck, Strings
and Handle archives. It checks each package's file lifecycle, saved-run recovery,
digest, ownership and collision boundaries. The batch does not launch a utility,
accept an EULA or activate a driver/service. The four Defender-detected NirSoft
files and other blocked collections remain outside this selection. Its manifest
is `.local/acceptance-input/SysinternalsProducts.json`, containing exactly one
`Id`/`Path` row per selected package. The protected controller must advertise
`FocusedPortableV1` before a run can be submitted; source preparation alone does
not imply that VM acceptance has been submitted or passed.

`RawCopy` runs the pinned RawCopy 1.0.0.22 package lifecycle, then invokes
`Invoke-RideRawCopySyntheticAcceptance.ps1` from the guest snapshot. Its exact
host archive is `.local/acceptance-input/RawCopy.json`. The guest creates one
4096-byte fixture on NTFS and requires the copied output hash to match. TCP
sending, metadata output and raw-directory listing are disabled; the runner has
no source-file parameter and does not inspect user or evidence data. A passing
run removes only the unique fixture and output; a failure retains its files and
JSON evidence. Submit through the existing registered task so no per-run UAC
prompt is needed:

```powershell
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite RawCopy -TimeoutMinutes 60
```

`WinPmem` is a separate fixed single-file package batch. It will verify only
RIDE's exact executable-file ownership, install/repeat/remove and saved-state
recovery. It never launches the executable or loads, unloads or tests the
kernel driver; driver behavior and memory capture are distinct acceptance work.
The host manifest must be `.local/acceptance-input/WinPmem.json` and contain
exactly one `Id`/`Path` row for `package.winpmem`. This checkout has no retained
asset yet, and the registered protected controller needs a one-time elevated
refresh to accept the new `WinPmem` selection. Defer submission until both are
ready; the target package remains unsupported until lifecycle evidence is
reviewed and support is explicitly promoted.

After the official executable has been acquired and hash-checked into the local
review cache, create the one-row manifest using its literal local path, refresh
the existing controller during the next planned elevated session, then submit:

```powershell
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite WinPmem -TimeoutMinutes 60
```

The guest runner requires an Off disposable Windows 11 VM and its registered
checkpoint. It captures install/repeat/remove and exact saved-state recovery,
then restores the checkpoint. It does not load the WinPmem driver or create a
memory image.

Local runner contract checks now pass: exact selector/inert-payload cases 2/2 and mocked fixed-controller dispatch matrix 10/10 in Windows PowerShell 5.1/Pester 5.7.1. These checks do not refresh the protected controller or establish guest behavior. See [latest regression and host-access evidence](../../docs/archive/evidence/winpmem-runner-current-source-regression-and-vm-cim-block-2026-10-28-1030.json). The batch does not change Defender or promote catalog support by itself. Keep
Windows 11 support pending until the correlated package lifecycle, synthetic
behavior evidence, and checkpoint recovery all pass review.

`ImageMagick` is an explicit one-package Windows 11 batch for the pinned portable
Q16 7.1.2-34 archive. It checks whole-archive ownership, the executable signature,
license/notice files, and package lifecycle recovery while preserving a synthetic
unowned file. Its only feature execution reports the version and creates/identifies
a synthetic 1x1 PNG in the run evidence folder. It does not open user images or
claim support for Server. The package preflights for `vcomp140.dll` and leaves the
shared Visual C++ runtime outside RIDE's install/remove ownership. The disposable
guest runner installs Microsoft's signed x64 v14 redistributable only when the DLL
is missing, then records installer and runtime signatures, hashes, and version in
`imagemagick-runtime-prerequisite.json`; checkpoint recovery removes that guest
change. The retained archive manifest is
`.local/acceptance-input/ImageMagick.json`.

Two additional batches are explicit selections and are not included by
`AllReviewed`: `PSScriptTools` verifies all 360 reviewed source files, then runs
a separate dependency acceptance probe; `OfflineCaffeine` checks the already
accepted, pinned Caffeine portable package through disconnected CLI install/
profile apply and saved recovery. Each requires a manifest containing only its
one package ID and retained ZIP. Use `-TimeoutMinutes 40` for the larger
PSScriptTools file lifecycle.
The portable guest runner retains each saved state directory as a ZIP under
`evidence/saved-state`, with its file count checked before collection. This avoids
long member paths during guest-to-host evidence copying. Preserve these archives
alongside the scenarios and source manifest; inspect them without executing their
contents.

The PSScriptTools source-file lifecycle does not execute its payload. After the
package is staged, `Invoke-RidePSScriptToolsRuntimeAcceptance.ps1` imports the
pinned module in fresh Windows PowerShell 5.1 and PowerShell 7 child processes
when each edition is installed. Each child uses a unique `TEMP`/`TMP` directory
under that run's evidence folder. It verifies the module's CIM namespace job,
one `System.Drawing`-backed function and one ThreadJob-backed function, and
removes only the module's known temporary file. A second probe hides available
modules and confirms import fails on the required ThreadJob dependency before
creating the CIM file; it does not install dependencies. Inspect
`psscripttools-runtime/summary.json` separately from the package lifecycle.
Missing PowerShell 7 is recorded as partial acceptance, not installed by the
runner. The probe requires the disposable-VM guard and guest elevation.

`OfflineCaffeine` records the actual guest target, builds a private acceptance
profile/bundle bound to current source hashes and the checkout HEAD, and disables
any Up guest network adapters before invoking the engine. Existing disconnected
guests remain disconnected. PowerShell Direct still collects evidence; checkpoint
recovery restores the original adapter state. The test covers missing/corrupt/
omitted payload and target mismatch refusals before state writes, offline preview,
install/apply repeat and exact saved-file recovery. No Caffeine executable runs.
The generated profile is an acceptance fixture, not a proposed deployment profile
or distribution approval. Inspect `network-before.json`, `network-after.json`,
`bundle-manifest.json`, scenarios and the host recovery result. Broader installer,
servicing, dependency and interruption acceptance remains separate.

For repeated `NTCore`, `NTCoreAdditional`, `MiTeCMailHistoryViewers`, `MiTeCAnalysisTools`, `MiTeCSystemAndTelephony`, `PSScriptTools`, `OfflineCaffeine`, `SQLiteQuery`,
`MiTeCUtilityFiles`, `SysinternalsSuite`, `ImageMagick` and `RawCopy` batches, prefer the
registered task instead of launching this standalone host runner with `RunAs`
each time. NTCore includes the 4GB Patch candidate's file lifecycle and its
bounded synthetic-PE functional check.
The installed controller must advertise `FocusedPortableV1`; the client refuses
older installations before queuing or opening an elevation prompt. An idle,
one-time elevated refresh uses the existing installed configuration and preserves
its VM/checkpoint pins:

```powershell
# Repository root, elevated Windows PowerShell 5.1, owning account; one time.
$configuration = 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json'
.\tests\integration\Register-RideVmTestTask.ps1 -ConfigurationPath $configuration -Confirm:$false
```

Place the one-package retained-archive manifests at
`.local/acceptance-input/PSScriptTools.json`,
`.local/acceptance-input/OfflineCaffeine.json`,
`.local/acceptance-input/SQLiteQuery.json`,
`.local/acceptance-input/SysinternalsSuite.json`,
`.local/acceptance-input/SysinternalsProducts.json` and
`.local/acceptance-input/ImageMagick.json`. `SysinternalsProducts.json` contains
nine `Id`/`Path` rows; the other manifests contain one package unless the
paragraph below specifies a three-package batch. The three-package selections use
`.local/acceptance-input/NTCore.json` and
`.local/acceptance-input/NTCoreAdditional.json`,
`.local/acceptance-input/MiTeCMailHistoryViewers.json`,
`.local/acceptance-input/MiTeCUtilityFiles.json`, and
`.local/acceptance-input/MiTeCAnalysisTools.json`, and
`.local/acceptance-input/MiTeCSystemAndTelephony.json`. `MiTeCMailHistoryViewers.json`
contains four `Id`/`Path` rows. All use the `Id`/`Path` format
below.
Requests accept no caller-supplied script or payload path. The protected runner
reads only the selected manifest and verifies its exact catalog identity/hash;
the snapshot still excludes `.local`. From ordinary PowerShell in the owning
signed-in account, submit and wait for each result:

```powershell
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite PSScriptTools -TimeoutMinutes 60
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite OfflineCaffeine -TimeoutMinutes 60
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite SQLiteQuery -TimeoutMinutes 60
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite MiTeCUtilityFiles -TimeoutMinutes 60
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite SysinternalsSuite -TimeoutMinutes 60
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite SysinternalsProducts -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite ImageMagick -TimeoutMinutes 60
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite NTCoreAdditional -TimeoutMinutes 60
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite MiTeCMailHistoryViewers -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite MiTeCAnalysisTools -TimeoutMinutes 60
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath $configuration -IntegrationSuite MiTeCSystemAndTelephony -TimeoutMinutes 60
```

`SQLiteQuery` is deliberately limited to the package file lifecycle and recovery:
it stages the pinned executable and bundled SQLite files, then checks repeat,
remove and saved-run restoration. It does not launch the UI, open or mutate a
database, or establish feature, build-provenance or license acceptance. Its
candidate remains unsupported until those independent gates are reviewed. The
existing protected controller must be refreshed once while idle to include these
new batches; do not submit them until that refresh and their fixed retained-archive
manifest are available.

`MiTeCUtilityFiles` stages only the pinned UUID Generator, Certificate Generator
and Certificate Information executables and checks managed-file repeat/remove
and saved-state recovery. It does not query identifiers, generate or inspect
certificates, open user files or add a trust-store item. All three candidates
remain unsupported and have version-specific local `NeedsReview` license records.

`MiTeCAnalysisTools` stages MiTeC EXE Explorer 3.7.5 and HexEdit 7.1.0 from
their exact retained archives. It checks repeat install/remove, saved-state
recovery and preservation of unrelated or modified files. It does not launch
either utility, inspect real executables or disks, use VirusTotal/API/network
features, or test process-memory or raw-disk editing. Both packages remain
unsupported pending Windows 11 lifecycle and the separate synthetic-file
feature checks. The controller must be refreshed to advertise
`MiTeCAnalysisToolsV1` before submitting this batch.

`MiTeCSystemAndTelephony` stages MiTeC System Information eXtra 16.0.0 and
TAPI Monitor 1.2.0 from the exact retained archives. It checks repeat
install/remove, saved-state recovery and preservation of unrelated or modified
files. It does not create or retain system reports, access system inventory,
enumerate or configure TAPI providers, inspect calls, or launch either utility.
Both packages remain unsupported pending Windows 11 lifecycle acceptance.
Report-field/redaction review and simulated-provider behavior remain separate
acceptance work. The controller must be refreshed to advertise
`MiTeCSystemAndTelephonyV1` before submitting this batch.

The worker serializes both requests, runs the protected host child without UAC,
and retains timeout/process termination and checkpoint recovery. Focused results
are under `results/<request-id>/focused`; require Passed, evidence collected and
ResetAndOff. These suites use PowerShell Direct, including during disconnection,
and run their focused integration assertions without the general guest Pester
suite. Local regression validation remains a separate prerequisite. They do not
support CI source or PAT, and do not alter the existing settings fixture. An
installed-controller refresh and its first native dispatch are separate acceptance
gates; preparing source does not claim they passed.

Start in the repository root in elevated **Windows PowerShell 5.1**, using the
owning account of an existing registered disposable controller. The host must
already meet its AutomatedLab prerequisites, including running VMMS/WinRM and
existing remoting configuration. The runner refuses missing prerequisites;
it does not repair host services, policies, Defender or controller registration.
The VM must be Off, the controller Ready, its queues empty and recovery unblocked.
The configured VM and checkpoint IDs must still match their registered objects.

Prepare a local JSON manifest with exactly one retained archive per selected
package. Replace the example paths with existing reviewed files; do not include
Defender-blocked archives or extract them. For `AllReviewed`:

```json
[
  {"Id":"package.mitec-json-viewer","Path":"C:\\Acceptance\\JSONView.zip"},
  {"Id":"package.mitec-xml-viewer","Path":"C:\\Acceptance\\XMLView.zip"},
  {"Id":"package.ntcore-pe-detective","Path":"C:\\Acceptance\\PE_Detective.zip"},
  {"Id":"package.ntcore-cff-explorer","Path":"C:\\Acceptance\\CFF_Explorer.zip"},
  {"Id":"package.ntcore-4gb-patch","Path":"C:\\Acceptance\\4gb_patch.zip"}
]
```

Save it as `.local/portable-acceptance-input.json` and create the local output
directory. Preview validates archive selection and catalog-pinned SHA-256 values
without accessing or changing the VM. Then run the same command without `-WhatIf`:

```powershell
$null = New-Item -ItemType Directory -Path '.local\portable-vm-acceptance' -Force
$acceptance = @{
  ConfigurationPath = 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json'
  ArtifactManifestPath = '.local\portable-acceptance-input.json'
  OutputDirectory = '.local\portable-vm-acceptance'
  Batch = 'AllReviewed'
}
.\tests\integration\Invoke-RidePortableVmAcceptance.ps1 @acceptance -WhatIf
.\tests\integration\Invoke-RidePortableVmAcceptance.ps1 @acceptance
```

The runner exclusively locks the existing controller, stages a verified checkout
and the selected pinned archives, restores the registered checkpoint, and uses
its lab credential through PowerShell Direct. Guest checks cover preview,
install/repeat, exact member selection, remove/repeat, saved removal restoration,
original absence restoration, unowned-file collision refusal and preservation
of modified/unowned files. Payloads are staged and inspected, never launched.
The guest uses the real engine/provider with its cache seeded from the verified
archives; this is not disconnected/offline acceptance.

Each generated run directory retains `result.json`, source/payload manifests,
and, once available, `evidence/acceptance.log`, `scenarios.json`, `summary.json`,
saved state and artifact observations. `Passed` requires all selected cases plus
checkpoint recovery. Verify `Cleanup = ResetAndOff`; `NotStarted` means the VM
was untouched. Failed recovery records a controller block and requires the
[existing recovery procedure](automatedlab-tasks.md#recovery-and-teardown) before
further work. Evidence is collected before recovery, including after failure.
GUI behavior, parser correctness and real licence/settings activation remain
separate acceptance gates; this runner does not promote catalog support.

### Existing application suites

`ApplicationsBatch1` selects conventional application candidates;
`ApplicationsBatch2` selects managed portable candidates and the ShareX portable
variant. `ApplicationsBatch3` selects both Docker Desktop variants;
`ApplicationsBatch3AllUsers` isolates the elevated system-wide variant on the
pinned Windows 11 controller. These suites run guest
validation/Pester before preview, install/repeat, remove and saved-run recovery.
Every ApplicationsBatch1 package receives synthetic user data in its documented
profile/configuration location or a user-selected Documents location. The batch
checks its exact bytes after install, the vendor uninstaller, and saved-state
recovery. Browser profiles, chat/mail profiles, VS Code settings/extensions,
Autopsy settings/case data, Wireshark preferences, GnuPG configuration, and
TMOG data are covered. No utility or application is launched to create data;
the fixtures contain no credentials, keys, certificates, messages, or real case
content. The TMOG scenario does not enter a license key or launch TMOG.
`ApplicationsBatch4` selects the Slack and Discord current-user EXE candidates,
checks their pinned source evidence, and exercises their install/remove lifecycle
on the disposable Windows 11 guest. Its Pester selection includes the focused
chat-package pin checks; Discord's source digest must match the publisher payload.
`ApplicationsBatch5` selects only the Microsoft Visual C++ v14 x64 runtime. Run
it on the registered Windows 11 VM. If the checkpoint already has an adequate
v14 runtime or an installed catalog-dependent package, it records `NotApplicable`
and preserves that baseline. Otherwise,
it verifies the minimum registered and `System32/vcomp140.dll` versions, then
checks preview, repeat install, removal, repeat removal and saved-run recovery.
The controller restores the same checkpoint; production `SupportedTargets`
remains empty until guest evidence passes.
`ApplicationsBatch6` selects the twelve machine-scope Artcraft MSI applications
on Windows 11. The separate current-user ArtCraft Launcher is excluded because
it has its own execution boundary. Owner-specific Artcraft code/asset/brand
reviews remain marked in the private review store and do not gate this technical
package lifecycle batch; no redistribution approval or production support is
implied.
`ApplicationsBatch7` selects only the separate current-user ArtCraft Launcher
MSI on Windows 11. It checks launcher install/repeat/uninstall/recovery without
starting the launcher, downloading applications, or changing launcher
configuration. Its owner-specific review marker does not gate technical package
migration.
`ApplicationsBatch8` selects the four pinned Microsoft OpenJDK MSI versions on
Windows Server 2025. It verifies side-by-side installation, exact `java.exe`
and `javac.exe` versions, repeat/remove/recovery, and preservation of machine
and current-user `JAVA_HOME`, `PATH`, and `.jar` associations. It does not
promote package support until acceptance passes.
Docker acceptance checks each install scope independently and requires its
publisher-preserved Docker resources to remain after removal. Portable tests
preserve user files and restore the exact owned bytes after removal. Run batches
1 and 2 on the pinned Windows 11 and prepared Server 2025 controllers; batches 3,
5 through 7 and the focused all-users suite are Windows 11 only; batch 8 is
Server 2025 only. Other package candidates stay
test-only until their applicable scenarios pass; Docker Desktop is enabled for the
owner's physical-machine RIDE review after the Hyper-V guest attempts proved
inconclusive. Driver/OEM tools require matching guests. See the
[application ledger](../../docs/migrations/application-migration-review.md).

`ApplicationsBatch9` selects only MiTeC InfoBar 4.6.2 on Windows 11. It checks
the pinned installer version, repeat install, removal, repeat removal and saved
install/removal recovery. It does not launch InfoBar, configure startup behavior,
or access a weather location, API key, RSS feed, or personal data. Startup and
network behavior remain separate acceptance work. The task client requires the
registered controller capability `ApplicationsBatch9InfoBarV1`; refresh the
controller before queuing the suite. That refresh is deferred, so this preparation
does not dispatch a task or install the package.

`ApplicationsBatch10` selects only MiTeC Project Maker 1.9.0 on Windows 11. It
checks the pinned installer version, repeat install, removal, repeat removal and
saved install/removal recovery. It does not launch Project Maker, open a project,
invoke a compiler, run before/after actions, patch versions, sign, or protect a
binary. Those feature checks require a separate synthetic Delphi project and
disposable signing key. The task client requires the registered controller
capability `ApplicationsBatch10ProjectMakerV1`; refresh only if that capability
is absent. Native acceptance remains pending. Runner 0.19.4 records machine
lifecycle stages in `application-progress.jsonl` and adds the documented Inno
Setup [`/LOG` switch](https://jrsoftware.org/ishelp/topic_setupcmdline.htm) to
retain `project-maker-install.log`. The limited-user path retains its existing
`application-user-progress.jsonl` name. Partial collection can retain closed
progress records when an active transcript is locked; the installer log may also
be unavailable if locked. Recovery installation can overwrite the installer log.
After the 2026-10-30 timeout, use one diagnostic request with `-TimeoutMinutes 20`,
then inspect evidence before any further retry. The timeout bounds controller
execution; evidence collection and checkpoint cleanup follow it.

`ApplicationsBatch11` selects only HashCheck Shell Extension 2.6.3 on Windows 11. It checks installer identity, install/repeat, removal/repeat and saved install/removal recovery; it does not launch HashCheck or invoke Explorer. The request requires both registered controller capabilities `ApplicationsBatch11HashCheckV1` and `ApplicationsBatch11InteractiveV1`. The runner directs the publisher's `/LOG=` output to `hashcheck-install.log` in the collected guest result directory, including on installation failure. Inspect this log and `applications-batch11.json` before retrying a failed installation; later install/recovery attempts in the same run can overwrite the publisher log. See the [application migration ledger](../../docs/migrations/application-migration-review.md) for dated acceptance results.

HashCheck release 2.6.3 registers installed version 2.6.3.0; acceptance checks that
exact four-part version while retaining the release/download pin. Its Windows 11
sparse-package registration requires the tested interactive execution context.
The controller selects exactly one desktop belonging to its guest administrator,
then runs the suite through a temporary `Interactive` / `Highest` task. The worker
checks the machine, SID, session and elevation before running. An absent or
ambiguous desktop fails the request; there is no Session 0 fallback. The runner
does not configure automatic sign-in or store a password in the task. The worker
launches the suite in a fresh Windows PowerShell process in that same session;
this keeps Pester command discovery and mocks outside the coordinator module's
scope. A failed child process or suite summary fails acceptance.

Refresh the idle protected controller using `Register-RideVmTestTask.ps1` and its
existing configuration before queuing this suite. Use current Local or CI source
containing both interactive guest files. The pinned disposable baseline must
provide the intended signed-in administrator desktop after startup. The temporary
task has a 30-minute limit and is removed after completion or failure; the host
collects evidence and restores its pinned checkpoint. Task cleanup errors fail
the run. Direct `Invoke-RideVmTest.ps1` calls also require `ResultDirectory`.

Inspect `interactive-request.json`, `interactive-task.xml`, `interactive-task.json`,
`interactive-worker.json` and `interactive-output.log` beside the existing suite
summary and Pester evidence. Require matching run IDs, a passed worker, task exit
code zero, task removal and successful host recovery. Duplicate dispatch is
refused before executing the suite again. Logged-out installation, Explorer
behavior and full controller certification remain separate acceptance gates;
never run this state-changing suite on the development host.

`ApplicationsBatch12` selects only `package.ntcore-explorer-suite` on Windows 11. It checks the retained publisher installer identity, install/repeat, removal/repeat and saved install/removal recovery; it does not launch any suite utility or open target files. The request requires the registered controller capability `ApplicationsBatch12NtcoreExplorerSuiteV1`. The exact-version license marker is administrative and does not gate migration. Check the configured capability before submitting; refresh only if it is absent. Runner 0.19.3 admits the exact pending candidate in the guarded guest catalog and includes vendor removal/repeat/recovery. Production support remains pending until Windows acceptance passes.

ApplicationsBatch1 can be split into `ApplicationsBatch1Machine` and
`ApplicationsBatch1User`. Use the split suites when accepting it: the machine
suite covers the nine machine-scoped packages, while the user suite covers
Thunderbird and Gpg4win in a temporary standard account. The user worker has a
60-minute execution limit and retains a JSON-lines stage log if it times out.
The task client submits these split suites only when the registered controller
advertises `ApplicationsBatch1SplitV1`; refresh an idle controller before
queuing them.
The unsplit `ApplicationsBatch1` suite remains available for a single combined
run.

```powershell
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch1Machine -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch1User -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test\configuration.json' -IntegrationSuite ApplicationsBatch2 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch3 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch3AllUsers -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch4 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch5 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch6 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch7 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test\configuration.json' -IntegrationSuite ApplicationsBatch8 -TimeoutMinutes 180
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch9 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch10 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch11 -TimeoutMinutes 90
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite ApplicationsBatch12 -TimeoutMinutes 90
```

Verify the actual Server VM ID, edition and checkpoint; the example
`RIDE-S25-Test` name is not proof of live identity. Controller evidence includes
correlated `applications-batch1.json` or `applications-batch2.json`, acquisition
observations, saved state and checkpoint cleanup results. Refresh protected
controller files only while the registered task and its children are idle.

The remaining-settings session has two package-free selections.
`SettingsRemainingBatch1` covers 21 task, policy and Explorer operations, three
pending BitLocker drive-type method policies, the pending current-user Click
to Do policy candidate, the pending Storage Sense machine-policy candidate, and
the pending BitLocker Wizard and Power Options current-user shortcuts (28 total).
The Storage Sense candidate runs only on a Windows policy edition listed by
Microsoft; its acceptance tests the local override lifecycle and exact restore
without requesting cleanup. The shortcut scenarios only create/remove their
links and never launch the targets. `SettingsRemainingBatch2` covers 19 network,
Defender, power, sound and Edge operations. Each runs validation and guest
Pester, then preview, every available state, repeat apply and exact saved-run
restore. Missing resources and missing
power-scheme variants are reported separately. Task definitions, network peers,
sign-in, sound playback and browser behavior require additional acceptance.
The BitLocker cases verify only future-encryption policy registry lifecycles;
they do not encrypt or convert a volume. The Click to Do case tests only the
per-user `DisableClickToDo` policy value and exact saved-state recovery. It does
not test the separate user-facing toggle, Copilot+ hardware requirements,
device-policy precedence, or visible feature behavior. The published candidates
remain unsupported until the VM evidence is reviewed.
See the [decision ledger](../../docs/migrations/remaining-settings-decisions.md).

The sixty-setting session has a package-free suite selected with
`Invoke-RideVmTest.ps1 -IntegrationSuite SettingsBatch60`. It covers all 60
new catalog operations and their declared states across registry values,
coordinated values, namespace keys, services, power indexes and BCD. Each
operation is restored in finally; unsupported power controls are reported
as unavailable rather than passed. This suite does not reboot the guest or
establish UI, preboot, suspension, gaming or effective security behavior.
See the [batch ledger](../../docs/MIGRATION-PLAN.md#sixty-setting-session-2026-10-10).

Both `Invoke-RideVmTest.ps1` and the registered-task client
`Invoke-RideVmTestTask.ps1` accept `-IntegrationSuite`. Refresh the protected
controller through `Register-RideVmTestTask.ps1` after reviewing these changes;
older installed controllers do not forward suite selection. The controller
verifies that the correlated guest summary names the requested suite.
`SettingsBatch60Recovery` selects the BCD recovery policy and eleven coordinated
registry settings from this batch, retaining the same state/preview/repeat/exact
restore checks. It runs validation and guest Pester before these twelve scenarios
and does not enter package tests. For example:

```powershell
.\tests\integration\Invoke-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json' -IntegrationSuite SettingsBatch60Recovery -TimeoutMinutes 25
```

The forty-setting follow-up has a package-free acceptance suite. Select it
explicitly with `Invoke-RideVmTest.ps1 -IntegrationSuite SettingsBatch40` and
the normal VM transport/evidence parameters; the default remains `Full`.
`-UnitOnly` cannot be combined with this integration selection. The new script
`Invoke-RideSettingsBatch.ps1` covers all 81 explicit states, preview, repeat
apply, baseline removal and exact registry restore. UI and feature behavior
remain separate acceptance checks; see the
[batch ledger](../../docs/MIGRATION-PLAN.md#forty-setting-follow-up-2026-10-09).

The 9 October optional-settings migration adds 20 registry round trips across
UI, privacy, service and Explorer families. They check every explicit state,
apply/restore preview, repeat apply, override-removal baseline, and exact prior
value/type recovery. These checks do not exercise visual refresh, sensor or
biometric hardware, app access, network peer transfers, hibernation, sign-out
history deletion or actual crash recovery. See the
[migration results](../../docs/MIGRATION-PLAN.md#optional-windows-settings-session-2026-10-09)
for executed evidence and remaining acceptance limits.

The current VM suite checks Explorer settings; install, idempotence, and removal for 7-Zip, Notepad++, and Sysmon; the inking and typing setting; network category apply/restore for all non-domain profiles; Remote Assistance policy; the Microsoft product updates preference; and the BitLocker encryption-method policy on Windows 11. Git for Windows installation is not yet covered. The suite does **not yet** perform real-Windows round-trip tests for the service, UWP per-app override, or boot configuration handlers.

The optional [God Mode folder](../../docs/god-mode.md) scenario checks preview,
repeat apply and exact saved-run restore on Windows 11. Use a clean VM desktop;
the scenario refuses a nonempty God Mode folder. Manually open the folder in
Explorer to verify that it displays Control Panel tasks. The folder lifecycle
scenario passed in the Windows 11 VM on 9 October
2026 (run `959e8b4c2a374041a792497f42dd2588`); the manual visual check remains
pending.

The package checks download installers from their declared upstream sources, so the guest needs outbound internet access while the suite runs. The VM does not need access to shared host folders or production credentials.

The host runner launches `Invoke-RideGuestTests.ps1` in a fresh Windows
PowerShell process inside the VM. This keeps Pester's mock call stack outside
the remoting thread. The guest entry point requires the host runner's VM marker;
use the host runner or registered task rather than invoking it on a workstation.
Refresh an installed controller through registration while its worker is idle
after reviewing runner changes; see [task setup](automatedlab-tasks.md#2-register-once).

When using AutomatedLab, the runner waits up to five minutes for a guest PowerShell remoting session before staging files. A timeout indicates the guest is still starting or its WinRM listener/network firewall is unavailable; no RIDE test code runs until that session is established.

## 1. Check the Hyper-V host

Use a Windows Pro, Enterprise, Education, or Windows Server host with hardware virtualization enabled. Hyper-V is not included with Windows Home. You need permission to create Hyper-V VMs and enough free storage for the ISO and VM disk. A practical starting allocation is 4 virtual processors, 8 GB of guest memory, and a dynamically expanding 100 GB virtual disk; reduce these only if the host is resource constrained.

In one elevated PowerShell session on the host, run this complete block to check whether Hyper-V is available. Paste or run the entire block together; `elseif` and `else` belong to the same `if` statement and cannot be entered as separate commands after it has executed.

```powershell
if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
} elseif (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    Get-WindowsFeature -Name Hyper-V
} else {
    throw 'Hyper-V management commands are unavailable on this host.'
}
```

If the feature is disabled, enable it through **Turn Windows features on or off** on Windows client, or install the Hyper-V role on Windows Server, then restart when Windows asks. Follow Microsoft's [Hyper-V installation requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v).

## 2. Register and download the Windows evaluation ISO

For a key-free test VM, use Microsoft's [Windows 11 Enterprise Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise): register, choose the x64 ISO, and complete the download form. Microsoft describes it as a 90-day evaluation and says a product key is not required. The Enterprise Evaluation image used in this RIDE pilot completed setup without requiring a Microsoft account. OOBE behavior varies by edition, media, and build; see the [Windows local-account setup guide](../../docs/windows-local-account-setup.md) for current observations and alternatives. Do not use a work or production identity in a test VM.

You can also download a standard 64-bit Windows 11 ISO from [Microsoft's Danish Windows 11 download page](https://www.microsoft.com/da-dk/software-download/windows11). Microsoft describes this as a multi-edition ISO and says a product key is needed to unlock the matching edition. The ISO download itself does not ask for a key, but installation and activation still require the applicable license or digital entitlement. Use this option if you have a license for the edition you want to test; otherwise use the evaluation ISO. Microsoft provides instructions to [verify the ISO hash](https://www.microsoft.com/da-dk/software-download/windows11).

Save the ISO in a location you control, for example `D:\VMs\RIDE-Test\ISO\Windows11-Enterprise-Eval.iso`. Create the folder first. Use another drive/path if `D:` is unavailable. Do not choose ARM64 unless your Hyper-V host is Windows on Arm.

## 3. Create the VM in Hyper-V Manager

On the host, open **Hyper-V Manager** and use **New > Virtual Machine**:

1. Name it `RIDE-Win11-Test` and store its files under a dedicated VM folder, for example `D:\VMs\RIDE-Test\Windows11`.
2. Select **Generation 2**.
3. Assign 8192 MB startup memory if available. Dynamic Memory can be enabled.
4. Connect it to **Default Switch** during setup and integration testing. This gives the guest outbound network access for Windows setup, Pester, and package downloads. Do not join it to a domain or sign into production services.
5. Create a new dynamically expanding VHDX, with a maximum size of 100 GB.
6. Select **Install an operating system from a bootable image file** and point to the ISO downloaded in step 2.
7. Finish the wizard. Before starting the VM, open **Settings > Security** and confirm Secure Boot is enabled with the Microsoft Windows template. Enable **Trusted Platform Module** if the host supports it and Windows setup requires it. Set the processor count to 4 if the host has capacity.

Start the VM, connect with **VMConnect**, and complete Windows setup. Install the Windows 11 Enterprise evaluation. After first sign-in, run Windows Update and restart until no further updates are offered. Keep the VM off your domain and avoid storing personal or production data in it.

For the Hyper-V wizard and PowerShell alternatives, see Microsoft's [create a virtual machine guide](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/Create-a-virtual-machine-in-Hyper-V).

### Optional: provision this VM with AutomatedLab

The Hyper-V Manager flow above remains the primary setup path. For repeatable, host-driven provisioning, use the [AutomatedLab setup guide](automatedlab.md) and its OS-selectable script. The script checks host permissions and lab prerequisites, installs Pester through `Invoke-LabCommand`, creates the clean checkpoint, and performs the AutomatedLab copy step. AutomatedLab is an external dependency and is not installed by RIDE.

## 4. Install the test dependency in the guest

Open **PowerShell as Administrator inside the guest VM**. Install the same Pester version used by CI:

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Scope CurrentUser -Force
Install-Module -Name Pester -RequiredVersion 5.7.1 -Repository PSGallery -Scope CurrentUser -Force -SkipPublisherCheck
Get-Module Pester -ListAvailable | Where-Object Version -eq '5.7.1'
```

Windows includes Pester 3.4.0 signed by Microsoft; Pester 5.7.1 has a different signing publisher. The Pester project recommends `-SkipPublisherCheck` for this side-by-side installation. Keep the install pinned to version 5.7.1 and review the [Pester Gallery listing](https://www.powershellgallery.com/packages/Pester/5.7.1) before installing. This setup currently supports Windows PowerShell and PowerShell 7; using Windows PowerShell is sufficient for this first pilot.

## 5. Create a clean checkpoint

Shut down the guest after updates and Pester installation. In Hyper-V Manager, select the VM and choose **Checkpoint**. Rename it `RIDE-clean-test-base`.

Restore this checkpoint after each integration run. The integration suite changes settings and installs/removes software; the VM checkpoint is the broad recovery boundary if a test fails before RIDE can restore an individual operation. Because this checkpoint is taken before copying the checkout into the guest, copy the current working tree again after each restore.

## 6. Copy this working tree into the guest

Run the copy from PowerShell with the current directory set anywhere inside this Git checkout. `git rev-parse` finds the checkout root, so you do not need to enter your Windows profile name.

### 6A. If the VM was created with AutomatedLab

AutomatedLab's `Copy-LabFileItem` copies files and directory trees to a lab VM using its lab connection context. Import the lab with its actual lab name; the current example uses `RIDEWin11Test`. The VM name is `RIDE-Win11-Test`.

```powershell
$labName = 'RIDEWin11Test' # Change only if your existing lab has a different name.
$vmName = 'RIDE-Win11-Test'
$repoRootOutput = & git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0 -or -not $repoRootOutput) {
  throw 'Run this command from inside the ride-windows Git checkout.'
}
$repoPath = $repoRootOutput.Trim()

Import-Lab -Name $labName -NoValidation
Start-LabVM -ComputerName $vmName -Wait -TimeoutInMinutes 10 -ErrorAction Stop
Invoke-LabCommand -ComputerName $vmName -ScriptBlock {
  $ErrorActionPreference = 'Stop'
  New-Item -ItemType Directory -Path 'C:\RIDE' -Force | Out-Null
  Test-Path -LiteralPath 'C:\RIDE' -PathType Container
} -PassThru
Copy-LabFileItem -Path $repoPath -ComputerName $vmName -DestinationFolderPath 'C:\RIDE' -Recurse
Invoke-LabCommand -ComputerName $vmName -ScriptBlock {
  Test-Path 'C:\RIDE\ride-windows\tools\validate.ps1'
} -PassThru
```

The final command should return `True`. Here, `-NoValidation` avoids rechecking installation-media paths after the VM has already been provisioned; it skips all lab-definition validators, so do not use it to provision a new lab. AutomatedLab's [Import-Lab reference](https://automatedlab.org/en/latest/AutomatedLabCore/en-us/Import-Lab/) documents the switch. Its [file-copy command](https://automatedlab.org/en/stable/AutomatedLabCore/en-us/Copy-LabFileItem/) supports recursive directory copies, and [Invoke-LabCommand](https://automatedlab.org/en/stable/AutomatedLabCore/en-us/Invoke-LabCommand/) runs the directory checks inside the guest. This path reuses the lab's guest access; it does not prompt for the guest username again.

### 6B. If the VM was created manually in Hyper-V Manager

PowerShell Direct copies files without enabling PowerShell remoting over the VM network. Run this on the host from anywhere inside the checkout; `git rev-parse` supplies the repo path automatically. This fallback prompts once for the guest's local account credentials:

```powershell
$vmName = 'RIDE-Win11-Test'
$repoRootOutput = & git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0 -or -not $repoRootOutput) {
  throw 'Run this command from inside the ride-windows Git checkout.'
}
$repoPath = $repoRootOutput.Trim()
$guestPath = 'C:\RIDE\ride-windows'
$credential = Get-Credential
$session = New-PSSession -VMName $vmName -Credential $credential
Invoke-Command -Session $session -ScriptBlock {
  New-Item -ItemType Directory -Path 'C:\RIDE\ride-windows' -Force | Out-Null
}
Copy-Item -Path (Join-Path $repoPath '*') -Destination $guestPath -ToSession $session -Recurse -Force
Remove-PSSession $session
```

If PowerShell Direct cannot connect, confirm the VM is running, the guest has completed setup, and Hyper-V integration services are enabled. Microsoft's [PowerShell Direct guide](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct) lists requirements and troubleshooting steps.

## 7. Run validation and the integration suite

For an opt-in elevated task, local watcher and GitHub Actions entry point,
follow [the task controller runbook](automatedlab-tasks.md). Host UAC is not
inspected or enforced; administrator elevation and VM recovery are still required.
The existing direct commands below retain their default behavior. Validate the
new controller on a separate pilot before agreeing a cutover.

You can run the checks from the Hyper-V host after copying the current checkout into the guest (step 6). The shared script block regenerates the catalog documentation, runs validation and Pester, then runs the guarded integration suite. It checks Pester's returned result and stops if any tests failed.

For repeated runs, the repository includes a production-test runner that copies the current working tree into the VM, regenerates `docs/OPERATIONS.md`, runs validation and Pester, and then runs the integration suite. It supports both VM setup paths above. The default run changes VM settings and installs/removes test packages, so use it only with the disposable test VM and restore the clean checkpoint afterward.

From the repository root, run one of these on the host:

```powershell
# AutomatedLab-provisioned VM
.\tests\integration\Invoke-RideVmTest.ps1 -Transport AutomatedLab -LabName 'RIDEWin11Test' -VMName 'RIDE-Win11-Test'

# VM created manually in Hyper-V Manager; prompts for a guest administrator credential
.\tests\integration\Invoke-RideVmTest.ps1 -Transport PowerShellDirect -VMName 'RIDE-Win11-Test'
```

Add `-UnitOnly` to copy the current checkout and run validation plus Pester without applying real Windows changes or installing packages. The detailed remote script below shows each test command separately; use it when learning the process or troubleshooting the runner.

```powershell
$remoteScript = {
  $ErrorActionPreference = 'Stop'
  Set-Location -LiteralPath 'C:\RIDE\ride-windows'

  & .\tools\Export-RideCatalog.ps1
  & .\tools\validate.ps1

  $pesterResult = Invoke-Pester -Path .\tests -PassThru
  if ($pesterResult.FailedCount -gt 0) {
    throw "Pester reported $($pesterResult.FailedCount) failing test(s)."
  }

  $env:RIDE_INTEGRATION_VM = '1'
  & .\tests\integration\Invoke-RideVmSuite.ps1
}
```

### If the VM was created with AutomatedLab

Run the following from the host after importing the lab. `Invoke-LabCommand -PassThru` returns the guest output to the host:

```powershell
$labName = 'RIDEWin11Test' # Change only if your existing lab uses another name.
$vmName = 'RIDE-Win11-Test'
Import-Lab -Name $labName -NoValidation
Invoke-LabCommand -ComputerName $vmName -ScriptBlock $remoteScript -PassThru
```

### If the VM was created manually in Hyper-V Manager

PowerShell Direct runs the same block without requiring guest network remoting. Enter the guest's local administrator credentials when prompted:

```powershell
$vmName = 'RIDE-Win11-Test'
$credential = Get-Credential -Message 'Enter the local administrator account for the guest VM'
$session = New-PSSession -VMName $vmName -Credential $credential
try {
  Invoke-Command -Session $session -ScriptBlock $remoteScript
}
finally {
  Remove-PSSession $session
}
```

The integration script checks that it is running as an administrator inside the guest, and that the guest is Windows 11 or Windows Server 2025. If the remote session fails that administrator check, run the commands in an elevated PowerShell window inside the guest. You can also run the commands interactively inside the guest:

```powershell
Set-Location C:\RIDE\ride-windows
& .\tools\Export-RideCatalog.ps1
& .\tools\validate.ps1
$pesterResult = Invoke-Pester -Path .\tests -PassThru
if ($pesterResult.FailedCount -gt 0) { throw "Pester reported $($pesterResult.FailedCount) failing test(s)." }
$env:RIDE_INTEGRATION_VM = '1'
& .\tests\integration\Invoke-RideVmSuite.ps1
```

The integration suite has a deliberate environment-variable guard and an administrator check. It will exercise the current integration paths and may download/install then uninstall 7-Zip and Notepad++. Leave the VM connected to Default Switch while these package checks run. Do not run the suite on your daily workstation.

If validation or Pester fails, capture the complete error and test summary. If the integration suite fails, keep the VM powered off before investigating, and retain any reported RIDE run ID so the saved state can be inspected. Restore `RIDE-clean-test-base` before another attempt.

## 8. Report the first-run result

Please send back:

- whether each numbered step worked, and the step number for any failure;
- Windows edition, version, and build from `winver`;
- host Windows edition and Hyper-V availability;
- PowerShell and Pester versions;
- the final output from `tools/validate.ps1`, Pester, and the integration suite;
- any run ID printed after an integration failure.

Do not include passwords, Microsoft account details, or unrelated personal data in the report.

## Windows Server 2025 follow-up

After the Windows 11 pilot is successful, repeat the VM checks on Windows Server 2025 for operations whose catalog metadata declares server support. Microsoft provides an official [Windows Server 2025 evaluation ISO and VHD](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025); the evaluation is time-limited and requires internet activation. Keep that VM separate from the Windows 11 VM and use a clean checkpoint for each run.
