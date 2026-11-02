# Explicit Sysmon configuration and recovery

`modules/RIDE.SysmonConfiguration.psm1` provides a candidate workflow for an
already running standalone `Sysmon64` service on native Windows 11 x64 with
PowerShell 5.1 or 7. Native acceptance remains pending. Downloading the three
catalogued Sysmon Modular XML artifacts never applies them, and this workflow
does not install Sysmon or change its service startup settings.

Supply the exact Microsoft-signed service executable, its reviewed SHA-256 and
installed version. The candidate currently admits explicitly selected Sysmon
15.x versions starting with 15.21 and schema 4.91 XML. This is a source eligibility
check, not proof that an untested binary accepts a particular configuration.
The selected catalog inputs target 15.21; a different installed version needs
its own native configuration and recovery evidence.

## Selected acceptance executable

The disposable test input is now pinned in
`tests/fixtures/sysmon-executable.acceptance.psd1`: Microsoft-signed AMD64
`Sysmon64.exe` 15.22, 3,203,368 bytes. It was selected from the already retained
Sysinternals Suite snapshot `snapshot-20261017-e1e75de5`; no new payload download
or executable launch was needed. The executable, `Eula.txt` and `readme.txt`
match the [original acquisition inventory](archive/evidence/sysinternals-suite-source-review-2026-10-17.json).
The fixture records their exact hashes and source provenance. Keep the two
upstream notices alongside the executable when staging the guest.

The complete input set passes read-only checks in PowerShell 5.1 and 7: executable
digest, actual version, valid Microsoft Authenticode signature, AMD64 PE header,
both upstream notices, all three XML digests and their license, and the synthetic
baseline. The [input verification evidence](archive/evidence/sysmon-complete-inputs-2026-11-02.json)
records these checks. It does not establish installation or configuration acceptance.

The XML artifacts still target **15.21**. Selecting the retained **15.22** binary
does not relabel those artifacts or prove compatibility. The disposable run must
verify that this exact binary accepts each XML, produces the expected events and
recovers the known baseline. Do not replace a pin with whatever executable happens
to be installed, and do not interpret retained publisher notices as redistribution
approval or a personal/company license-review decision.

## Prerequisites and preview

Run from the repository directory in the intended target's PowerShell session.
Actual changes require existing elevation and fresh `-AllowCandidate`; no UAC
prompt is launched. Use only the disposable test guest for acceptance.

Provide both the new XML and the exact original XML, with reviewed SHA-256
digests. The original must match the SHA-256 recorded by the latest Sysmon
configuration-change event. Missing, ambiguous or SHA-1-only evidence refuses
the change. The workflow does not assume a text dump is restorable XML.
Microsoft documents `-c <file>` as configuration application and `-c` without
a file as a configuration dump; [event 16 records configuration changes](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

Create the local machine recovery directory explicitly. Each new record is
administrator-owned with protected Administrators/SYSTEM permissions; existing
file or directory permissions are not repaired automatically. Sources and
state must be local and have no reparse ancestors or alternate data streams.
XML is bounded to two MiB, its digest is checked and DTD/external-entity
processing is disabled. Keep the acquired license and upstream notices.

```powershell
Import-Module .\modules\RIDE.SysmonConfiguration.psm1
$selection = @{
  ConfigurationPath = 'C:\Inputs\sysmonconfig.xml'
  ConfigurationSha256 = '<reviewed-new-xml-sha256>'
  PriorConfigurationPath = 'C:\Inputs\previous-sysmon.xml'
  PriorConfigurationSha256 = '<reviewed-prior-xml-sha256>'
  ExecutablePath = 'C:\Windows\Sysmon64.exe'
  ExpectedExecutableSha256 = '<reviewed-service-executable-sha256>'
  ExpectedSysmonVersion = '15.21'
  ExpectedComputerName = '<disposable-guest-name>'
  ExpectedBuild = '26300'
  ExpectedEditionId = 'EnterpriseEval'
  StateDirectory = 'C:\RIDE\SysmonState'
}
Set-RideSysmonConfiguration @selection -WhatIf
```

Preview writes no files and launches no Sysmon process. It still checks source,
service, signature, target and recovery prerequisites. An unelevated session may
lack read access to the required event evidence; preview is not a promise that
later application will succeed.

## Apply and recover

```powershell
$run = Set-RideSysmonConfiguration @selection -AllowCandidate -Confirm:$false
Restore-RideSysmonConfigurationRun -RunId $run.RunId `
  -StateDirectory $selection.StateDirectory -WhatIf
Restore-RideSysmonConfigurationRun -RunId $run.RunId `
  -StateDirectory $selection.StateDirectory -AllowCandidate -Confirm:$false
```

Apply retains original and selected XML bytes plus an intent record before
launching the pinned executable. The checked XML is held open against write or
delete replacement while Sysmon reads it. Success requires a zero exit code,
a newer event 16 matching the retained path and SHA-256, and unchanged running
service/executable/target identity. Only then is an applied record saved.
Repeat application to the currently recorded desired hash returns
`AlreadyDesired` without a new run. There is no saved run ID to restore in that
case; preserve the ID from the actual change.

Restore validates the private original bytes, target/account/executable identity
and current event against the completed run before applying the captured XML.
It requires a new matching event and service health afterward. A repeated
restore returns `AlreadyRestored` when the original hash is already current.
`-RunId` completes from bounded local applied-record filenames without invoking
Sysmon or querying Windows configuration.

The configuration source path recorded by Sysmon becomes the retained private
XML path. Recovery restores the original XML content, not the historical event
record or source-path spelling. Original input files remain untouched. Event
hashes establish source correlation; they do not prove every rule's detection
behavior. No such broader claim is made by these commands.

Failure reports the run ID and retains source/state. Incomplete runs without an
applied record refuse automatic restore. Inspect service health, the latest
configuration event and retained XML before recovery. A 30-second command
timeout terminates only the child configuration process and leaves the run
incomplete; it does not stop or uninstall the service. An ambiguous timeout must
never be treated as proof that Sysmon rejected the new configuration.

Configuration recovery does not remove events, reverse telemetry already
collected or delete FileDelete archives. The FileDelete variant can archive
deleted files; Microsoft notes that its archive can grow substantially. Use the
disposable guest for the approved three-configuration scenario and retain that
distinction in its evidence. See [Sysmon FileDelete behavior](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-23-filedelete-file-delete-archived).

## Acceptance still required

The focused source tests use inert XML and mocked Sysmon, service and event
providers. They prove capture/recovery control flow and file checks, not native
acceptance. The three real pinned XML sources are independently parsed and
hash-checked without application.

Prepare a disposable Sysmon installation with a known XML baseline and retained
installation/source evidence. Apply each selected configuration explicitly,
verify its new event/source hash and service health, repeat without change,
then restore the baseline before the next configuration. Preserve correlated
before/after events and private state. Starting from undocumented/default
configuration is not sufficient for this XML recovery workflow; establish the
known fixture during separate disposable installation preparation.

The guarded guest scenario and optional known-baseline fixture preparation are
source-tested; protected controller dispatch and actual execution remain pending.
See [dated source evidence](archive/evidence/sysmon-configuration-source-2026-11-02.json)
and the [remaining-test assessment](migrations/migration-completion-reassessment-2026-11-02.md#required-evidence-by-remaining-family).

## Disposable guest entry point

`tests/integration/Invoke-RideSysmonAcceptance.ps1` offers two completable modes:
`PrepareFixture` and `Configurations`. Both require an independently identified
Windows 11 x64 Hyper-V guest, existing elevation for changes and controller-set
`RIDE_TEST_GUEST=1`, `RIDE_INTEGRATION_VM=1`, and `RIDE_TEST_RUN_ID` markers. The
request ID must match. The entry point refuses a workstation, target drift or
reused evidence directory and never prompts for elevation.

Starting in the staged repository's guest PowerShell session, supply the acquired
Microsoft `Sysmon64.exe` path, reviewed executable digest and actual version,
plus exact target identity. Retain the upstream executable license and acquisition
evidence separately. Create separate local evidence roots for preparation and
configuration acceptance.

```powershell
$executablePin = Import-PowerShellDataFile .\tests\fixtures\sysmon-executable.acceptance.psd1
$target = @{
  RunId = '<correlated-request-id>'
  ExpectedExecutableSha256 = $executablePin.Executable.Sha256
  ExpectedSysmonVersion = $executablePin.SysmonVersion
  ExpectedComputerName = '<disposable-guest-name>'
  ExpectedBuild = '26300'
  ExpectedEditionId = 'EnterpriseEval'
  DisposableVm = $true
}
$fixture = .\tests\integration\Invoke-RideSysmonAcceptance.ps1 @target `
  -Mode PrepareFixture -ExecutablePath 'C:\Inputs\Sysmon64.exe' `
  -EvidenceRoot 'C:\RIDE\SysmonFixtures' -WhatIf
```

For authorized preparation, replace `-WhatIf` with `-Confirm:$false`. Preparation
refuses existing `Sysmon`/`Sysmon64` services, known Sysmon drivers or destination
files. It records intent, retains the repository's synthetic schema 4.91 baseline
privately, rechecks absence and executable identity, then explicitly installs
with that XML and accepts the Sysmon EULA. Executable and XML handles deny
write/delete replacement during the installer call. Successful preparation needs
the pinned running service, a matching new configuration event and no new Sysmon
error event. Its result is `Prepared`, with `NativeAcceptancePassed=false`.

Preparation leaves the fixture installed. It is disposable setup, not package
installation acceptance or a captured restore of an existing installation. It
does not overwrite an existing configuration to manufacture a baseline. Existing
installations can use `Configurations` directly only when their original XML is
available and matches the current event hash.

After successful preparation, use its returned paths and digest:

```powershell
if ($fixture.Status -ne 'Prepared') { throw 'Known Sysmon fixture is not ready.' }
.\tests\integration\Invoke-RideSysmonAcceptance.ps1 @target `
  -Mode Configurations -ExecutablePath $fixture.InstalledExecutablePath `
  -BaselineConfigurationPath $fixture.BaselineConfigurationPath `
  -BaselineConfigurationSha256 $fixture.BaselineConfigurationSha256 `
  -InputDirectory 'C:\Inputs\sysmon-configs' `
  -EvidenceRoot 'C:\RIDE\SysmonAcceptance' -WhatIf
```

Use `-Confirm:$false` instead of `-WhatIf` for the authorized acceptance run. The
input directory must contain `license.md` and the retained acquisition layout
`<artifact-id>/a45dedb13a43/<asset-name>`. The versioned acceptance fixture lists
all three exact selected artifact IDs, file digests and the license digest. The
runner checks them against the catalog using its data-only reader before any
mutation. It does not download missing files or silently test a subset.

For each profile, five checks verify preview, apply, unchanged repeat, baseline
restore and unchanged repeated restore. Apply/restore require newer events with
the expected source hash/path and unchanged executable/service identity, with no
new event 255 errors. Actual machine-private records and captured XML hashes must
also validate. All fifteen checks must pass before the report can say `Passed`.
This does not claim exhaustive detection-rule coverage or cleanup of event logs
and FileDelete archives.

Private preparation intent, baseline XML and results remain in its request
directory. Configuration acceptance retains its initial observation, per-profile
before/applied/restored event identities, lifecycle run IDs and private state.
On failure it stops before later profiles and leaves evidence for inspection;
it never blindly restores or uninstalls. Fixture or partial-run cleanup uses the
separately controlled disposable checkpoint path and is not counted as a passing
configuration restore. Command and output waits are bounded, but a timed-out
installer can already have changed the guest and must be inspected.

The combined source suite passes 31/31 in both shells: 14 lifecycle cases and
17 orchestration/fixture/source-gate cases, with native providers mocked. The
real three-source/license gate also passes in each shell without Sysmon execution.
See [guest preparation evidence](archive/evidence/sysmon-acceptance-preparation-2026-11-02.json).

## Retained host dispatch

`Invoke-RideSysmonVmPhase` in `tests/integration/RIDE.SysmonVm.psm1` connects the
guest scenarios to the registered disposable lab. Run it directly from the
registered checkout in an **already elevated Windows PowerShell 5.1 x64** host
session, as the account that owns the installed controller. It reuses the lab's
guest credential without printing or saving it. No UAC, task registration or
generic queue request is launched. The installed controller does not currently
expose this route; a successful non-elevated preview does not grant execution.

Prepare requires the exact existing VM/checkpoint, an idle controller and an Off
guest. It reserves a durable controller hold, snapshots eight source/data files
and seven pinned inputs, then restores the clean checkpoint, starts the VM and
installs the known-baseline fixture. No legacy or component directory is staged.
The guest must match the selected Windows 11 build, edition, name and x64 Hyper-V
identity and have only `C:` as a fixed volume. The retained session also checks
the build revision before configuration acceptance.

Start in the repository root with the installed configuration path and local
inputs prepared as described above:

```powershell
Import-Module .\tests\integration\RIDE.SysmonVm.psm1
$session = @{
    ConfigurationPath = '<installed-controller-configuration.json>'
    RunId = [guid]::NewGuid().ToString('N')
}
$inputs = @{
    ExecutableDirectory = 'C:\Inputs\sysmon-executable-15.22'
    InputDirectory = 'C:\Inputs\sysmon-configs'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
}
Invoke-RideSysmonVmPhase @session @inputs -Phase Prepare -WhatIf
$prepared = Invoke-RideSysmonVmPhase @session @inputs -Phase Prepare -Confirm:$false
if ($prepared.Status -ne 'Prepared') { throw 'Retain the VM and inspect preparation evidence.' }
$tested = Invoke-RideSysmonVmPhase @session -Phase Configurations -Confirm:$false
if (-not $tested.NativeAcceptancePassed) { throw 'Retain the VM and inspect test/export evidence.' }
```

Prepare returns `Prepared`, never a native acceptance pass. Configurations must
return all five checks for each distinct pinned XML, exact executable/target
identity and captured baseline recovery. The host verifies and exports evidence
before setting its own `NativeAcceptancePassed` to true. This claims only the
three configuration lifecycles on the selected target and executable. It does
not promote a catalog operation or establish package-install/uninstall support.
Each retained run permits one Configurations attempt; existing evidence refuses
replacement. A failed attempt needs inspection and appropriate captured-state
recovery before cleanup or a new clean run.

`Collect` independently exports retained source, private state, a fresh complete
Sysmon Operational EVTX snapshot and readable `C:\Sysmon` archive files. Guest
paths are fixed; the host checks correlation, safe unique paths, sizes and
SHA-256 hashes and independently hashes each written file. Exports are private
to Administrators/SYSTEM. Limits are 512 entries, 16 MiB per file and 32 MiB per
collection. Prior EVTX snapshots remain retained and count towards these limits.
The collection is a point-in-time export, not an atomic snapshot of all activity.

Sysmon's [archive directory is protected by a SYSTEM ACL](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
The route does not change that ACL or start a SYSTEM helper. If the existing
guest account cannot read an archive, or evidence exceeds the limits, collection
fails and the VM/hold remain for a separately reviewed export. The native archive
permission and transport behavior still need verification. Event log export uses
the [Windows EventLogSession API](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.exportlog),
without clearing the channel.

After successful tests and review of exported evidence, explicit cleanup is:

```powershell
$recovered = Invoke-RideSysmonVmPhase @session -Phase Reset -Confirm:$false
if ($recovered.Status -ne 'ResetAndOff') { throw 'Keep the retained hold and inspect recovery evidence.' }
```

Reset requires another verified export, complete archive coverage and the loaded
synthetic baseline. It then restores the pinned checkpoint, verifies Off, writes
a private recovery receipt and releases only the matching hold. A retry from Off
requires a saved pre-reset intent and unchanged exported bytes. Reset is lab
cleanup, not evidence that captured configuration recovery passed. No automatic
reset runs after a failure. Early preparation failures before a session descriptor
or VM intent need controller recovery inspection.

Phase and edition values offer completion from their declared sets; later RunId
completion reads the private hold. Preview validates local inputs/configuration
but creates no hold, snapshot or VM session. Remote readiness is bounded to three
minutes; configuration execution to ten minutes; other remote jobs to three
minutes. Job timeout is not proof that every guest activity stopped. Existing
host dependency/Hyper-V calls have no additional watchdog.

The [host source evidence](archive/evidence/sysmon-vm-source-2026-11-02.json)
separates mocked dispatch checks, real local input checks and installed-controller
preview from unrun native installation, transport, archive export and recovery.
