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

The guarded guest scenario and protected controller dispatch remain pending.
See [dated source evidence](archive/evidence/sysmon-configuration-source-2026-11-02.json)
and the [remaining-test assessment](migrations/migration-completion-reassessment-2026-11-02.md#required-evidence-by-remaining-family).
