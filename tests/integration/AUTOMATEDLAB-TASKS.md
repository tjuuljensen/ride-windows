# AutomatedLab task controller with host UAC enabled

This is an **opt-in implementation awaiting pilot validation**, not a certified
stable configuration. Existing direct VM commands continue to work. Do not
redirect the current Windows 11 lab until an agreed cutover.

## Configuration contract

| Item | Required configuration |
| --- | --- |
| Controller | 64-bit Windows PowerShell 5.1 |
| AutomatedLab | 5.61.0; AutomatedLab.Common 2.3.37 |
| Guest Pester | 5.7.1 |
| Host account | Existing lab administrator; same account for setup, task requests, watcher and CI runner |
| Task principal | `LogonType Interactive`, `RunLevel Highest` |
| Host session | Signed in, including locked; signed-out execution is unsupported |
| Host UAC | `EnableLUA=1`, prompting enabled, secure desktop enabled |
| VM | Explicitly disposable Hyper-V VM; one controller configuration per VM |
| Checkpoint | `RIDE-clean-test-base`, pinned by ID during registration |
| Results/configuration | `%ProgramData%\RIDE\TestAutomation\<Name>` |
| Guest security | AutomatedLab defaults; guest UAC changes are outside this workflow |

Windows can run an elevated scheduled task while UAC remains enabled. Initial
registration needs an elevated session; subsequent requests run from ordinary
PowerShell. The configured account receives task read/execute access, while
task ownership, worker files and configuration remain administrative.
[Microsoft task security](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks).

AutomatedLab host remoting is a separate requirement. Version 5.61.0 checks
WinRM, CredSSP, wildcard TrustedHosts, fresh/saved credential delegation and
`AllowEncryptionOracle=2`. Its setup can modify these policies. Keeping UAC on
does not remove those changes. Review and prepare them explicitly according to
[AutomatedLab's host-remoting documentation](https://automatedlab.org/en/latest/AutomatedLabCore/en-us/Enable-LabHostRemoting/).
The test controller checks existing preparation and fails instead of calling
`Enable-LabHostRemoting`. It also checks services before the upstream check,
which otherwise starts WinRM when stopped.

## 1. Prepare the host and a separate pilot

Finish existing jobs before changing host security or rebooting. Open 64-bit
**Windows PowerShell as administrator** and verify the actual token:

```powershell
[Security.Principal.WindowsPrincipal]::new(
  [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Get-Service vmms, WinRM
Get-VMHost
Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop
```

Hyper-V Administrators membership alone is insufficient for AutomatedLab's
elevation checks. A restricted agent shell can report a different effective
token or service view; verify in the real host session before diagnosing a
missing Hyper-V installation.

If you disabled UAC during troubleshooting, restore it through the policy/UI
that controls your host and reboot when existing work has stopped. On an
unmanaged Windows host, these are Microsoft's default recovery values; preserve
stricter organizational policies instead of overwriting them:

```powershell
# Explicit recovery only, after existing jobs finish; not part of test execution.
$policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty -LiteralPath $policyPath -Name EnableLUA -Value 1
Set-ItemProperty -LiteralPath $policyPath -Name ConsentPromptBehaviorAdmin -Value 5
Set-ItemProperty -LiteralPath $policyPath -Name PromptOnSecureDesktop -Value 1
# Save other work and reboot the host, then verify the values and elevation token.
```

[Microsoft UAC defaults and policy configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration).

Install the pinned AutomatedLab version using the upstream installation
instructions. Its companion modules must also be 5.61.0; do not mix versions.
The controller records the versions actually loaded, including remaining
dependencies, and rejects later drift. Dependency upgrades require revalidation.

Use [the provisioning guide](AUTOMATEDLAB.md) for a **separate pilot**. For
example, use lab `RIDEWin11Pilot` and VM `RIDE-W11-Pilot`, never the active
`RIDE-Win11-Test` lab during acceptance. Select the exact OS name from your ISO.
Install guest updates, Pester 5.7.1 and create the clean checkpoint through that
guide. Automatic task runs neither provision labs nor update Windows.

## 2. Register once

Copy `automation.example.psd1` to a local file outside the repository. Fill in
the real checkout paths, ISO used for provisioning, and pilot VM ID:

```powershell
Get-VM -Name 'RIDE-W11-Pilot' | Select-Object Name, Id
Get-VMSnapshot -VMName 'RIDE-W11-Pilot' -Name 'RIDE-clean-test-base'

# Example local seed: C:\RIDE-Automation\pilot.psd1
.\tests\integration\Register-RideVmTestTask.ps1 `
  -ConfigurationPath 'C:\RIDE-Automation\pilot.psd1' -WhatIf
.\tests\integration\Register-RideVmTestTask.ps1 `
  -ConfigurationPath 'C:\RIDE-Automation\pilot.psd1' -Confirm:$false
```

Registration does not start tests or restore the VM. It creates `\RIDE\<Name>`
and installs the worker, runner, collector and client into a protected `bin`
directory. No host or guest password is stored by the task; AutomatedLab uses
its existing lab credentials. The generated `configuration.json` pins VM and
checkpoint identities. `evidence.json` records host build, UAC settings,
dependency versions, ISO SHA-256, VM settings and installed controller hashes.
Its validation status starts as `NotValidated`.

Installed controller processes use `-ExecutionPolicy Bypass` for that process
only so Windows PowerShell's script policy cannot stall an unattended run.
Machine/user execution policies and UAC settings are not changed. Use
`Get-Help <script path> -Full` for the public scripts' parameter help; finite
`-Action` and `-Source` values offer completion through their declared sets.

Re-register after reviewed controller changes. Do not do so during a run.
Keep local seed files outside source control and use the same account that owns
the existing lab. Setup stops rather than replacing an unrelated task.

## 3. Request tests from ordinary PowerShell

```powershell
$configuration = "$env:ProgramData\RIDE\TestAutomation\RIDEWin11Pilot\configuration.json"
$client = Join-Path (Split-Path -Parent $configuration) 'bin\Invoke-RideVmTestTask.ps1'
& $client -ConfigurationPath $configuration
# Faster diagnosis without real RIDE operations:
& $client -ConfigurationPath $configuration -UnitOnly
```

`-Source Local` is the default. `-Source CI` selects the separately approved CI
checkout. Requests cannot supply arbitrary command text, worker scripts or VM
identities. `-TimeoutMinutes` defaults to 90 and includes queue waiting; the
client allows five additional minutes for recovery. `-ReceiptPath <json>`
exports the run ID and exact result directory even when the run later fails.

The worker claims requests once in order and holds an exclusive lock. The client
retries starting pending work, covering the race where a worker is exiting.
Each run stages an immutable copy, including uncommitted/untracked source files,
and records file hashes. Git metadata, private presets/configuration, caches and
test outputs are excluded. Reparse points are rejected. A detected edit during
file copy fails the request; submit again after edits settle.

The worker restores the clean checkpoint, starts the guest, checks guest
administrator access, and invokes the existing VM runner with optional exports.
The guest generates documentation, validates, runs Pester and runs the guarded
integration suite. Results must identify the request and confirm every requested
stage; a zero process exit code alone cannot produce success.

Before restoring the checkpoint again, collect `guest/transcript.log`,
`guest/pester.xml`, `guest/summary.json` and saved machine/user RIDE state.
Installer caches are excluded. Failures and timeouts attempt additional partial
collection with a separate 60-second bound. Unreachable guest evidence is
reported as `CollectionError`, and reset still proceeds. The VM remains off on
the clean checkpoint after each run.

`result.json` contains the terminal status, errors, cleanup outcome and before/
after host UAC settings. Keep the complete result directory for diagnosis.
Source snapshots and results are retained; there is no automatic deletion.

## 4. Watch local edits

Run from ordinary PowerShell in the same signed-in account:

```powershell
.\tests\integration\Watch-RideVmTests.ps1 -ConfigurationPath $configuration
```

The watcher polls every two seconds and waits 30 quiet seconds before requesting
the full suite. It watches modules, catalog, profiles, components, tests, tools
and maintained entry scripts (including `docs/bootstrap.ps1`). It excludes Git internals, generated
documentation and test outputs. Edits during a run yield one subsequent run
after they settle. Failures are printed without silently disabling the watcher.
Ctrl+C stops watching; the active task finishes collection and recovery.

## 5. GitHub Actions

Configure a **repository-scoped** self-hosted Windows x64 runner with label
`ride-hyperv`, installed at `C:\RIDE-CI\runner` for the example configuration.
Run `run.cmd` unelevated under the same signed-in account, not as a Windows
service. The runner can remain active while the session is locked; signing out
ends this execution model. Verify its actual checkout path matches
`CIRepositoryPath` before requesting tests.

Set repository Actions variables:

| Variable | Value |
| --- | --- |
| `RIDE_AUTOMATION_CONFIGURATION` | Full path to installed `configuration.json` |
| `RIDE_VM_TESTS_ENABLED` | `true` only after pilot acceptance and agreed activation |

The separate `vm-integration.yml` workflow runs on `master` pushes or manual
dispatch on `master`. It checks out into the CI workspace, invokes the installed
client, and uploads only that request's logs, summary, hashes and guest evidence
even after failure. It excludes the staged source snapshot. Repository content
permissions are read-only. Existing hosted validation for pushes/pull requests
is unchanged; pull requests do not invoke this VM workflow. Only trusted
maintainers should control code/workflows executed on this personal host.
[GitHub guidance for self-hosted runner security](https://docs.github.com/en/actions/reference/security/secure-use).

## Recovery and teardown

Failed cleanup creates `runtime/blocked.json`. An interrupted worker also blocks
later work if it finds a request in `queue/running`. Subsequent requests fail
until explicit recovery. Do not clear the block while any controller or collector
process remains active.

Stop the watcher/CI runner. In elevated PowerShell, inspect the registered task,
its child processes, the matching request directory and logs. After confirming
the worker and its children have stopped, load the installed helpers and restore
only the verified pilot:

```powershell
$root = Split-Path -Parent $configuration
Import-Module (Join-Path $root 'bin\RIDE.TestAutomation.psm1') -Force
$config = Read-RideAutomationConfiguration $configuration
$null = Assert-RideAutomationHost $config
Reset-RideAutomationVm $config
# Archive any interrupted queue/running request to queue/finished after recording
# the interruption in its result directory. Then clear only this block marker:
Remove-Item -LiteralPath (Join-Path $root 'runtime\blocked.json') -ErrorAction SilentlyContinue
```

If a checkpoint was deleted or replaced, recovery refuses it: investigate and
revalidate a new clean baseline before re-registering. Never point the controller
at another checkpoint merely to bypass the identity check. A host UAC drift
failure also requires inspection; the controller never repairs UAC automatically.

Remove the task with the repository registration script in elevated PowerShell:

```powershell
.\tests\integration\Register-RideVmTestTask.ps1 `
  -ConfigurationPath $configuration -Action Remove -WhatIf
.\tests\integration\Register-RideVmTestTask.ps1 `
  -ConfigurationPath $configuration -Action Remove -Confirm:$false
```

Removal retains configuration, queue, snapshots and results. Disable the GitHub
workflow variable and stop the watcher/runner separately. It does not undo host
remoting policies or change UAC; review policy recovery against your captured
baseline rather than resetting unrelated configuration to Windows defaults.

## Pilot acceptance and replication evidence

### Runtime evidence, 2026-10-08

The user confirmed the locked-PC full-suite test passed. Ordinary-shell
controller request `20cb460af8be447dafcfc62662f99d35` also passed all 103 guest
tests and integration, including Git installation, local commit verification,
repeat installation and removal. Failure requests
`a2a2539763bf43e4a2981404d33a39e2` and
`e58d341c3b7d443e8807a34f3834972b` collected observations and state, reported
failure and completed checkpoint recovery with unchanged host UAC. A failed
unit-test request `92e7d36ff7b34f94a5055441ad85fe4d` also failed explicitly.
These are useful runtime results, not full pilot certification.

Full request `9744844940fd4ca498ef6486092ac831` passed 128 guest tests and
integration, including Git functionality, standalone Git LFS, Joplin, ShareX,
WinDirStat, PowerShell 7, Sysmon and two new user-policy round trips. It ran
2026-10-08 13:15:56-13:33:55 UTC. The user confirmed the host remained locked
throughout this run, so it supplies additional locked-session evidence.
Collection and cleanup errors were null; UAC remained 1/5/1. A separate native
Hyper-V read confirmed `RIDE-Win11-Test` was Off and its pinned
`RIDE-clean-test-base` checkpoint GUID remained
`a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9`.

Together with ordinary-shell request `20cb460af8be447dafcfc62662f99d35` and
watcher-triggered request `fd51fb002a1d4741a938381c41e5acd8`, these provide
ordinary-shell, locked-session and watcher-triggered full-suite passes in that
order. The failure requests above occurred between the ordinary-shell and
locked-session passes, so that earlier trio was not consecutive. A fresh,
uninterrupted sequence later passed in order: ordinary-shell
`d5f80c427abc4f83837c50949d5c56f8`, locked-session
`4140ba445a0844af851f774584fc89e2`, and watcher-triggered
`a64381f1d64c4d2cb50af20604e9de89`.

The registered worker may retain older protected runner/collector copies.
The guest suite exports observations through the existing results-path handoff;
new source versions make that handoff explicit and collect observations on
failure. Apply those protected-copy updates through elevated registration when
the worker is idle; editing repository copies alone does not update installed
controller hashes. Do not overwrite protected binaries manually.

The watcher requirement has runtime evidence from requests
`fd51fb002a1d4741a938381c41e5acd8` and
`a64381f1d64c4d2cb50af20604e9de89`. CI dispatch/push, overlapping local/CI
requests, timeout/interruption recovery and Server acceptance below still need
runtime evidence. Keep `evidence.json` validation status unchanged until those
requirements pass.

An earlier sequence attempt began with ordinary-shell request
`88176dd6babb4bd0809689e4223860b1`, which passed validation, integration and
134/134 Pester tests on 2026-10-09 06:38:11-07:16:18 UTC. The following full
request, `d0a464fb89594a309dc6dff4f8633cb5`, passed but the user unlocked the
host before it finished, so it did not satisfy the locked-session case and
interrupted that sequence.

A restarted ordered sequence began with ordinary-shell request
`d5f80c427abc4f83837c50949d5c56f8`, which passed validation, integration and
134/134 Pester tests on 2026-10-09 10:14:48-10:30:28 UTC. Execution, collection
and cleanup errors were empty; host UAC remained 1/5/1.

Locked-session request `4140ba445a0844af851f774584fc89e2` passed validation,
integration and 134/134 Pester tests on 2026-10-09 10:34:05-10:52:18 UTC.
The user confirmed the host remained locked throughout. Execution, collection
and cleanup errors were empty; host UAC remained 1/5/1.

Watcher-triggered request `a64381f1d64c4d2cb50af20604e9de89` passed validation,
integration and 134/134 Pester tests on 2026-10-09 12:12:26-12:30:04 UTC.
Execution, collection and cleanup errors were empty; host UAC remained 1/5/1.
This completes the fresh uninterrupted three-run Windows 11 sequence.

Acquisition observations are collected as metadata in each request's
`guest/artifact-observations.json`. Review and merge using
`tools/Import-RideArtifactObservations.ps1`; see the verification matrix for
retention and interpretation. Installer caches are excluded from collection
and disappear when the checkpoint is restored.

Do not label this configuration stable until all applicable checks pass:

1. Three consecutive complete Windows 11 runs: ordinary-shell request,
   locked-session request, watcher-triggered request. Save each run ID.
2. Manual GitHub dispatch, then a trusted `master` push; verify exact CI source
   hashes and uploaded evidence.
3. Overlapping local and CI requests: distinct correlated results, no concurrent
   guest testing, and checkpoint restoration between runs.
4. A deliberate failing test in the pilot checkout, a bounded timeout and a
   missing-checkpoint configuration: all fail, never report success. Missing
   checkpoint preflight must leave the VM untouched.
5. Simulated cleanup failure/interrupted worker: later work blocks and the
   explicit recovery procedure restores the pinned checkpoint.
6. Host UAC unchanged, guest identity/build/Pester version recorded, state
   evidence collected, VM returned to the clean checkpoint after every run.
7. Windows Server 2025 acceptance performed separately before calling that
   configuration validated.

Record results and any unavailable scenarios alongside `evidence.json`, using a
local `acceptance.md` with dates, configuration/controller hashes, run IDs,
outcomes and cutover decision. Registration and mocked tests do not establish
runtime stability. Reproduce on another host from the pinned dependency list,
matching ISO hash and declared VM settings, regenerate host/VM-specific IDs,
and repeat acceptance. Existing labs move only after the agreed cutover.
