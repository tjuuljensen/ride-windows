# Hibernation file mode and size

`windows.hibernation` is an optional Windows 11 implementation candidate. It is
excluded from all bundled profiles. Apply and preview require explicit
`-AllowCandidate` while disposable Windows acceptance is pending. Windows
Server support is not declared. The source supports Windows PowerShell 5.1 and
PowerShell 7 on Windows; mocked tests do not establish native behavior.

The operation controls `hiberfil.sys` as one machine setting because enabling,
file type and sizing affect each other. It requires administrator privileges
for writes and enough free space on the system drive. It never requests an
immediate suspend, shutdown or restart.

| State | Requested behavior |
| --- | --- |
| `Off` | Run `powercfg /hibernate off`. Remove the file, preventing hibernation, hybrid-sleep recovery and Fast Startup. |
| `Full` | Enable hibernation and request `/type full`, without an explicit size command. An already full file, including a custom-sized one, is left alone. Windows can resize a file when changing its type. |
| `Reduced` | Enable the file, reset sizing with `/size 0`, then request `/type reduced`. This supports Fast Startup only, not session hibernation or hybrid sleep. |
| `Size50` through `Size100` | Enable a full file and request `/size NN`, where NN is an integer percentage of physical RAM, not GB or a percentage of the previous file. |

For example, `Size75` requests 75% of physical RAM. Actual allocation and successful
hibernation still depend on Windows and the device. Microsoft documents a 40%
full-file default and a 20% reduced-file default in its
[power-state reference](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#hibernation-file-types),
while the [powercfg reference](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#hibernate-or-h)
states a 50% minimum for custom sizing and documents the special `/size 0` reset.
The candidate therefore exposes conservative explicit sizes of 50..100, keeping
the OS-managed reset inside the Reduced transition. It does not advertise those
default percentages as verified defaults for every target or configuration.

Fast Startup's own preference, the Hibernate menu checkbox, power-plan timers,
button actions and lid actions remain independent. A reduced file does not mean
Fast Startup is enabled, and a full file does not prove S4 is available or that
resume works. Firmware, drivers and managed policies can limit the result.

## Discovery and proposed use

From the repository root, these discovery commands are read-only:

```powershell
.\ride.ps1 search hibernation
.\ride.ps1 show windows.hibernation
```

`show` reads native power capabilities, the configured `HiberFileSizePercent`
and file metadata. It reports mode, percentage, file bytes, S4 availability and
whether the observation has an understood recovery path. Denied inspection is
an error; an unknown or incomplete configuration is unavailable for writes.
It does not infer file type from localized `powercfg /a` prose.
Read-only `show` is available while normal apply is gated. The reader uses
file metadata directly because Windows PowerShell 5.1 `Get-Item -Force` can
misreport an existing active hibernation file as missing. It does not open the
file contents, and genuine metadata errors remain errors rather than implying Off.

From an elevated PowerShell session at the repository root, explicitly opt in
to candidate preview before choosing a change:

```powershell
.\ride.ps1 set windows.hibernation -State Reduced -AllowCandidate -WhatIf
.\ride.ps1 set windows.hibernation -State Full -AllowCandidate -WhatIf
.\ride.ps1 set windows.hibernation -State Size75 -AllowCandidate -WhatIf
```

Tab completes the operation ID and both named and positional states from the
same catalog used for execution. There is no arbitrary native-command argument,
separate percentage parameter, `Baseline` alias or `unset` state. Omitting
`-WhatIf` applies the selected change and captures prior state. The switch
permits only the declared Windows 11 candidate; it does not grant Server support,
bypass privilege/build/handler checks, or establish native acceptance. Keep
state-changing acceptance testing on disposable targets.

## Capture and recovery

The engine saves a version-1, operation-bound snapshot under the machine state
store before the first native command. It captures active file mode and the
observed percentage together. The handler rechecks that configuration before
writing, checks each command's exit code, and verifies the final observation.
A failed command stops the sequence; the engine reports the saved run ID for
recovery. Repeat application is a no-op when the requested state already matches.

Recovery is **conditional configuration recovery**, not exact file restoration:

- A prior full file is recreated with its captured percentage. A captured 40%
  default is requested through Windows-managed sizing and its result is checked.
- A prior reduced file is recreated through `/size 0` followed by `/type reduced`.
- A prior Off state restores file absence. Inactive registry sizing/type values
  left behind while disabled are not replayed.
- The prior file contents, hibernated session, exact byte allocation and registry
  value absence are not restored. A changed Windows sizing result fails the
  recovery postcondition rather than being reported as exact restoration.
- Saved-run recovery intentionally reapplies the captured configuration; later
  manual mode/size changes may be overwritten. Review the saved run first.

The candidate recognizes full sizing observations of 0, 40 and 50..100 and reduced
observations of 0 or 20. Other active configurations are refused before apply
until their recovery behavior has evidence. No direct registry writes or manual
deletion of `hiberfil.sys` are used. The regular recovery interface is
`.\ride.ps1 restore -RunId <saved-run-id> -AllowCandidate` with elevation for
machine scope. Use the same command with `-WhatIf` first. The opt-in must be
supplied again for restore; it is not inherited from the saved run.

## Disposable Windows 11 acceptance

The prepared `HibernationMatrix` fixture runs through the existing settings
fixture runner. It permits only `windows.hibernation`, Windows 11 and the six
ordered states below. The runner validates the request ID, elevation and Hyper-V
guest identity before creating a temporary private catalog override for this
single operation. The published catalog and bundled profiles stay unchanged.
Never invoke the guest runner or set its guest markers on a workstation.

| Starting configuration | Choices exercised from each starting configuration |
| --- | --- |
| Off | Off, Full, Reduced, Size50, Size75, Size100 |
| Reduced | Off, Full, Reduced, Size50, Size75, Size100 |
| Full at Size75 | Off, Full, Reduced, Size50, Size75, Size100 |

Each of these 18 cases checks apply preview, native desired-state observation,
repeat application without new commands or runs, saved predecessor content,
restore preview, captured configuration recovery and repeated restore. Each
case returns to its starting configuration; each starting configuration returns
to the original. A final controlled interruption occurs after the real
`/hibernate /size 0` succeeds while changing Size75 to Reduced, before the type
command. The test requires an observed partial change and recovery from its
saved run. This exercises interruption recovery, not a native disk/access error.

Evidence includes build, PowerShell version, RAM, initial disk space, source
hashes, mode/percentage/file bytes/S4 observations, raw `powercfg /a` diagnostics,
native command outcomes and saved run IDs. Fast Startup/menu/mirror/policy
registry preferences and the active power scheme are compared throughout.
No sleep, shutdown or reboot is requested. File bytes and S4 availability are
observations; recovery compares active mode and percentage, ignoring dormant
sizing when Off. `ExactRecovery` remains false.

### Prepare a bound source copy

Start in the repository root on a Windows Hyper-V host. Use a dedicated disposable
Windows 11 VM, a known clean checkpoint, Pester 5.7.1 in the guest, and its guest
administrator credentials. Reserve exclusive access to this VM for the whole run;
do not share it with an active test controller. The matrix needs enough system-drive
space for a full RAM-sized file plus 64 MiB; native allocation can still fail.
The harness fails before writing if initial observation is not recoverable or
the capacity check fails. Use Windows-native PowerShell, elevated for the VM steps.

This preparation copies current source, including uncommitted changes, into a
unique directory. It does not start a VM. Do not put the bound fixture in the
development checkout: its presence changes guest suite selection.

```powershell
$ErrorActionPreference = 'Stop'
$source = (Get-Location).Path
$runId = [guid]::NewGuid().ToString('N')
$stage = Join-Path $env:TEMP ('RIDE-hibernation-source-' + $runId)
$results = Join-Path $source ('.local\acceptance\hibernation-' + $runId)
New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
Get-ChildItem -LiteralPath $source -Force |
    Where-Object Name -NotIn @('.git', '.local', 'testResults.xml') |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $stage -Recurse }
$template = Join-Path $stage 'tests\integration\fixtures\hibernation.fixture.psd1'
$bound = Join-Path $stage 'tests\integration\settings-validation.fixture.psd1'
$text = [IO.File]::ReadAllText($template).Replace(('0' * 32), $runId)
[IO.File]::WriteAllText($bound, $text, [Text.UTF8Encoding]::new($false))
Import-Module (Join-Path $stage 'modules\RIDE.SettingsFixtureData.psm1') -Force
$null = Read-RideSettingsFixture -Path $bound -RunId $runId -IntegrationSuite SettingsBatch60 -CatalogPath (Join-Path $stage 'catalog\operations.psd1')
New-Item -ItemType Directory -Path $results -ErrorAction Stop | Out-Null
git rev-parse HEAD | Set-Content -LiteralPath (Join-Path $results 'source-revision.txt')
git status --short | Set-Content -LiteralPath (Join-Path $results 'source-status.txt')
Copy-Item -LiteralPath $bound -Destination (Join-Path $results 'request.fixture.psd1')
```

Keep the staged source until evidence review finishes: the commit ID alone does
not identify uncommitted source. The all-zero template ID is deliberately rejected.

### Run and recover the disposable guest

Use the manual VM runner with the exact bound `RunId`. The registered queue/task
runner generates its own ID and is not the route for this prebound fixture.
`SettingsBatch60` selects this fixture in place of the general settings suite;
it does not apply all settings. Do not add `-UnitOnly`.

First preview the existing runner; this does not start the VM or dispatch tests:

```powershell
$vmName = '<dedicated Windows 11 VM name>'
$checkpointName = '<clean checkpoint name>'
$runner = Join-Path $stage 'tests\integration\Invoke-RideVmTest.ps1'
& $runner -Transport PowerShellDirect -VMName $vmName -RepositoryPath $stage -RunId $runId -IntegrationSuite SettingsBatch60 -ResultDirectory $results -WhatIf
```

The manual runner does **not** restore a checkpoint. In the same attended host
session, select exactly one VM/checkpoint and restore the clean starting point:

```powershell
$vm = Get-VM -Name $vmName -ErrorAction Stop
if (@($vm).Count -ne 1 -or $vm.State -ne 'Off') { throw 'Select one powered-off disposable VM.' }
$checkpoint = @(Get-VMSnapshot -VM $vm -Name $checkpointName -ErrorAction Stop)
if ($checkpoint.Count -ne 1 -or $checkpoint[0].VMId -ne $vm.Id) { throw 'Select one clean checkpoint for this VM.' }
Restore-VMSnapshot -VMSnapshot $checkpoint[0] -Confirm:$false
Start-VM -VM $vm | Out-Null
```

Wait for Windows to finish booting and PowerShell Direct to become available
before dispatch; the manual transport does not retry a premature connection.

```powershell
& $runner -Transport PowerShellDirect -VMName $vmName -RepositoryPath $stage -RunId $runId -IntegrationSuite SettingsBatch60 -ResultDirectory $results
```

The runner prompts for the guest administrator credential and exports results
even when testing fails. Inspect `$results\guest\summary.json`,
`$results\guest\settings-fixture.json`, the transcript/Pester results and exported
machine state records. Both reports must match `$runId`; require summary and
fixture `Status = Passed`, 18 passing cases, `ControlledFailure.Triggered` and
`ControlledFailure.RecoveryPassed`, `LifecyclePassed`, `RecoveryPassed`, empty
`UnrecoveredRunIds`, and no error/recovery error. A refusal or incomplete matrix
is not a pass. A native error retains its command outcome and failure evidence.

On failure the guest preserves its private candidate directory, reported as
`PrivateCandidateRoot`, together with saved run IDs. The harness attempts recovery
in reverse order. If export failed, collect the guest evidence from
`C:\RIDE\TestResults\<runId>` and the machine state store before discarding it;
retain the staged source and private candidate copy if recovery diagnosis needs
them. Recovery through the public CLI requires `-AllowCandidate` while the
catalog target is pending. Use only the matching guest's saved run and source;
the run ID is not transferable recovery state for a different machine.

After evidence has been exported, reset the disposable VM regardless of pass or
failure. Run these cleanup commands separately even if the test command threw:

```powershell
if ((Get-VM -Id $vm.Id).State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Confirm:$false }
Restore-VMSnapshot -VMSnapshot $checkpoint[0] -Confirm:$false
if ((Get-VM -Id $vm.Id).State -ne 'Off') { throw 'Disposable VM did not return to Off.' }
```

Retain host evidence and record checkpoint recovery separately from RIDE's
configuration recovery. Review the [dated preparation record](migrations/settings-post-migration-review.md#hibernation-acceptance-preparation-2026-11-01)
before any support declaration changes.

## Acceptance still required

Preparing or passing this configuration matrix never enables normal apply:
`PromotionReady` and `PowerTransitionPassed` remain false. No disposable Windows
run has yet been recorded for this candidate. A VM lacking S4 may accept file
configuration commands, or refuse them; record that actual result without
claiming hibernate/resume support. Unsupported native behavior is a failed
configuration case, not a skipped success.

Actual hibernate/resume, hybrid-sleep recovery and Fast Startup behavior require
separate observed power-transition acceptance on suitable disposable hardware.
Native access denial, actual disk exhaustion, unexpected native sizing, managed
precedence and target defaults also remain acceptance work; the prepared harness
does not exhaust a disk or change permissions. Server remains a separate future
review and acceptance batch. The [legacy mapping](migrations/settings-post-migration-review.md#hibernation-file-control-candidate-2026-11-01)
retains the deferred menu/mirror scope. Do not promote the candidate based only
on successful commands or registry round trips.
