# Screen-lock helper impact evaluation

Evidence dates: 2026-10-11 and 2026-10-12 (Europe/Copenhagen; timestamps below use UTC). **Preliminary Windows 11 full/Light, Zhorn x64 and idle-host pilots
are recorded; campaign acceptance remains pending. No memory, execution-write
or idle-lock-prevention ranking has been established.**

## Findings and practical selection

The goal is preserving an already unlocked session when a physical jiggler or
another suitable option is unavailable. A tool must pass the actual idle-lock
test before a footprint advantage matters. None of these tools unlocks a locked
session. A successful package deployment, loop, or power request is insufficient.

| Option | Established by source or publisher documentation | Practical implication pending measurements |
| --- | --- | --- |
| Full RIDE caffeine 0.2.2 | Scroll Lock pair immediately and every 120 seconds by default; console clearing/colors/title; hourly reports; optional duration | Keep it for visible status and configurable cadence. `-NoConsoleCustomization -ReportIntervalSeconds 0` avoids those optional actions. Console clearing cannot be reversed. |
| Light RIDE caffeine 0.1.0 | Same key pair, fixed 60 seconds, indefinite, zero parameters; one COM object; start/stop messages | A straightforward fallback if an interactive PowerShell host and WScript.Shell already work. Smaller source does not establish lower total host memory. |
| Zhorn Caffeine 1.98 | Default F15 key-up every 59 seconds; configurable cadence/keys; separate power-request switches | Evaluate the native executable if a new PowerShell host is undesirable. Its total memory advantage is a hypothesis. F15 can affect foreground applications. |
| Arkane Mouse Jiggler 3.0.0 | Normal and Zen mouse modes; mainline needs .NET 10 Desktop Runtime; standalone bundles its runtime; source saves user settings | Evaluate mouse input when keystrokes interfere. Existing runtime availability matters for deployment cost. Standalone avoids a runtime install but is much larger on disk; neither packaging size establishes RAM use. |

The script statements are inspection of the pinned working-tree files. Zhorn
describes F15 key-up, Shift/full-key alternatives and power-request behavior on
its [official page](https://www.zhornsoftware.co.uk/caffeine/).
Arkane's [release readme](https://github.com/arkane-systems/mousejiggler/blob/3.0.0/README.md)
and [project file](https://github.com/arkane-systems/mousejiggler/blob/3.0.0/MouseJiggler/MouseJiggler.csproj)
describe packaging. The pinned
[MainForm source](https://github.com/arkane-systems/mousejiggler/blob/3.0.0/MouseJiggler/MainForm.cs)
saves settings in property setters, including period and distance set during
construction. CLI options are not evidence of configuration-free execution.
Zen avoids visible pointer travel; its effect on each lock mechanism still needs
testing. Keep the release's modified Microsoft Public License (Ms-PL) and notices
with both Arkane packages; do not describe it as unmodified Ms-PL. Licensing
is not a selection obstacle for this user's evaluation; no new catalog entry,
startup entry or real-host deployment was requested.

For forensic work, use a guest-verified mode and record the exact invocation.
Prefer an already available execution path that meets the behavioral requirement
and the investigation's write/configuration constraints. Do not install a runtime
on the investigated system merely to improve a hypothetical memory ranking.
The scripts intentionally have no file/registry/startup writes, but PowerShell,
COM activation, Windows and security services can leave execution artifacts.
The key pair is not atomic and can leave Scroll Lock changed if interrupted.
All options require foreground/elevation and cleanup checks below.

## Evidence obtained and execution boundary

[Detailed pilot and tracing evidence](archive/evidence/screen-lock-pilots-2026-10-11-12.md)
retains the dated runs, failures, measured values, hashes and instrumentation
limits. The [development record](archive/evidence/screen-lock-helper-development-2026-10-11.md)
retains implementation and harness validation. The acceptance table below owns
the current open campaign work; archiving run narratives does not accept it.

Before running a case, check current VM/checkpoint identity, controller queues,
watchers and ownership using the [AutomatedLab runbook](../tests/integration/automatedlab.md).
Do not infer present guest state or permission from a dated report. Use an actual
interactive guest desktop and record the session and transport; remoting alone
does not establish input delivery.

## Pinned evaluation inputs

Source HEAD: `5b672ad3d0949990a3430aca722c0f8721d095b4`, with uncommitted changes.
The script hashes identify actual evaluation bytes; HEAD alone does not.
Acquisition used the current checkout, not committed release defaults.

| File | Version / architecture | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `scripts/caffeine.ps1` | 0.2.2 / host-dependent | 8,895 | `79f297a942322f9670763957a8fd01b620f854708b1971f7e90a5d81abaf3c4d` |
| `scripts/caffeine-light.ps1` | 0.1.0 / host-dependent | 2,834 | `8d2db98db485803fb12510b33a365e79171e55601220b84173f9dc0254ca17ed` |
| `zhorn/caffeine32.exe` | 1.98 (`1, 9, 8, 0`) / x86 | 337,408 | `327fe70ed4f6502ebf8f3d4c5f890960eb7a357529c14f078999829b6f78fb9d` |
| `zhorn/caffeine64.exe` | 1.98 (`1, 9, 8, 0`) / x64 | 438,784 | `98c0af01b4257e12679aaba3c148cdc95c9168f95ad17add25287a584d9070bf` |
| `arkane-mainline/MouseJiggler.exe` | 3.0.0.0 / x64 | 24,997,331 | `8ced59411379259d00bf37a2a4f77589421b68d4032ba95e4c354e180b8f32bd` |
| `arkane-standalone/MouseJiggler.exe` | 3.0.0.0 / x64 | 140,864,731 | `185ff8d8cfebd8d9b3905a281e0143035d96595f8853ad5d5c3bc7ed8e07d8af` |

Both Arkane executables' product version resources identify
`3.0.0+3e3ceb71f4e3e0d9810ea7de81557d0d19debbaa`. Architecture was checked in
the executable PE headers; version inspection did not execute them.

Official archives (acquired and hashed locally):

| Source | Bytes | SHA-256 |
| --- | ---: | --- |
| [Zhorn caffeine.zip](https://www.zhornsoftware.co.uk/caffeine/caffeine.zip) | 316,991 | `4a259c348e59eb51bbb75aac7fdcc798705496d575892ee1e01fff6970d5ba1c` |
| [Arkane 3.0.0 mainline x64](https://github.com/arkane-systems/mousejiggler/releases/download/3.0.0/MouseJiggler-mainline-x64.zip) | 6,372,841 | `389bc7e4166aeb9c3b43380fad9dd3e4e65ddd0de5e6f25f296c9d3bcc5bcc16` |
| [Arkane 3.0.0 standalone x64](https://github.com/arkane-systems/mousejiggler/releases/download/3.0.0/MouseJiggler-standalone-x64.zip) | 52,274,827 | `7b4d95659b3777789e7cfaff62e60f095e06ad6d321dd61c65dd87f792339953` |

Arkane release API asset digests matched local ZIP hashes. Zhorn's mutable URL
is pinned by the existing catalog acquisition hash; changed bytes must fail
acquisition rather than silently enter the campaign. ARM64 is excluded from
this x64 VM campaign. The Zhorn legacy installer is outside portable execution
cost; assess separately if deployment is later relevant.

The identified local evidence root is
`C:\Users\tjuuljensen\git\ride-windows\.local\screen-lock-impact\2026-10-11`.
`inputs/manifest.json` contains file hashes, archive URLs, version resources,
launch cases, source revision/status and acquisition timestamp. Notices and
payloads remain under `inputs/`; `host-inventory.json` records access findings.
Large guest PML/CSV/JSON traces belong under `runs/<target>/<case>/<repetition>/`
after collection. `binary-inspection.json` records architecture checks;
`validation-Desktop.json` and `validation-Core.json` record 10/10 synthetic tests
and parser/native-help checks in Windows PowerShell 5.1.26100.9549 and PowerShell
7.6.5. Pester 5.7.1's unused TestRegistry plugin was disabled in sandboxed local
validation. There are **no real guest run traces yet**. Synthetic test
fixtures and acquisition files must never be counted as benchmark results.
`.local/` is already ignored; results do not enter catalog acquisition evidence.

## Reproduce acquisition and choose cases

From the Windows-hosted checkout, using native PowerShell:

```powershell
.\tests\integration\New-RideScreenLockInputs.ps1 `
  -Destination .\.local\screen-lock-impact\new-campaign\inputs -WhatIf
# Repeat without WhatIf to acquire. Nothing is launched or installed.
```

Stage the acquired directory and the current checkout in the reserved guest.
The manifest uses relative paths and `{Inputs}` substitutions, so guest paths
can differ from host paths. It does not bypass execution policy; record policy
and prerequisite failures. Pin the guest PS7 executable/runtime before creating
the measurement checkpoint. Mainline Arkane requires the matching .NET 10
**Desktop** Runtime, not just the base .NET runtime. Record exact version,
architecture, installer source/hash, install/extraction file changes and reboot
cost in a separate deployment experiment. Standalone must also be tested on a
checkpoint without an externally installed .NET Desktop Runtime. Repeat on a
runtime-equipped checkpoint for a direct packaging comparison.

The manifest declares 33 cases. For each PowerShell host it includes an idle
control, full defaults, full quiet defaults, full at 60 seconds, full quiet at
60 seconds, and fixed light. Host launch is
`<host> -NoLogo -NoProfile -File "<script>" <options>`, using `powershell.exe`
or `pwsh.exe`.
Full defaults are indefinite with hourly reports; quiet options are
`-NoConsoleCustomization -ReportIntervalSeconds 0`. The light case receives
**no parameters** and remains indefinite. An existing interactive PowerShell
console can be evaluated as an additional scenario, with its own idle control;
do not present the incremental script cost as the cost of a new host process.

For each Zhorn architecture: empty arguments (F15 key-up/59 seconds), `60`,
`60 -useshift`, `60 -keypress`, `-stes` and `-allowss`.
Power-request cases are labeled separately and cannot count as proven
input-based lock prevention. For each Arkane packaging: empty arguments
(first-launch/configuration experiment, jiggling disabled), `--jiggle`
(clean default settings), `--jiggle --mode Normal --seconds 60 --distance 1`,
and the same with `--mode Zen`. Do not reuse saved settings between cases.
Common cadence means a scheduled input opportunity every 60 seconds, not an
equal count/type of keyboard or mouse events; verify event timing independently.

## Guest preparation, controls and capture

1. Start on Windows 11. Reserve the existing guest, restore its clean checkpoint
   by pinned identity using the existing runbook, stage the working checkout,
   inputs and instrumentation, and sign in through VMConnect. Record Windows
   caption, build plus UBR, edition, Desktop Experience, account/integrity,
   keyboard layout, CPU/RAM, dynamic-memory state, storage and console host.
2. Prepare an idle-lock mechanism (for example, a 180-second machine inactivity
   limit) **only in the disposable guest**, preserving other effective policies.
   Record the literal/effective policy, screensaver configuration and sleep/display
   timers. Prevent sleep from confounding this lock experiment consistently.
   Observe three no-tool controls locking within the configured interval plus
   declared tolerance, without guest operator input. Also run an idle sampler
   control to establish that observation/instrumentation does not prevent locking.
3. Install/approve measurement prerequisites, retain their notices, then create a
   distinct `RIDE-screen-lock-measurement-base` checkpoint. Do not overwrite the
   integration suite's original checkpoint. Keep a second prepared checkpoint
   for standalone-without-runtime cases. Record all checkpoint IDs and differences.
4. Restore the applicable prepared checkpoint for every repetition. Use fixed
   memory where practicable; stabilize the guest for five minutes. Keep Defender,
   EDR, update state and network conditions consistent. Do not disable security
   software to make a tool appear quieter. Alternate/randomize case order and
   record the order/seed. Run at least three repetitions per condition.
5. Copy and complete
   [screen-lock-conditions.example.json](../tests/integration/screen-lock-conditions.example.json).
   Use exact guest-observed build/runtime versions; do not infer them from an ISO
   filename. Replace every placeholder. `ControlLockObservedSeconds` must contain
   the measured no-tool control; the harness rejects a zero/unobserved value.
6. Take scoped file/registry/startup snapshots before tracing/timing. Place
   evidence on a dedicated guest evidence VHD if possible. Snapshot reads and
   hashes can trigger security activity; finish them, then stabilize again.
7. Run the capture script from the **guest desktop**, with the same sampler host
   across cases. It checks VM model, hostname attestation, interactive session,
   accessible input desktop, conditions and every input hash. `-WhatIf` validates
   read-only prerequisites before previewing launch. Tab completion for `CaseId`
   reads the manifest when `ManifestPath` precedes it.

```powershell
.\tests\integration\Invoke-RideScreenLockCapture.ps1 `
  -ManifestPath C:\RIDE\inputs\manifest.json -CaseId ps51-light `
  -ConditionsPath C:\RIDE\conditions.json -ExpectedComputerName RIDE-Win11-Test `
  -DisposableVm -RunNumber 1 -OutputDirectory E:\evidence\ps51-light-1
```

The default is 60 seconds prelaunch baseline, 120 seconds startup, a total
4,200 seconds running (including the full script's hourly report), 120 seconds
allowed for operator exit, and 300 seconds post-exit. Sampling requests 1 second;
actual gaps and timestamps are retained. For startup characterization repeat
with 250 ms samples and matching controls; do not compare runs with different
sampling schedules as equivalent. First-launch-disabled cases may use a
shorter separately documented duration. Early exit, exit timeout and interrupted
capture are explicit incomplete statuses. Workloads are never forcibly stopped
by this sampler. Stop scripts with Ctrl+C in their own window, Arkane via Exit,
and Zhorn via its tray Exit. Do not Ctrl+C the sampler. Stopping is operator
activity and belongs to the exit phase, not the undisturbed idle-lock window.

Repeat the campaign on Windows Server 2025 **Desktop Experience** before making
matching support claims. Existing package support describes deployment, not
this interactive behavior. Neither operating system has passed this campaign.

## Memory interpretation and analysis

The sampler records working set, private bytes (the byte-valued .NET
[PrivateMemorySize64 property](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.privatememorysize64)),
page-file usage, lifetime per-process peaks and cumulative I/O counters. The raw
CIM `PrivatePageCount` is retained without inferring units from its name.
Private-memory access/identity failures are recorded; incomplete private totals
are excluded from statistics and counted rather than silently interpreted as
zero. Keep units as bytes and present MiB as bytes / 1,048,576. It discovers
descendants with PID plus creation-time identities; a PID alone is not stable.
Very short-lived children can escape sampling: reconcile with the trace process
tree. Shared console infrastructure may not be a descendant. All session
`conhost`, `OpenConsole` and `WindowsTerminal` processes are labeled
`ConsoleCandidate`; assign only the relevant identities after trace review.
Shared pre-existing terminal cost needs both a marginal delta and a documented
allocation policy. Do not charge the sampler's console to the workload.

```powershell
.\tests\integration\Get-RideScreenLockSummary.ps1 `
  -RunDirectory E:\evidence\ps51-light-1 `
  -AssignedConsoleKey '<PID:creation ticks from processes.json>' |
  ConvertTo-Json -Depth 8 | Set-Content E:\evidence\ps51-light-1-summary.json
```

The summary adds process memory **at each sample**, then computes phase median,
p95 (nearest rank), and sampled peak. It does not sum different processes'
lifetime peaks. Working-set totals can double-count shared pages; private bytes
must be reported alongside them. Across repetitions report median and min/max of
each run's steady median and startup/steady peaks, sample count and actual gaps.
Subtract the matching idle PS host/control statistic to estimate incremental
script cost; show raw total host-plus-console figures beside that estimate.
Do not silently clamp negative control-adjusted differences to zero or imply
control subtraction establishes causal precision. Report both measurement
noise and unmatched-host/runtime limitations.

The sampler buffers rows in RAM until final export; this reduces intentional
sampler writes during running but increases sampler RAM over time. CIM/provider
and system activity remain. Report its samples separately and compare
instrumentation-only, matching idle host, and traced/untraced runs. Absolute
system-wide commit/disk effects need corresponding system counters/traces; the
process totals alone cannot provide them. Sampled peaks can miss short spikes;
retain lifetime process peaks as additional bounds and use a faster startup
repeat where necessary. No current output asserts `BehaviorVerified=true`.

## Writes, configuration and attribution

Use [Microsoft Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
from its official source in the guest. Pin executable SHA-256/version and record
its own deployment, EULA approval/configuration writes before the prepared
checkpoint. Do not accept an EULA silently in the harness. Capture File System,
Registry and Process/Thread events, keeping process tree and command lines;
network/profiling capture is unnecessary for this file/configuration experiment.
Save the exact PMC configuration. **Do not enable Drop Filtered Events** or
capture only the root process: runtime, security-service and child activity would
be lost. Save all captured events to PML on the evidence volume, then export all
events to CSV with process IDs, time, operation, path, result and detail. Record
loss/drop indications; an incomplete trace cannot establish absence of writes.

Start tracing before first launch and retain it through steady running, normal
exit and post-exit. Use identical duration/configuration for controls. Capture
acquisition/extraction/runtime-install cost separately from launch cost. Keep
phase timestamps from metadata and trace clock alignment. Snapshot immediately
after exit and at post-exit completion, outside the steady timing interval;
compare paths/hashes and registry values by identity, not JSON ordering.

```powershell
.\tests\integration\Export-RideScreenLockSnapshot.ps1 `
  -ExpectedComputerName RIDE-Win11-Test -DisposableVm `
  -FileRoot C:\RIDE\inputs,$env:TEMP,$env:LOCALAPPDATA,$env:APPDATA `
  -RegistryRoot 'HKCU:\Software','HKCU:\Control Panel\Desktop','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' `
  -OutputPath E:\evidence\before.json
```

Add `RunOnce`, policy Run keys and any paths
identified by the trace; the script also inventories scheduled tasks and both
startup folders. Use the same explicit scopes before/after; note permission
errors and current 32/64-bit registry view. Expand scopes to discovered runtime
and shared-machine paths for a second clean repetition. Scoped inventories do
not capture deleted temporary files or unseen locations; traces do. In
particular inspect first-launch `user.config`, .NET bundle/extraction locations
(including `%TEMP%\.net` where applicable), input-directory files, PS analysis
caches/logs, startup registrations and registry writes. Absence/presence is an
observation, not an assumption about single-file runtime extraction.

Report per phase: successful `WriteFile` requested length totals/counts, created,
renamed, modified and deleted paths, successful registry writes/deletions, and
persisting file/value/startup differences. The sum of successful requested write
lengths is logical application write volume; overwrites count repeatedly and
metadata-only changes need separate reporting. Cache flushes, memory-mapped
writes, NTFS journaling and device writes complicate physical-volume attribution.
Process I/O deltas from samples are lower bounds and include pipes/devices;
[GetProcessIoCounters documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessiocounters)
must not be interpreted as physical disk bytes.

Use three attribution labels: direct workload/descendant events with reviewed
identity; runtime/host events (PS, COM, .NET); contemporaneous Windows/security
events (for example Defender, Prefetch, event logs, Amcache and cache/journal
activity). A runtime write on the app's PID remains direct **process** activity
but is not necessarily explicit application code. Match stack/module evidence
where available and controls/phase timing otherwise; record uncertainty. System
or Defender writes at the same time are not automatically causally attributable.
Preserve raw all-process traces so disputed attribution can be revisited.
Include instrument writes separately. No execution path is labeled artifact-free.

## Independent behavior and cleanup acceptance

Perform these observations separately from quiet footprint runs, recording
timestamps, foreground application/version and account integrity:

- Observe at least three idle-lock timeouts with no guest operator input while
  each enabled tool runs. Verify the same mechanism locks in the no-tool and
  instrumented idle controls. Record the maximum undisturbed unlocked duration.
  Check the guest lock screen independently through console observation and,
  if already enabled in the prepared checkpoint, lock/unlock security events.
  Neither the sampler's desktop-access boolean nor session-scoped
  [GetLastInputInfo](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getlastinputinfo)
  is authoritative proof of unlocked state. Audit enabling itself has artifacts.
- Test normal foreground text editor, a key-sensitive application where
  available, and elevated foreground editor while the workload stays standard.
  Repeat elevated workload separately. Observe cursor/key interference and
  timer pauses. UAC/secure-desktop tests are separate boundaries; no assumption
  that ordinary synthetic input reaches an elevated or secure desktop.
- For the scripts, observe Scroll Lock before/after multiple pairs, normal exit
  and Ctrl+C near a pair. Test starting On and Off, noting race/concurrent-input
  limitations. Independently record full script title/colors restoration and
  cleared-history limitation. Light has no console customization to restore.
- Check normal exit, Ctrl+C, full optional duration (separate case), and post-exit
  process/child/COM disappearance. A forced-termination failure test is a
  distinct cleanup scenario; never present it as normal exit. Confirm expected
  idle locking resumes after exit and no startup/configuration leftovers were
  overlooked. Do not add a duration parameter to light for automation.

Keep an `observations.json` with each check's Pass/Fail/NotRun, times, evidence
paths, observer and deviations. Keep memory/write results even if behavior
fails, labeling the mode unsuitable for that tested mechanism. Then restore
the guest measurement checkpoint and return it to its reserved owner; collect
evidence before restoration. Verify temporary paths before any cleanup.

## Acceptance status

| Evidence class | Current result |
| --- | --- |
| Official archive and executable hashes/version/architecture | Recorded above; acquisition completed |
| Source/publisher behavior and prerequisites | Reviewed; hypotheses explicitly distinguished |
| Tooling parser/help/preview and synthetic analysis tests | Recorded in the archived development record; no guest behavior inferred |
| No-tool idle-lock control | One Windows 11 control at 185.891 s idle and one instrumented pilot at 185.735 s idle; three undisturbed repetitions and Server 2025 pending |
| Runtime and instrument preparation | Win11 PS7/.NET/Procmon prepared; actual PMC exported, hashed and reloaded with Drop Filtered Events off and profiling disabled; synthetic file/registry marker recovery validated and collected hashes verified; capture/UI exits recorded result 1; separate preparation PML/CSV retained; deployment-write totals and workload trace finalization/loss checks pending |
| Startup/steady memory and peaks, controls/repetitions | Two elevated PS5.1 Light pilots, one full-default pilot, one native Zhorn x64 default pilot and three idle-host pilots recorded; idle 1 has a console mismatch, idle 2 extra input, idle 3 one startup reset then a quiet window; accepted subtraction/ranking, clean repetitions and other cases/targets pending |
| Direct/runtime/system write attribution and persistent leftovers | Warm restored Win11 idle control captured; all three PML parts and recovered all-event CSV hash-verified, sampled family native start/exit identities corroborated; before/final inventories compared with 172 errors each; immediate inventory and original close/export failed, detached-console repair validated; native loss/stack review, causal attribution, complete retrial and both-target acceptance pending |
| Actual idle-lock prevention, foreground/elevated interaction and Scroll Lock | Light, full-default and native Zhorn x64 default pilots reported unlocked over 600 s; full lacks independent visual/root-token confirmation; Zhorn and Light have passive visual observations; other contexts/tools, Scroll Lock/key-interference verification and clean/both-target acceptance pending |
| Normal exit/Ctrl+C/console/COM cleanup | Light/full exited with code 0 after console Ctrl+C, Zhorn x64 after publisher -appexit; locking resumed after Light and Zhorn, while extra post-exit input prevents full resumed-lock acceptance; exact COM/key-state/console restoration and other cleanup scenarios pending |

README guidance is provisional until this table has actual guest evidence.
Replace pending values with measured units/conditions and trace references;
never promote acquisition bytes, source claims or synthetic fixtures into RAM
or lock-prevention measurements.
