# Mouse jigglers, Caffeine and lock blockers

Decision and follow-up record: 2026-10-11. System-impact measurements are pending.

## Purpose and accepted decisions

The intended outcome is to preserve an already unlocked interactive Windows
session during an investigation when a physical mouse jiggler or another
suitable option is unavailable. Preventing sleep and preventing idle screen
locking are distinct outcomes. A power request alone is not an equivalent
replacement for the accepted screen-lock blocker.

Keep different execution options available rather than assuming one is usable
on every host. Prioritize minimal memory use, disk writes and persistent
configuration. Licensing is not a selection obstacle for this user's Arkane
evaluation; retain accurate upstream notices and catalog metadata nevertheless.

- `components/scripts/caffeine.ps1`, version 0.2.2, retains a visible console
  color/title by default. `-NoConsoleCustomization` skips those changes.
  `-IntervalSeconds` defaults to 120; the old `sleep` parameter has no alias.
  Execution remains indefinite by default. `-StopAfterSeconds` optionally limits
  duration. `-ReportIntervalSeconds` defaults to 3600; 0 disables periodic reports.
  Console clearing remains; resizing was removed. Captured color/title properties
  are restored in cleanup, but cleared history cannot be restored. One COM object
  is used, and initialization/input failures
  stop execution. The launcher resolves its own script path and forwards arguments.
- `components/scripts/caffeine-light.ps1`, version 0.1.0, is a separate standalone
  fallback. It intentionally has no parameters or time limit. It sends a pair
  immediately, then sleeps 60 seconds between pairs until Ctrl+C. It has only
  start/stop messages, no console customization, stopwatch or periodic reports,
  and no dependency on the full script or RIDE modules. Native `Get-Help` provides
  documentation and the version; the zero-parameter design is an explicit
  exception to the usual help/version/preview command-line switches.
- Both scripts use one `WScript.Shell` object and send
  `{SCROLLLOCK}{SCROLLLOCK}` in one call, with terminating operational errors and
  COM cleanup in `finally`. No explicit file, registry, startup or power-plan
  writes appear in their current operational code. This is source inspection,
  not proof that execution leaves no artifacts or uses less RAM.
- Zhorn Caffeine is a distinct executable product, catalog ID `package.caffeine`.
  Its x86/x64 executables and legacy installer are one product, not separate
  solutions. Catalog deployment does not automatically start it. See the
  [existing package evidence](../migrations/application-follow-up-2026-10-11.md).
- Arkane Mouse Jiggler remains an evaluation candidate, not an accepted new
  catalog package. Move Mouse was discussed but is outside this four-tool
  measurement request. Hardware jigglers are also outside the benchmark.

Neither script unlocks a locked session or guarantees that every lock mechanism
accepts its input. Keystrokes reach the foreground application. A pair reduces
the interruption window but is not atomic; interruption or concurrent input can
leave Scroll Lock changed. Forced process termination bypasses script cleanup.
PowerShell, Windows and security software may create execution artifacts.

## Measurement follow-up delivered on 2026-10-11

The [detailed impact evaluation and run procedure](../../screen-lock-impact.md) records
source/publisher findings, exact script and official executable hashes/versions,
case commands, runtime prerequisites, attribution limits, controls and acceptance.
Official Zhorn 1.98 and Arkane 3.0.0 mainline/standalone x64 archives were acquired,
hashed and extracted without executing them. PE architecture/version resources
were inspected. No binary or key-sending script ran on the developer workstation.

New integration tooling prepares download-only pinned inputs, guards workload
launch by disposable-guest identity and interactive desktop, samples process
memory/I/O by phase, captures scoped before/after inventories, and summarizes
simultaneous memory totals with explicit console assignment. Case completion
reads the same manifest used for execution. The light script and full script
were not changed by the measurement work. Light remains zero-parameter and
indefinite. Trace acquisition and independent desktop observations are operator
steps in the guest runbook; sample capture never asserts behavioral acceptance.

Read-only native inventory confirmed both RIDE VMs Off, existing clean
checkpoints and Ready controllers. Restricted-shell CIM access failed but native
host access succeeded. The initial attempt did not initialize the separate
Computer Use plugin; its conclusion that desktop automation was unavailable
was too broad and is corrected by the retry below. No VM/controller was modified
or run during that initial attempt. Measurements remain pending
on both target operating systems, including writes/leftovers, actual idle-lock
prevention, foreground/elevated input, Scroll Lock and exit/cleanup. The README
now provides provisional selection guidance without inventing a ranking, and
the TODO remains open for this acceptance.

Local inputs and future large traces are identified under
`C:\Users\tjuuljensen\git\ride-windows\.local\screen-lock-impact\2026-10-11`.
They are ignored local evidence, not shared catalog defaults or distribution
approval. Do not confuse acquisition sizes or synthetic arithmetic tests with
real footprint results.

Tooling validation passed 10/10 Pester 5.7.1 tests on Windows PowerShell
5.1.26100.9549 and PowerShell 7.6.5. All five new workload/tool scripts passed
parser and native help checks; the four management scripts' `-Version` paths
returned before operational work. Input acquisition `-WhatIf` and disposable
identity rejection were nonmutating, and manifest case completion passed.
Pester's unused TestRegistry plugin was disabled for sandboxed local validation.
Windows PowerShell's initial authorization check required a process-only
`-ExecutionPolicy Bypass` for the scratch validation driver; no persistent policy
was changed and measurement launch does not bypass guest execution policy.
Evidence is in `validation-Desktop.json` and `validation-Core.json` beneath the
local root. `binary-inspection.json` records PE architecture checks.

### Retry: interactive access and guest staging

On the retry, the supported `@oai/sky` runtime initialized and VMConnect was
accessible. With idle/empty controller queues checked and a lease held during
restore/start, Windows 11 was restored from its pinned clean checkpoint and
started. Native WinRM staged the inputs and tooling at
`C:\RIDE\ScreenLockImpact`; all 16 pinned input files passed guest-side hash
verification. Windows 11 reports build 26300.9457 and PowerShell 5.1.26100.9444.
PowerShell 7 and the .NET Desktop Runtime were initially absent. Server 2025 stays Off.

After the user's manual sign-in, VMConnect showed the unlocked desktop. The
guest-only no-tool control used a secure blank screen saver with an effective
180-second timeout and disabled AC sleep/display power-off. It locked at
185.891 seconds of measured idle time; WTS flags changed from 1 to 0 and a
separate VMConnect observation showed the password screen. Raw samples and
effective/prior settings are in `control-observation.csv`, `control-result.json`,
`control-prepared.json` and `control-prior.json` beneath the local evidence root.

Prerequisite preparation then staged portable PowerShell 7.6.5, installed
Microsoft .NET Desktop Runtime 10.0.12 (verified official SHA-512 and Microsoft
signature, exit 0), and initialized signed Process Monitor 4.11. Runtime
preparation has an installer log but no deployment trace; do not present it as
measured deployment-write totals. A separate 124,037,461-byte instrumentation
preparation PML was retained. It contains no keep-awake workload; capture settings
and event classes still need review. Publisher input pins are in
`instrument-inputs/pins.json` and `instrument-inputs/procmon-pins.json`.

Capture 0.1.1 now records documented WTS lock flags beside memory samples. Its
parser/help/version checks and all 10 safety/analysis tests passed again on
native Windows PowerShell 5.1 and PowerShell 7.6.5. Export still does not set
behavioral acceptance automatically.

The first RAM checkpoint retained an old idle timer and relocked after resume.
Screen saving is paused only for prerequisite preparation. Windows 11 remains
Running and requires another manual unlock before an unlocked preparation
checkpoint can be saved. Authentication dialogs are not automated. No keep-awake
workload has launched; memory/write rankings, helper behavior and both-target
acceptance remain pending as described in the impact report.

On the next continuation, the user's unlock allowed a paused preparation RAM
checkpoint to be saved (`759d1c1a-8053-4a15-bd5a-6c6d459599ff`). A capture-only
pilot then verified that the sampler still allows idle locking: passive WTS
flags reported locked at 17:00:47 UTC and VMConnect showed the password screen.
The user subsequently unlocked it; operator intervention is recorded separately.
That pilot is behavioral control evidence, not an undisturbed memory comparison.
Initial setup used two guest mouse moves once before the timed baseline; no
preparation input is sent to a locked session. Each subsequent case must restore
the paused checkpoint, reset its idle interval and verify the secure timeout.

Capture 0.1.2 now writes invariant-culture CSV numeric fields; summary 0.1.1
rejects ambiguous older decimal-comma timing fields. All 12 safety/analysis
tests, including Danish-culture fractional timing and legacy rejection, pass on
Windows PowerShell 5.1 and PowerShell 7.6.5. Older raw evidence is retained;
any reviewed conversion must be a separately identified derived copy.

The completed pilot's retained raw CSV and derived invariant copy show locking
at 185.735 seconds idle, manual unlock, then locking again at 186.641 seconds
idle. Restoring its paused RAM checkpoint returned the guest to a locked session;
Light's first preflight stopped before launching the helper. The scratch driver
now explicitly resumes Hyper-V's Saved state after restore. It still requires
manual sign-in whenever Windows reports the session locked, so this checkpoint
does not remove the authentication handoff for repeated cases.

The next manual unlock enabled the first completed Light pilot under PS5.1.
All 601 running samples reported unlocked over a 600-second workload window;
idle resets occurred at approximately 60-second intervals. Console Ctrl+C
produced exit code 0, the root/direct conhost child disappeared, and locking
resumed 187.525 seconds after observed process exit. This was an elevated-token
run with Windows Terminal 1.24.12741.0, correcting the earlier preparation
assumptions. Steady root medians were 25.387 MiB working set and 46.988 MiB
private memory; matching idle-host subtraction and comparative acceptance remain
pending. Raw evidence and the timing discrepancy between session idle and
post-exit lock are detailed in the impact report. No writes/persistence or
preserved Scroll Lock state were verified in this pilot.

The completed PS5.1 idle-host control locked 186.851 seconds after root launch,
with no detected idle resets, then exited with code 0 on console Ctrl+C. Its
steady root medians were 28.686 MiB working set and 45.063 MiB private. Active
Terminal was 1.18.10301.0, unlike Light's 1.24.12741.0. The recorded Light-minus-
idle arithmetic (-3.299 MiB working set, +1.926 MiB private) is rejected as an
incremental-cost estimate because of that mismatch. Lock-state cohorts also
show substantial working-set variation. Matching console versions, repeated
clean runs and write/configuration acceptance remain pending. The separate
preparation PML was exported to CSV outside timed captures; it supplies no
workload-write or trace-completeness claim.

A second elevated PS5.1 Light pilot (run 3) also reported unlocked in all 601
running samples, exited with code 0 on normal console Ctrl+C, and locked
187.502 seconds after observed root exit. Its steady root medians were
20.102 MiB working set and 46.762 MiB private. Active Terminal was again
1.24.12741.0, differing from idle run 1. The two Light pilots' differing working
sets illustrate why single raw medians do not establish precise incremental
cost. Clean repetitions, matching controls, standard-token/key-state and
write/configuration acceptance remain pending. See the impact report for
raw hashes and timing. The second idle control used Terminal 1.24.12741.0 but
contained extra input during the sleeping root's run, so its apparent console
match does not permit accepted RAM subtraction. An age-matched early unlocked
comparison also contains those resets and is rejected.

Full 0.2.2's default PS5.1 pilot reported unlocked in all 602 running samples,
with approximately 120-second idle resets and exit code 0 after Ctrl+C. Steady
root medians were 19.281 MiB working set and 50.395 MiB private. Actual Terminal
was 1.24.12741.0; the root token and visual state were not independently checked
during this pilot. Post-exit input kept the session unlocked, preventing resumed-
lock acceptance. Different cadences/history and missing clean repetitions also
prevent ranking full against Light. Hourly reporting, writes, exact COM/key
state and console restoration remain unverified.

Idle run 3 also used Terminal 1.24.12741.0 and a verified High root token. It
contained one unexplained startup reset, then locked at 186.594 seconds idle
and stayed locked through normal exit and capture end. Its steady root medians
were 28.840 MiB working set and 44.785 MiB private. The later root-age 60 to
under 180 second window had 120 unlocked samples with no resets. Exploratory
early-window helper-minus-idle differences were +2.031 MiB private for Light
run 3 and +5.660 MiB for full default; both remain unaccepted as incremental
costs. The corresponding working-set differences change sign when comparing
whole-steady mixed lock states, illustrating the importance of the window.
Three clean repetitions and execution-write comparisons remain pending.

Zhorn Caffeine 1.98 x64's default pilot reported unlocked in all 603 running
samples, with approximately 59-second idle resets. Passive views showed the
unlocked desktop past nine minutes. Publisher `-appexit` produced exit code 0;
the root disappeared and locking resumed 185.400 seconds after observed exit,
confirmed by a password-screen observation, with no post-exit idle resets.
Steady native-root medians were 17.016 MiB working set and 5.375 MiB private.
No descendants were sampled, and the PS instrumentation/console are excluded.
These raw private figures are below the script-host totals in these pilots,
but clean repetitions, x86/alternate modes, standard-token/foreground tests and
Server 2025 remain pending. Zero sampled I/O deltas are not proof of no file or
registry writes; workload tracing and scoped snapshots are the next preparation.

## Completed verification and remaining acceptance

The implementation work ran 14 mocked tests for the full script and 6 for the
light script in both Windows PowerShell 5.1 and PowerShell 7. Parser, native help
and safe launcher checks passed. These implementation tests did not measure
real key injection, idle-lock prevention, interactive console restoration,
memory use or execution writes; subsequent guest pilots are recorded above. Package deployment acceptance does not establish running Caffeine's
behavior or system impact. No relative memory ranking is established.

## Follow-up: measure system impact

The Windows 11 Procmon configuration has now been exported, hashed and reloaded
with no process-name restriction, Drop Filtered Events off and thread profiling
disabled. Configuration review ran with capture stopped. Both UI exits left the
instrument absent but recorded task result 1; workload trace finalization still
requires verification. A separate warm prepared checkpoint retains the reviewed
configuration and earlier pilot history for restored matching trials. It does
not establish first-launch writes. See the [configuration review evidence](screen-lock-pilots-2026-10-11-12.md#process-monitor-configuration-review-2026-10-11).

A separate synthetic validation recovered the known file and registry writes
from their exact PowerShell PID. The native PML and all-event CSV were collected
with matching hashes before restoring the warm checkpoint again. This validates
marker recovery, not lossless tracing or a tool's write footprint. See the
[synthetic tracing evidence](screen-lock-pilots-2026-10-11-12.md#synthetic-tracing-validation).

The first warm restored traced idle control completed 601 running samples with
no detected idle resets and a normal Ctrl+C exit code 0. It locked at 245.672
seconds idle. Its immediate inventory failed after console detachment, and
Procmon closing exceeded the original timeout; the failed receipts remain
preserved. All three native PML parts were collected with verified hashes. A
separate detached-console snapshot validation passed after suppressing console
progress/output. This is incomplete persistence evidence, with no accepted RAM
or write ranking. See the [traced control evidence](screen-lock-pilots-2026-10-11-12.md#warm-restored-traced-idle-control-4).

Compare these four tools using reproducible measurements in disposable Windows
VMs, not the developer workstation:

| Tool | Cases to distinguish |
| --- | --- |
| `caffeine.ps1` | Default visible behavior; console customization disabled and reporting disabled; Windows PowerShell 5.1 and PowerShell 7 |
| `caffeine-light.ps1` | Fixed, parameterless behavior; Windows PowerShell 5.1 and PowerShell 7 |
| Zhorn Caffeine | Pinned publisher release and architecture; input mode; power-request mode only as a separately labeled sleep-prevention comparison |
| Arkane Mouse Jiggler | Pinned publisher release; normal and Zen input modes; framework-dependent and standalone builds where available |

Record the exact source revision/script hash or executable version/hash, source
URL, architecture, launch command, OS/build, runtime prerequisites, account and
elevation, VM configuration and instrumentation. Acquire binaries from official
publisher releases. Separate acquisition, extraction and runtime installation
from the footprint of launching and running the tool.

Use a clean checkpoint for each case, an instrumentation-only idle control,
consistent sampling and observation periods, and repeat runs. Include startup,
steady execution, normal exit/Ctrl+C and post-exit observation. Account for the
PowerShell host, console host and any child processes; use an idle PowerShell
control with the same launch options when measuring script overhead. Report
total host-process cost as well as the increment attributable to the script.
Use both default behavior and a comparable input cadence when configurable;
the light script remains fixed at 60 seconds.

Measure working set, private bytes/commit and startup/steady-state peaks, with
units and sampling conditions. Capture created/modified files, bytes written,
temporary extraction, configuration/registry writes and persistent startup
entries. Distinguish direct tool/child-process writes from runtime-generated
writes and Windows/security-service artifacts. Observe deletions and leftovers
after exit. Document instrumentation overhead and attribution uncertainty rather
than treating every contemporaneous write as caused directly by the application.

Preliminary [Arkane source inspection](https://github.com/arkane-systems/mousejiggler/blob/master/MouseJiggler/MainForm.cs)
found user-settings saves during initialization and setting changes. Its
[publisher documentation](https://github.com/arkane-systems/mousejiggler)
distinguishes a .NET-dependent build from a much larger standalone build. These
are reasons to measure the exact release, not an established runtime footprint
or RAM ranking. Recheck the pinned release's source and packaging before testing.

Verify the intended outcome separately: idle-lock prevention, foreground-app
interaction (including elevated windows), Scroll Lock state before/after,
console cleanup and stop behavior. A smaller footprint is useful only if the
needed session-preservation behavior works. Start on Windows 11; validate
Windows Server 2025 Desktop Experience before claiming corresponding support.
Run tools in an actual interactive guest user session. A loop running through
WinRM or a noninteractive job does not demonstrate that desktop input or
screen-lock prevention works.

Keep evidence and a detailed comparison in a repository report, with large/raw
temporary traces in a clearly identified local results directory rather than
the shared catalog. Then update README's "Mouse jigglers, Caffeine and lock
blockers" section with measured tradeoffs, practical selection guidance and a
link to the report. Do not label any option artifact-free or claim that a smaller
script/download proves lower RAM consumption. If VM access is unavailable,
deliver the harness and procedure and explicitly leave measurements pending.
