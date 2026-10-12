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

Completed here: Windows-native checkout/attribute inspection, read-only native
Hyper-V/task inventory, official archive acquisition and SHA-256 verification,
executable version-resource inspection, source review, and tooling validation.
No evaluation executable or input script was launched on the developer host.
At the initial inventory both RIDE guests were Off. The retry below started and
prepared the disposable Windows 11 guest; Server 2025 remains Off.

| Existing disposable infrastructure | Observed identity |
| --- | --- |
| `RIDE-Win11-Test` / lab `RIDEWin11Test` | VM `6a5c9f91-91f9-44c5-924a-d1b5f863e16f`; clean checkpoint `a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9` |
| `RIDE-S25-Test` / lab `RIDESrv2025Test` | VM `06c2ae01-bf82-4634-9215-f240f3ea4147`; clean checkpoint `4a5b49ba-0795-480a-8d01-6f4f670577c8` |
| Host dependencies | AutomatedLab 5.61.0; Hyper-V module 2.0.0.0; RIDE tasks Ready; current controller shell unelevated |

Restricted-shell CIM initially failed; a native read-only query succeeded.
Therefore this is **not absence of Hyper-V or disposable VMs**. The initial
attempt did not initialize the separate Computer Use plugin after finding the
CUA native surface disabled. Its conclusion about all native desktop control
being unavailable was too broad; the retry below corrects that assessment.
The existing controllers run guest workloads via
remoting; host task `LogonType Interactive` does not establish guest desktop
input. Extending their protected suite selectors would require a distinct
interactive orchestration workflow. This evaluation leaves controllers and
their existing unrelated suites untouched.

Use the existing [AutomatedLab runbook](../tests/integration/AUTOMATEDLAB.md)
and [checkout staging steps](../tests/integration/README.md#6a-if-the-vm-was-created-with-automatedlab).
Do not rerun provisioning for these existing lab names. Before using a guest,
check its controller queue/runtime lock and any watcher; reserve the guest for
this measurement campaign. Do not restore a VM in use by another campaign.
Use its basic VMConnect console, sign in explicitly, and record session ID and
transport. Enhanced-session/RDP behavior is a separate condition.

### Retry access and staging, 2026-10-11

The supported `@oai/sky` Computer Use runtime initialized successfully and
returned the Hyper-V Manager and VMConnect windows. Both controller queues were
empty, tasks Ready, and neither controller blocked. The Windows 11 controller
lease was acquired for the restore/start operation. VM
`6a5c9f91-91f9-44c5-924a-d1b5f863e16f` was restored from clean checkpoint
`a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9` and started. Server 2025 was left Off.
The registered controllers and their suite selectors were not changed.

The Windows 11 guest was inspected and staged through native Windows PowerShell
5.1 WinRM using its existing lab credential in memory; credentials were not
printed or exported. Guest evidence reports Windows 11 Enterprise Evaluation
build **26300.9457**, Windows PowerShell **5.1.26100.9444**, no PowerShell 7 and
no installed .NET Desktop Runtime. These are observed prerequisites, not results
for running any of the four tools.

All 16 pinned input files passed guest-side SHA-256 verification under
`C:\RIDE\ScreenLockImpact\inputs`. Capture/snapshot/summary tooling and the
runbook were staged alongside them. Local evidence is
`retry-guest-inspection.json` and `retry-staging.json` under the existing local
root. **No keep-awake workload was launched.**

The user signed in manually and replied ready. VMConnect then visibly showed
the unlocked desktop. A session reported Active by `quser` alone would not have
established that state. Authentication dialogs were not automated.

Guest-only preparation enabled the blank screen saver, password on resume and
a 180-second timeout through documented
[SystemParametersInfo](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa)
calls. AC sleep and display timeouts were disabled to distinguish idle locking
from power management. Effective values and previous settings are retained in
`control-prepared.json` and `control-prior.json` in the local evidence root.
The guest has fixed 8 GiB RAM and four processors. A separate Standard RAM
checkpoint, `34b858c9-c5f3-405b-868b-a9d35ffdf2d8`, preserves this signed-in
preparation; the original clean checkpoint and Production checkpoint preference
are retained. Resuming this checkpoint is a warm resume, not a cold boot.

The no-tool control runs as an interactive guest task and records
[WTSINFOEX session lock flags](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
and session-local idle time. A guest-console click at 16:37:19 UTC started a
fresh idle interval. No further guest input is sent during the control.
The control passed: session flags changed from unlocked (1) to locked (0) at
16:40:24 UTC, with **185.891 seconds of session-local idle time**. The setting
was 180 seconds and samples were two seconds apart. A separate VMConnect
observation at approximately 16:41 UTC showed the password screen. No keep-awake
workload ran; `powercfg /requests` reported no active requests. Raw evidence is
`control-observation.csv` and `control-result.json`. This is one successful
prepared Windows 11 control, not acceptance of any helper or Server 2025.

Capture tooling 0.1.1 records the same documented WTS lock flags beside its
memory samples: 0 locked, 1 unlocked, -1 unavailable/unknown. These samples must
be reviewed alongside independent observations; export does not automatically
set behavioral acceptance. The initial RAM checkpoint retained an already old
idle timer and relocked after resume. It therefore requires replacement with a
checkpoint taken promptly after a fresh input interval. Screen saving is paused
only during prerequisite preparation and must be re-enabled for that checkpoint.
Alternatively, preserve the unlocked preparation with screen saving paused,
then start a fresh input interval and re-enable/verify the same secure timeout
after each restore, before the timed baseline. Record these preparation writes
separately and use exactly the same sequence for controls. A restored RAM
checkpoint's idle timer must never be assumed fresh.
Workload measurements and both-target acceptance remain pending; the initial
claim that native UI control was unavailable is withdrawn.

### Prerequisite and instrument preparation, 2026-10-11

The disposable guest now has portable **PowerShell 7.6.5 x64** under
`C:\RIDE\ScreenLockImpact\runtimes\ps7`, plus installed Microsoft.NETCore.App
and Microsoft.WindowsDesktop.App **10.0.12 x64**. The Desktop Runtime installer
passed the official release-metadata SHA-512 check and Microsoft Authenticode
signature verification, returned 0, and generated `runtime-install.log`.
`runtime-preparation.json` records the actual versions and timestamps. No
deployment trace was captured for that installation, so deployment-write totals
remain pending. These prerequisites were never installed on the developer host.

Official supplemental acquisitions are pinned in `instrument-inputs/pins.json`:

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| [PowerShell 7.6.5 x64 ZIP](https://github.com/PowerShell/PowerShell/releases/download/v7.6.5/PowerShell-7.6.5-win-x64.zip) | 106,319,290 | `32eb8f6cdce08f86e987d625a2733e54ac3e289ae7e1621b14c0b5bcec2434ea` |
| [.NET Desktop Runtime 10.0.12 x64 installer](https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/10.0.12/windowsdesktop-runtime-10.0.12-win-x64.exe) | 60,032,984 | `55a67d8476cde95a9cc43a95803b4f54446e7c9251ed22aa6421d4908174ae84` |
| [Process Monitor ZIP](https://download.sysinternals.com/files/ProcessMonitor.zip) | 3,199,668 | `80a6442b46af762ed1432f6fec3f7e20366bed62a2522b3486503398a40a1128` |

Signed **Procmon64 4.11** is 2,237,208 bytes, SHA-256
`fc3af5317c707e0555ad6e7590ad65ceb5c5085b053b41221944ac3ca3492d9c`.
It ran only in the disposable guest for instrument initialization, with explicit
`/AcceptEula /Quiet /Minimized /NoFilter /BackingFile` arguments, and exited
through `/Terminate`. Its license acknowledgment is an instrument registry
write. The separate preparation PML is 124,037,461 bytes, SHA-256
`511537008e64e036bdaa425ba33cb7f7b321e563f72ec2ff1cc8784fed01f0b6`.
It contains no keep-awake workload. Capture categories, dropped-event settings
and a pinned PMC configuration still require review before workload tracing.

Defender remained enabled, including real-time protection: product
4.18.26080.4, engine 1.1.26080.3, signatures 1.459.672.0 at preparation.
Windows Terminal package version is 1.18.10301.0; guest tasks visibly used
Windows Terminal. Console association and matching idle controls remain required.
These are preparation conditions, not an artifact or RAM ranking.

### Continued interactive control, 2026-10-11

After the second manual unlock, a separate paused preparation checkpoint was
saved: **759d1c1a-8053-4a15-bd5a-6c6d459599ff**. It includes the runtimes and
instrument initialization. The campaign holds the existing Win11 controller
lease; the registered controllers and original clean checkpoint remain intact.

An instrumentation-only pilot started at approximately 16:56 UTC through a
guest task configured with RunLevel Limited (actual token was not measured in
that pilot). Setup first verified that the session was
already unlocked and screen saving paused. Two guest-only mouse moves (+1 then
-1) reset its idle timer once, before enabling and verifying the secure
180-second timeout and entering the timed baseline. This is preparation input,
not a keep-awake loop; use the same sequence for controls and workloads. Setup
never sends input to a locked session. The sampler then ran with no helper and
no Procmon. A passive WTS query at 17:00:47 UTC reported locked (0), and VMConnect
independently showed the password screen. The user subsequently unlocked it;
that intervention is recorded in `operator-observation-instrumentation-1.json`
and excludes the subsequent interval from undisturbed behavioral acceptance.
The pilot began from the state just checkpointed, not a checkpoint restore;
its initial conditions timestamp must not be presented as a restore timestamp.

The pilot finished at 17:11:16 UTC and its raw samples were collected before
rollback. A separately identified invariant conversion in
`derived/instrumentation-1-invariant` retains the original decimal-comma CSV,
records its SHA256, and corrects the checkpoint-save/restore description.
Ordered samples show the first lock at elapsed 170.533 seconds (185.735 seconds
idle), manual unlock at elapsed 376.027 seconds, and another lock at elapsed
562.479 seconds (186.641 seconds idle). The latter interval includes operator
input and does not qualify as an undisturbed comparison control.

The pilot uses capture 0.1.1. Capture
**0.1.2** exports numeric CSV values using invariant culture and records the
sampler culture. Summary **0.1.1** rejects ambiguous decimal-comma timing values
instead of reading them as thousands. Parser/help/version and 12 Pester tests,
including Danish-culture fractional timings and legacy rejection, pass on
native Windows PowerShell 5.1 and PowerShell 7.6.5. Neither this control nor
synthetic checks establish helper memory, writes or lock prevention.

The first Light preflight on the restored checkpoint failed at 17:17:01 UTC:
Windows reported the session locked, so no input or workload was launched.
Hyper-V restored the RAM checkpoint into Saved state; the VM was explicitly
resumed, and the scratch launcher now resumes Saved/Off states before connecting.
A paused screen saver does not guarantee that Windows stays unlocked across
checkpoint restore. Manual authentication is still required when that gate fails.
The failed preflight and normal-stop timeout are retained under
`runs/ps51-light-1`; neither launched a keep-awake workload. Both tasks are Ready.
The controller lease was released at the manual sign-in handoff. Reacquire it
and verify the current guest/checkpoint state before retrying; do not label the
failed preflight as a completed Light measurement.

After manual sign-in, Light repetition 2 started from the current prepared state
at 17:51 UTC, without another restore. Setup recorded an unlocked session, two
preparation mouse events and re-enabled/verified the secure 180-second timeout.
The Light root launched at 17:52:03 UTC with no script arguments. This is a
600-second behavior/memory pilot, not one of three accepted clean repetitions.

Passive process-token inspection at 17:53:18 UTC corrected two preparation
assumptions: root PID 9748 and the sampler/stopper tokens were elevated with
integrity RID 12288 (High), despite the scheduled-task RunLevel being Limited.
Active Windows Terminal/OpenConsole paths identify **1.24.12741.0 x64**, rather
than the preparation inventory's 1.18.10301.0. Retain the raw conditions and this
separate observation; do not present task metadata as proof of standard-user
integrity or reuse the older terminal version as the active process version.
The native read uses Microsoft's
[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
and [token information classes](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class).
The observer performs no guest input. Its WinRM/CIM/token queries are additional
measurement activity, retained under `observations/` and separate from the
buffered sampler. No Procmon trace is running during this pilot.

### Completed elevated Light pilot, 2026-10-11

`runs/ps51-light-2` contains the original conditions, metadata, process inventory,
1,565,820-byte CSV, normal-stop record and derived `analysis.json`. Capture 0.1.2
finished with **Captured**, exit code **0**, no workload left running and
invariant numeric CSV (sampler culture da-DK). Raw CSV SHA256:
`c471191ff29af099b155e18aa8ece1169dce3b91a645af2a8fbbffa3518cee99`.
The 875.145-second capture ended at 18:06:08 UTC.

From launch through observed exit, all **601** samples reported unlocked (WTS
flag 1), maximum idle was **60.000 seconds**, and maximum sampling gap was
1.277 seconds. Ten detected idle resets occurred at roughly 60-second intervals;
they do not independently identify input source or prove Scroll Lock restoration.
Passive VMConnect screenshots and process-token observations are retained in
`observations/`; no operator input was made during the running/post-exit window.

The normal-stop helper verified console membership (only root PID 9748 and
stopper PID 5672), sent a console Ctrl+C event at 18:02:06.744 UTC, and exited
without forced termination. The root and its direct conhost child PID 6692 were
absent at the 18:02:41 observation. WTS changed to locked at 18:05:15.094 UTC,
**187.525 seconds after observed root exit**; VMConnect independently showed the
password screen. GetLastInputInfo then reported **246.797 seconds idle**, longer
than the no-tool control's 185.891 seconds. Record both clocks: this pilot does
not establish identical post-exit screen-saver and session-idle timing. Exact
COM release and preserved Scroll Lock state were not independently observed.

| Memory scope / phase | Samples | Median working set, MiB | Sampled peak working set, MiB | Median private, MiB | Sampled peak private, MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| PS5.1 Light root / startup | 60 | 74.387 | 74.641 | 46.980 | 47.324 |
| PS5.1 Light root / steady | 537 | 25.387 | 74.398 | 46.988 | 47.078 |
| Root plus direct conhost child / steady | 537 | 28.199 | 83.969 | 48.352 | 48.512 |

MiB means bytes / 1,048,576. Root-plus-child steady working-set p95 was 83.883 MiB;
private reads were complete. The large working-set range is retained rather than
equated to private commit. Shared Windows Terminal/OpenConsole processes remain
unassigned, and sampler/stopper costs are excluded from these workload figures.
No matching idle-host subtraction, three clean repetitions, standard-token
acceptance, trace write attribution, persistence audit or comparative ranking
is established. The completed idle-host control below records a console mismatch.

After preserving the raw run, checkpoint 759d1c1a-8053-4a15-bd5a-6c6d459599ff
was restored and resumed at 18:08:28 UTC. The 18:10:09 passive check found
screen saving paused (active 0), session locked (WTS flag 0), and no running
measurement tasks. The controller lease was released at this sign-in handoff.
`next-case.json` records `ps51-idle`, 600 seconds, run 1, using that current
prepared state after manual unlock; do not immediately restore and relock it.

### Idle-host control continuation, 2026-10-11

After the next manual unlock, `ps51-idle` run 1 started at 18:32 UTC without
another restore. It uses the pinned parameterless sleeping script in a newly
launched PS5.1 root, with the same capture/normal-stop timings as Light. Setup
recorded the unlocked/paused gate and re-enabled the secure 180-second timeout.
Root PID 10644 launched at 18:33:33 UTC. At 18:35:29, its token inspection
reported elevation 1, elevation type 1 and integrity RID 12288 (High).

Its active Terminal/OpenConsole paths identify **1.18.10301.0**, matching the
current package inventory but differing from the preceding Light pilot's
**1.24.12741.0**. This is an idle-host control in the same PS runtime, OS build,
fixed VM resources and high-integrity context; it is not a fully matched console
environment. Preserve separate raw results, flag the mismatch in any arithmetic
comparison, and repeat Light with the same active terminal environment before
interpreting subtraction as incremental script cost. No terminal or update
configuration was changed to conceal this difference.

The control finished at **18:47:39 UTC**, after 876.477 seconds, with capture
status Captured, exit code 0 and no root left running. Raw evidence is
`runs/ps51-idle-1`: conditions, metadata, process inventory, 1,578,162-byte CSV,
normal-stop receipt and analysis 0.1.1. CSV SHA256:
`14e1f0e5cc00c9c1d4f484ab2b8d2328cfac93afb746b25a56eaf6dd61ae490a`.
The 603 running samples contain no detected idle resets. WTS first reported
locked at **18:36:39.921 UTC**, **186.851 seconds after root launch**, while
GetLastInputInfo reported **234.406 seconds idle**. Preserve both clocks without
assigning an unverified cause to their difference. An independent VMConnect
screenshot showed the password screen. No operator input occurred within the
capture; the user's subsequent unlock came after completion.

The stopper verified only root PID 10644 and its own PID 5176 belonged to the
console, sent Ctrl+C at 18:43:36.976 UTC and reported no forced termination.
The root was absent at the 18:44:08 check. Maximum running sampling gap was
1.040 seconds. Private-memory reads were complete.

| Idle PS5.1 root memory scope | Samples | Median working set, MiB | Median private, MiB |
| --- | ---: | ---: | ---: |
| Startup | 60 | 70.840 | 45.375 |
| Entire steady phase | 538 | 28.686 | 45.063 |
| Steady while unlocked | 126 | 69.160 | 45.207 |
| Steady while locked | 412 | 23.852 | 45.063 |

Steady root sampled peaks were 70.766 MiB working set and 45.270 MiB private.
The root plus direct conhost child's steady medians were 32.310 MiB working set
and 46.457 MiB private; shared Terminal/OpenConsole costs remain unassigned.
Lock-state cohorts expose substantial working-set variation, so an all-phase
median alone does not explain incremental resource cost.

`derived/ps51-light-2-v-idle-1.json` retains the checked conditions and arithmetic
Light-minus-idle differences: **-3.299 MiB working set** and **+1.926 MiB private**
for the root steady medians. The negative result is retained. Because active
console versions differ, `CheckedEnvironmentEqual` and
`AcceptedIncrementalCost` are false. These are arithmetic observations, not an
accepted RAM saving, causal estimate or tool ranking. Three clean repetitions,
matching console versions and other tool/target cases remain required.

The original preparation-only PML was exported outside timed cases at
18:49:58-18:50:04 UTC with `/NoConnect /NoFilter /OpenLog /SaveAs`, without
`/SaveApplyFilter`, returning 0. `instrument-preparation-all.csv` is
49,604,621 bytes, SHA256
`09ec0b546f221c602325cb40b4250ebf6b28565c8002a4e635c406f5ba82ec10`.
It contains 301,191 rows with Time of Day, Process Name, PID, Operation, Path,
Result and Detail columns. The export receipt is
`instrument-preparation-export.json`. This is instrument preparation evidence;
it contains no keep-awake workload and does not establish capture-category,
dropped-event or trace completeness, deployment-write totals, or absence of
workload writes.

Offline inventory found 838 WriteFile events, including 836 SUCCESS events.
The detail fields use Danish thousands separators: `Length: 4.096` means
4,096 bytes. Analysis 0.1.1 explicitly uses da-DK and preserves the raw export;
all 836 successful lengths parsed, totaling **94,285,387 requested bytes**.
These are captured event lengths, including repeated/layered writes, not
physical bytes, deployment totals or helper cost. Successful registry mutations
included 530 RegSetValue, 36 RegDeleteValue and one RegDeleteKey event; 258
RegDeleteValue attempts returned NAME NOT FOUND.
`derived/preparation-trace-writes.json` retains process-name/PID labels as
unreviewed identities. Earlier
partial length parsing is separately retained rather than silently overwritten.
Trace completeness and causal attribution remain unverified.

After the user reported unlocking at approximately 18:50 UTC, the preparation
pause failed its fresh unlocked gate. Passive VMConnect observations at 18:54
and 18:58 showed the password screen. A bounded three-minute WTS unlock wait
then ended without launching Light run 3. No checkpoint was restored and no
authentication interaction was automated. `light-3-preparation-handoff.json`
and the separate preparation screenshot retain this setup interruption;
`next-case.json` records the same-state Light pilot to resume after sign-in.
It is not a failed Light behavior test or a clean repetition.
At 19:00:34 UTC, the final read-only check confirmed locked session flag 0,
screen saving paused (active 0) and no running measurement tasks. The controller
lease was released. Leave that paused setup state intact for the next manual
unlock; the case wrapper re-enables and verifies the secure timeout before timing.

### Light pilot continuation, 2026-10-11

The next manual unlock passed the fresh preparation gate at 19:09:05 UTC:
WTS unlocked (1), screen saving paused (0), no measurement tasks or Procmon
running. Without another checkpoint restore, `ps51-light` run 3 started at
19:09:15 UTC with the same ten-minute running and four-minute post-exit
schedule. It follows idle run 1 and preparation-only CSV export in the same
guest state, so it is a pilot rather than a clean repetition. Setup recorded
two guest-only preparation mouse events, 0.125 seconds idle, and re-enabled
and verified the secure 180-second timeout before timed sampling.

The 19:09:51 observation recorded installed Terminal **1.24.12741.0 x64** and
active OpenConsole/WindowsTerminal paths with that version, whereas idle run 1
used 1.18.10301.0. The 19:10:14 passive VMConnect screenshot visibly showed Light
running on an unlocked desktop; no guest input was sent. Preserve the repeated
console mismatch rather than treating this as a matched subtraction or changing
update/Terminal settings during the experiment. Results will be collected after
capture and normal-stop tasks complete.

At 19:11:02 UTC, a separate read-only process-token query found the Light root
PID 1512, created at 19:10:05.375 UTC, and direct conhost child PID 9480. Both
reported elevation 1, elevation type 1 and High integrity RID 12288. Their
sampler parent was PID 9120. This confirms elevated execution despite task
RunLevel Limited; it does not establish standard-user behavior. The passive
query is additional observation activity and is retained separately.

At 19:19:23 UTC, a passive VMConnect screenshot still showed the unlocked
Light window, more than nine minutes after launch. The normal stopper then
verified console membership (root PID 1512 and stopper PID 6484), sent Ctrl+C
at 19:20:08.665 UTC and recorded no forced termination. At 19:20:39, a separate
process query found root, direct conhost child and stopper absent; WTS remained
unlocked. A passive screenshot showed the desktop after the window closed.
The remaining timed post-exit samples must finish before preparation is changed.

### Completed second elevated Light pilot, 2026-10-11

`runs/ps51-light-3` retains the original metadata, conditions, process inventory,
normal-stop receipt, 1,563,589-byte raw CSV and analysis 0.1.1. Capture 0.1.2
finished at **19:24:09.816 UTC**, after **874.561 seconds**, with status Captured,
exit code **0** and no root left running. CSV SHA256:
`4506fdea537e123e76d4ff81c4c241bc9d95e4eb4058e637af814443c6a3586c`.

All **601 running samples** reported unlocked, maximum idle **59.890 seconds**,
maximum sample gap **1.027 seconds**. Eleven detected idle resets occurred at
approximately 60-second intervals, including the final one in ExitWait just
before Ctrl+C. Unlike run 2's ten resets, this run reached the next input cycle
before stopping; exact key-state preservation and input attribution remain
unverified. Independent console observations showed the unlocked Light window
past nine minutes, the desktop after exit, and the password screen afterwards.

WTS first reported locked at **19:23:16.696 UTC**, **187.502 seconds after
observed root exit**, while session-local idle was **188.750 seconds**. This
retains both clocks alongside run 2's different idle-at-lock value of 246.797
seconds, without assigning an unverified cause. Root, direct conhost child and
stopper had disappeared at the independent 19:20:39 check. Exact COM and Scroll
Lock restoration remain separate pending checks.

| Memory scope / phase | Samples | Median working set, MiB | Sampled peak working set, MiB | Median private, MiB | Sampled peak private, MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| PS5.1 Light run 3 root / startup | 60 | 72.680 | 74.438 | 46.992 | 47.406 |
| PS5.1 Light run 3 root / steady | 538 | 20.102 | 68.551 | 46.762 | 46.898 |
| Root plus direct conhost child / steady | 538 | 22.322 | 77.340 | 48.109 | 48.328 |

Private reads were complete. The family steady working-set p95 was 73.988 MiB;
unassigned shared Terminal/OpenConsole and sampler/stopper costs are excluded.
`derived/ps51-light-3-v-idle-1.json` again rejects accepted subtraction because
Terminal differs (1.24 versus 1.18). The separate Light run 3 versus run 2
comparison has equal checked fields, but remains unaccepted: these are two
pilots with differing preparation history rather than three clean repetitions.
Raw steady root medians differ by -5.285 MiB working set and -0.227 MiB private;
retain that variation rather than presenting one run as a precise footprint.

After collection, the guest preparation pause task returned 1 and did not
produce a fresh receipt. A separate 19:26:40 read reported screen saving paused
(active 0), locked WTS flag 0 and no running measurement tasks; the old receipt
was not promoted as proof of successful preparation. The user unlocked again,
and a fresh interactive pause at **19:28:20 UTC** verified active 0 and unlocked
flag 1 successfully. No authentication interaction was automated.

`ps51-idle` run 2 started at **19:28:29 UTC** from this current prepared state,
without another restore, using the same timing and normal-stop procedure.
Its actual console version must be verified before calling it a matched control.

The 19:29:41 read-only observation found root PID 10484 (parent 2716), created
at 19:29:21.896 UTC, with elevation 1, elevation type 1 and High integrity RID
12288. Active Terminal paths and package inventory both reported
**1.24.12741.0 x64**, matching the two Light pilots on that checked condition.

However, at 19:33:22 WTS still reported unlocked. VMConnect screenshot capture
at 19:32:02 was unavailable because the host window was minimized; no stale
image was used. A separate read-only
[WTSINFOEX timing query](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
at **19:35:32.730 UTC** reported locked (0), and last input at
**19:30:50.928 UTC**, after preparation and during the sleeping root's run.
The query ran in WinRM session 0 and explicitly read session 1; it validates the
structure size (232 bytes), level, session ID and managed layout before decoding
the documented UTC FILETIME values. This is WTS timing, not session-local
GetLastInputInfo. The input source is unverified. No controller command sent
guest input after the recorded preparation reset. Treat this control as
disturbed rather than accepting its Terminal match as sufficient comparison.

After WTS had reported locked, the documented host-window recovery sequence
refreshed the VMConnect window, activated it and refreshed its state once.
The 19:36:18 screenshot independently showed the password screen. This host
activation is recorded as observer activity; no guest keys or clicks and no
authentication interaction were sent. Collection occurred after capture and the
normal-stop task finished; the extra input remains a recorded deviation.

### Completed disturbed idle control, 2026-10-11

`runs/ps51-idle-2` retains the capture, conditions and normal-stop receipt.
Capture started at **19:28:51.581 UTC**, ended at **19:43:26.790 UTC**, and lasted
**875.203 seconds**. Status was Captured, exit code 0, no root left running.
The 1,573,945-byte raw CSV has SHA256
`fb4debbe77f00a32cde1f8bfd4de760c46c48255b82d181c24f561a245022266`.
All 602 running samples had gaps no larger than 1.031 seconds. WTS first
reported locked at **19:33:57.112 UTC**, sample 305.477, idle 186.188 seconds.

Eight idle resets occurred across the capture, including four before lock and
three while locked. Their UTC times were 19:29:09.707, 19:29:57.034,
19:30:26.059, 19:30:51.234, 19:36:17.750, 19:36:45.855, 19:37:55.209 and
19:42:55.683. The 19:36:17 reset coincides with the recorded host-window
activation; this does not identify the other resets' source. The independent
WTS last-input value corroborates the 19:30:51 reset. These resets invalidate
undisturbed-control acceptance even though Terminal matched Light.
Ctrl+C at **19:39:25.867 UTC** targeted the verified root console containing
stopper 2228 and root 10484; no forced termination was used.

| Memory scope / phase | Samples | Median working set, MiB | Median private, MiB |
| --- | ---: | ---: | ---: |
| Idle run 2 root / startup | 60 | 70.895 | 44.750 |
| Idle run 2 root / steady, mixed lock states | 538 | 21.852 | 44.734 |
| Idle run 2 root / steady, unlocked | 214 | 50.801 | 44.641 |
| Idle run 2 root / steady, locked | 324 | 15.324 | 44.766 |
| Root plus direct conhost / steady | 538 | 24.520 | 46.129 |

`derived/ps51-light-3-v-idle-2.json` records equal checked environment fields,
but explicitly records a disturbed control and rejects incremental-cost
acceptance. The arithmetic Light-minus-idle steady root difference is
**-1.750 MiB working set and +2.027 MiB private**. The separate early unlocked
comparison selects 120 samples each at root age 60 to under 180 seconds;
idle still has two unexplained resets within that window. Its arithmetic
**-3.527 MiB working set and +2.242 MiB private** is also unaccepted. Neither
mixed lock-state medians nor this disturbed early window establishes ranking.

A preparation-only diagnostic after collection succeeded at **19:45:26.965 UTC**
with screen saver active 0 and locked flag 0. It did not reproduce the earlier
pause failure, so its cause remains unverified. This task sent no input and
its receipt is separate from timed measurement evidence.

### Completed full default pilot, 2026-10-11

After manual unlock, a fresh preparation receipt at **19:48:47.137 UTC** verified
screen saver active 0 and unlocked flag 1. `ps51-full-default` run 1 used the
current guest state without another checkpoint restore: prior case/instrument
artifacts remain, so this is a pilot rather than a clean repetition. Full
0.2.2 used its default 120-second cadence and console customization, with no
duration parameter. Its hourly reporting interval was not reached.

`runs/ps51-full-default-1` retains exact capture/conditions/normal-stop files and
analysis 0.1.1. Capture started at **19:49:51.408 UTC**, ended at
**20:04:26.648 UTC**, and lasted **875.246 seconds**. Status was Captured,
exit code 0, with no root left running. The 1,569,103-byte CSV has SHA256
`4888149ee9510069f7206faa7dd825aa3f2703186858bda73af0164bd8a61bcc`.
Root 2144 was created at **19:50:21.671 UTC**, with sampler parent 10084 and
direct conhost child 2228. Actual Terminal/OpenConsole paths identify
**1.24.12741.0**. The sampler and stopper tokens were High at the 19:49:58 read;
that read preceded root creation, so the root's actual token was not independently
queried. Do not substitute the task's RunLevel or parent token for that check.

All **602 running samples** reported unlocked; maximum idle was **119.813 seconds**
and maximum gap **1.022 seconds**. Five idle resets occurred at approximately
120-second intervals, from 19:50:26.685 through 19:58:26.462 UTC. A passive
console screenshot was stopped by the user's Escape key before capture, so
independent visual confirmation is absent for this pilot. Ctrl+C at
**20:00:25.622 UTC** targeted console PIDs 9476 and 2144; forced termination was
false. The sampler observed root exit at offset 634.534 seconds.
The independent 20:11:19 and 20:15:05 session-process inventories also contained
neither the full root nor its direct conhost PID; the focused absence receipt
is retained in `observations/ps51-full-default-1-family-absence.json`.

Two additional idle resets at **20:01:21.141** and **20:04:20.702 UTC** occurred
after root exit, with source unverified. WTS remained unlocked throughout the
post-exit samples. Consequently resumed locking is **not verified** by this
run; the extra input invalidates that acceptance window. Do not infer persistent
helper activity from unlocked state after the root exited.

| Memory scope / phase | Samples | Median working set, MiB | Sampled peak working set, MiB | Median private, MiB | Sampled peak private, MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full default root / startup | 60 | 74.000 | 78.277 | 50.617 | 50.957 |
| Full default root / steady | 538 | 19.281 | 72.227 | 50.395 | 50.617 |
| Root plus direct conhost / steady | 538 | 21.910 | 80.883 | 51.734 | 52.043 |

Private reads were complete. Shared Terminal/OpenConsole, sampler and stopper
are excluded from those root/family figures. The raw full-minus-Light run 3
steady difference is **-0.820 MiB working set and +3.633 MiB private** in
`derived/ps51-full-default-1-v-light-3.json`; acceptance remains false despite
equal checked fields. Different cadences, preparation history, missing root
token/visual checks and lack of clean repetitions prevent causal comparison.
Writes, exact COM/Scroll Lock state and console restoration remain unverified.

### Idle control continuation and startup deviation, 2026-10-11

The user confirmed the guest was ready and agreed to leave it untouched through
collection. A fresh preparation pause at **20:09:45.265 UTC** verified unlocked
flag 1 and active 0; `ps51-idle` run 3 then started without another restore.
The one preparation input reset occurred at **20:10:04.077 UTC**, before the
timed baseline, and the secure 180-second screen saver was re-enabled.

At **20:11:19 UTC**, root 848 (sampler parent 4252, direct conhost 10032) was
independently queried: elevation 1, elevation type 1, High integrity RID 12288.
Its creation time was **20:10:56.661 UTC**. Actual Terminal/OpenConsole paths
identify **1.24.12741.0**. A passive WTS query at **20:15:05 UTC** reported locked;
the subsequent console screenshot showed the password screen. No host-window
activation or guest input was requested for that observation.

Ctrl+C was requested at **20:20:59.828 UTC** in the verified console containing
stopper 10428 and root 848, with no forced termination. At **20:21:07.371 UTC**
the stopper was Ready, and root/direct child/stopper were absent from the focused
session-process inventory. WTS remained locked while post-exit sampling continued.

Collection confirmed case and stopper Ready at **20:25:33.303 UTC**, both result
0, with complete capture and no failure. `runs/ps51-idle-3` retains capture
0.1.2 and analysis 0.1.1. Capture started at **20:10:26.321 UTC**, ended at
**20:25:01.877 UTC**, and lasted **875.549 seconds**, exit code 0, no root left
running. The 1,573,490-byte raw CSV SHA256 is
`cf513ec8226da2cf4798dc64415f57e9c586771cb8cc8685921438b311d8760d`.

There was **one unexplained startup idle reset** at **20:11:12.739 UTC**, root
age **15.996 seconds**, idle 0.641 seconds. No further resets occurred through
capture end. Controller input was limited to the earlier preparation reset;
the startup reset's source is unverified. Thus the whole capture cannot be
accepted as undisturbed despite the user's agreement to leave the VM untouched.
WTS first reported locked at **20:14:25.700 UTC**, sample 239.303, idle
**186.594 seconds** and **208.946 seconds after recorded launch**. It remained
locked thereafter. The 601 running samples had a maximum gap of **1.058 seconds**.

| Memory scope / phase | Samples | Median working set, MiB | Sampled peak working set, MiB | Median private, MiB | Sampled peak private, MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Idle run 3 root / startup | 60 | 66.824 | 71.012 | 44.961 | 45.309 |
| Idle run 3 root / steady, mixed lock states | 537 | 28.840 | 64.930 | 44.785 | 44.961 |
| Root plus direct conhost / steady | 537 | 34.590 | 73.586 | 46.164 | 46.402 |

Steady root samples split into 148 unlocked (59.113 MiB median working set,
44.734 MiB private) and 389 locked (25.285 MiB working set, 44.785 MiB private).
Startup/steady private reads were complete. One ExitWait private read was
missing; it is preserved as missing and excluded from complete family-private
statistics rather than counted as zero. Shared console/sampler/stopper remain
excluded from root/family totals.

The root-age 60 to under 180 second control window contains **120 unlocked
samples and no resets**, with medians **60.754 MiB working set and 44.867 MiB
private**. Derived comparisons retain both this later quiet window and the
whole-capture startup deviation:

| Helper minus idle run 3, root medians | Whole-steady working set, MiB | Whole-steady private, MiB | Early-unlocked working set, MiB | Early-unlocked private, MiB |
| --- | ---: | ---: | ---: | ---: |
| Light run 2 | -3.453 | +2.203 | +11.910 | +2.055 |
| Light run 3 | -8.738 | +1.977 | +1.332 | +2.031 |
| Full default run 1 | -9.559 | +5.609 | +10.014 | +5.660 |

Each pair has equal checked environment fields and retained raw CSV hashes in
`derived/*-v-idle-3.json` and `*-early-unlocked.json`. These are exploratory
arithmetic differences, **not accepted incremental costs or a ranking**.
Whole-steady comparisons mix lock states, and the later quiet window does not
erase startup input or differing prior execution histories. Three clean
repetitions, foreground/root-token checks and write attribution remain pending.
The early windows contain 119 Light run 2 samples and 120 in each other run.

After collection, a preparation-only pause at **20:26:49.831 UTC** verified
active 0, unlocked flag 1, matching collected metadata hash and measured family
absence. The user manually signed in and confirmed readiness for the next case;
no authentication was automated.

### Native Zhorn x64 default pilot continuation, 2026-10-11

After the user's readiness confirmation, a fresh pause at **20:27:40.364 UTC**
verified active 0 and unlocked flag 1. `zhorn64-default` run 1 started from the
same current guest state, without checkpoint restore. Preparation reset idle
once at **20:28:02.949 UTC**, then re-enabled the secure 180-second screen saver.
The case runs the pinned **Caffeine 1.98 x64** executable with no arguments;
the [publisher documents](https://www.zhornsoftware.co.uk/caffeine/) this as F15
key-up every 59 seconds and documents `-appexit` for normal process exit.
Those mode statements are publisher claims, not independent key-event capture.

The **20:29:09.495 UTC** passive query found native root 8552, parent sampler
11092, created **20:28:59.226 UTC**, with elevation 1, elevation type 1 and High
integrity RID 12288. WTS reported unlocked. The sampler's active Terminal paths
identify 1.24.12741.0; that console is instrumentation, not native-root memory.
No Procmon trace or configuration snapshot was added during this quiet pilot.
Normal stop and post-exit samples must complete before collection/acceptance.

### Completed native Zhorn x64 default pilot, 2026-10-11

`runs/zhorn64-default-1` retains capture 0.1.2, conditions, publisher-exit receipt
and analysis 0.1.1. Capture started at **20:28:28.778 UTC**, ended at
**20:43:03.825 UTC**, and lasted **875.053 seconds**. Status was Captured,
exit code 0, no root left running. The 1,284,016-byte CSV has SHA256
`436fa17f4409c137dd8acc12a372dc5d516acc5bd15dd3ab6e0448645892145a`.
The resolved executable hash/version matched the pinned x64 1.98 artifact.

All **603 running samples** reported unlocked, with maximum idle **115.859
seconds** and maximum sample gap **1.028 seconds**. Ten detected idle resets
occurred at approximately 59-second intervals, from **20:29:59.358** through
**20:38:51.367 UTC**. The first was detected about 60 seconds after recorded
launch, explaining the larger idle maximum before that first reset; exact
key-event attribution remains unverified. Passive screenshots independently
showed the unlocked desktop after the first 180-second interval and past nine
minutes. No host-window activation, guest keys or clicks were requested.

The normal-stop helper invoked the publisher's `-appexit` at
**20:39:02.563 UTC**, with helper exit code 0 and no forced termination. At
**20:40:02 UTC** neither native root nor stopper remained in the focused process
inventory. WTS first reported locked at **20:42:08.816 UTC**, idle **198.250
seconds**, **185.400 seconds after observed root exit**. A separate passive
console observation confirmed the password screen. No post-exit idle resets
were detected, and the case/stopper were Ready with complete capture at
**20:43:36.031 UTC** before collection and any preparation changes.

| Native root / phase | Samples | Median working set, MiB | Sampled peak working set, MiB | Median private, MiB | Sampled peak private, MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Zhorn x64 default / startup | 60 | 19.484 | 19.496 | 5.465 | 5.484 |
| Zhorn x64 default / steady | 539 | 17.016 | 19.535 | 5.375 | 5.453 |

Private reads were complete. Only the native root was observed in its measured
family; no descendants were sampled. The sampler/stopper and their console
infrastructure are excluded. The native app is not charged for the PowerShell
instrumentation host, and a PS idle-host value is not subtracted from native
root memory. Sampled process I/O write deltas were zero in startup, steady and
ExitWait, but these counters **do not prove absence of file or registry writes**.
No workload trace or scoped before/after snapshot exists for this pilot.

The raw private median is below the observed PS-hosted script totals in these
pilots; this is an observation rather than an accepted ranking. The run used
the current prepared state and High token, not three clean repetitions or a
standard-token/foreground-interference test. Zhorn x86, alternate input/power
modes, Windows Server 2025, persistence/write attribution and broader cleanup
acceptance remain pending. Process Monitor configuration review and workload
trace setup are the next preparation step, after manual sign-in.

### Process Monitor configuration review, 2026-10-11

The preparation pause attempted after Zhorn's completed capture failed its
fresh-receipt gate. No previous receipt was promoted. The user manually
unlocked the guest, but it locked again before the first configuration controller
reached its gate; that attempt launched neither Procmon nor a workload. A second
manual unlock was observed by a bounded WTS wait. The fresh interactive pause
receipt at **20:52:24.404 UTC** recorded screen saver active 0 and unlocked flag 1.
Collected Zhorn metadata matched the guest and its measured family was absent.

Pinned Procmon64 **4.11** was launched in guest session 1 with
`/NoConnect /Quiet`, using its existing EULA acceptance. The guest UI explicitly
reported **No events (capture disabled)** throughout review. The filter dialog
contained only three event-class display exclusions: Profiling, IPC and Network.
File System, Registry and Process/Thread remained visible, with no process-name
restriction. **Drop Filtered Events was unchecked**, and **Generate thread
profiling events was unchecked**. Network visibility was turned off; a display
exclusion does not establish that raw network collection is disabled. Retain
all-process PML and export without applying these display filters.

`File > Export Configuration` saved
`file-registry-process-20261011-205202.pmc` in the guest's `trace-review` directory
at **20:54:20.548 UTC**. The local copy is **1,957 bytes**, SHA-256
`ad0b539843ed535183a36c4905c22558089481ae40b1c0b8d8a6c164410b7105`.
The file was reloaded with `/NoConnect /Quiet /LoadConfig` after another fresh
pause at **20:56:43.251 UTC**. UI observations confirmed the same display filters,
unchecked Drop Filtered Events and disabled profiling. Selected saved registry
values corroborated `DestructiveFilter=0`, `Profiling=0` and `EulaAccepted=1`.
The exported file's hash and last-write time remained unchanged.

Both reviews exited through the application's UI without forced termination.
Native checks found Procmon absent and both tasks Ready, but **LastTaskResult
was 1**, including after the second review used `File > Exit`. Preserve that
nonzero result; do not claim a zero-code instrument exit or infer successful
trace finalization from process absence. No timed workload, workload PML, or
before/after artifact inventory ran during this configuration review.

Receipts, the actual PMC and reload verification are retained under
`trace-review/20261011-205202` and `trace-review/20261011-205623-reload`; UI evidence
is under `observations/procmon-review-*` and `observations/procmon-reload-*`.
Current configuration review does not retroactively prove completeness of the
earlier preparation trace. Workload trace loss/drop checks, matched controls,
write attribution and first-launch evidence remain pending.

A separate warm trace checkpoint, **0f16aaef-1733-45ea-a302-c77256d938cf**
(`RIDE-screen-lock-w11-20261011-procmon-reviewed-warm`), was created at
**21:01:45.182 UTC**. Its fresh interactive preparation receipt at
**21:01:20.407 UTC** verified active 0 and unlocked flag 1. All current case
captures matched their collected metadata and measured families were absent;
the failed Light preflight remained a failure record. Capture, normal-stop,
case and scoped-snapshot tooling were staged and hashed. Procmon/helpers were
absent, no campaign task was running, and the selected Procmon driver-name
inventory returned no entries. That scoped inventory is not a complete driver
or instrumentation-residue audit.

The checkpoint retains Windows build **26300.9457**, installed Terminal
**1.24.12741.0**, fixed 8 GiB/four processors, installed runtimes, the reviewed
PMC and earlier pilot history. It is a fixed starting state for **warm restored
trace repetitions and matching controls**, not first-launch clean-machine
evidence. Restore this exact checkpoint for each such repetition, stabilize
consistently, inventory explicit scopes outside timing, and reset idle/re-enable
the secure 180-second timeout before capture. A separate pre-workload branch
is required for first-launch writes, recording its console/runtime differences.
Every earlier checkpoint was retained and the VM's Production checkpoint
preference was restored. The receipt is `trace-measurement-checkpoint.json`;
the earlier `measurement-checkpoint.json` was preserved. No timed case was
started from the new checkpoint during this setup.

### Synthetic tracing validation

After restoring the warm checkpoint, a fresh interactive preparation pause at
**21:19:24.503 UTC** verified active 0 and unlocked flag 1. A separate synthetic
validation ran at **21:21:13.178-21:21:25.407 UTC**, without a benchmark workload.
It loaded the pinned PMC, waited for capture readiness, wrote a known file and
registry marker from PowerShell PID **6120**, and stopped Procmon normally.
The unfiltered CSV contains **117,772 rows**, including one successful
`WriteFile` on the exact marker file and one successful `RegSetValue` on the
exact marker value, both attributed to that PID. Task result, readiness helper,
termination helper and CSV export returned 0; the capture process returned
**1**, which remains recorded separately.

Evidence is collected under `trace-smoke/20261011-211935`, with guest originals
retained and both collected hashes verified:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Native PML | 48,217,222 | `66f315d38460dc91021df6a00e5ac7cd2f350c83176693852755a54594b7e02d` |
| All-event CSV | 20,566,218 | `5385a772d53a839e73b97934921f6ebe55b4d03e017efe48eb4939da528a5662` |

The CSV operation/result text scan found no drop/loss indication. This limited
scan and successful marker recovery do not establish lossless capture; native
PML/UI review remains pending. These are instrument-validation writes, not tool
footprint measurements. Restore the warm checkpoint again after collection so
these markers and validation activity stay outside the control's starting state.

The detailed checkpoint receipt contains case-variant keys in a deserialized
Hyper-V enum that Windows PowerShell 5.1 cannot deserialize. The original is
preserved. `trace-checkpoint-identity.json` projects only primitive identity
fields and records the source receipt hash for native restore commands. A UTC
guard initially rejected the validation before task registration because one
comparison operand used local time; both operands now compare UTC. That rejected
attempt launched no capture or workload.

The post-validation restore resumed the exact warm checkpoint at
**21:26:01.906 UTC** (`trace-restore-20261011-212605.json`). A passive check at
**21:27:24.226 UTC** found session 1 locked, no campaign task or Procmon running,
and **18,020,052,992 bytes** free on guest C:. No traced idle control was
registered at that check. The next case requires a new manual unlock and fresh
interactive pause, then five minutes of stabilization and scoped inventories
before timing. Native Windows PowerShell 5.1 parser checks passed for all ten
tracing controllers; independent analysis of the collected CSV recovered the
same exact marker writes and verified both artifact hashes.

The bounded preparation wait subsequently expired without observing a fresh
manual unlock and launched no workload. A final passive check at
**21:30:09.655 UTC** again found the session locked, no registered traced control,
no running campaign task and no Procmon process. The campaign lease was released
after saving the handoff; the next continuation must reacquire it and establish
a fresh interactive pause. No traced control result is claimed from this setup.

### Warm restored traced idle control 4

The later manual unlock was followed by a fresh interactive pause at
**21:48:30.380 UTC**. Control task `ps51-idle-4` started at **21:49:00.460 UTC**
from the post-validation restore of warm checkpoint
`0f16aaef-1733-45ea-a302-c77256d938cf`. The task stabilized for 300 seconds.
Its before inventory ran **21:54:04.870-21:56:28.976 UTC**, outside capture.
Pinned Procmon/PMC readiness succeeded at **21:56:30.928 UTC**, with
`DestructiveFilter=0` and `Profiling=0`; raw `HistoryDepth=18` remains undecoded.
This is a warm instrumented control, not first-launch or quiet-memory evidence.

Memory capture ran **21:56:58.227-22:11:33.472 UTC** for **875.248 seconds**.
Idle-host root **9340**, created at **21:57:28.455 UTC**, and conhost **9972**
were recorded by creation-time identity. Independent native inspection found
High integrity RID **12288**, elevated 1/type 1, despite scheduled-task RunLevel
Limited; Terminal **1.24.12741.0** was present. Passive VMConnect observations
showed the unlocked desktop and later the password screen, without activation
or input.

There were **601 running samples**, maximum gap **1.089 seconds**, and **no
detected idle resets** across capture. First sampled lock was
**22:00:34.674 UTC**, **245.672 seconds idle**, or about **186.219 seconds after
root creation**. The configured secure timeout remained 180 seconds; preserve
the observed latency rather than substituting that configured value. The
session stayed locked thereafter. This is one control, not three repetitions.

Owned-console Ctrl+C was requested at **22:07:32.245 UTC**, with console PIDs
`6916,9340` and no forced termination. Root exit code was **0**, and neither
measured family identity remained. The raw memory CSV is retained under
`runs/ps51-idle-4`, SHA-256
`9ca3afa963a250d324c82ef5577fc135449f7fb4946bee893927519f510dbc1d`.
All root private-byte samples were complete. Steady root median working set was
**26.964844 MiB**, private bytes **44.738281 MiB**; root plus sampled descendant
medians were **30.046875/46.148438 MiB**. These traced values have no accepted
subtraction or ranking against the earlier memory-only pilots.

The immediate after-exit inventory **failed at 22:11:49.582 UTC** with an invalid
console-output handle after the stopper detached its owned console. No such
inventory is available. The final inventory succeeded at
**22:11:56.018-22:19:18.454 UTC**, taking **442.436 seconds** while tracing its
reads. Its comparison with the before inventory found **5 file differences,
2 registry-key differences, 28 registry-value differences and 1 task-definition
difference**; both inventories recorded **172 errors**. The task difference is
the observer's stop task. File differences include Explorer icon caches,
PowerShell startup-profile data and a recent-destination file. These are scoped
observations with concurrent runtime/system/instrument activity; they are not
causally attributed to idle-host code. Zero observed startup-folder differences
does not establish absence of startup artifacts.

Normal Procmon termination exceeded the original 60-second waits. The original
trace receipt and case failure remain **Failed**, with no forced kill; a later
native check at **22:24:42.995 UTC** found all Procmon processes absent. The
original controller did not reach CSV export. All three native PML parts,
available inventories and failure receipts were subsequently collected and
hash-verified. The WinRM transfer was switched to the VM's existing SMB share
through a temporary nonpersistent PSDrive; its partial file was retained.
The **11,325,639,868-byte** PML total includes substantial observer activity and
is not a workload-write measurement.

Separate offline recovery `20261011-224700` opened the retained native trace
without connecting to a capture session and exported all events with native
exit code **0**. Its **4,382,317,885-byte** CSV was collected and hash-verified:
`f8619197a5485dfa9cdefc71bfbc0d27b686b375effe23485a3d9629be2a9f14`.
The original failed receipt remains unchanged. Streaming analysis found
**19,095,658 rows**, spanning **21:56:30.890-22:19:18.532 UTC** and one local
midnight rollover. No rows fell outside the expected trace window plus the
60-second tolerance. Each sampled root/conhost identity had one matching native
start by name and creation time and one native exit event. Native exits were
**22:07:32.448 UTC** for root 9340 and **22:07:34.310 UTC** for conhost 9972.

Within the sampled family intervals, root 9340 had **8 successful WriteFile
events requesting 35,191 bytes during startup** and **61 requesting 19,576
bytes during exit wait**. Startup paths included PowerShell policy-test files,
a recent-destination temporary file, the filesystem journal and a named pipe;
exit writes targeted PowerShell startup-profile data. These are requested
logical lengths across different object types, not physical disk bytes or
direct idle-script writes. There were **17 successful root RegSetValue events
during startup**, one at exit, and one conhost RegSetValue event after root
exit, including ZoneMap and background-activity state paths. Successful
RegCreateKey detail review found **all 221** successful root events reported
`REG_OPENED_EXISTING_KEY`; they do not represent 221 new persistent keys.
The two policy-test files each had one successful **60-byte** requested write.
The other startup lengths were **20,480 bytes** to the filesystem journal,
**14,431 bytes** to the recent-destination temporary file and **160 bytes** to
the named pipe. No family mutation rows were labeled steady phase;
neither that observation nor the empty operation/result loss-label scan proves
absence or lossless capture. Broader caller attribution and capture-completeness
checks remain necessary. Derived analysis is retained as `trace-analysis.json` beside
the original trace evidence.

On **12 October**, the user unlocked the guest for a bounded native PML review.
The test screen saver was paused for preparation; no workload or capture was
started. Procmon opened the retained trace with `/NoConnect /NoFilter /OpenLog`,
showing **19,095,658 total events** and the final backing part `events-2.pml`.
The Filter menu showed Drop Filtered Events unchecked. Existing profiling/IPC
display exclusions were visible while the initial display showed 98% of the
total;
the root WriteFile view showed **71 events**, with the named-pipe event hidden
by the IPC exclusion. This display filtering does not revise the CSV totals.

Native properties confirmed the policy-test `.ps1` write at
**21:57:29.5670497 UTC**, length **60**, offset 0. Its stack resolved Windows
kernel/`ntdll`/`KernelBase` write frames but ended with an unknown user frame;
the exact caller remains unresolved. The first startup-profile exit write at
**22:07:32.4247701 UTC**, length **64**, offset 0, had .NET Framework
`clr.dll` and `mscoreei.dll` frames. This supports runtime attribution for that
representative event; it does not assign every contemporaneous write to the
same mechanism. Event/detail/stack screenshots and bounded CSV path/disposition
review are retained under `observations` and `runtime-event-review.json`.
Matching native/CSV totals and successful opening of all parts do not prove
lossless recording or repair the missing immediate snapshot.
Procmon was closed through File > Exit, without forced termination. Passive
inspection at **02:51:01 UTC on 12 October** found no campaign tasks or Procmon
processes running and the session unlocked. The review task was Ready with
**last task result 1**, recorded separately from the successful offline export;
no zero-code UI exit is claimed. The test screen saver remained paused for
setup (`ScreenSaveActive=0`, secure flag 1). No checkpoint restore or timed
workload followed this review.

| Native part | Bytes | SHA-256 |
| --- | ---: | --- |
| `events.pml` | 4,691,197,535 | `acf9469ca6c83355d2a810ae5e7569cc101195a38f067ed896b431bc371b4518` |
| `events-1.pml` | 5,445,497,782 | `90425c7d34b704fe19ce553934e36605dc773ee7b25280273d32eb023377e50b` |
| `events-2.pml` | 1,188,944,551 | `ce491822dfcd310cf23fedc2967e67e5d826b7ed09d117f434743707af590ba6` |

The collector now preserves numbered PML/CSV parts, uses verified temporary
files for resumable copies, and requires a complete hashed collection before
restoration. Future snapshot calls suppress console progress/output and retain
warnings; future trace completion rejects a failed or missing immediate
inventory. Longer bounded normal-close/export waits are prepared. The original
support source is preserved by hash under `source-history`. Separate validation
`20261011-222700` deliberately detached its console and completed the repaired
snapshot path with **task result 0**, **22:27:39.012-22:42:26.646 UTC**. The
15,282,010-byte validation snapshot was collected with SHA-256
`f6f6b8dde89c18a13ccdd3a7c0fb44e6934f05ebec675dcd6241394f956baf60`.
This validates the detached-console path; it cannot replace this case's missing
immediate snapshot or establish complete inventory coverage. Detailed capture
loss/finalization review, unresolved caller attribution and a complete retrial
remain pending.

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
| Tooling parser/help/preview and synthetic analysis tests | Recorded in SCREEN-LOCK-HELPERS; no guest behavior inferred |
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
