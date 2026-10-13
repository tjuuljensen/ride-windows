# WAP Push and Windows Search service settings

The optional machine-scoped controls `windows.wap-push-service` and
`windows.search-indexing-service` use one coordinated service handler. Configuration
changes require administrator rights. They are outside recommended profiles.
WAP Push can affect device-management workloads; disabling Windows Search can
impair indexed search. RIDE does not change dependencies, triggers, index files,
enrollment or synchronization settings, and does not force dependent services to stop.

## Choices and runtime effects

| State | Startup choice | Runtime action | Delay flag |
| --- | --- | --- | --- |
| `AutomaticRunning` | Automatic | Start/resume now | Preserve captured SCM and literal flag |
| `Disabled` | Disabled | Stop | Preserve dormant SCM and literal flag |
| `AutomaticDelayedRunning` | Automatic (Delayed Start) | Start/resume now | On through SCM |
| `AutomaticStartup` | Automatic | Keep current runtime | Off through SCM |
| `AutomaticDelayedStartup` | Automatic (Delayed Start) | Keep current runtime | On through SCM |
| `ManualStartup` | Manual | Keep current runtime | Preserve dormant flag |
| `DisabledStartup` | Disabled | Keep current runtime | Preserve dormant flag |

The first two presets retain their published meanings. The declared RIDE baseline
is `AutomaticRunning`; select that explicit state to request it. It does not infer
a Windows factory default or restore a previous run. Service controls have no
`unset`/override-removal state. Initial service defaults depend on the image,
edition and platform configuration. Exact prior configuration uses
`restore -RunId <id>`.

Delayed auto-start controls scheduling at the next boot, with no specific delay
guarantee. An explicit start action starts on demand instead of waiting for boot
scheduling. The flag is inactive for Manual/Disabled startup. These semantics
come from Microsoft's [delayed auto-start API reference](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info).

Use `show` for current startup/runtime, SCM delay and stored delay value/type/absence.
`plan` and profile `status` show whether runtime is preserved and delay is explicit
or preserved. Press Tab after `-State` to select a catalog-declared state; completion
reads metadata without inspecting services or invoking handlers.

```powershell
.\ride.ps1 show windows.search-indexing-service
.\ride.ps1 set windows.search-indexing-service -State AutomaticDelayedRunning -WhatIf
.\ride.ps1 set windows.wap-push-service -State AutomaticDelayedStartup -WhatIf
```

## Saved state and failure reporting

New delayed-start snapshots use service snapshot version 2 within the existing
run-record schema. They identify the exact service and record startup type,
Running/Stopped/Paused runtime, the SCM-reported delay flag, and the literal
`DelayedAutoStart` registry value, type and absence. Literal capture is a recovery
mechanism; the Microsoft API reference does not document that registry mapping.

The handler uses [QueryServiceConfig2](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w)
and [ChangeServiceConfig2](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
for the SCM flag. It configures startup/delay before any requested runtime action,
then verifies startup, runtime, effective delay and any restored literal state.
Native errors, unstable transition states, readback disagreement and missing
services stop the operation. Failures identify the stage; the engine retains the
complete pre-change record and run ID for recovery. RIDE does not silently force
dependencies, reboot or declare a failed stage successful.

Recovery rejects unknown snapshot versions, redirected service identities and
untyped delay snapshots before writes. Unversioned records retain their literal
delay recovery path; they contain no prior SCM capture, so RIDE does not invent
one. A prior Disabled-but-running/paused combination may require temporary Manual
startup to recover runtime before returning to Disabled. That intermediate
configuration can also fail and is reported explicitly.

The 2026-10-13 follow-up corrects key-existence capture: the generic registry
reader returns value existence/data/type only, so the service handler now records
the service key separately and refuses an unavailable key. Older unversioned
service records without `KeyExisted` restore the named value conservatively while
retaining the service key; their missing key-state history is not inferred.
The combined keyboard/service follow-up passed 51 selected mocked checks per
PowerShell edition, including actual-reader and missing-field recovery fixtures.

## Acceptance hold, 2026-10-13

New choices and strengthened recovery are implemented for local mocked validation.
GUI, SCM normalization, next-boot scheduling, triggers/dependencies and real
device-management/search workload acceptance remain pending. Existing Windows 11
target metadata is retained; this increment adds no Server support declaration.
Local checks cannot establish those feature outcomes.

Final focused mocked Pester validation passed 38 tests on each of Windows
PowerShell 5.1 and PowerShell 7. The preceding broader settings regression passed
235 tests. Parser/catalog/profile/generated-reference validation passed on both
editions. Native API compilation is covered without opening service handles;
all Windows service effects are mocked.

**Do not start disposable VM tests until the user manually confirms that testing
may resume after the GitHub cache/backoff investigation.** A reset time, quota
reading or elapsed time is not that confirmation. No VM acceptance is scheduled
or launched by this migration increment.

When released from the hold, verify both services on Windows 11 in disposable VMs:
preview, each available state, repeat apply, exact serialized recovery (including
absent/noncanonical typed delay and Disabled-but-running state), normalization and
partial failure. Separately verify Services GUI, next-boot behavior, dependencies,
triggers and real workloads. Report unavailable services rather than installing
them. Server applicability and acceptance remain independent future work.
