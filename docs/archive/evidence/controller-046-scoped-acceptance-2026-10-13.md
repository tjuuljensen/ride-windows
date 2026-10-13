# Controller 0.4.6 scoped acceptance, 2026-10-13

Controller 0.4.6's source validation, protected installation, normal execution,
bounded timeout collection/recovery and refusal probes are accepted on both
pinned configurations. Broader stable-controller certification remains open;
registration stays NotValidated. The [active acceptance matrix](../../migrations/controller-certification.md)
owns remaining trigger and cutover requirements. The earlier
[anonymous bridge pairs](github-quota-bridge-pair-gate-complete-2026-10-13.md)
remain accepted on their recorded baseline and their heartbeat stays disabled.

## Source and installation

Published candidate source is `3107711e3c6dd27bc67a61c50e1cb33866c15880`.
Module 0.4.6 includes removal of host-UAC inspection and normalizes DateTime
values parsed from queue JSON back to UTC round-trip strings. This repairs
the reproduced PowerShell 7/Danish-culture queue defect. Native Windows
PowerShell 5.1 passed all 109 focused controller/profile/release tests;
PowerShell 7 passed 107 with only two intentionally skipped Windows PowerShell-
only host-preflight tests. Neither had failures or unrun tests. These are
focused source checks, not full-repository validation of newer migration work.

Administrator-approved registration 0.1.3 refreshed both controllers
12:37:53-12:40:02 UTC while both worker locks were held. All five installed
hashes matched the reviewed source, and VM/checkpoint/account/ISO/repository
pins remained unchanged. Module SHA-256 is
`2920E1BCF41EB61564F74315FC1D004872DC0BD2DF1697CC65420A30293F2507`.
Collector stayed 0.4.1. New registration evidence omits Host.Uac and retains
ValidationStatus NotValidated. No host-UAC reads, repairs or global policy
changes were part of the candidate checks.

| Installed file | SHA-256, identical on both controllers |
| --- | --- |
| RIDE.TestAutomation.psm1 | 2920E1BCF41EB61564F74315FC1D004872DC0BD2DF1697CC65420A30293F2507 |
| Invoke-RideVmTestTaskWorker.ps1 | 36A81A1392D5BEAEFD8CE85F8D90DE95F76E14479475E56872550A79870C9C6A |
| Invoke-RideVmTest.ps1 | 03166FC83F3E80E5309AE08A346F82E9CB3F76D7B51C0A80203B6E2B75F7A1AF |
| Invoke-RideVmTestTask.ps1 | 87CB49843350782D6624E0DA8664D0C6204607D79094D448D6E3BF15A38CA558 |
| Export-RideVmTestEvidence.ps1 | ACB739EFD9ECD3423EC4B0E9217DA08352F586A0F2747D32B2045BB21587CA14 |

Reviewed per-controller acceptance records and their configuration/source hashes
are prepared in `.local/controller-046-per-controller/manifest.json`. Saving
acceptance.md beside each protected evidence.json awaits the Windows elevation
dialog. This pending record write does not change the accepted runtime outcomes
or promote registration to Validated.

## Fresh installed-controller runs

Every request used the installed registered client, Source CI and UnitOnly.
The guest source remained the clean published frozen checkout
`a15647590a1324681bbe4a69cbb55e498a623522`; it was not reset or advanced.
This accepts new host-controller behavior over that known guest source;
newer guest/migration settings are outside these results.

| Configuration/scenario | Run ID | UTC interval | Accepted outcome |
| --- | --- | --- | --- |
| Server normal, 90-minute limit | `20186578684e4716a1f633a99393fe9d` | 12:43:08-13:03:10 | Passed: validation, 1,280 Pester tests, 217 source hashes, export and recovery |
| Windows 11 normal, 90-minute limit | `3c0a98c38c5b42b5991f9a5f8f150e0d` | 13:07:39-13:32:02 | Passed: validation, 1,280 Pester tests, 217 source hashes, export and recovery |
| Server intentional five-minute timeout | `e9dbd5a238914edea6915bb6de7eeea7` | 13:33:15-13:39:10 | Expected TimedOut/client exit 1; process tree terminated, bounded partial collection and recovery passed |
| Windows 11 intentional five-minute timeout | `c61528bb07394d02aec9430ac17dfa9c` | 13:41:55-13:47:43 | Expected TimedOut/client exit 1; process tree terminated, bounded partial collection and recovery passed |

Normal runs have zero XML failures/errors/skips/unrun tests.
IntegrationPassed=false is expected for UnitOnly; these are not additional
Full bridge integration passes. Both timed-out controllers terminated their
process trees. The installed collector returned successfully under its enforced
90-second limit with empty stderr and null CollectionError/CleanupError.
Server copy ran 13:39:05.998-08.163 UTC, session closed 08.207. Windows 11 copy
ran 13:47:27.782-41.128 UTC, session closed 41.173. Readable artifact-observation
and partial guest-identity files were retained. Both locked transcripts were
explicitly listed in collection-omissions.json; no complete transcript or
Pester completion is claimed for interrupted runs. Retained state JSON/manifests
were zero in these unit-only runs. Observation-library files are retained
evidence, not proof of new request-owned publisher acquisition.

All four final results omit UacBefore/UacAfter. Audits verified the correlated
results, all 217 snapshot/CI hashes, unchanged five installed hashes and pins,
pinned checkpoint presence, target VM Off/task Ready/queues empty/lock available/
no recovery block, clean CI source and no ArtCraft Launcher process.
Local receipts/audits use `.local/controller-046-{server,win11}-{normal,timeout}-`.

## Refusal probes

Administrator-approved probes ran 13:50:14-13:50:53 UTC with both worker locks,
in-memory configuration copies and isolated local result roots. They submitted
no altered configuration to a registered task and edited no real queue.

| Configuration | Scenario | Probe ID | Accepted outcome |
| --- | --- | --- | --- |
| Server | Missing checkpoint | `20ee11146d3142b39907e8ba7ded0712` | Expected Failed before VM use |
| Server | Expired request | `ed90d17bc68a47f9a50c49464cbf6edb` | Expected Failed before VM use |
| Windows 11 | Missing checkpoint | `cbc6ba82706f4258b3bdcfabd9e84c03` | Expected Failed before VM use |
| Windows 11 | Expired request | `0c42251a6f7d4596b9d139a77c9af3a9` | Expected Failed before VM use |

Each failed for the intended reason, omitted host-UAC fields, left its VM Off,
and preserved the full snapshot-ID set and installed configuration hash.
Evidence is `.local/controller-046-guards/result.json` and its correlated roots.
Final readiness at 13:52:48 UTC found both configurations idle with all pins/
installed hashes unchanged, clean frozen CI and launcher absent.

## Reused evidence and remaining certification

AST delta review against published 0.4.3 baseline `55e97c0` found changes only
to host preflight, queue timestamp normalization and request UAC observations,
plus removal of Get-RideAutomationUac. Worker locking, task parameters, lab/
checkpoint checks, reset, process termination, bounded collector launcher and
terminating JSON writes are unchanged. Runner/worker/collector/watcher file
changes otherwise concern documentation casing; the VM workflow is unchanged.
Older ordinary-shell/locked-session/watcher, overlapping Local/CI submission
and interrupted-worker/block/recovery evidence remains historical evidence
with this delta rationale. It is not relabeled as a fresh 0.4.6 run. Current
normal/timeout/refusal cases cover the changed preflight/result paths.

GitHub can read the default master README, but that branch's VM workflow
returns 404. GitHub documents the
[default-branch requirement for manual dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).
Manual workflow_dispatch and trusted master-push acceptance remain
deferred behind default-branch publication. No master, activation variable or
registration validation status was changed. Final certification and any
unavailable scenarios must be recorded explicitly before calling the broader
configuration stable. ArtCraft Launcher must not be restarted after testing.
