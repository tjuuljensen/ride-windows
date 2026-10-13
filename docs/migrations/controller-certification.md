# Disposable VM controller acceptance

The current candidate is controller module **0.4.6**, registration **0.1.3**
and failure collector **0.4.1**. Broader controller certification and default-
branch cutover remain open. This ledger tracks the installed controller change;
the [anonymous bridge pair gate](../archive/evidence/github-quota-bridge-pair-gate-complete-2026-10-13.md)
remains accepted on its recorded CI/controller baseline.

## Acceptance matrix

| Requirement | Current evidence | Remaining acceptance |
| --- | --- | --- |
| Controller/profile/release mocked regression | Windows PowerShell 5.1: 109 passed; PowerShell 7: 107 passed, two host-preflight checks intentionally skipped | Complete for the reviewed 0.4.6 source; hosted full-repository validation remains separate |
| Host preflight and result contract | Mocks forbid host registry inspection; elevation refusal and recovery checks pass; result omits UAC fields | New registration evidence verified; installed result contract remains pending |
| Queue claim/serialization | Danish-culture timestamp regression and ordered claims pass on both editions | Review applicability of historical overlapping Local/CI runtime evidence to the installed candidate |
| Installed hashes, task/account and VM/checkpoint pins | Both controllers refreshed to 0.4.6 from published 3107711; all five hashes match, pins unchanged, new registration omits host-UAC fields | Refresh accepted; retain hashes and recheck before each request |
| Normal registered execution | Candidate Server request 20186578684e4716a1f633a99393fe9d accepted: validation/Pester1280, 217 source hashes, new result contract and recovery | Candidate Windows 11 request 3c0a98c38c5b42b5991f9a5f8f150e0d running |
| Failure/timeout evidence and recovery | Earlier real collector 0.4.1 quota failures and timeout/interruption probes retained | Candidate failure/timeout result contract and recovery acceptance; reuse unchanged collector logic with explicit rationale |
| Ordinary-shell, locked-session and watcher execution | Historical Windows 11 ordered trio and Server ordinary/locked passes retained in the controller guide | Record delta review; repeat only scenarios affected by candidate changes |
| Missing checkpoint, cleanup block and interrupted-worker recovery | Historical Server probes plus current mocked guards retained | Record applicability to the candidate and exercise any changed or uncovered paths |
| GitHub delivery and artifact correlation | Historical trusted migration-push pilots and uploads retained | Final candidate delivery coverage; manual workflow dispatch/master push stay subject to the separate cutover gate |
| Certification record | This ledger and historical run records | Complete per-controller acceptance record with dates, hashes, run IDs and explicit unavailable scenarios; registration remains NotValidated until applicable gates close |

Default-branch publication remains deferred. No historical record is rewritten
to claim it ran newer code. An accepted scenario names its actual source,
installed controller and configuration hashes. Unchanged behavior can retain
earlier evidence after a documented delta review; registration and mocked tests
alone do not establish runtime stability. Other migration activity owns its
own VM tests and must remain untouched while busy.

## Controller 0.4.6 regression validation, 2026-10-13

The 0.4.5 source committed in `5fdde5d` passed 108 focused checks on Windows
PowerShell 5.1. PowerShell 7 reproduced the earlier queue-claim failure:
`ConvertFrom-Json` produced a DateTime submission value; subsequent string
coercion produced `10/13/2026` under a Danish parser, so valid requests were
quarantined. This was a real compatibility defect, not a passing queue check.

Controller 0.4.6 normalizes DateTime values read from queue JSON back to UTC
round-trip strings before existing request validation. The request schema,
ordering, malformed-request quarantine and Windows PowerShell controller
requirement remain unchanged. A regression queues an October 13 UTC request
under Danish culture, requires it to be claimed and preserves its exact UTC
instant. Existing ordered-claim and malformed-JSON checks remain intact.

Native Windows PowerShell 5.1 passed all 109 checks across controller, profile-
acceptance boundaries and release discovery. Native PowerShell 7 passed 107;
the two Windows PowerShell-only host-preflight checks were intentionally skipped.
Neither edition had failures or tests left unrun. Pester 5.7.1 used isolated
temporary files and mocked system/network calls; no VM, publisher request,
installer, host registry or global setting was changed. Logs/XML/results and
source hashes are retained under `.local/controller-045-ps51` and
`.local/controller-045-ps7`, with pre-fix evidence retained separately.

The reviewed controller delta removes host UAC reads and optional UAC evidence
fields while retaining elevation, service/dependency, VM/checkpoint, correlation
and recovery guards. Other installed runner/worker/collector changes since the
accepted baseline are documentation-link casing changes. Current recovery
guidance was corrected to match the absence of host-UAC drift inspection.
Both VMs were observed Off/tasks Ready/queues empty before preparation; recheck
before refresh or submission. No candidate live acceptance is claimed yet.

ArtCraft Launcher remains closed and must not be restarted, including after
testing completes. Optional GitHub authentication is separate pending scope;
the accepted anonymous bridge behavior is retained without token forwarding.

## Guarded controller refresh, 2026-10-13

Source fix and this matrix were published in `3107711e3c6dd27bc67a61c50e1cb33866c15880`
with skip-CI to avoid another queued Full request. An isolated copy of the six
reviewed registration/controller files retained the exact tested module hash
`2920E1BCF41EB61564F74315FC1D004872DC0BD2DF1697CC65420A30293F2507`.
Administrator-approved registration ran 12:37:53-12:40:02 UTC, holding both
worker locks and refusing busy tasks/queues/recovery blocks. It refreshed both
controllers without changing VM/checkpoint/account/ISO/repository pins.
All five installed hashes matched the reviewed source. Registration 0.1.3
omitted Host.Uac and retained ValidationStatus NotValidated. Collector stayed
0.4.1. No VM run or host-UAC inspection was part of this refresh. Readiness at
12:42:30 UTC found both VMs Off/tasks Ready/queues empty/locks available/no
recovery blocks, clean frozen CI `a156475` and ArtCraft Launcher absent.

The first candidate live request is Server unit-only CI request
`20186578684e4716a1f633a99393fe9d`, submitted through the installed registered
client. Its guest snapshot is the clean approved frozen CI source; this tests
new host-controller execution and result/recovery behavior without claiming
new migration settings or newer guest source acceptance. Its subsequent pass is recorded below.
Refresh evidence is `.local/controller-046-refresh/result.json`; current
request state is `.local/controller-certification-status.json`.

## GitHub trigger boundary, 2026-10-13

A current GitHub read could fetch the default-branch README (display URL names
master), but `.github/workflows/vm-integration.yml` returned404 on that branch.
The migration branch contains the opt-in workflow. Manual workflow_dispatch
acceptance therefore remains dependent on default-branch publication, which
is still deferred. No master or activation-variable change was made.
Historical trusted migration-push delivery/artifact evidence remains distinct
from a new manual dispatch and from master-push acceptance.

## Server normal execution accepted, 2026-10-13

Registered unit-only CI request `20186578684e4716a1f633a99393fe9d` passed
12:43:08-13:03:10 UTC under installed controller 0.4.6/collector 0.4.1.
Guest validation and all 1,280 Pester tests passed; XML has zero failures,
errors, skipped or unrun tests. IntegrationPassed=false is expected for
UnitOnly. All 217 source hashes match the retained snapshot and clean frozen
CI revision `a15647590a1324681bbe4a69cbb55e498a623522`. The new final result
omits UacBefore/UacAfter. Export and checkpoint cleanup had no error; no state
JSON/manifests were produced by this unit-only run. Target VM ended Off, task
Ready, queues empty, worker lock available, no recovery block, unchanged pins/
checkpoint and five installed hashes. ArtCraft Launcher was absent. Audit:
`.local/controller-046-server-normal-audit.json`.

Both controllers were idle at the next readiness check. Windows 11 unit-only
request `3c0a98c38c5b42b5991f9a5f8f150e0d` then started through its installed
registered client on the same frozen CI source. It remains pending. These
runs accept candidate host-controller behavior; they do not count as another
Full bridge pair or acceptance of newer guest migration source.
