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
| Host preflight and result contract | Mocks forbid host registry inspection; elevation refusal and recovery checks pass; result omits UAC fields | Verify new registration evidence and installed results omit those optional fields |
| Queue claim/serialization | Danish-culture timestamp regression and ordered claims pass on both editions | Review applicability of historical overlapping Local/CI runtime evidence to the installed candidate |
| Installed hashes, task/account and VM/checkpoint pins | Existing installed 0.4.3 baseline accepted; candidate source reviewed | Refresh while both controllers are idle; retain before/after pins and five installed hashes |
| Normal registered execution | Earlier bridge pairs passed on 0.4.3 | A correlated candidate run on each target, with source hashes, guest evidence and final checkpoint recovery |
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
