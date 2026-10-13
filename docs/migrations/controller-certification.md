# Disposable VM controller acceptance

Controller module **0.4.6**, registration **0.1.3** and failure collector
**0.4.1** have completed scoped source, installation and runtime acceptance on
both pinned configurations. Broader stable-controller certification and
default-branch cutover remain open; registration stays **NotValidated**.
See the [dated candidate evidence](../archive/evidence/controller-046-scoped-acceptance-2026-10-13.md)
for source/configuration boundaries, run IDs, fault results and delta review.
The earlier [anonymous bridge pair gate](../archive/evidence/github-quota-bridge-pair-gate-complete-2026-10-13.md)
remains accepted on its recorded baseline; its heartbeat is disabled.

Full hosted regression also passed for published candidate **f5e3218**, through
an identical-tree review-branch trigger. See the
[hosted validation evidence](../archive/evidence/hosted-final-source-validation-2026-10-13.md).
Master publication remains held until **v3 reaches release-candidate state**.

## Acceptance matrix

| Requirement | Current evidence | Remaining acceptance |
| --- | --- | --- |
| Controller/profile/release mocked regression | Focused 0.4.6 checks passed; full hosted candidate f5e3218: Windows PowerShell 5.1 1,455 passed, PowerShell 7 1,453 passed/two expected host-preflight skips; catalog/syntax checks passed both | Complete for the recorded published candidate; subsequent implementation and eventual RC source require validation |
| Host preflight and result contract | No host registry inspection; elevation and recovery guards retained; fresh registration and normal/timeout/refusal results omit UAC fields | Complete for candidate |
| Queue claim and serialization | Native ordered claims and timestamp regression pass; historical overlapping Local/CI runtime evidence retained with unchanged locking/task logic | Candidate delta reviewed; historical runs retain their actual versions |
| Installed hashes, account and VM/checkpoint pins | Both controllers refreshed from published 3107711; all five hashes match; pins/configurations unchanged | Complete; recheck before future use |
| Normal registered execution | Server 20186578684e4716a1f633a99393fe9d and Windows 11 3c0a98c38c5b42b5991f9a5f8f150e0d: validation, 1,280 tests, 217 hashes and recovery each | Complete for candidate over frozen guest CI source a156475; UnitOnly does not accept newer guest source or add Full bridge passes |
| Timeout collection and recovery | Server e9dbd5a238914edea6915bb6de7eeea7 and Windows 11 c61528bb07394d02aec9430ac17dfa9c: expected TimedOut, process trees terminated, collection under 90 seconds, explicit locked-transcript omissions, clean recovery | Complete for candidate; partial evidence is not Pester completion |
| Missing checkpoint and expired request | Fresh isolated probes on both configurations failed for intended reasons before VM use; full snapshot sets/configuration hashes unchanged | Complete for candidate |
| Ordinary-shell, locked-session, watcher, cleanup block and interrupted-worker recovery | Historical evidence retained; function delta confirms worker locks, checkpoint/reset, termination and collector launcher unchanged | Reuse rationale recorded; no historical case relabeled as a fresh 0.4.6 run |
| GitHub delivery and artifact correlation | Historical trusted migration-push pilots/uploads retained; workflow unchanged | New manual dispatch and trusted master-push acceptance remain deferred behind default-branch publication |
| Per-controller certification records | Both protected acceptance.md records saved 2026-10-13 at 14:16:41 UTC, verified against reviewed hashes; configurations unchanged | Candidate record step complete; keep registration NotValidated until broader applicable gates close |

The default master branch currently lacks the VM workflow. GitHub documents
the [default-branch requirement for manual dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).
No master or activation-variable change was made. The user requires v3 release-
candidate readiness before master publication. Before broader certification,
complete the deferred delivery/cutover gates and reconcile applicable hosted
validation with the final published source; record any unavailable scenario
explicitly. Optional GitHub authentication and newer settings acceptance remain
separate work.

Other migration activity owns its VM tests. Leave busy resources untouched and
recheck readiness before use. ArtCraft Launcher remains closed and must not be
restarted, including when testing or its automation finishes.
