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

## Resume near v3 release candidate

The user will return to this work near the v3 RC milestone. No further run is
scheduled. The completed bridge heartbeat is PAUSED; its historical prompt and
saved retry deadlines are not instructions to restart testing. Resume from this
ledger and the evidence links, rather than from an archived chat or ignored
`.local` state. Do not commit to master before v3 reaches release-candidate state;
RC readiness does not itself enable the VM activation flag or authorize a merge.

### Accepted baselines

| Scope | Published baseline | Evidence and limit |
| --- | --- | --- |
| Anonymous quota/cache/backoff bridge | Guest CI a156475; installed controller 55e97c0/module 0.4.3; collector 0.4.1 | Two consecutive complete Full passes per target, Windows 11 and Server 2025; [pair evidence](../archive/evidence/github-quota-bridge-pair-gate-complete-2026-10-13.md) |
| New host controller | Controller source 3107711/module 0.4.6; registration 0.1.3; collector 0.4.1; guest CI still a156475 | Fresh normal UnitOnly, expected timeout and refusal cases on both configurations; protected records saved; [scoped evidence](../archive/evidence/controller-046-scoped-acceptance-2026-10-13.md) |
| Full hosted regression | Candidate f5e3218; content-identical trigger cc5481f | Both PowerShell editions passed in [run 38413683226](https://github.com/tjuuljensen/ride-windows/actions/runs/38413683226); [source/tree and log evidence](../archive/evidence/hosted-final-source-validation-2026-10-13.md) |

These are different source boundaries. Newer guest source, unfinished migration
fixtures, native/GUI setting effects and future RC revisions were not accepted
by these results. Preserve historical passes with their actual revisions; do not
relabel UnitOnly or hosted regression as new Full integration evidence. The
installed configurations remain NotValidated for broader certification.

### Remaining work and sequence

1. Select the reviewed RC source and compare its engine, controller, workflow
   and tests with the accepted baselines. Run full hosted validation on that
   published revision in both PowerShell editions. Repeat live scenarios where
   changed behavior invalidates earlier evidence; explain any historical reuse.
2. Recheck competing migration activity, both VM/task states, queues, worker
   locks, recovery blocks, five installed controller hashes and pinned VM/
   checkpoint/account/ISO/repository configuration. Leave busy resources alone.
   Preserve unrelated work and repository switches. The previously frozen CI
   checkout must not be reset or silently advanced; coordinate an intentional
   clean published-source update when future CI testing requires it.
3. When renewed Full bridge acceptance is needed, check publisher availability
   once after any current backoff deadline and submit serialized registered-task
   requests with Source CI, IntegrationSuite Full, TimeoutMinutes 90 and correlated
   receipts. The pair gate is two consecutive complete Full passes per target on
   a coherent published source/controller baseline. Failed or quota-deferred
   acceptance clears the affected target's current sequence. Retain diagnostics,
   digest/cache provenance, cleanup and final idle evidence. Schedule retries
   only as authorized; the completed heartbeat stays paused.
4. After RC readiness and an agreed publication/activation decision, publish the
   VM workflow to the default branch. Complete a real workflow_dispatch and then
   a trusted master push, verifying actual source hashes, correlated guest results,
   uploaded evidence and recovery. A manual re-run of an old job is not dispatch
   acceptance. The workflow selects one configuration at a time; serialize the
   coverage required for each configuration being certified.
5. Reconcile the [controller runbook's applicable checks](../../tests/integration/automatedlab-tasks.md),
   record unavailable scenarios explicitly and update acceptance.md beside each
   protected evidence.json before changing broader certification status. The
   runbook also calls for reproduction on another host using pinned dependencies,
   matching ISO/settings and regenerated host/VM IDs; no such portability evidence
   is claimed by this chat's single-host results.

[Optional PAT-based GitHub authentication](../MIGRATION-PLAN.md#optional-github-authentication-v3-scope)
remains approved high-priority v3 work with implementation and acceptance pending.
Anonymous behavior stays supported; explicit protected credential references,
account/cache separation and guest credential boundaries require their own tests.
No credential was configured here. Reusable release-module extraction remains
[deferred downstream work](../../TODO.md#optional-reusable-github-release-discovery-module).
Unrelated settings acceptance belongs to its own migration ledger and holds.

### Knowledge and constraints to retain

- Release metadata is process/module-local for five minutes, bounded to 64
  endpoints and two MiB per response. It does not persist across processes or
  restored checkpoints. Payload caching is separate. Follow the
  [release-discovery contract](../github-release-discovery.md), including no
  expired fallback, silent authentication or token forwarding.
- Host preflight cannot reserve shared-IP quota for a guest. At exhaustion, use
  the later of primary reset plus one second and Retry-After; missing usable
  timing uses the documented conservative one-minute fallback. Do not poll or
  start a knowingly blocked Full test. Saved quota/idle observations are dated,
  not current availability.
- PowerShell 7 can deserialize queue timestamps as DateTime. Controller 0.4.6
  restores UTC round-trip strings before validation; retain the Danish-culture
  regression. It also intentionally removes host-UAC inspection/evidence while
  retaining elevation and recovery guards. Do not reintroduce old UAC reads or
  policy repair from historical automation instructions.
- Collector 0.4.1 has a 90-second bound. Successful partial collection with an
  explicit locked-transcript omission is fault-path evidence, not proof that
  guest Pester or Full integration completed.
- ArtCraft Launcher must not be restarted, including after testing or archiving.
  Only a later explicit user request changes this constraint. Its observed TCP
  connections did not establish API request counts or prove the source of all
  quota consumption; that attribution remains unresolved.
- Detailed raw diagnostics remain in ignored `.local` folders and protected
  controller result roots. Committed dated reports retain run IDs, revisions,
  hashes and outcomes. Preserve raw evidence when moving or rebuilding the host;
  another clone will not contain those local files or credential/configuration
  stores. Runtime pins and availability must be rediscovered on the actual host.
