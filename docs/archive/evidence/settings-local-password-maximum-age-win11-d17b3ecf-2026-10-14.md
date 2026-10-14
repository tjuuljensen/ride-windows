# Local maximum-age 1/2/998-day boundaries Windows 11 lifecycle passed, 2026-10-14

Request: `d17b3ecf49084aac8fa0bf45ed8eaa0c`. Controller result: **Passed**, finished
`10/14/2026 12:37:14`. Local source revision: `2b799873f0f95b7569945373ab576f00d13a5b40`
plus its retained uncommitted source. Retained manifest: 358 files;
preflight differences: 0. Fixture SHA-256:
`47EBC724A5BD37C5753455500F0D841A8D1A2BB2541724512DEC7FB49399F9BF`. Source catalog SHA-256:
`CCADC1F33882D23CE1EC9832E32BCBAB6C06E638C8DCDEAA868EAE2A68FF91B7`; private candidate catalog:
`A446E81D24D0AC3A5D5A33F93B20FC193F3CB2A5D8004B96F0F951C9F03C3378`. Published support declarations are unchanged.

All 358 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 153
passed, 0 failed, 154 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
Days1, Days2, Days998. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption after a real focused native configuration write; native writes=1, changed mutations=1, run=0bbe0597de084cb69749ccc00c6d7f33, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

Additional consumer/component observations were not included in this snapshot.

Owned-copy drift checks were not part of this fixture.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/d17b3ecf49084aac8fa0bf45ed8eaa0c`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/d17b3ecf49084aac8fa0bf45ed8eaa0c`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
