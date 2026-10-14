# Shutdown Event Tracker Windows Server 2025 lifecycle passed, 2026-10-13

Request: `2479f56603b1464598f23d47ab7a5363`. Controller result: **Passed**, finished
`10/13/2026 18:02:08`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 300 files;
preflight differences: 0. Fixture SHA-256:
`08F172EF2D59EFF65AA80D02DFE7C0C074F8262CB6887F7FC9FA6E9737C7D59E`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`D63C600A9C36B93135C4CCE4B58855DAE27510E9140CDE31ED5CFF5B300FA962`. Published support declarations are unchanged.

All 300 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 182
passed, 0 failed, 183 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
Always, Disabled, ServerOnly, WindowsDefault, WorkstationOnly. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption after the first state-changing native New-ItemProperty write; native writes=1, changed mutations=1, run=c228f38fea88424ea505efacfb3671a2, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

Additional consumer/component observations were not included in this snapshot.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/2479f56603b1464598f23d47ab7a5363`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/2479f56603b1464598f23d47ab7a5363`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
