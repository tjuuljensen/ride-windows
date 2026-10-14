# Firewall enable-all source-reconciled Windows 11 lifecycle passed, 2026-10-13

Request: `fd277d27cf694ad7a764005e804e37fd`. Controller result: **Passed**, finished
`2026-10-13T16:13:37.7926782Z`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 286 files;
preflight differences: 2. Fixture SHA-256:
`962457558C2EE92BCF667C3BEA823F2CC4CDC2BF09B99DF594A07EA844093618`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`66A6F5BB9F02D45D83B516381B9E93ADA10DE0FE89D4CD8E606C667DEB96813B`. Published support declarations are unchanged.

All 286 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: docs\MIGRATION-PLAN.md. Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 142
passed, 0 failed, 143 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
On. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption before the second profile setter after one real native change; native writes=1, changed mutations=1, run=3af53125fab2488084b9d3b947944fb4, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/fd277d27cf694ad7a764005e804e37fd`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/fd277d27cf694ad7a764005e804e37fd`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
