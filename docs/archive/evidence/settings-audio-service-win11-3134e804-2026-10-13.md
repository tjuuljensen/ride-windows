# Guarded Windows Audio service Windows 11 lifecycle passed, 2026-10-13

Request: `3134e804661844108b9ed894cde274a2`. Controller result: **Passed**, finished
`10/13/2026 19:00:26`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 311 files;
preflight differences: 0. Fixture SHA-256:
`915B26C214A45D986ACE702CEE2E49F8CDA1E3F3D88BFB44227E7EE99255BC55`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`79C97D43847B3FFFC5A4C01195DC0F57A37B95B24272912679860FEF09981C98`. Published support declarations are unchanged.

All 311 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 170
passed, 0 failed, 171 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
AutomaticRunning, ManualStopped. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption after a real focused native configuration write; native writes=1, changed mutations=1, run=2fd82164a01d4cd698969367adabd747, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/3134e804661844108b9ed894cde274a2`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/3134e804661844108b9ed894cde274a2`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
