# Owned Balanced power plan Windows 11 lifecycle failed or incomplete, 2026-10-13

Request: `7a00278ac82a41ef9d47cd2a59186df2`. Controller result: **Failed**, finished
`2026-10-13T16:56:59.7500855Z`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 294 files;
preflight differences: 0. Fixture SHA-256:
`32ED54681EEE90FA56F3A0B33F6931D11B6C8B9E86B485A2FD07031A23E57570`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`3B7F60EA4BAAB8D8FD33EF5B7BE208AC1756248B86416865768BB62A0839E72B`. Published support declarations are unchanged.

All 294 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 147
passed, 0 failed, 148 discovered.
Fixture lifecycle: True; declared recovery mode:
Compensating; recovery passed: False; exact recovery: False.
Completed states:
Create. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Owned copy changed or native export is not reproducible; refusing deletion..

Controlled native-mutation failure evidence was not included in this snapshot.

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/7a00278ac82a41ef9d47cd2a59186df2`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/7a00278ac82a41ef9d47cd2a59186df2`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
