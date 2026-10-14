# Owned Balanced SettingDrift Windows 11 SettingDrift guard passed, 2026-10-13

Request: `75c3d9e2ece44fb9ad98a2a385cade8a`. Controller result: **Passed**, finished
`10/13/2026 20:06:53`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 321 files;
preflight differences: 0. Fixture SHA-256:
`33E1EE1E2A4A114346D45D9E1DA0FEFE3FF9D7700C48D12F161A61D4F081BAE8`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`3B7F60EA4BAAB8D8FD33EF5B7BE208AC1756248B86416865768BB62A0839E72B`. Published support declarations are unchanged.

All 321 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 156
passed, 0 failed, 157 discovered.
Fixture lifecycle: False; declared recovery mode:
CheckpointOnly; recovery passed: False; exact recovery: False.
Completed states:
Create. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled native-mutation failure evidence was not included in this snapshot.

Additional consumer/component observations were not included in this snapshot.

Owned-copy drift checks were not part of this fixture. Guard scenario: {"Method":"AC sleep timeout mutation on the fixture-owned inactive copy","OriginalValue":900,"ChangedValue":120,"Readback":120,"LogicalFingerprintChanged":true,"RestorePreviewPassed":true,"DeletionRefused":true,"DestinationRetained":true,"Error":"Owned copy changed or native export is not reproducible; refusing deletion.","Recovery":"CheckpointOnly; changed copy is deliberately retained"} This is accepted refusal evidence only. RIDE recovery did not occur; the Intent/changed copy was retained until host checkpoint cleanup.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/75c3d9e2ece44fb9ad98a2a385cade8a`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/75c3d9e2ece44fb9ad98a2a385cade8a`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
