# Owned Balanced SettingDrift Windows Server 2025 SettingDrift guard passed, 2026-10-13

Request: `8889c7171a8f4a9ebac14a5e456c271b`. Controller result: **Passed**, finished
`10/13/2026 19:59:45`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 320 files;
preflight differences: 0. Fixture SHA-256:
`A694394DACE810E78E97CC00A80159B57721B17FE90A662B19FEDD3DD7E5C81B`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`5FE708608E6CED3D21B969A52926701B448DB794E7413AF01C61AC78856148EE`. Published support declarations are unchanged.

All 320 retained snapshot files were independently checked against the
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

Owned-copy drift checks were not part of this fixture. Guard scenario: {"Method":"AC sleep timeout mutation on the fixture-owned inactive copy","OriginalValue":0,"ChangedValue":120,"Readback":120,"LogicalFingerprintChanged":true,"RestorePreviewPassed":true,"DeletionRefused":true,"DestinationRetained":true,"Error":"Owned copy changed or native export is not reproducible; refusing deletion.","Recovery":"CheckpointOnly; changed copy is deliberately retained"} This is accepted refusal evidence only. RIDE recovery did not occur; the Intent/changed copy was retained until host checkpoint cleanup.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/8889c7171a8f4a9ebac14a5e456c271b`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/8889c7171a8f4a9ebac14a5e456c271b`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
