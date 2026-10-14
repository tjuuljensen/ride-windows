# Owned Balanced InterruptedCreation Windows Server 2025 InterruptedCreation guard failed or incomplete, 2026-10-13

Request: `77ef1aa1c89240ddbb7d70e9dc4045f7`. Controller result: **Failed**, finished
`10/13/2026 20:12:29`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 322 files;
preflight differences: 0. Fixture SHA-256:
`BCA7523568C550B829FDD2D8551452029686AE5E880B7CA64261361B33335CD5`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`5FE708608E6CED3D21B969A52926701B448DB794E7413AF01C61AC78856148EE`. Published support declarations are unchanged.

All 322 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 156
passed, 0 failed, 157 discovered.
Fixture lifecycle: False; declared recovery mode:
CheckpointOnly; recovery passed: False; exact recovery: False.
Completed states:
. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: Interrupted creation did not retain the exact captured inactive Intent copy.; recovery: .

Controlled native-mutation failure evidence was not included in this snapshot.

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/77ef1aa1c89240ddbb7d70e9dc4045f7`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/77ef1aa1c89240ddbb7d70e9dc4045f7`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
