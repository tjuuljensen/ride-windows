# Owned Balanced InterruptedCreation Windows Server 2025 InterruptedCreation guard passed, 2026-10-13

Request: `bf89d6e09ab8448e8e5a2e3cf3312bc3`. Controller result: **Passed**, finished
`10/13/2026 20:17:40`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 323 files;
preflight differences: 0. Fixture SHA-256:
`CC3C25C05CDFA200A3518C766D7237F01C6A1C17F75B4CF9774E9D0AB8B46350`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`5FE708608E6CED3D21B969A52926701B448DB794E7413AF01C61AC78856148EE`. Published support declarations are unchanged.

All 323 retained snapshot files were independently checked against the
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

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled native-mutation failure evidence was not included in this snapshot.

Additional consumer/component observations were not included in this snapshot.

Owned-copy drift checks were not part of this fixture. Guard scenario: {"Method":"Injected interruption after successful native duplication","Stage":"Intent","CreationError":"RIDE operation 'windows.owned-balanced-power-plan' failed. Run ID: df30fed0896c481ca0fc5e79821d6949. Saved state: windows.owned-balanced-power-plan. Completed operations: <none>. Error: RIDE fixture interrupted creation after successful native duplication.","SavedCapture":{"SnapshotVersion":1,"OperationId":"windows.owned-balanced-power-plan","SourceGuid":"381b4222-f694-41f0-9685-ff5bb260df2e","DestinationGuid":"fd38789f-56f1-4895-928b-8449fd0209b4","OwnerToken":"138b8674-402b-4663-9591-218c8a8a12ba","OriginalRecord":null,"OriginalOwned":false,"SourceAvailable":true,"Available":true,"DestinationExists":false,"Active":false,"Value":false,"Stage":"Absent","ConfigurationComparison":"Not performed during read-only inspection; checked by export before recovery"},"ObservedIntent":{"SnapshotVersion":1,"OperationId":"windows.owned-balanced-power-plan","SourceGuid":"381b4222-f694-41f0-9685-ff5bb260df2e","DestinationGuid":"fd38789f-56f1-4895-928b-8449fd0209b4","OwnerToken":"138b8674-402b-4663-9591-218c8a8a12ba","OriginalRecord":{"Version":2,"OperationId":"windows.owned-balanced-power-plan","SourceGuid":"381b4222-f694-41f0-9685-ff5bb260df2e","DestinationGuid":"fd38789f-56f1-4895-928b-8449fd0209b4","OwnerToken":"138b8674-402b-4663-9591-218c8a8a12ba","Stage":"Intent","ExportSha256":null,"Comparison":"LogicalExportV1","ConfigurationSha256":null},"OriginalOwned":true,"SourceAvailable":true,"Available":true,"DestinationExists":true,"Active":false,"Value":false,"Stage":"Intent","ConfigurationComparison":"Not performed during read-only inspection; checked by export before recovery"},"RestorePreviewPassed":true,"DeletionRefused":true,"DestinationRetained":true,"Error":"Ownership mismatch or incomplete creation; manual review required.","NativeCalls":["/list","/query","/list","/query","/list","/query","/duplicatescheme","/list","/query","/getactivescheme","/list","/query","/getactivescheme","/list","/list","/query","/getactivescheme"],"Recovery":"CheckpointOnly; Intent record and incomplete copy retained"} This is accepted refusal evidence only. RIDE recovery did not occur; the Intent/changed copy was retained until host checkpoint cleanup.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/bf89d6e09ab8448e8e5a2e3cf3312bc3`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/bf89d6e09ab8448e8e5a2e3cf3312bc3`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
