# Owned Balanced active-copy refusal Windows Server 2025 ActiveRefusal guard passed, 2026-10-13

Request: `4c1579dfc525486a9812979ca8b05a20`. Controller result: **Passed**, finished
`10/13/2026 19:46:43`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 318 files;
preflight differences: 0. Fixture SHA-256:
`E16A6A9CBCD5C0F664051DE7F308519FB6C14FE1C8B75E38F0897D63EB4C4B05`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`F0B41C4EB94ABD573FB634980BA4E8F8DD7C2E848EACF3F7162C7EAD6921B088`. Published support declarations are unchanged.

All 318 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 156
passed, 0 failed, 157 discovered.
Fixture lifecycle: True; declared recovery mode:
Compensating; recovery passed: True; exact recovery: False.
Completed states:
Create. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled native-mutation failure evidence was not included in this snapshot.

Additional consumer/component observations were not included in this snapshot.

Owned-copy drift checks were not part of this fixture. Guard scenario: {"Method":"Engine-captured selection of the fixture-owned copy","SelectionRunId":"07936255794e4c44afc9b71f6175896d","SelectionPreviewPassed":true,"DeletionRefused":true,"DestinationRetained":true,"SelectionRecoveryPassed":true,"Error":"Owned copy is active; restore the saved selection first."}

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/4c1579dfc525486a9812979ca8b05a20`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/4c1579dfc525486a9812979ca8b05a20`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
