# Owned High Performance logical-export recovery Windows Server 2025 lifecycle passed, 2026-10-13

Request: `6021fbd5f4254fc1932e6828ee35fdfc`. Controller result: **Passed**, finished
`10/13/2026 19:15:48`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 314 files;
preflight differences: 0. Fixture SHA-256:
`BD6D388A61CA093D698CA429636A5D0F902D585235A0D4009BA8C1D0CFB5488D`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`6FA1405B195FA92368A981AD91614E8F81C6E1B43B846933900A75DBF015625F`. Published support declarations are unchanged.

All 314 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 151
passed, 0 failed, 152 discovered.
Fixture lifecycle: True; declared recovery mode:
Compensating; recovery passed: True; exact recovery: False.
Completed states:
Create. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled native-mutation failure evidence was not included in this snapshot.

Additional consumer/component observations were not included in this snapshot.

Owned-copy drift: {"Method":"Temporary name change on the fixture-owned inactive copy","DeletionRefused":true,"DestinationRetained":true,"SeedRecovered":true,"Error":"Owned copy changed or native export is not reproducible; refusing deletion."}

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/6021fbd5f4254fc1932e6828ee35fdfc`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/6021fbd5f4254fc1932e6828ee35fdfc`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
