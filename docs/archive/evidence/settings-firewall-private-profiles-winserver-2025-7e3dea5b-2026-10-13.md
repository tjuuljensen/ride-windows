# Private firewall profile Windows Server 2025 lifecycle passed, 2026-10-13

Request: `7e3dea5bf4df48c485077c4df9e274c8`. Controller result: **Passed**, finished
`2026-10-13T16:48:29.7326086Z`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 293 files;
preflight differences: 0. Fixture SHA-256:
`F07F493028DA439950F9BB30647179EF0708549D81872459A4E252A8E5BFD9BF`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`B94004F56CF3727FC21E5E6F7D282499D3027C927009E7C32B929E7713E88315`. Published support declarations are unchanged.

All 293 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 142
passed, 0 failed, 143 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
Off, On. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/7e3dea5bf4df48c485077c4df9e274c8`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/7e3dea5bf4df48c485077c4df9e274c8`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
