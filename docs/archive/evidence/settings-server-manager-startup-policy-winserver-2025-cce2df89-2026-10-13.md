# Server Manager startup policy Windows Server 2025 lifecycle passed, 2026-10-13

Request: `cce2df896ad047a6b71d9df6aa4f8230`. Controller result: **Passed**, finished
`10/13/2026 17:58:54`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 299 files;
preflight differences: 0. Fixture SHA-256:
`28C8855C7D8E34222FBEF1DF6FB313D63C4E5BB9A9CF06D5A37619A0B9478E1E`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`9A571B15B10B2E123CE4B0DD8589326995DF9337091A123DC89DEC398D3EA3FA`. Published support declarations are unchanged.

All 299 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 182
passed, 0 failed, 183 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
AutomaticStartup, Suppressed, WindowsDefault. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption after the first state-changing native New-ItemProperty write; native writes=1, changed mutations=1, run=594d6255081a48c79978b63d2db50549, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

Conditional component observations: {"Area":"Server Manager","ExecutablePresent":true,"PolicyConsumptionVerified":false,"FeatureAcceptance":"Pending applicable desktop/logon and console-preference behavior"}

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/cce2df896ad047a6b71d9df6aa4f8230`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/cce2df896ad047a6b71d9df6aa4f8230`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
