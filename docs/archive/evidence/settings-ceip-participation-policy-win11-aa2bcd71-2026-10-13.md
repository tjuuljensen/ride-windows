# CEIP policy source-reconciled Windows 11 lifecycle passed, 2026-10-13

Request: `aa2bcd713bc74c1f8bdad36d134c7e92`. Controller result: **Passed**, finished
`2026-10-13T15:53:40.7167128Z`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 284 files;
preflight differences: 2. Fixture SHA-256:
`3157FFCC2DDD168E2EE61B09FE14ACE928E522724D0223F3C01C07B9C9093304`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`5D7087EBB35D24BE9CE5BE2EEECCE47C3C1EB830AF2DE6C7891E2C97873492E7`. Published support declarations are unchanged.

All 284 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: tests\GitHubAuthentication.Tests.ps1. Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 182
passed, 0 failed, 183 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
OptedIn, OptedOut, WindowsDefault. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption after the first state-changing native New-ItemProperty write; native writes=1, changed mutations=1, run=f4bc851c2d49468c9533371ccd145bfb, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/aa2bcd713bc74c1f8bdad36d134c7e92`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/aa2bcd713bc74c1f8bdad36d134c7e92`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
