# Firewall enable-all seed-recovery attempt Windows 11 lifecycle failed or incomplete, 2026-10-13

Request: `ffca76b53da744bfbe200daaeaec271f`. Controller result: **Failed**, finished
`2026-10-13T16:03:53.3451088Z`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 285 files;
preflight differences: 0. Fixture SHA-256:
`95E29EB9C916B09B1686447DAB5764D62DE4989B362F53719B133CAB983844E8`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`66A6F5BB9F02D45D83B516381B9E93ADA10DE0FE89D4CD8E606C667DEB96813B`. Published support declarations are unchanged.

All 285 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 142
passed, 0 failed, 143 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
On. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: The term 'Restore-RideFirewallProfileState' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again..

Controlled fault: Injected interruption before the second profile setter after one real native change; native writes=1, changed mutations=1, run=64e2e213809d4bcaa95d5f7c7107c0b0, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/ffca76b53da744bfbe200daaeaec271f`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/ffca76b53da744bfbe200daaeaec271f`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
