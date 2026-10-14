# CEIP policy controlled-failure attempt Windows 11 lifecycle failed or incomplete, 2026-10-13

Request: `85e70971f142431bac40fc8d250caf4d`. Controller result: **Failed**, finished
`2026-10-13T15:42:28.2282882Z`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 283 files;
preflight differences: 0. Fixture SHA-256:
`1057FEF6A4786463D6D804EE5166CCEA767D6F12F236649D8ED3EBEB7EF9FC94`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`5D7087EBB35D24BE9CE5BE2EEECCE47C3C1EB830AF2DE6C7891E2C97873492E7`. Published support declarations are unchanged.

Guest validation: True. Focused Pester: 182
passed, 0 failed, 183 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
OptedIn, OptedOut, WindowsDefault. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Controlled native-write interruption did not trigger..

The exact recovery above occurred before the unsuccessful fault phase. That phase did not record a failed run or verify RIDE recovery; its final recovery boundary was the pinned checkpoint. The overall request is failed, and no complete CEIP acceptance is claimed.

Controlled fault: Injected interruption after the first state-changing native New-ItemProperty write; native writes=0, changed mutations=0, run=, preview=False, recovery=False, repeat recovery=False. This is injected failure evidence, not a real operating-system access-denied result.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/85e70971f142431bac40fc8d250caf4d`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/85e70971f142431bac40fc8d250caf4d`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
