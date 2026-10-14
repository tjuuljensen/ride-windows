# Conditional radio policy Windows 11 lifecycle passed, 2026-10-13

Request: `9cbb0b2a72e94a9ea14900842e5faac3`. Controller result: **Passed**, finished
`10/13/2026 17:48:52`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 297 files;
preflight differences: 0. Fixture SHA-256:
`17AF96208863FC35B10263820B3459DB0412C4D7AC2316D0E86FD8B62861F238`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`863215ADACE7BBF3CF61AA65F4F4DF269589586655E8751324875811B6D38F53`. Published support declarations are unchanged.

All 297 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 182
passed, 0 failed, 183 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
Blocked, PolicyDisabled, WindowsDefault. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption after the first state-changing native New-ItemProperty write; native writes=1, changed mutations=1, run=803b3f8ec63f490e8fd6d178dd78649d, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

Conditional component observations: {"Area":"Legacy Windows Media Player","ExecutablePaths":["C:\\Program Files\\Windows Media Player\\wmplayer.exe","C:\\Program Files (x86)\\Windows Media Player\\wmplayer.exe"],"ExecutablePresent":true,"PolicyConsumptionVerified":false,"FeatureAcceptance":"Pending radio-feature and consumer evidence, regardless of executable presence"}

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/9cbb0b2a72e94a9ea14900842e5faac3`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/9cbb0b2a72e94a9ea14900842e5faac3`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
