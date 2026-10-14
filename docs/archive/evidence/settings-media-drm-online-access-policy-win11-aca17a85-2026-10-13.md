# Conditional Windows Media DRM policy Windows 11 lifecycle passed, 2026-10-13

Request: `aca17a85e3ab46a1bf4664b93cd40c3e`. Controller result: **Passed**, finished
`10/13/2026 17:54:45`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 298 files;
preflight differences: 0. Fixture SHA-256:
`767FA15F2752E94FACCF980C89AFED5959172D473DB97B98CBB927ADB011D3A4`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`99DBECEBAC8D2F260EBD45E219D7E431336CF6388D9BB27758E79E777C01918C`. Published support declarations are unchanged.

All 298 retained snapshot files were independently checked against the
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

Controlled fault: Injected interruption after the first state-changing native New-ItemProperty write; native writes=1, changed mutations=1, run=7fa74e5ebf154017b8c708baa56ffe8a, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

Conditional component observations: {"Area":"Windows Media DRM","ConsumerPresenceVerified":false,"PolicyConsumptionVerified":false,"FeatureAcceptance":"Pending applicable backend/client and license-acquisition evidence; no consumer is inferred from registry values"}

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/aca17a85e3ab46a1bf4664b93cd40c3e`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/aca17a85e3ab46a1bf4664b93cd40c3e`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
