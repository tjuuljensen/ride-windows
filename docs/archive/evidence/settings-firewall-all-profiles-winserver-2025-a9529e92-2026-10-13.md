# Firewall enable-all Windows Server 2025 lifecycle passed, 2026-10-13

Request: `a9529e92f9a04790b96ef69e3c33701b`. Controller result: **Passed**, finished
`2026-10-13T16:17:43.2337066Z`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 287 files;
preflight differences: 0. Fixture SHA-256:
`72D628FD205FBDAF015A0E77B4C631A6C1923043E00F20C12103925259AE886D`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`FF7F58D65717879EB028D2EBE99223BB8D77B05E08531DA2E77C57D6B1B66B8A`. Published support declarations are unchanged.

All 287 retained snapshot files were independently checked against the
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

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption before the second profile setter after one real native change; native writes=1, changed mutations=1, run=9483b572205640efbeceeb20df0e4c2b, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/a9529e92f9a04790b96ef69e3c33701b`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/a9529e92f9a04790b96ef69e3c33701b`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
