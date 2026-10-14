# Local SAM maximum password age Windows 11 lifecycle passed, 2026-10-13

Request: `95845a6e61344116bc5684aae0ec18b7`. Controller result: **Passed**, finished
`10/13/2026 18:24:31`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 304 files;
preflight differences: 0. Fixture SHA-256:
`8E7461588132BB773B84FC61A7266439A690073D27BBC6D7EBE8CAC77B007D5A`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`8F53E21F1FCBBEA0713838C9C51D5C9E44BBBE3C6264A5B5AB906BEEC5B85DE5`. Published support declarations are unchanged.

All 304 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 142
passed, 0 failed, 143 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
NoExpiry, Days90, Days999. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled fault: Injected interruption after a real focused native configuration write; native writes=1, changed mutations=1, run=ad1a12b91b1a47a7ab9527954caccfbb, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/95845a6e61344116bc5684aae0ec18b7`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/95845a6e61344116bc5684aae0ec18b7`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
