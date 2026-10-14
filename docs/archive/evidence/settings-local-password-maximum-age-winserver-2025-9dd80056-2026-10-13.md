# Local SAM maximum password age Windows Server 2025 lifecycle passed, 2026-10-13

Request: `9dd8005663cc4a5894c97b6ec04bb047`. Controller result: **Passed**, finished
`10/13/2026 18:18:34`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 303 files;
preflight differences: 0. Fixture SHA-256:
`9AF53E50EE71ABB6188F3D23B3728E345C30677645AEA1C95929EB86FA0874E5`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`08684DC41C3CFD8DD4194F781D808C9273A034833421363B55FE5BE06B1D1A0E`. Published support declarations are unchanged.

All 303 retained snapshot files were independently checked against the
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

Controlled fault: Injected interruption after a real focused native configuration write; native writes=1, changed mutations=1, run=ff6a06a4f9ef446ab513452c7c612c6c, preview=True, recovery=True, repeat recovery=True. This is injected failure evidence, not a real operating-system access-denied result.

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/9dd8005663cc4a5894c97b6ec04bb047`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/9dd8005663cc4a5894c97b6ec04bb047`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
