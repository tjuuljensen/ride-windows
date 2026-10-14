# Local SAM maximum password age Windows Server 2025 lifecycle failed or incomplete, 2026-10-13

Request: `acf7c02d919c40208548d1cdf93fa9b7`. Controller result: **Failed**, finished
`10/13/2026 18:06:46`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 301 files;
preflight differences: 0. Fixture SHA-256:
`5DCA6367C11D1452702DD83EB5774C031C998CEF2F08118F2D551081701DEA0C`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`08684DC41C3CFD8DD4194F781D808C9273A034833421363B55FE5BE06B1D1A0E`. Published support declarations are unchanged.

All 301 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 141
passed, 0 failed, 142 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: False; exact recovery: False.
Completed states:
NoExpiry, Days90, Days999. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Local maximum age or related policy context changed; refusing stale recovery..

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/acf7c02d919c40208548d1cdf93fa9b7`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/acf7c02d919c40208548d1cdf93fa9b7`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
