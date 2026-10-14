# Local maximum-age conflicting minimum Windows 11 MinimumAgeConflict guard passed, 2026-10-14

Request: `660dac2bfa0d45f3ac8d6e1f46dcc7eb`. Controller result: **Passed**, finished
`10/14/2026 13:00:31`. Local source revision: `2b799873f0f95b7569945373ab576f00d13a5b40`
plus its retained uncommitted source. Retained manifest: 360 files;
preflight differences: 0. Fixture SHA-256:
`9454FD88FDC370A36FCCC1691B124A1D42583F698D88BBC728CDC915C8C47CA6`. Source catalog SHA-256:
`CCADC1F33882D23CE1EC9832E32BCBAB6C06E638C8DCDEAA868EAE2A68FF91B7`; private candidate catalog:
`A446E81D24D0AC3A5D5A33F93B20FC193F3CB2A5D8004B96F0F951C9F03C3378`. Published support declarations are unchanged.

All 360 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 154
passed, 0 failed, 155 discovered.
Fixture lifecycle: False; declared recovery mode:
ExactFixtureSeed; recovery passed: False; exact recovery: False.
Completed states:
. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Native minimum-age conflict: {"Method":"Native local level-1003 one-day minimum seed; attempt maximum Days1","MaximumAgeRefused":true,"MaximumNativeWrites":0,"PolicyUnchangedAfterRefusal":true,"FailedRunId":"2989facd67e64fd29147445ddaca720f","FailedRunRecoveryPassed":true,"MinimumSeedRecoveryPassed":true,"Error":"RIDE operation 'windows.local-password-maximum-age' failed. Run ID: 2989facd67e64fd29147445ddaca720f. Saved state: windows.local-password-maximum-age. Completed operations: <none>. Error: Explicit maximum password age must be greater than the current minimum age; minimum age is never changed implicitly.","Seed":{"Available":true,"Policy":{"SamDomainSid":"S-1-5-21-3381495413-3650599264-2815280620","MaxAgeSeconds":3628800,"MinAgeSeconds":86400,"MinLength":0,"ForceLogoffSeconds":4294967295,"HistoryLength":0},"Value":42,"GuiCompatible":true,"EffectivePolicy":"Local SAM currently applied field; local definitions and managed source not inspected","Interpretation":"42 days"}} Zero primary native writes; exact fixture seed recovery is distinct from primary apply lifecycle.

Additional consumer/component observations were not included in this snapshot.

Owned-copy drift checks were not part of this fixture.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/660dac2bfa0d45f3ac8d6e1f46dcc7eb`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/660dac2bfa0d45f3ac8d6e1f46dcc7eb`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
