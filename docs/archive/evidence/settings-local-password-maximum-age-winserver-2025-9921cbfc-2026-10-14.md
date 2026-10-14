# Local maximum-age conflicting minimum Windows Server 2025 MinimumAgeConflict guard passed, 2026-10-14

Request: `9921cbfc65c44a718fb1f872213e82f0`. Controller result: **Passed**, finished
`10/14/2026 13:05:53`. Local source revision: `2b799873f0f95b7569945373ab576f00d13a5b40`
plus its retained uncommitted source. Retained manifest: 361 files;
preflight differences: 0. Fixture SHA-256:
`6A973F2D950327D7D345365AB6F8231A85D41C9A34F635C2B61FE42B4E14C4B5`. Source catalog SHA-256:
`CCADC1F33882D23CE1EC9832E32BCBAB6C06E638C8DCDEAA868EAE2A68FF91B7`; private candidate catalog:
`601F4B6A8B4451E66983420CE3D0615474FE9DA36B89DE9E644998FF5A9085D2`. Published support declarations are unchanged.

All 361 retained snapshot files were independently checked against the
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

Native minimum-age conflict: {"Method":"Native local level-1003 one-day minimum seed; attempt maximum Days1","MaximumAgeRefused":true,"MaximumNativeWrites":0,"PolicyUnchangedAfterRefusal":true,"FailedRunId":"ac505fcaaa4e4cd695433f183f68952a","FailedRunRecoveryPassed":true,"MinimumSeedRecoveryPassed":true,"Error":"RIDE operation 'windows.local-password-maximum-age' failed. Run ID: ac505fcaaa4e4cd695433f183f68952a. Saved state: windows.local-password-maximum-age. Completed operations: <none>. Error: Explicit maximum password age must be greater than the current minimum age; minimum age is never changed implicitly.","Seed":{"Available":true,"Policy":{"SamDomainSid":"S-1-5-21-2869704422-843773509-957391554","MaxAgeSeconds":3628800,"MinAgeSeconds":86400,"MinLength":0,"ForceLogoffSeconds":4294967295,"HistoryLength":0},"Value":42,"GuiCompatible":true,"EffectivePolicy":"Local SAM currently applied field; local definitions and managed source not inspected","Interpretation":"42 days"}} Zero primary native writes; exact fixture seed recovery is distinct from primary apply lifecycle.

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test/results/9921cbfc65c44a718fb1f872213e82f0`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/9921cbfc65c44a718fb1f872213e82f0`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
