# WAP Push focused lifecycle, 2026-10-13

Corrected fixture request `807cb015f98047548c59941bc5da3460` passed on disposable
Windows 11 Enterprise Evaluation build 26300, Windows PowerShell 5.1.26100.9444,
through the pinned controller 0.4.6. It ran from Local source revision
`00e820f876f6c00f70750c732b3057f5e82f79bd` plus uncommitted fixture code. All 273
retained source-file hashes match the preflight snapshot, including the current
service implementation. Fixture SHA-256:
`5BDD0568153D983202F4D4B7968157DBCFFD8A6EBC60B3809FA3325FAE6C9350`.

Guest validation and 162 focused Pester checks passed, with one
WindowsIntegration excluded. The real native fixture passed all seven states,
repeat apply, startup-only runtime preservation, apply/restore preview and
explicit declared baseline application. Captured recovery exactly restored the
original Manual/stopped state, DelayedAutoStart DWORD 1/key-present and effective
SCM delay true. This supersedes the baseline-call failure in the
[first fixture](settings-wap-first-fixture-2026-10-13.md), without deleting its evidence.

Final controller result was Passed at 15:03:01 UTC; Error, CleanupError and
CollectionError were null, as was guest StateCollectionError. Normal export
completed; the failure collector was not needed. Independent postflight verified
both VMs Off, tasks Ready, empty pending/running queues, available locks, no blocks
and unchanged pinned checkpoint identities. No package or GitHub acquisition,
host UAC change, boot scenario or developer-machine integration was performed.

This is **lifecycle evidence**, not complete feature acceptance. Actual Services
GUI/session refresh, boot delay behavior, device-management workload, managed
precedence/defaults and deliberately induced native partial failures remain
pending. Published SupportedTargets are unchanged and no Server claim is added.
No whole legacy outcome or estimate count is closed by this run.

Protected evidence:
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results\807cb015f98047548c59941bc5da3460`.
Retained files include source manifest/snapshot, final result, guest summary,
Pester XML, transcript and `settings-fixture.json`. Local preflight manifest,
receipt and postflight are under `.local/settings-validation/807cb015f98047548c59941bc5da3460`.
The active [settings review](../../migrations/settings-post-migration-review.md)
retains the partial outcome and remaining acceptance.
