# WAP Push first focused fixture, 2026-10-13

Request `ee270da2819b48b78683aa09147a23be` ran on the pinned disposable Windows 11
Enterprise Evaluation build 26300 through controller 0.4.6. Local source was
commit `f5e32180faf96508c35534ba46677bc78d0fe889` plus the uncommitted fixture
implementation. All 270 source-file hashes were retained; the fixture SHA-256
was `FA9CFFFD39D5AC9547C8019D3A0F8E45CB53CE699B89943D2E259CB58251F207`.
The service module hash was
`CB708C4BFD49F1BA527A59672A585CF2E0DEEAE008710538DFDA189E9246A8EC`.
This source includes the migration; it is not the old frozen CI revision.

Validation passed and 162 of 163 focused Pester checks passed, with one
WindowsIntegration excluded. No unit failures. The native fixture passed all
seven WAP service states and repeat apply, including startup-only runtime
preservation. Its original Manual/stopped state had literal DelayedAutoStart
DWORD 1 and effective SCM delay true. Captured recovery returned that exact
configuration, including key existence, type and both delay observations.

The overall request **failed** because fixture 0.1.0 then passed the literal
`Baseline` alias to service planning. That alias is supported for selected
registry/profile kinds, while this service path requires its declared
`AutomaticRunning` state. No handler defect or complete acceptance is claimed.
Fixture 0.1.1 uses `BaselineState` directly; repeat validation remains necessary.
Apply preview passed; restore preview and complete baseline coverage were not
reached in this attempt. Native deliberate partial failures and GUI/boot/workload
evidence remain pending.

Controller final result was Failed at 14:49:03 UTC, with null CleanupError and
CollectionError. Guest StateCollectionError was null; collection errors and
omissions were empty. The pinned checkpoint recovered cleanly. No GitHub request,
package acquisition, Windows restart scenario or developer-machine integration
was performed. Published support declarations remain unchanged.

Protected evidence is under
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results\ee270da2819b48b78683aa09147a23be`:
`source-files.json`, final result, guest summary/Pester XML/transcript and
`guest\settings-fixture.json`. The original source snapshot and local preflight
manifest/receipt preserve exact reproduction. The active
[settings ledger](../../migrations/settings-post-migration-review.md) retains
the partial legacy outcome and subsequent validation status.
