# Owned Balanced export diagnostic Windows 11 lifecycle failed or incomplete, 2026-10-13

## Consecutive-export diagnostic

Three native exports of the same unchanged inactive copy were retained under
`guest/owned-plan-exports`. Each is 8,192 bytes and begins with `regf`; their
SHA-256 hashes are `0F61408A2787B893AAD9714FD0D3F14B3F4E52EB7F7BE8127E3CD64F4435568D`,
`010B2847C2607E27DD4ABD84303CBD3395515C121E068B41B4360BDEDFF68A07` and
`8EFF2430C905704BA38C811A542A832D60E351A23A25E89E79904B393D505393`.
Each adjacent pair differs at nine bytes: offsets 12-14, 112, 128, 148 and 508-510.
This establishes raw export instability in this request, without an intervening
fixture plan mutation. It does not justify masking those offsets or relaxing
the product's unchanged-copy guard. Guarded RIDE deletion refused; checkpoint
recovery succeeded. All 296 tested snapshot hashes matched with no preflight delta.

A read-only prototype parsed private scratch copies of these retained files with
Microsoft's [RegLoadAppKey](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeyw).
It never mounted HKLM/HKU or invoked a power-plan setter on the workstation.
The API exposes an application hive through a private handle. All three parsed
representations matched: two keys, 748 bytes, SHA-256
`AD0540D8C0BFFBC8CFF9B49D1D6F720AC1B2E210624D6DC5750AF49142BCA82A`.
The prototype includes sorted key paths, raw named value types/bytes and
owner/group/DACL; key class and SACL are not included. This is diagnostic research,
not a production replacement or complete power-plan acceptance. Original retained
export files were preserved. A complete versioned comparison still requires
implementation, mocked mutation/error checks and disposable native acceptance.
Version-1 ownership records must retain safe compatibility/refusal behavior.

Request: `94297e8f3d5646308f11e786355584bf`. Controller result: **Failed**, finished
`10/13/2026 17:41:15`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 296 files;
preflight differences: 0. Fixture SHA-256:
`96DD435689AB42F170C89C20077544779917DDAEC229D8D398764C16313A25BD`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`3B7F60EA4BAAB8D8FD33EF5B7BE208AC1756248B86416865768BB62A0839E72B`. Published support declarations are unchanged.

All 296 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 147
passed, 0 failed, 148 discovered.
Fixture lifecycle: True; declared recovery mode:
Compensating; recovery passed: False; exact recovery: False.
Completed states:
Create. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Owned copy changed or native export is not reproducible; refusing deletion..

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

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/94297e8f3d5646308f11e786355584bf`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/94297e8f3d5646308f11e786355584bf`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
