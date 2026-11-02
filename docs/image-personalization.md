# Image input preparation and pending personalization acceptance

RIDE can validate selected local static PNG inputs and prepare a machine default
lock-screen image through a guarded lifecycle candidate. Default wallpaper and
per-user lock-screen handlers are not implemented yet. Source tests and policy
readback are not Windows visual acceptance passes.

## Validate an input

Start in the repository root using native Windows PowerShell 5.1 or PowerShell 7
on Windows. No elevation is needed. Select a local `.png` and obtain its expected
SHA-256 from the reviewed input manifest, independently of this validation call:

```powershell
Import-Module ./modules/RIDE.ImageFiles.psm1
Get-RidePngSource -Path 'C:\Inputs\wallpaper.png' -ExpectedSha256 $selectedHash
```

The command reads a stable snapshot and checks its hash before decoding. It
accepts static PNGs up to 16 MiB, 8192 pixels on either axis and 32 million total
pixels. It checks the signature, critical chunk envelope, CRCs, dimensions,
compressed-data header, bounded scanlines and inflated-data checksum, then asks
Windows GDI+ to decode the snapshot. Animated PNGs, alternate streams, network
paths and reparse paths refuse. This is a bounded source gate, not a complete PNG
conformance test or a claim that Windows will use the image for a given policy.

The result contains the hash, byte count and dimensions. `-IncludeContent` also
returns the exact validated `Content` byte array for a future lifecycle writer.
That writer must use the returned bytes instead of reopening an input that may
have changed. Validation does not edit the source, create an installed asset or
change personalization. There is no system change to restore.

## Machine default lock-screen candidate

`Set-RideDefaultLockScreenImage` creates a unique PNG in an existing owned asset
directory and sets only the machine `LockScreenImage` policy. It preserves
existing user-change restrictions, per-user preferences and Windows inbox
images. It adds no restriction preventing users from changing their image;
existing restrictions can still apply. Source and previously referenced images
are untouched.

Run only inside the selected disposable Windows 11 x64 Hyper-V guest, using an
already elevated native PowerShell 5.1/7 session. The guest must have controller
markers `RIDE_TEST_GUEST=1` and `RIDE_INTEGRATION_VM=1`; the module also checks the
actual virtual-machine manufacturer/model. The explicit computer/build/edition
must match. Candidate editions are `Enterprise`, `EnterpriseN`, `EnterpriseEval`,
`Education` and `EducationN`. No UAC or automatic sign-out/reboot is launched.

Prepare the existing directories separately in that guest. The asset directory
and its parent must be Administrators/SYSTEM owned and grant modification only
to those principals; the asset directory needs Builtin Users read/execute access.
Conflicting read/execute deny rules refuse. The separate state directory must
already exist below a local drive root. No reparse or network paths are
allowed. The command does not repair permissions or create parent directories.

From the repository root in that guest:

```powershell
Import-Module ./modules/RIDE.DefaultLockScreen.psm1
$selection = @{
    Path = 'C:\Inputs\default-lock.png'
    ExpectedSha256 = $selectedHash
    AssetDirectory = 'C:\RIDE-Test\Images'
    StateDirectory = 'C:\RIDE-Test\State'
    ExpectedComputerName = '<disposable-guest-name>'
    ExpectedBuild = '<exact-build-number>'
    ExpectedEditionId = 'EnterpriseEval'
}
Set-RideDefaultLockScreenImage @selection -WhatIf
$run = Set-RideDefaultLockScreenImage @selection -AllowCandidate -Confirm:$false
Set-RideDefaultLockScreenImage @selection -AllowCandidate -Confirm:$false
Restore-RideDefaultLockScreenRun -RunId $run.RunId -StateDirectory $selection.StateDirectory -WhatIf
Restore-RideDefaultLockScreenRun -RunId $run.RunId -StateDirectory $selection.StateDirectory -AllowCandidate -Confirm:$false
```

The schema-1 result includes `Scope`, `Status`, `RunId` and
`NativeVisualAcceptance`. Apply returns `Applied` with `AssetPath`; a matching,
unchanged completed run returns `AlreadyDesired` without creating another run.
Preview returns `Preview` and writes nothing. Actual apply and restore each
require `-AllowCandidate`. `ExpectedEditionId` and saved restore `RunId` values
offer read-only completion; supply `StateDirectory` to discover saved IDs.

Before the first image/policy write, RIDE creates a private machine intent file
owned by Administrators, accessible only to Administrators/SYSTEM. A verified
apply adds a separate completed record. The public image file grants Users read
and execute access, with write access limited to Administrators/SYSTEM. Recovery
checks its hash, length, owner/group/DACL, attributes and creation/write times,
plus directory security, target identity and the complete personalization key.
Unrelated policy values, child keys and existing key security must remain equal.

Restore reinstates the captured string/expandable-string value or absence and
removes only the unchanged image created by that run. It preserves previously
referenced files. A run-created policy key is removed only after removing its
owned value and checking that the key is empty; deletion is nonrecursive. A
second restore returns `AlreadyRestored` only when captured policy and image
absence both match. If policy restoration succeeded but file removal stopped,
retry may remove the still-unchanged owned image. Records remain available.

Other policy types, missing completed records or conflicting changes refuse
automatic recovery. On failure retain the reported run ID, private records and
guest checkpoint; inspect before cleanup. An incomplete apply may leave its
new image or policy in place. The command does not substitute a default reset
for captured restore. Windows policy refresh, cached images and visible lock
screen state are not captured or claimed restored by registry/file readback.

## Phased disposable-guest acceptance

`tests/integration/Invoke-RideDefaultLockAcceptance.ps1` provides separate `Apply`
and `Restore` phases for the pinned `suit_sharpened_4k.png` fixture. The matching
module command is `Invoke-RideDefaultLockAcceptance`. Each phase explicitly runs
the candidate lifecycle within the attested guest; saved evidence never starts
the next phase automatically. `-Version` prints `0.1.0` without inspecting Windows.

The prerequisites above still apply. The existing `EvidenceRoot` must be owned
by Administrators/SYSTEM and grant modification only to them. The controller
must set `RIDE_TEST_RUN_ID` to the same 32-character lowercase hexadecimal request
ID for both phases, in addition to the two guest markers. Apply creates a new
request directory, public-readable image directories and private machine state.
It refuses an existing request directory. Restore requires the private completed
apply report and the matching lifecycle records; it does not need the source PNG.

Capture the initial signed-out/default image before Apply. In the already
attested, elevated disposable guest, from the repository root:

```powershell
Import-Module ./tests/integration/RIDE.DefaultLockAcceptance.psm1
$target = @{
    RunId = $env:RIDE_TEST_RUN_ID
    ExpectedComputerName = '<disposable-guest-name>'
    ExpectedBuild = '<exact-build-number>'
    ExpectedEditionId = 'EnterpriseEval'
    EvidenceRoot = 'C:\RIDE\Evidence'
    DisposableVm = $true
}
Invoke-RideDefaultLockAcceptance @target -Phase Apply -SourcePath 'C:\Inputs\suit_sharpened_4k.png' -WhatIf
$applied = Invoke-RideDefaultLockAcceptance @target -Phase Apply -SourcePath 'C:\Inputs\suit_sharpened_4k.png' -Confirm:$false
# Independently inspect and capture the signed-out/default image before Restore.
Invoke-RideDefaultLockAcceptance @target -Phase Restore -WhatIf
$restored = Invoke-RideDefaultLockAcceptance @target -Phase Restore -Confirm:$false
# Independently inspect and capture visible recovery before guest checkpoint cleanup.
```

Apply checks no-change preview, policy/image/private-state readback and unchanged
repeat, then returns `AwaitingVisualVerification` with `RecoveryRequired=true`.
It leaves the selected image active. Restore checks no-change preview, captured
state recovery and repeated restore, then returns `LifecyclePassedVisualPending`
with `NativeLifecycleAcceptancePassed=true`. A restored policy does not prove
that Windows refreshed a cached image. `NativeVisualAcceptancePassed` and
`NativeAcceptancePassed` remain false in both phases; these are stable schema-1
fields, not an overall success indication from the process exit code.

Retain the initial, applied and recovered screenshots with the request ID,
guest/build/edition, session state and any explicit refresh/sign-out/restart
steps. Verify the machine default shown while signed out, separately from a
signed-in user's lock-screen preference. The visible applied image must match
the selected input, and visible recovery must match the captured initial state.
No visual acceptance can be inferred from the PNG hash or registry readback.

Private `before.json`, `applied-snapshot.json`, `apply.json`, lifecycle state and
uniquely named `restore.<attempt-id>.json` reports remain under the request
directory. Failed steps return `Failed` with stage and known state run IDs; they
retain the guest and require inspection. A completed apply can be recovered after
a failed restore without overwriting prior attempt reports. Failed/incomplete
apply evidence cannot be used to bypass lifecycle recovery refusal. Saved
request IDs offer read-only completion for both entry points when `Phase=Restore`
and `EvidenceRoot` are supplied.

Protected host dispatch that retains the guest between these phases is still
pending. Its [coordination boundary](#retained-host-coordination) is source-ready.
The existing generic queue resets the VM after each request and must
not be used for this phased scenario. Neither guest entry point signs out,
reboots, resets a checkpoint or performs failure cleanup. Export private evidence
and verify visible recovery before any separately authorized checkpoint reset.

### Retained host coordination

`tests/integration/RIDE.RetainedGuest.psm1` supplies the internal reservation
boundary for a future retained host dispatcher. It does not yet supply that
dispatcher, guest staging, evidence export or checkpoint-recovery receipt writer.
Do not reserve a real guest until those phases are available and reviewed.

`New-RideRetainedGuestHold` requires the installed configuration, exact VM and
checkpoint IDs, registered host account, native Windows PowerShell 5.1, existing
elevation, an idle controller and an Off disposable VM. Under the existing worker
lock it creates a private machine `runtime/blocked.json` record. It never replaces
a previous block. Ordinary queue requests recognize this block and refuse before
host preparation or VM reset. A unique lease ID distinguishes separate reservations
even if their request IDs are accidentally reused.

`Open-RideRetainedGuestPhase` validates the private hold, configuration digest and
registered identities under the worker lock, then returns that lock to the caller.
The dispatcher must retain it through execution, export and journal writes and
dispose it in `finally`. The durable block remains between phases and after
exceptions. Neither function starts, stops or restores a VM.

`Remove-RideRetainedGuestHold` accepts only a private schema-1
`RetainedGuestRecovery` receipt containing matching `RunId`, `LeaseId`, `VMId`,
`CheckpointId` and `ConfigurationSha256`, boolean `EvidenceExportVerified=true`
and `CheckpointResetVerified=true`, and `Status=ResetAndOff`. It rechecks the pinned
VM is Off under the same lock before deleting only the owned block. An Off VM
alone cannot prove checkpoint recovery. The future dispatcher must produce the
receipt after actual export/reset verification; operators must not manufacture a
receipt to unblock a guest. Ordinary failure blocks and stale receipts are refused.

Reservation/release previews do not acquire the worker lock, query host services
or inspect a VM. They validate accessible configuration/state only and cannot
certify actual availability. Saved run completion reads only the bounded private
hold. Stable schema-1 results are `Reserved`, `Released` or `Preview`, always with
`NativeAcceptancePassed=false`; a reservation establishes no test result.
The [source evidence](archive/evidence/retained-guest-coordination-source-2026-11-02.json)
records mocked host/VM checks and real temporary user-scope file/lock checks.

## Three separate acceptance workflows

| Requested workflow | Implementation and acceptance required |
| --- | --- |
| Machine/default wallpaper | Establish supported default-user behavior and an owned asset location; preserve default-profile state and verify a newly created disposable user's visible desktop. A forced wallpaper policy or current-user preference does not establish this outcome. |
| User lock-screen image | Run in the intended interactive user's context. Capture the original image and selection mode; static-image byte recovery alone does not recover Spotlight or slideshow behavior. Verify the actual lock screen and repeat/restore. |
| Machine default lock-screen image | Source lifecycle and retained two-phase guest scenario are prepared. Protected host dispatch, actual ACL/lifecycle checks, signed-out/default image verification and visible recovery remain open. No user-change restriction is added. |

Microsoft's detailed [default lock-screen policy documentation](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_forcedefaultlockscreen)
limits that policy to Enterprise, Education and Server editions. A Windows 11 Pro
registry round trip must not be reported as a successful default-image test.
Windows Server support also requires its own native acceptance evidence.

The legacy `SetDefaultLockScreen` removes old overrides; it is a reset action,
not an existing second-image setter. Keep that mapping separate from the newly
requested default-image workflow. The legacy wallpaper ownership changes and
inbox-file overwrites, and the Pro lock-screen CSP registry workaround, are not
approved replacements for documented behavior and captured recovery.

Each future disposable-guest scenario must preview without changes, apply,
verify the visible effect, repeat without new mutations, restore the captured
state and verify recovery. Refuse conflicting policy/file changes and retain
incomplete-run evidence. Do not delete or overwrite Windows inbox images,
shared source images or unrelated user assets. Image refresh/caching and
sign-out requirements need native evidence; registry equality alone is not
visual verification.

## Current evidence

The three [selected inputs](archive/evidence/custom-ride-image-inputs-2026-11-02.json)
remain hash-pinned copies of the user-supplied images. The
[source-validation evidence](archive/evidence/image-source-validation-2026-11-02.json)
records both PowerShell versions, malformed-input checks and real input decoding.
All three selected images are 3840 by 2160. The
[default lock-screen lifecycle evidence](archive/evidence/default-lock-screen-source-2026-11-02.json)
records 27 focused mocked lifecycle/security checks and the 16 shared image
source checks in each shell. The
[phased guest preparation evidence](archive/evidence/default-lock-screen-acceptance-preparation-2026-11-02.json)
adds 17 orchestration/source/directory checks per shell, plus a real pinned-input
check. No image was applied to Windows.
The [remaining-test assessment](migrations/migration-completion-reassessment-2026-11-02.md)
owns the broader component status and test strategy.
