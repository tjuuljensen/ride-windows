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

## Three separate acceptance workflows

| Requested workflow | Implementation and acceptance required |
| --- | --- |
| Machine/default wallpaper | Establish supported default-user behavior and an owned asset location; preserve default-profile state and verify a newly created disposable user's visible desktop. A forced wallpaper policy or current-user preference does not establish this outcome. |
| User lock-screen image | Run in the intended interactive user's context. Capture the original image and selection mode; static-image byte recovery alone does not recover Spotlight or slideshow behavior. Verify the actual lock screen and repeat/restore. |
| Machine default lock-screen image | Source candidate provides owned public-readable assets, private machine recovery and policy/file conflict checks. Guarded native dispatch, actual ACL/lifecycle checks, signed-out/default image verification and visible recovery remain open. No user-change restriction is added. |

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
source checks in each shell. No image was applied to Windows.
The [remaining-test assessment](migrations/migration-completion-reassessment-2026-11-02.md)
owns the broader component status and test strategy.
