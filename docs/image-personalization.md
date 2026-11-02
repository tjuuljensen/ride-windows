# Image input preparation and pending personalization acceptance

RIDE can validate selected local static PNG inputs and prepare machine first-logon
wallpaper and default lock-screen images through guarded lifecycle candidates.
The per-user lock-screen handler is not implemented yet. Source tests and policy
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

## Machine first-logon wallpaper candidate

`Set-RideDefaultWallpaperImage` uses the documented machine
[Load a specific theme policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_settheme).
It sets `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\ThemeFile`
to a new owned `.theme` file referencing a new owned PNG. Windows documents this
policy for first sign-in and permits users to personalize the theme afterwards.
The candidate edits neither the default-user hive nor Windows inbox images.
This is separate from the deprecated unattended `CustomDefaultThemeFile` setting
and from forcing a wallpaper on existing user desktops.

The generated theme uses the documented required desktop, visual-style and master
selector sections. It selects the PNG with aspect-preserving fill/crop and the
built-in Aero visual style, leaving other sections unspecified. A theme is broader
than an image: native acceptance must check effects on colors, sounds, icons and
other defaults, as well as the image. Source generation does not prove those
defaults are preserved. The theme is UTF-16LE with BOM and CRLF for Windows INI
consumption; module/test sources remain repository UTF-8/LF. Caller-supplied theme
content is not accepted, and embedded image paths reject INI/environment syntax.

Run only inside the selected, already elevated Windows 11 x64 Enterprise/Education
Hyper-V test guest, with `RIDE_TEST_GUEST=1` and `RIDE_INTEGRATION_VM=1`. The same
existing asset/state directory and parent ownership/read-access requirements as
the [default lock-screen candidate](#machine-default-lock-screen-candidate) apply.
This candidate has no accepted Windows target and does not add a catalog operation.
The documented policy supports more editions than this initial candidate permits;
that is not evidence of runtime acceptance on those editions.

From the repository root in that guest:

```powershell
Import-Module .\modules\RIDE.DefaultWallpaper.psm1
$pin = Import-PowerShellDataFile .\tests\fixtures\default-wallpaper.acceptance.psd1
$selection = @{
    Path = 'C:\Inputs\fedora_sharpened_4k.png'
    ExpectedSha256 = $pin.Sha256
    AssetDirectory = 'C:\RIDE-Test\Images'
    StateDirectory = 'C:\RIDE-Test\State'
    ExpectedComputerName = '<disposable-guest-name>'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
}
Set-RideDefaultWallpaperImage @selection -WhatIf
$run = Set-RideDefaultWallpaperImage @selection -AllowCandidate -Confirm:$false
Set-RideDefaultWallpaperImage @selection -AllowCandidate -Confirm:$false
Restore-RideDefaultWallpaperRun -RunId $run.RunId -StateDirectory $selection.StateDirectory -WhatIf
Restore-RideDefaultWallpaperRun -RunId $run.RunId -StateDirectory $selection.StateDirectory -AllowCandidate -Confirm:$false
```

The schema-1 result reports Applied, AlreadyDesired, Restored, AlreadyRestored or
Preview; `NativeVisualAcceptance` always remains false. Apply returns the run ID,
PNG `AssetPath` and `ThemePath`. Saved run IDs and edition choices offer completion.
Preview writes nothing. Actual apply and restore each require `-AllowCandidate`.
Private machine intent captures the complete policy key state, directory security
and user-profile SID/path inventory before either new file or policy is written.
Completed records bind image/theme hashes, ACLs, attributes and timestamps. Repeat
requires matching owned content and policy. No original image/theme is overwritten.

Restore reinstates the captured policy or absence and removes only the unchanged
owned theme/image pair. Unrelated values, child keys and prior key security must
still match. A newly created key is removed only when empty, nonrecursively.
Recovery can finish file removal after policy restoration or one owned file's
removal was interrupted. Incomplete apply records do not authorize blind recovery.

A changed user-profile SID/path inventory refuses automatic recovery before policy
or asset removal: the first-logon policy may already have affected another user.
The module never deletes accounts/profiles or restores those users' preferences.
Its inventory guard is not an exhaustive reference scan for manually selected
theme/image files. Existing consumers outside the declared lifecycle require
inspection. Keep the guest and private records on any conflict or partial failure.

The native scenario must retain evidence across these stages:

1. Record the original policy/default appearance and an already initialized
   control user's desktop and personalization defaults.
2. Preview, apply, verify owned bytes/permissions and repeat with no new mutations.
3. Create one uniquely owned disposable user/profile; verify its first desktop
   displays the selected image, check other theme defaults and confirm the
   pre-existing control user's settings did not change.
4. Change the test user's wallpaper, sign out/in and verify the first-logon policy
   does not replace that later choice. Export observations before fixture cleanup.
5. Remove only that owned test account/profile through a verified fixture cleanup
   route, then restore the machine policy/assets and repeat restoration. Do not
   remove unrelated profiles merely to satisfy the recovery guard.
6. Create a separate owned recovery-test user and verify the original first-logon
   default is restored. Retain and export evidence before checkpoint cleanup.

The machine guest phases, owned test-user fixture and retained host dispatch
below are source-prepared. Existing elevated execution, native account/profile
behavior and visual acceptance remain open.
The [source evidence](archive/evidence/default-wallpaper-source-2026-11-02.json)
does not establish that Windows consumed the generated theme.

### Wallpaper guest acceptance phases

Use `tests/integration/Invoke-RideDefaultWallpaperAcceptance.ps1` inside the
already elevated, selected disposable guest, from its staged repository root.
The existing evidence parent must be administrator/SYSTEM owned and writable
only by those principals. Choose a short local path: the eventual owned PNG path
must fit the candidate's 240-character limit. The runner checks this before
creating evidence. It validates the pinned `fedora_sharpened_4k.png`, exact guest
name/build/edition, Hyper-V identity and matching controller request marker.
No UAC, account creation, sign-in, sign-out, reboot or checkpoint reset is launched.

After capturing the initialized control user's original desktop and other
personalization defaults, use the controller's correlated request ID:

```powershell
$request = @{
    RunId = $env:RIDE_TEST_RUN_ID
    ExpectedComputerName = '<disposable-guest-name>'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
    EvidenceRoot = 'C:\RIDE-Test\Evidence'
    DisposableVm = $true
}
.\tests\integration\Invoke-RideDefaultWallpaperAcceptance.ps1 @request -Phase Apply -SourcePath 'C:\Inputs\fedora_sharpened_4k.png' -WhatIf
.\tests\integration\Invoke-RideDefaultWallpaperAcceptance.ps1 @request -Phase Apply -SourcePath 'C:\Inputs\fedora_sharpened_4k.png' -Confirm:$false
```

Apply creates only a new request directory, public-read asset directories and
private machine state/reports. Its three checks verify preview without changes,
the applied policy/theme/image/private-state chain, and repeated application
without new state. Readback includes both file identities and the profile SID/path
inventory. It leaves the guest at `AwaitingVisualVerification`; it does not create
the first-logon test user. Perform stages 3-5 above through the owned test-user
fixture, export the observations, and verify only that fixture's account/profile
has been removed before recovery. Do not reset the VM between these phases.

```powershell
.\tests\integration\Invoke-RideDefaultWallpaperAcceptance.ps1 @request -Phase Restore -WhatIf
.\tests\integration\Invoke-RideDefaultWallpaperAcceptance.ps1 @request -Phase Restore -Confirm:$false
```

Restore accepts the completed matching Apply record and no source-image input.
Its three checks verify recovery preview without changes, captured machine
policy/assets/profile-inventory recovery and repeated restoration. Changed profile
identities fail before invoking the lifecycle restore; neither the runner nor
the handler deletes a profile to satisfy that guard. Each recovery attempt adds
a new private report. Incomplete Apply is retained for inspection and cannot be
automatically converted into a Restore phase. Export all records before any
checkpoint cleanup, then perform the recovery-user visual check in stage 6.

Schema-1 results include `RunId`, `Phase`, `Status`, `Stage`, `Context`,
`RecoveryRequired`, `LifecycleRunId`, `AssetPath`, `ThemePath`, `Checks` and
`EvidenceDirectory`. A successful Restore reports `LifecyclePassedVisualPending`
and `NativeLifecycleAcceptancePassed=true` for its machine-state checks only.
`NativeFirstLogonAcceptancePassed`, `NativeVisualAcceptancePassed` and
`NativeAcceptancePassed` always remain false. Independent evidence must establish
the full first-logon/user-choice/default-recovery outcome. `Failed` retains the
last stage and recovery requirement. Outer `-WhatIf` writes nothing and returns
`Preview`; it does not prove the later native phase is ready. Phase/edition values
and saved Restore request directories offer read-only completion.
The [guest preparation evidence](archive/evidence/default-wallpaper-acceptance-preparation-2026-11-02.json)
records mocked orchestration tests and read-only real input checks, not VM results.

### Owned wallpaper test users

`tests/integration/RIDE.WallpaperTestUser.psm1` provides `New-`, `Get-` and
`Remove-RideWallpaperTestUser` for the Control, FirstLogon and Recovery fixtures.
Use these only in the selected, already elevated disposable guest with the same
controller request marker as the wallpaper phase. An existing private fixture
directory must be outside the test profiles, administrator/SYSTEM owned and
writable only by those principals. Native local-account/CIM APIs are required.
No account/profile change has yet been verified on the test VM.

From the staged repository root in that guest, import the module and supply a
synthetic `SecureString` password of 16-128 characters through the private test
harness. Native password policy may impose additional requirements. Keep this
credential available for interactive sign-in; the fixture never persists or
returns it. Real network or personal credentials are unnecessary.

```powershell
Import-Module .\tests\integration\RIDE.WallpaperTestUser.psm1
$fixture = @{
    RunId = $env:RIDE_TEST_RUN_ID
    StateDirectory = 'C:\RIDE-Test\Users'
    ExpectedComputerName = '<disposable-guest-name>'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
    DisposableVm = $true
}
New-RideWallpaperTestUser @fixture -Purpose Control -WhatIf
$control = New-RideWallpaperTestUser @fixture -Purpose Control -Password $testPassword -Confirm:$false
```

The generated name includes the purpose and request ID. A name or predicted
profile-directory collision refuses instead of adopting an existing user. Private
intent is written before account creation; the returned SID is saved before
adding only Builtin Users membership. Repeating creation verifies the existing
fixture and does not reset its password. The fixture does not load a profile or
start Explorer. Windows creates the profile at first sign-in; an account alone
does not establish that the theme was consumed. See Microsoft's
[local profile lifecycle](https://learn.microsoft.com/en-us/windows/win32/shell/local-user-profiles)
and [local account creation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1).

Sign in as Control and initialize its desktop **before** the wallpaper Apply
phase. Record its visible desktop and other theme defaults. Retain its profile
through machine restoration because it belongs to the captured profile inventory.
After Apply, create FirstLogon with the same fixture parameters and a synthetic
password, sign in, verify the selected image and other defaults, change that user's
wallpaper, then sign out/in to verify the later choice persists. This requires an
interactive desktop; a batch/password-logon task is not first-desktop evidence.

Inspect identity/profile state from the coordinator without changing Windows:

```powershell
$savedFixture = @{
    RunId = $fixture.RunId
    StateDirectory = $fixture.StateDirectory
    DisposableVm = $true
}
Get-RideWallpaperTestUser @savedFixture -Purpose FirstLogon
```

Export visual observations and the private fixture records before deleting the
test profile. Sign the user out normally. Cleanup refuses active logon sessions,
loaded/referenced, special, roaming, temporary/corrupt or moved profiles, changed
account identity/description, unexpected group membership and orphan directories.
The recorded local SID, generated name and exact path beneath the original
ProfilesDirectory must agree. Profiles assigned a suffixed or redirected path
require inspection; the fixture does not widen its deletion target.

```powershell
Remove-RideWallpaperTestUser @savedFixture -Purpose FirstLogon -WhatIf
Remove-RideWallpaperTestUser @savedFixture -Purpose FirstLogon -Confirm:$false
```

After private cleanup intent, removal disables only that account, rechecks its
sessions/profile, calls the documented
[DeleteProfileW API](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deleteprofilew)
with the exact SID/path and a local-machine argument, verifies profile/directory
absence, then deletes the account by SID. It does not force logoff, recursively
delete a directory in PowerShell, alter ACLs or reset a checkpoint. This destroys
the owned fixture's profile and settings; it is test cleanup, not RIDE setting
recovery. Failed cleanup may leave the account disabled. Keep the guest and private
records; retry only after resolving the reported stage. An interrupted final
receipt write can finish after verified account/profile absence. Creation without
a completed SID record and conflicting/orphan state require inspection.

With FirstLogon cleanup verified, run wallpaper Restore while Control still
exists. Then create and initialize Recovery to verify the original first-logon
appearance. Export that evidence before removing Recovery and finally Control.
Do not remove a pre-existing user or unrelated profile to satisfy the wallpaper
inventory guard. Do not recreate a fixture already being cleaned up; use a new
controlled run if the scenario must restart.

Schema-1 fixture results report request/purpose, generated name, SID, profile
path and observed account/profile/groups/session count. Statuses are Created,
AlreadyCreated, Observed, Preview, Removed and AlreadyRemoved. First-logon and
full native acceptance flags always remain false; these results prove no visible
wallpaper behavior. Phase failures retain intent and any saved SID; cleanup
failures add a private stage record. Purpose/edition values and correlated/saved
request IDs offer bounded, read-only completion. Source checks are recorded in
[fixture evidence](archive/evidence/wallpaper-test-user-source-2026-11-02.json).

### Wallpaper retained host dispatch

Import `tests/integration/RIDE.DefaultWallpaperVm.psm1` from the registered
checkout in an already elevated native Windows PowerShell 5.1 host session.
The installed controller/AutomatedLab prerequisites and
[retained reservation boundary](#retained-host-coordination) apply. Do not use
the generic reset-per-request queue for this scenario. The dispatcher uses the
existing lab credential and fixed PowerShell Direct scriptblock; it does not
request UAC, register a task or start an interactive sign-in.

Prepare reserves the idle Off guest, restores the pinned checkpoint and stages
exactly six source/data files plus `fedora_sharpened_4k.png`. Both ends verify
the selected bytes. The guest name, Hyper-V identity, x64 architecture, Windows
build/edition and elevation must match; later native phases also require the
prepared build revision. No legacy/component asset directory is traversed.
The snapshot includes the wallpaper lifecycle, guest phases, owned-user fixture,
image/private-file helpers and image pin. The host hold persists between calls.

The following sequence requires the interactive observations described above.
Review each result and stop on `Failed`; comments are separate evidence gates,
not automated sign-ins or visual assertions. Supply `$testPassword` as a synthetic
`SecureString` retained privately by the harness. CreateUser requires 16-128
characters; preview does not require a password. This is distinct from the lab
credential used to reach the guest. The dispatcher passes the SecureString as a
separate remoting argument and never writes it to its snapshot, descriptor or
phase reports. PowerShell documents SecureString remoting key exchange in its
[security features](https://learn.microsoft.com/en-us/powershell/scripting/learn/security-features).
Actual PowerShell Direct transport remains a native acceptance gate.

```powershell
Import-Module .\tests\integration\RIDE.DefaultWallpaperVm.psm1
$session = @{
    ConfigurationPath = '<installed-controller-configuration.json>'
    RunId = [guid]::NewGuid().ToString('N')
}
$prepare = @{
    Phase = 'Prepare'
    SourcePath = '<local-path-to-fedora_sharpened_4k.png>'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
}
Invoke-RideDefaultWallpaperVmPhase @session @prepare -WhatIf
$prepared = Invoke-RideDefaultWallpaperVmPhase @session @prepare -Confirm:$false
$control = Invoke-RideDefaultWallpaperVmPhase @session -Phase CreateUser -Purpose Control -UserPassword $testPassword -Confirm:$false
# Sign in as Control; record its original desktop and other theme defaults.
Invoke-RideDefaultWallpaperVmPhase @session -Phase InspectUser -Purpose Control -Confirm:$false
$applied = Invoke-RideDefaultWallpaperVmPhase @session -Phase Apply -Confirm:$false
$first = Invoke-RideDefaultWallpaperVmPhase @session -Phase CreateUser -Purpose FirstLogon -UserPassword $testPassword -Confirm:$false
# Verify FirstLogon's desktop/defaults and later wallpaper choice after sign-out/in.
# Verify Control is unchanged. Export visual observations and sign FirstLogon out.
Invoke-RideDefaultWallpaperVmPhase @session -Phase InspectUser -Purpose FirstLogon -Confirm:$false
Invoke-RideDefaultWallpaperVmPhase @session -Phase RemoveUser -Purpose FirstLogon -Confirm:$false
$restored = Invoke-RideDefaultWallpaperVmPhase @session -Phase Restore -Confirm:$false
$recovery = Invoke-RideDefaultWallpaperVmPhase @session -Phase CreateUser -Purpose Recovery -UserPassword $testPassword -Confirm:$false
# Sign in as Recovery; verify the original first-logon default and export visuals.
# Sign Recovery and Control out normally before their owned fixture cleanup.
Invoke-RideDefaultWallpaperVmPhase @session -Phase RemoveUser -Purpose Recovery -Confirm:$false
Invoke-RideDefaultWallpaperVmPhase @session -Phase RemoveUser -Purpose Control -Confirm:$false
Invoke-RideDefaultWallpaperVmPhase @session -Phase Collect -Confirm:$false
Invoke-RideDefaultWallpaperVmPhase @session -Phase Reset -Confirm:$false
```

CreateUser, InspectUser and RemoveUser require only their named Purpose selection;
UserPassword is accepted only by CreateUser. InspectUser reads guest account/profile
state, then the host records and exports that observation. The dispatcher validates
the fixture's request, lease, purpose, generated account name, SID, result schema
and relevant state. It does not infer an initialized desktop from profile presence
or enforce the operator's full visual sequence. All phase results retain
`NativeAcceptancePassed=false`.

Each phase exports the bounded retained guest directory into a new private host
export below `retained.<lease-id>`. Collection includes staged sources, private
machine/fixture records and observations actually placed in that directory;
it does not copy entire user profiles or automatically capture screenshots.
Save visual evidence separately before deleting its fixture. Limits are 512
entries, 16 MiB per file and 32 MiB total; unsafe paths, reparse points, changed
bytes or unreadable/oversized evidence refuse. Host readback verifies the export.
RemoveUser requires a verified nonempty export **before** dispatching deletion
and exports again afterwards. A failed pre-cleanup export cannot delete a user.

Reports use schema 1 and include Phase, Purpose, Stage, Status, GuestResult,
PreCleanupExport, EvidenceExport, RecoveryRequired and Store. In addition to the
machine phase statuses, user phases return Created/AlreadyCreated, Observed or
Removed/AlreadyRemoved. Removal is fixture cleanup; Restore is the separate
captured machine-setting recovery. The private guest fixture directory is
`C:\ProgramData\RIDE\RetainedAcceptance\<lease-id>\users`.

Failures retain the guest and hold; failed guest actions attempt partial export.
Reset is explicit checkpoint cleanup or deliberate abandonment after evidence
inspection. It exports first, verifies the pinned guest is Off after reset, then
releases only the matching hold. Reset from an already Off guest requires a saved
reset intent and unchanged verified export. Early preparation failures without a
session/intent require controller inspection. None of these cleanup results proves
RIDE restored a setting or that the original image is visible.

Remote jobs have a 180-second limit and readiness a separate three-minute loop.
A timed-out local job does not prove all guest activity has stopped; inspect before
recovery. Existing host Hyper-V/dependency calls have no additional watchdog.
All phases offer `-WhatIf`; phase, purpose, edition and retained run IDs offer
completion. The real installed Prepare preview and both-shell source checks are
recorded in [dispatch evidence](archive/evidence/default-wallpaper-vm-source-2026-11-02.json).

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

The [direct host dispatcher](#retained-host-dispatch) stages and invokes these
phases in an already elevated registered host session. Native execution remains
pending. The generic queue resets the VM after each request and must not be used
for this scenario. Neither guest entry point signs out, reboots or resets a
checkpoint. Export private evidence and verify visible recovery before explicit
host cleanup.

### Retained host dispatch

From the registered repository in an already elevated native Windows PowerShell
5.1 session, import `tests/integration/RIDE.DefaultLockVm.psm1`. The host must
already satisfy the existing AutomatedLab/controller prerequisites. This route
uses the existing lab credential through
[PowerShell Direct](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct); it does not register
a task, request UAC or expose a credential parameter. Do not submit it through
the ordinary test queue. Host Hyper-V/dependency calls keep their existing API
behavior; this direct route does not add the queue's independent host watchdog.

```powershell
Import-Module ./tests/integration/RIDE.DefaultLockVm.psm1
$session = @{
    ConfigurationPath = '<installed-controller-configuration.json>'
    RunId = [guid]::NewGuid().ToString('N')
}
$prepare = @{
    Phase = 'Prepare'
    SourcePath = '<local-path-to-suit_sharpened_4k.png>'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
}
Invoke-RideDefaultLockVmPhase @session @prepare -WhatIf
$prepared = Invoke-RideDefaultLockVmPhase @session @prepare -Confirm:$false
# Capture the initial signed-out/default image before Apply.
$applied = Invoke-RideDefaultLockVmPhase @session -Phase Apply -Confirm:$false
# Inspect and capture the applied signed-out/default image before Restore.
$restored = Invoke-RideDefaultLockVmPhase @session -Phase Restore -Confirm:$false
# Inspect and capture visible recovery before explicit cleanup.
$collected = Invoke-RideDefaultLockVmPhase @session -Phase Collect -Confirm:$false
$reset = Invoke-RideDefaultLockVmPhase @session -Phase Reset -Confirm:$false
```

Review each returned result before advancing; the example comments identify
independent visual gates, not automated actions. `Prepare` reserves an idle Off
VM, captures a private session descriptor and stages exactly five source files
plus the pinned image. It restores the pinned checkpoint, starts the VM and
verifies guest name, Hyper-V identity, build, edition, architecture and existing
elevation. Guest files live under
`C:\ProgramData\RIDE\RetainedAcceptance\<lease-id>`. No legacy/component asset
tree is traversed. Both ends check staged byte counts and SHA-256 values; later
apply/restore phases refuse changed source bytes. The prepared guest revision
must remain unchanged for the candidate lifecycle.

`Apply` and `Restore` run the matching guest scenario and retain the guest.
`Collect` only exports its current retained directory. Exports are bounded to
512 entries, 16 MiB per file and 32 MiB total; reparse points, escaping paths,
duplicate destinations and digest mismatches are refused. Each export has a
private receipt and independent host file-hash readback. Phase reports,
snapshots and exports remain in the protected controller's
`retained.<lease-id>` directory. Failed guest phases attempt partial export;
failed collection leaves the guest/hold available for inspection and retry.
Prepare and Apply each start once per reservation; the Apply scenario itself
checks repeated application. Restore can retry only with a completed guest apply
record. Failed/incomplete apply still requires inspection, not another blind apply.

`Reset` is explicit destructive test cleanup, not captured setting recovery or
test acceptance. Use it after visible recovery verification, or to abandon a
failed test after inspecting its evidence. It exports before restoring the pinned
checkpoint, verifies Off state, writes a private recovery receipt and releases
the hold. If interrupted after reset, an Off guest can retry only from a matching
pre-reset intent whose saved export files still verify. An arbitrary Off guest
without that evidence is refused. Preparation failures before a session descriptor
or VM intent is saved retain the block for controller recovery inspection; they
are not silently cleaned up. Never delete the block to bypass missing evidence.

Remote jobs have a 180-second phase limit and a separate three-minute readiness
loop. Timeout stops/removes the local job and retains the guest; it does not prove
that every guest-side activity has stopped. Inspect before recovery after a timeout.
All phases offer `-WhatIf`; only Prepare accepts source/build/edition inputs.
Run-ID completion reads the existing private hold for later phases.

Schema-1 reports include `RunId`, `LeaseId`, `Phase`, `Status`, `Stage`,
`RecoveryRequired`, `GuestResult`, `EvidenceExport`, `Error` and `Store`.
Statuses are `Preview`, `Prepared`, `AwaitingVisualVerification`,
`LifecyclePassedVisualPending`, `Collected`, `ResetAndOff` or `Failed`.
`NativeAcceptancePassed` is always false: visible initial/applied/recovered
images still require independent evidence. Host `RecoveryRequired` tracks the
retained VM/hold; the nested guest result separately reports setting recovery.
Source checks and real input decoding
are recorded in [host-dispatch evidence](archive/evidence/default-lock-vm-source-2026-11-02.json).

### Retained host coordination

`tests/integration/RIDE.RetainedGuest.psm1` supplies the internal reservation
boundary used by the direct host dispatcher above. Use that dispatcher for
staging, guest execution, export and checkpoint recovery rather than manually
assembling phase records or reserving a guest without a dispatch plan.

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
alone cannot prove checkpoint recovery. The dispatcher produces the
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
| Machine/default wallpaper | The first-logon ThemeFile policy/image candidate, guest phases, owned account/profile fixture and retained host dispatch are source-prepared. Verify a newly created disposable user's visible desktop, other theme defaults, existing-user preservation, later user choice and original-default recovery. Existing elevation, native transport/fixture cleanup and visual acceptance remain open. |
| User lock-screen image | Run in the intended interactive user's context. Capture the original image and selection mode; static-image byte recovery alone does not recover Spotlight or slideshow behavior. Verify the actual lock screen and repeat/restore. |
| Machine default lock-screen image | Lifecycle, guest scenario and direct retained host dispatch/export are source-prepared. Already elevated execution, actual ACL/lifecycle checks, signed-out/default image verification and visible recovery remain open. No user-change restriction is added. |

For the user lock screen, the documented
[LockScreen API](https://learn.microsoft.com/en-us/uwp/api/windows.system.userprofile.lockscreen)
provides image get/set methods; its image-feed methods are Windows 8.1-only.
Microsoft also documents lock-screen mode in its
[settings portability reference](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#lock-screen),
read through the
[Cloud Data Store reader](https://learn.microsoft.com/en-us/windows/apps/develop/settings/readclouddatasettings-exe).
That is a read interface, not a documented write/restore interface for Spotlight
and slideshow. Missing reader data is not proof of Picture mode. No such reader
was run and no user's settings were exported during this review. Mode recovery
and intended interactive-user execution must be established before implementing
or accepting the full user lock-screen workflow.

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
