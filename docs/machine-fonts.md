# Machine font lifecycle candidate

RIDE can prepare and apply a hash-pinned batch of single-face TrueType fonts for
all users on a Windows 11 x64 candidate target. Native acceptance is pending.
The current implementation is an isolated module; it is not yet a catalog
operation or a default profile selection. It installs new files and registration,
preserves already matching fonts, and refuses conflicting files or registrations.
It never overwrites a font, clears the font cache or kills a consuming process.

## Inputs and preview

Start in the repository root using native Windows PowerShell 5.1 or PowerShell 7.
Supply a local PSD1 manifest, the original license notice and exact SHA-256 hashes.
The manifest selects 1-32 `.ttf` files with at most eight MiB total font payload;
each individual source is bounded to 16 MiB. Font collections, CFF/OpenType files
and ambiguous/missing Windows English names are currently outside this candidate.
The license file must be nonempty, hash-pinned and at most one MiB. Network paths,
alternate streams and reparse sources refuse.

```powershell
@{
    SchemaVersion = 1
    Fonts = @(
        @{ Path = 'Example-Regular.ttf'; Sha256 = '<64-hex-font-sha256>' }
    )
    License = @{ Path = 'OFL.txt'; Sha256 = '<64-hex-license-sha256>' }
}
```

Relative paths resolve beside the manifest. Use the actual source hashes in place
of the placeholders. To inspect identity without loading or installing a font:

```powershell
Import-Module .\modules\RIDE.FontFiles.psm1
Get-RideTrueTypeMetadata -Path 'C:\Inputs\Fonts\Example-Regular.ttf'
```

The schema-1 result contains source path, filename, byte count, SHA-256, family,
subfamily, full name, PostScript name and intended registry name. These names come
from the [OpenType naming table](https://learn.microsoft.com/en-us/typography/opentype/spec/name),
not the filename. `FontLoadPerformed` and `InstallationPerformed` describe this
read-only call; the command does not inspect whether the font is installed.
Metadata validation is not validation of every glyph or table and is not license
approval. Keep the original upstream notice with the selected sources.

Use an existing local recovery directory dedicated to machine fonts, for example
under `C:\ProgramData\RIDE\State\Fonts`. Creating that directory is an explicit
preparation step. Preview does not create it or any run record:

```powershell
Import-Module .\modules\RIDE.MachineFonts.psm1
$fonts = @{
    ManifestPath = 'C:\Inputs\Fonts\fonts.psd1'
    StateDirectory = 'C:\ProgramData\RIDE\State\Fonts'
    ExpectedComputerName = '<selected-target>'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
}
Install-RideMachineFonts @fonts -WhatIf
```

An install preview can run without elevation or candidate opt-in. Actual changes
require an already elevated process and `-AllowCandidate`. There is no UAC handoff.
The complete batch, destination filenames, embedded identities, registration
aliases and source/license hashes are checked before the first font writer.

## Apply, remove and recover

For disposable-target acceptance, apply only after the exact target and recovery
checkpoint have been identified. Run each command separately and verify its
result before proceeding:

```powershell
$install = Install-RideMachineFonts @fonts -AllowCandidate -Confirm:$false
$repeat = Install-RideMachineFonts @fonts -AllowCandidate -Confirm:$false
$remove = Remove-RideMachineFonts -OwnerRunId $install.RunId `
    -StateDirectory $fonts.StateDirectory -AllowCandidate -Confirm:$false
Restore-RideMachineFontRun -RunId $remove.RunId `
    -StateDirectory $fonts.StateDirectory -AllowCandidate -Confirm:$false
Restore-RideMachineFontRun -RunId $install.RunId `
    -StateDirectory $fonts.StateDirectory -AllowCandidate -Confirm:$false
```

`AlreadyDesired` writes no new state and does not adopt existing fonts. Keep the
original successful install run ID for ownership. A partially pre-existing batch
installs only the absent fonts; later removal touches only those created by that
run. Removing them creates a separate recovery run. Restore that removal to
recover their captured bytes, owner/group/DACL, attributes, creation/last-write
times and registration. Restoring the original install recovers original absence
while preserving fonts that existed before it.

Files go in the native Windows Fonts directory. Registration uses the embedded
full font name with the ` (TrueType)` suffix in the machine Fonts registry key.
RIDE calls [AddFontResourceW](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-addfontresourcew)
for the current session and submits a font-change notification. Registry-backed
installation persists across restart; other active sessions may need a restart
before the new font is available. RIDE does not restart automatically. File and
registry readback alone does not prove availability in every application/session.

Recovery intent is written before the first font mutation, retaining the exact
font payloads and license bytes. A separate applied record is written only after
verification. Machine records have a protected administrator/SYSTEM DACL and
Administrators ownership, verified through the open file handle. Reading them
requires those machine permissions; an unelevated saved-run preview can therefore
report an access prerequisite. These records are separate from user-scope WLAN
records; the shared file helper's user default is unchanged.

Public schema-1 results contain `Status`, `RunId` and `Scope`; apply/removal also
report action and changed-font count. Native acceptance remains false. Saved-run
completion reads only matching filenames from an explicitly supplied state
directory and never loads fonts, reads their payloads or inspects the registry.

## Recovery limits and native acceptance

Restore requires the recorded machine/build/edition/revision, original account
and session. It refuses changed bytes, permissions, attributes, timestamps,
registration kinds/values and extra aliases. It does not repair unrelated font
registrations or their key permissions. Audit ACLs (SACLs), application font
caches and native reference counts are not captured or restored.

[RemoveFontResourceW](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-removefontresourcew)
can leave a resource in use by an application or another session. The handler
requires confirmed unloading and stops if file deletion fails. It does not loop
to force unrelated references away, kill applications, schedule deletion or
reboot. A failure may leave partial file/registration changes; the error includes
the run ID and the private intent remains. Incomplete runs without an applied
record refuse automatic restore. Inspect that state and active consumers before
choosing recovery; do not discard records or count checkpoint cleanup as a RIDE
restore pass.

The approved local input contains 14 Open Sauce Sans TrueType files with the
retained SIL OFL notice. All 14 source identities and their hashes validate.
The source suite covers naming-table bounds, whole-batch collision refusal,
repeat apply, preservation of existing fonts, owned removal, captured file and
registration recovery, conflicts, candidate/target/privilege guards, persistence
and native-unload failure, and read-only completion. Font/GDI/registry providers
are mocked; TestDrive files exercise bytes, DACLs and timestamps. Machine-state
file creation is substituted with current-user private files for unelevated
testing; the administrator/SYSTEM descriptor is checked in memory. This does not
establish native machine ACL creation or font availability.

The guarded guest route below is source-tested. Native GUI/session behavior,
machine-state ACL creation, removal and exact recovery remain pending. See
[dated source evidence](archive/evidence/machine-font-lifecycle-source-2026-11-02.json).

## Disposable-target acceptance entry point

From the staged repository in the already elevated disposable Windows 11 x64
guest, use `tests/integration/Invoke-RideFontAcceptance.ps1`. The controller must
set `RIDE_TEST_GUEST=1`, `RIDE_INTEGRATION_VM=1` and a correlated
`RIDE_TEST_RUN_ID`. Supply that request ID, the independently verified target
name/build/edition, an existing local evidence root and the reviewed manifest
for the real licensed fonts. The name-table-only unit fixtures are not fonts
and must never be passed to native loading. The retained host route below is
source-prepared; native execution remains pending.

```powershell
.\tests\integration\Invoke-RideFontAcceptance.ps1 `
  -RunId '<correlated-request-id>' -ManifestPath 'C:\Inputs\fonts.psd1' `
  -ExpectedComputerName '<guest-name>' -ExpectedBuild '26300' `
  -ExpectedEditionId 'EnterpriseEval' -EvidenceRoot 'C:\RIDE\FontEvidence' `
  -DisposableVm -WhatIf
```

Use the same arguments with `-Confirm:$false` instead of `-WhatIf` for the
authorized native run. Preview creates no evidence or recovery records. The
runner refuses a workstation, mismatched target, reused evidence directory or
existing selected fonts; missing elevation returns `NotRun`. It does not prompt
for elevation, reboot or connect to another computer.

The seven checks cover preview, install/readback, repeat, owned removal,
restoration of removal, restoration of original absence and repeated restore.
Readback combines captured file/registration state with independent native
[font enumeration](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumfontfamiliesexw)
of every selected full name. The runner reads actual private machine records
through their owner/DACL checks. It retains administrator-owned `before.json`,
`installed.json`, `result.json` and lifecycle records in the request directory.
Files, owner/group/DACL, timestamps, registration and unrelated registry state
must match after each applicable restore.

Any failing step stops without automatic cleanup. Inspect its stage, outstanding
lifecycle run IDs and retained state before restoring completed runs. A VM
checkpoint is a separate cleanup fallback and never a passing RIDE recovery.
The runner reports current-session acceptance only. Cross-session visibility,
restart availability and active-consumer behavior require separate native
evidence; their absence does not become a pass when this scenario succeeds.
The runner's ten orchestration/layout tests pass in both PowerShell editions
with native providers mocked and no font APIs invoked; see
[preparation evidence](archive/evidence/font-acceptance-preparation-2026-11-02.json).

## Retained host dispatch

Use `tests/integration/RIDE.FontVm.psm1` from the registered checkout in an
already elevated native Windows PowerShell 5.1 x64 host session. The installed
controller configuration, AutomatedLab credential, pinned disposable VM and
checkpoint must match the [retained reservation requirements](image-personalization.md#retained-host-coordination).
This direct route does not submit work to the reset-per-request queue, request
UAC, change a task or restart the host.

Prepare accepts the directory containing the selected 14 Open Sauce Sans files
and `OFL.txt`. The versioned pin is
`tests/fixtures/machine-fonts.acceptance.psd1`; no caller-supplied manifest is
executed or substituted. Hashes and embedded font names are read without loading
fonts. Prepare stages exactly four source modules, that manifest, the 14 fonts
and the original notice. No legacy/component directory is traversed. A private
host snapshot and fixed guest allowlist bind the selected paths and bytes.

Start in the registered repository root. Review each result before the next
call; stop on `Failed` or inspect the stated `NotRun` reason.

```powershell
Import-Module .\tests\integration\RIDE.FontVm.psm1
$session = @{
    ConfigurationPath = '<installed-controller-configuration.json>'
    RunId = [guid]::NewGuid().ToString('N')
}
$prepare = @{
    Phase = 'Prepare'
    InputDirectory = '<local-directory-with-the-pinned-fonts-and-OFL.txt>'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
}
Invoke-RideFontVmPhase @session @prepare -WhatIf
$prepared = Invoke-RideFontVmPhase @session @prepare -Confirm:$false
$lifecycle = Invoke-RideFontVmPhase @session -Phase Lifecycle -Confirm:$false
Invoke-RideFontVmPhase @session -Phase Collect -Confirm:$false
# Inspect the exported lifecycle/recovery evidence before checkpoint cleanup.
Invoke-RideFontVmPhase @session -Phase Reset -Confirm:$false
```

Prepare reserves the idle Off guest, restores the pinned checkpoint, starts it
and stages the source/input snapshot. It does not install fonts. The route checks
the guest name, Hyper-V manufacturer/model, Windows 11 build, selected
Enterprise/Education edition, x64 architecture and existing elevation. Lifecycle
also requires the prepared build revision to remain unchanged.

Lifecycle runs all seven guest checks, including both captured restores, within
one PowerShell Direct invocation. This preserves the original account/session
boundary required by font recovery. It refuses already present selected fonts;
`NotRun` is retained without a pass. A passing guest result must contain the exact
14-font selection, all seven checks and both distinct completed recovery runs.
The host's `CurrentSessionAcceptancePassed` becomes true only after that result
and its evidence export verify. The guest's `NativeAcceptancePassed` field covers
only its documented current-session scenario. The host's broader
`NativeAcceptancePassed`, `CrossSessionAcceptancePassed`,
`RestartAcceptancePassed` and `ActiveConsumerAcceptancePassed` stay false.

Phase reports use schema 1 and include Phase, Stage, Status, GuestResult,
EvidenceExport, Store and RecoveryRequired plus the acceptance fields above.
Statuses include Preview, Prepared, Passed, NotRun, Collected, ResetAndOff and
Failed. A later Collect or Reset report does not carry forward a lifecycle pass;
retain and assess the original Lifecycle report. RecoveryRequired describes
the retained VM/hold as well as any failed operation; even NotRun requires
deliberate checkpoint cleanup before releasing the hold.

Every phase exports the retained guest directory into a new private host
directory under `retained.<lease-id>`. Export includes the source snapshot,
licensed inputs, guest observations and private machine lifecycle records.
Limits are 512 entries, 16 MiB per file and 32 MiB total. Paths, byte counts,
hashes and host readback must verify. This copies neither the full Windows Fonts
directory nor unrelated user data. Failures preserve the VM and hold; failed
guest phases attempt a partial evidence export. No font cache reset, process
termination, forced unloading or automatic reboot is added.

Reset is explicit checkpoint cleanup, including deliberate abandonment after
failure inspection. It requires a verified export, restores the pinned checkpoint,
verifies Off and then releases the matching hold. It is not a RIDE recovery pass.
Retrying Reset from Off requires a saved reset intent and unchanged verified
export. Prepare may be retried with the same run ID only while the reserved VM
is Off and no checkpoint intent exists. The saved session must match the hold,
target and selected fonts; its original cached files must still pass their hashes.
Retry does not replace the snapshot or discard the failed phase record. Early
failures without a usable descriptor require controller inspection. Remote calls
time out after 180 seconds; readiness has
a separate three-minute limit. A local timeout does not establish that remote
work has stopped. Existing host Hyper-V/dependency calls have no added watchdog.

All phases support `-WhatIf`. Phase, edition and retained run IDs offer completion.
The 32 focused source cases per PowerShell edition, real font/input gates and
installed read-only Prepare preview are recorded in
[dispatch evidence](archive/evidence/font-vm-source-2026-11-02.json).
Native dispatch on Windows 11 EnterpriseEval build 26300 subsequently passed
preparation, preview, installation of all 14 selected fonts and repeat apply.
Removal returned Applied and restored the selected file/registration state, but
native enumeration still returned Open Sauce Sans Light Italic. Current-session
lifecycle therefore failed before either saved restore ran; no complete font
acceptance is claimed. A read-only Collect observation now separates file,
registry/security and selected native-name comparisons. Its bounded JSON is
included in the verified private export and the public diagnostic result; it
does not expose recovery payloads or alter fonts. Other sessions, restart
availability and active consumers remain unverified.

Microsoft documents that [outstanding references can retain a removed font](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-removefontresourcew)
and recommends notifying windows with WM_FONTCHANGE. The current native wrapper
already broadcasts that notification after each batch. The observed retained
name therefore needs further native investigation; it does not establish which
consumer retained a reference or permit forced unloading. Preserve the failed
run and validate both saved restores in a fresh disposable run after addressing
the native behavior.
