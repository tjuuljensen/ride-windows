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
and must never be passed to native loading. Controller dispatch is still pending.

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
