# Terminal JSONC field preparation

`modules/RIDE.TerminalJsonc.psm1` prepares, applies and reverses one root
`defaultProfile` edit. `Get-RideTerminalInstalledInstances` read-only discovery
reports current-user packaged Stable, Preview and Canary instances and their
package-bound `LocalState/settings.json` paths. The operator can select one exact
package name and pass it to `Set-RideTerminalInstalledInstanceDefaultProfile`,
which re-queries live AppX registrations and connects that verified instance to
the identity-bound writer. Synthetic inventory cannot authorize that command.
The explicit-path writer remains available for unpackaged/portable inputs. Neither
command proves that a declared/dynamic profile is currently available or
launchable. This remains a candidate outside the catalog pending disposable
Windows acceptance.

## Input and output contract

Supply explicit UTF-8 bytes with an optional UTF-8 BOM. The parser accepts JSON
with line/block comments and trailing commas, retaining source spans instead of
serializing the whole object. Limits are 1 MiB, 64 nested levels, 32,768 value
nodes and 4,096 declared profiles. Invalid UTF-8, UTF-16/32, invalid escapes,
unpaired Unicode surrogates, malformed numbers and duplicate property keys at
any nesting level are rejected. Escaped keys are decoded before duplicate checks.
Unknown fields, literal number spelling, comments, Unicode and line endings are
preserved byte for byte outside the selected value or inserted fragment.

| Command | Contract |
| --- | --- |
| `Get-RideTerminalDefaultProfileDocument -Bytes` | Report root value/absence and profiles explicitly declared in `profiles.list` or an older direct `profiles` array. All instance/availability flags remain false. |
| `Get-RideTerminalInstalledInstances` | Query the current user's documented Stable/Preview/Canary AppX registrations and derive each package's own settings path. Read existing files up to 1 MiB and report package identity plus declared profiles. Only a live `Get-AppxPackage` query marks the instance verified; injected package records are explicitly unverified. Never creates missing files or changes packages/settings. Unpackaged and portable distributions are not enumerated. |
| `Set-RideTerminalInstalledInstanceDefaultProfile -PackageName -ExpectedComputerName -ExpectedUserSid -ProfileId` | Requery current-user AppX registrations, select exactly one documented package identity, and apply through the exclusive, identity-bound writer. Requires an existing settings file and a declared visible profile. Honors `ShouldProcess`; `-WhatIf` writes neither settings nor a recovery snapshot. The result marks the instance verified but leaves profile availability false. |
| `New-RideTerminalDefaultProfilePatch -Bytes -ProfileId` | Return proposed bytes, Changed and snapshot version 1. Accept one existing declared GUID in braces, honoring declared hidden defaults/overrides and rejecting duplicate GUIDs. No file is written. |
| `Restore-RideTerminalDefaultProfilePatch -Bytes -Snapshot` | Validate the original/expected byte relationship and return proposed recovery bytes. Preserve unrelated edits or refuse a conflict. No file is written. |
| `Set-RideTerminalDefaultProfileFile -SettingsPath -ExpectedComputerName -ExpectedUserSid -ProfileId` | Under `ShouldProcess`, lock the existing `settings.json` exclusively, store original and expected bytes in a new user-state snapshot, write the narrow patch, flush and verify readback. `-WhatIf` writes neither file. |
| `Restore-RideTerminalDefaultProfileFile -SettingsPath -ExpectedComputerName -ExpectedUserSid -SnapshotPath` | Validate snapshot identity and hashes, lock the same file, preserve unrelated edits or refuse an owned-value conflict, then write and verify reconstructed prior bytes. The snapshot is retained. |

`ProfileId` completion reads only the supplied byte array, filters by the typed
prefix without case sensitivity, deduplicates IDs and excludes hidden entries.
Malformed or missing optional completion data fails quietly. Names are display
labels, not completion values. Dynamic profile declarations retain their source
but do not prove that a generator, shell, WSL distribution or command is available.
No dynamic profiles or GUIDs are invented from executable paths.

An existing `defaultProfile` can be a GUID or exact profile name. Before proposing
a replacement, it must resolve uniquely among visible supplied declarations so
the prior identity has a reviewable recovery path. Unknown/ambiguous prior names,
hidden profiles and undeclared generated profiles remain review cases. An already
selected GUID leaves its original spelling/escaping unchanged. A name-to-GUID
change is explicit and records the exact original string literal.

## Synthetic example

Start in the repository root, in native PowerShell 5.1 or 7. No elevation,
Terminal installation or network access is required. This example uses invented
fixture profiles and performs no disk writes:

```powershell
Import-Module .\modules\RIDE.TerminalJsonc.psm1
$fixture = @'
{
  // Preserved fixture comment
  "defaultProfile": "Original",
  "profiles": {"list": [
    {"guid":"{11111111-1111-1111-1111-111111111111}","name":"Original"},
    {"guid":"{22222222-2222-2222-2222-222222222222}","name":"Next"},
  ]},
}
'@
$bytes = [Text.Encoding]::UTF8.GetBytes($fixture)
$observation = Get-RideTerminalDefaultProfileDocument -Bytes $bytes
$patch = New-RideTerminalDefaultProfilePatch -Bytes $bytes `
  -ProfileId '{22222222-2222-2222-2222-222222222222}'
$recovery = Restore-RideTerminalDefaultProfilePatch -Bytes $patch.Bytes `
  -Snapshot $patch.Snapshot
[Convert]::ToBase64String($bytes) -ceq [Convert]::ToBase64String($recovery.Bytes)
```

The final result should be True. `MutationAuthorized` stays false in proposed
edit/recovery results. The file commands are the only writer and require the
operator to supply the exact instance path and identities; they do not change
Terminal installation, shells, WSL, or the OS default-terminal host. Snapshots
contain complete original/expected settings bytes and can include private
configuration. They are stored under the current user's RIDE state directory by
default, are not encrypted, and are retained after restore. File ACLs are not
captured or changed.

## Ownership and recovery

Replacement owns only the root value's original JSON string literal. Keys,
surrounding comments, separators and nested `defaultProfile` properties stay
untouched. Recovery accepts the expected literal or an already restored original;
another edit to that value is a conflict. The previous GUID/name must still be
uniquely declared and visible in the current supplied document.

When the root property is absent, preparation inserts an owned property fragment
after the root opening brace, including its own whitespace and separator. Recovery
removes exactly that fragment even when unrelated properties have moved its offset.
Changes inside the fragment require review. Removing an already removed property
is a no-op. The result is reparsed before being returned, and a changed BOM refuses
recovery. Snapshot fields are checked against a freshly reconstructed proposal;
they are not trusted as arbitrary substring positions or replacement source.

The guarded file commands bind the exact path to the current computer and SID,
reject a reparse-point file, take an exclusive handle and verify durable readback.
They do not capture ACLs, identify the owning Terminal package, prevent a parent
directory identity change, or prove profile availability. A failed write attempts
byte rollback and retains the saved snapshot. Keep the operator's [native recovery
workflow](windows-terminal-profile.md#recovery-and-pending-automation) until
disposable acceptance passes.

## Remaining integration and acceptance

The read-only inventory now binds packaged Stable, Preview and Canary registrations
for the current user to their exact LocalState settings paths, including separate
files for simultaneous editions. The operator must still select the intended
instance. Unpackaged and portable distributions require an explicit operator path;
the inventory does not inspect other users or portable settings directories.

Next, verify the selected profile is available and launchable in that instance
with the intended user. Then run disposable Windows checks for preview/apply/repeat, editor locking,
concurrent edits, failed-write rollback, exact restore, disappeared profiles and
new-tab behavior. Q09 accepts selecting an existing profile and asking for a
replacement if it is missing on another computer. The actual per-machine
selection remains required; no catalog operation or supported target is declared.

Run `tests/TerminalJsonc.Tests.ps1` on both native PowerShell editions. Disposable
integration must separately prove fresh profile discovery, preview/apply/repeat,
concurrent edits, exact restore and new-tab behavior, with unconditional VM
recovery. No package, shell, WSL component or
default-terminal-host change belongs to this field operation.

Microsoft documents the [default profile](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/startup#default-profile),
[package-specific settings-file locations](https://learn.microsoft.com/en-us/windows/terminal/faq)
and [packaged/unpackaged/portable distributions](https://learn.microsoft.com/en-us/windows/terminal/distributions).
Profile [GUID/source metadata](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/profile-advanced#unique-identifier)
does not prove that the profile is available or launchable.
The bounded parser, conservative declaration checks and byte-level snapshot are
RIDE implementation constraints. Dated evidence belongs in the
[migration ledger](migrations/settings-post-migration-review.md#b03-terminal-jsonc-preparation-2026-10-16).
