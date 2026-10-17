# Terminal JSONC field preparation

`modules/RIDE.TerminalJsonc.psm1` prepares and reverses one root `defaultProfile`
edit entirely in memory. It is a source-ready building block for the
[Terminal default-profile workflow](windows-terminal-profile.md), not an active
catalog operation or file writer. It does not discover an instance, read a user's
settings file, verify installed profiles, execute commands or change Windows.

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
| `New-RideTerminalDefaultProfilePatch -Bytes -ProfileId` | Return proposed bytes, Changed and snapshot version 1. Accept one existing declared GUID in braces, honoring declared hidden defaults/overrides and rejecting duplicate GUIDs. No file is written. |
| `Restore-RideTerminalDefaultProfilePatch -Bytes -Snapshot` | Validate the original/expected byte relationship and return proposed recovery bytes. Preserve unrelated edits or refuse a conflict. No file is written. |

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
edit/recovery results. A caller must not treat a completed proposal as permission
to write an arbitrary file. Snapshots contain complete original/expected settings
bytes; a future state store must preserve their privacy and access controls.

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

This is a byte/content proof only. It does not provide transactional file writes,
path/instance/SID binding, ACL recovery, lock acquisition, runtime availability or
GUI verification. Retain the operator's [native recovery workflow](windows-terminal-profile.md#recovery-and-pending-automation)
until those pieces are implemented and accepted. Do not bypass pending status by
writing the proposed byte array into a live settings file.

## Remaining integration and acceptance

The next implementation must bind one installed Terminal instance and intended
desktop user to an exact settings path, validate current profile availability,
capture file presence/bytes/identity, compare bytes under an exclusive handle,
honor ShouldProcess and retain a recoverable snapshot before writing. Conflicts,
settings-editor rewrites, absent/generated profiles and disappearance during
restore must fail explicitly. Q09 accepts selecting an existing profile and asking for a replacement if missing
on another computer. The actual per-machine selection is still required; this
module makes no such selection and unattended work must report it unresolved.

Run the in-memory regression fixture with `tests/TerminalJsonc.Tests.ps1` on both
native PowerShell editions. Disposable integration must separately prove fresh
profile discovery, preview/apply/repeat, concurrent edits, exact restore and new-tab
behavior, with unconditional VM recovery. No package, shell, WSL component or
default-terminal-host change belongs to this field operation.

Microsoft documents the root [default profile](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/startup#default-profile)
and profile [GUID/source metadata](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/profile-advanced#unique-identifier).
The bounded parser, conservative declaration checks and byte-level snapshot are
RIDE implementation constraints. Dated evidence belongs in the
[migration ledger](migrations/settings-post-migration-review.md#b03-terminal-jsonc-preparation-2026-10-16).
