# RIDE run-state retention

RIDE saves prior state under the current user's `%LOCALAPPDATA%\RIDE\State` or
the machine `%ProgramData%\RIDE\State`. Saved runs support exact setting restore
and package/component recovery. Cleanup permanently removes those recovery files;
it does not change the saved Windows setting or installed package itself.

## Preview and cleanup

Run these commands from the RIDE-Windows repository in Windows PowerShell 5.1
or PowerShell 7 on Windows:

```powershell
.\ride.ps1 prune-state -StateScope User -WhatIf
.\ride.ps1 prune-state -StateScope User -OlderThanDays 365 -WhatIf
.\ride.ps1 prune-state -StateScope User -OlderThanDays 365 -Confirm:$false
```

The default scope is `User`; the default minimum age is 365 days. The minimum
accepted age is 30 days. `-WhatIf` lists candidate run IDs, timestamps and byte
counts without deleting anything. Applying cleanup asks before each candidate
unless the caller explicitly supplies `-Confirm:$false`.

`-StateScope Machine` or `Both` requires an elevated PowerShell session. Use
`Machine` to limit cleanup to machine snapshots, or `Both` to consider both
stores. User-scope cleanup does not inspect the machine store.

Cleanup considers only 32-character run directories with a valid RIDE manifest,
matching scope and ID, parseable creation time older than the selected age, and
one uniquely matched progress entry per operation. Every operation must be
`Completed` or `AlreadyDesired`. Failed or unfinished runs, recent runs, invalid
or unknown contents, and trees containing reparse points are retained. Cleanup
never runs automatically.

Once a run is removed, its snapshots and any file backups in that run directory
cannot be restored through RIDE. Review and retain the `-WhatIf` output before
applying cleanup. Do not clean a run that may still be needed for recovery.

## ACL acceptance

The engine protects the machine state-root ACL and grants full control only to
SYSTEM and local Administrators; child snapshot files inherit that root ACL.
User snapshots are created under the current user's Local AppData and inherit
that directory's ACL. This source review does not verify effective ACLs on a
Windows installation. Runtime ACL inspection and Windows VM acceptance remain
open.
