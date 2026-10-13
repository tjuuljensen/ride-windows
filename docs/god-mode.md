# God Mode desktop shortcut

`windows.god-mode-shortcut` is an optional current-user Windows 11 setting.
It creates `GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}` on the resolved
desktop, following the folder method in the requested
[Tom's Hardware guide](https://www.tomshardware.com/how-to/enable-god-mode-windows-11).
Opening that folder provides a convenient view of Control Panel tasks. Creating
it does not grant privileges or change the settings exposed by those tasks.

Microsoft documents the general
[Shell namespace folder mechanism](https://learn.microsoft.com/en-us/windows/win32/shell/nse-junction).
That reference describes the `.CLSID` mapping, rather than documenting this
specific God Mode identifier.

## Commands and profiles

```powershell
.\ride.ps1 show windows.god-mode-shortcut
.\ride.ps1 set windows.god-mode-shortcut Present -WhatIf
.\ride.ps1 set windows.god-mode-shortcut Present
.\ride.ps1 unset windows.god-mode-shortcut -WhatIf
.\ride.ps1 unset windows.god-mode-shortcut
.\ride.ps1 restore -RunId <saved-run-id> -WhatIf
```

Select `State = 'Present'` or `State = 'Absent'` in a profile:

```powershell
@{ Id = 'windows.god-mode-shortcut'; State = 'Present' }
```

`Baseline` resolves to `Absent`; `unset` also selects `Absent`. The default
profile does not include this option. IDs and states support Tab completion.
Use the existing `list settings`, `list explorer`, `show`, `plan`, and `status`
workflows to inspect it. Creating the folder does not require elevation;
individual Control Panel tasks retain their normal privilege requirements.

## Files and recovery

RIDE resolves Windows' current-user `DesktopDirectory`, including a redirected
desktop, and requires that directory to exist. It manages only the fixed folder
name above. An existing directory is left unchanged when applying `Present`.
Other folder names and ordinary `.lnk` shortcuts are outside this option's scope.

Removal is nonrecursive. RIDE refuses a regular file, a reparse point, or a
folder containing files, including hidden files. It captures an empty folder's
path, presence, attributes, creation and modification timestamps, owner, group,
and discretionary access permissions before removing it. Restore recreates the
empty folder and recovers that metadata. When the folder was previously absent,
restore removes it only while it remains empty.

Files added after apply are preserved by refusing removal or metadata restore.
If the desktop was redirected since capture, restore rejects the changed path
and requires review. RIDE does not restore the contents of a nonempty folder.

The visible label, icon, and task list can vary with the Windows build. Isolated
folder lifecycle checks do not verify Explorer's rendered view. The disposable
Windows 11 VM suite's lifecycle scenario passed on 9 October 2026 (run
`959e8b4c2a374041a792497f42dd2588`). The manual check that opening the folder
displays Control Panel tasks remains pending.
Windows Server is not declared for this option.

Catalog, parser, profile and generated-document validation pass. All 201
isolated tests pass on Windows PowerShell 5.1 and PowerShell 7, including 16
Shell folder tests. The existing live-registry test is excluded from workstation
checks. Fixtures use TestDrive with desktop lookup mocked; no shortcut was
created on the developer's desktop.
