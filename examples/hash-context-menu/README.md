# Hashing context-menu candidates

Requested for RIDE v3 on 2026-10-11; tracked in the
[inclusion backlog](../../docs/candidate-tools.md#requested-v3-additions-2026-10-11).
The files are review material. No registry import or application installation
has been performed on the developer workstation.

## Supplied multi-algorithm solution

[Add_Hash_value_to_context_menu.reg.txt](Add_Hash_value_to_context_menu.reg.txt)
is an unchanged copy of the supplied attachment, retaining Shawn Brink's
authorship, dates and [tutorial link](https://www.elevenforum.com/t/add-hash-value-to-context-menu-of-files-in-windows-11.22212/).
It adds a Hash value submenu for files with MD5, SHA1, SHA256, SHA384, SHA512,
MACTripleDES, RIPEMD160 and Show all. Its commands invoke Windows PowerShell
through `cmd`, then keep the console open with `Start-Sleep 3600`.

The upstream tutorial was updated on 2026-09-25. Its thread documents a
double-space issue in an earlier command form; the author updated the tutorial.
A suggested workaround was later reported to fail with apostrophes. The
retained commands still reconstruct the path from echoed text, and their
behavior for unusual file names has not been tested through Explorer. Each
command also holds its console open with `Start-Sleep 3600`.
A synthetic local probe on Windows PowerShell 5.1 and PowerShell 7 found that
Windows PowerShell 5.1 accepts all seven listed algorithms, while PowerShell 7
accepts MD5, SHA1, SHA256, SHA384 and SHA512 but rejects MACTripleDES and
RIPEMD160. The supplied command invokes `powershell`, which selected Windows
PowerShell 5.1 in the test environment. The probe passed a synthetic path
containing double spaces, an apostrophe, ampersand, percent sign and Unicode
directly to `Get-FileHash -LiteralPath`; it did not test Explorer substitution.
The original attachment remains unchanged and was not executed. See the
[dated source review](../../docs/archive/evidence/hash-value-submenu-source-review-2026-10-22.json).

A RIDE-owned candidate now passes the selected path as a literal script
argument, invokes Windows PowerShell 5.1 to retain all seven algorithms, and
shows the requested result in one message box rather than leaving a console open.
Its 17 coordinated registry values register the submenu in the current user's
`HKCU\Software\Classes` view and capture exact prior state through the existing
`RegistryValueSet` lifecycle. The operation remains a Windows 11 candidate with
no supported target until Explorer placement, unusual filenames, repeat apply,
removal and exact saved-run restore pass on the disposable VM. The local
PowerShell tests do not exercise Shell substitution or GUI behavior. The
attachment is source material, not instructions to execute it.

## Corrected single-command solution

[sha256-certutil.reg](sha256-certutil.reg) contains the requested Certutil snippet:

```reg
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\*\shell\SHA-256 with Certutil]
"Icon"="shell32.dll,-152"

[HKEY_CLASSES_ROOT\*\shell\SHA-256 with Certutil\command]
@="cmd.exe /k certutil -hashfile \"%1\" SHA256"
```

`Icon` is the registry value name; the DLL resource reference is its data.
The menu label and verb key use `SHA-256 with Certutil`; the command retains
`SHA256` as Certutil's algorithm argument. Closing the command window ends the
session. The file makes no deletions. Adding the hyphen changes the registry key,
so importing this version leaves any earlier `sha256 with Certutil` registration
in place and can produce two menu entries.

The `.reg` retains the supplied HKCR location, which is the merged Classes view;
import can require elevation and does not capture previous state. Export the
affected verb key before any disposable-VM import so existing values can be
recovered. To undo a new registration, remove only the added verb key after
checking it contains no unrelated entries; otherwise restore the captured
values. RIDE's [authoring definition](../authoring/certutil-context-menu.psd1)
instead maps to HKCU\Software\Classes in User scope and captures prior values.
Example version 0.1.2 manages the icon and command at the new verb key. Retain
generated versions 0.1.0 and 0.1.1 and their manifests for old-run recovery.
Restore an earlier RIDE run with its original library before applying the new
version; for an earlier manual import, export and review the old verb key before
removing its registration. Neither example automatically deletes the old key.

Windows 11 classic/Show more options visibility, the icon resource on the
target build, actual hashing and unusual filename handling still need
disposable-VM acceptance. This static verb does not establish native Windows 11
modern-menu integration or Windows Server support.

The optional catalog candidate `windows.sha256-certutil-context-menu` maps the
two values to the current user's `HKCU\Software\Classes` view and uses exact
saved-state capture and restore. It remains unsupported until a disposable
Windows 11 run checks the icon, menu placement, percent/apostrophe/Unicode
filenames, repeat apply, unset and exact restoration. The menu candidates are
separate from each other and from the HashCheck package.

Microsoft documents [static verb registration](https://learn.microsoft.com/en-us/windows/win32/shell/context-menu-handlers)
and [Certutil hashing](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil#-hashfile).
The Shell reference does not identify `shell32.dll,-152` as a guaranteed icon
resource across Windows builds.
