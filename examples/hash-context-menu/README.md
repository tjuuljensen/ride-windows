# Hashing context-menu candidates

Requested for RIDE v3 on 2026-10-11; tracked in the
[inclusion backlog](../../docs/CANDIDATE-TOOLS.md#requested-v3-additions-2026-10-11).
The files are review material. No registry import or application installation
has been performed on the developer workstation.

## Supplied multi-algorithm solution

[Add_Hash_value_to_context_menu.reg.txt](Add_Hash_value_to_context_menu.reg.txt)
is an unchanged copy of the supplied attachment, retaining Shawn Brink's
authorship, dates and [tutorial link](https://www.elevenforum.com/t/add-hash-value-to-context-menu-of-files-in-windows-11.22212/).
It adds a Hash value submenu for files with MD5, SHA1, SHA256, SHA384, SHA512,
MACTripleDES, RIPEMD160 and Show all. Its commands invoke Windows PowerShell
through `cmd`, then keep the console open with `Start-Sleep 3600`.

Before implementation, check algorithm availability on the selected PowerShell
runtime, errors in Show all, filenames containing spaces, apostrophes,
ampersands, percent signs and Unicode, and submenu behavior on Windows 11.
Review scope, attribution/reuse terms, repeat apply and exact saved-run restore.
The attachment is source material, not instructions to execute it.

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

Microsoft documents [static verb registration](https://learn.microsoft.com/en-us/windows/win32/shell/context-menu-handlers)
and [Certutil hashing](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil#-hashfile).
The Shell reference does not identify `shell32.dll,-152` as a guaranteed icon
resource across Windows builds.
