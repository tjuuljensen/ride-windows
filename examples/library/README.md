# Main custom-library example

Copy this directory to start a custom library. One readable catalog demonstrates
three operation kinds and a group referencing a built-in package. The shared
namespace is `example.library`; schema 1 and library API 1 are unchanged.
Hand-written and helper-generated `.psd1` files use the same schema. Quoted keys,
expanded arrays and field order are formatting choices, not different interfaces.

| Catalog entry | Demonstrates |
| --- | --- |
| `example.library.preference-marker` | An inert user-scoped registry value and exact saved-state restore. |
| `example.library.sha256-certutil` | Coordinated Icon/default-command values under HKCU\Software\Classes. |
| `example.library.classic-msgames` | A machine-scoped ZIP/EXE package with separate archive/member hashes and omitted license URL. |
| `example.library.utilities` | A group referencing the existing `package.7zip` rather than duplicating its metadata. |

## Choose a profile

| Profile | Selection |
| --- | --- |
| `profiles/custom.psd1` | Only the inert marker; the minimal starter for copying and `-Add`. |
| `profiles/settings.psd1` | The marker and optional Certutil context menu. |
| `profiles/packages.psd1` | The 7-Zip group and Windows 7 Games; requires elevation for apply. |

From the repository root:

```powershell
.\tools\validate.ps1 -Library .\examples\library\ride-library.psd1
.\ride.ps1 list -Library .\examples\library\ride-library.psd1
.\ride.ps1 list profiles -Library .\examples\library\ride-library.psd1
.\ride.ps1 apply -Library .\examples\library\ride-library.psd1 -Profile .\examples\library\profiles\custom.psd1 -WhatIf
```

Choose the settings or packages profile explicitly to preview those selections.
Loading a library does not select its profile. Omitting `-Profile` uses RIDE's
normal built-in default; always supply the intended profile.

Copy before experimenting:

```powershell
Copy-Item -LiteralPath .\examples\library -Destination .\my-library -Recurse
.\tools\New-RideLibrary.ps1 -Path .\my-library -Add
```

`-Add` appends selections to custom.psd1, requires a higher version and retains
previous metadata. It preserves settings.psd1 and packages.psd1; update those
deliberately if you want a new operation in them. Review custom.psd1 again after
adding entries. Choose your own namespace and update operation/group/profile
references together before first publication. Later changes must retain stable
IDs and original versions.

## Acceptance and recovery

The marker keeps its original inert path under
`HKCU:\Software\RIDE\Examples\Contoso`; it does not configure a Windows feature.
Certutil uses the corrected Icon data, unnamed command value and `SHA-256 with
Certutil` verb. Icon rendering, classic/Show more options visibility, filename
quoting, hashing and exact restoration need acceptance in a disposable Windows 11 VM.
The [small authoring definition](../authoring/certutil-context-menu.psd1) also
demonstrates mapping HKCR to the chosen scope before publishing metadata.

Library 0.1.1 corrects Games detection to `^Windows 7 Games for Windows 11, 10 and 8$`,
matching the read-only uninstall registration observed for installed version 4.3
on 2026-10-12. The previous 0.1.0 metadata is retained under recovery/library/0.1.0.
The detection name is the whole installed product, not the included Solitaire game.
Verify payload support independently of the x86 launcher, `/SP- /SILENT`
installation, `/SILENT` removal, exit codes, selected games
and repeat installation in a disposable Windows 11 VM. The earlier pinned hashes
were retained; this merge downloaded nothing. License remains Unknown with no
invented URL or approval. Review payload terms/notices and record local approval
in the separate license-review store. Exact previous-package-version recovery is
not guaranteed. Windows Server is not declared for these custom operations.

This library introduces new IDs. See [recovery snapshots and ID mapping](../recovery/README.md)
before restoring old runs or switching an already-applied setup. Restore an
earlier run using its original manifest first; applying this library does not
migrate saved Windows state. See [custom libraries](../../docs/custom-libraries.md)
and [package licensing](../../docs/package-licensing.md) for detailed workflows.
