# RIDE examples

Start with **[examples/library](library/README.md)**. It is the one maintained,
copyable library example: one catalog under `example.library`, with separate
starter, settings and package profiles. It combines a registry marker, Certutil
setting, ZIP/EXE package and a group referencing built-in 7-Zip.

| Material | Purpose |
| --- | --- |
| [Main library](library/README.md) | Complete manifest, readable catalog and explicit profiles. |
| [KeePassXC definition](authoring/keepassxc.psd1) | Small MSI helper-input example with an optional product URL omitted. |
| [Windows 7 Games definition](authoring/windows7-games.psd1) | Small ZIP/EXE helper-input example with archive/member hashes and omitted license URL. |
| [Certutil definition](authoring/certutil-context-menu.psd1) | Small coordinated-registry helper-input example, HKCR mapping and an unnamed command value. |
| [Hash context-menu material](hash-context-menu/README.md) | Corrected .reg and preserved upstream attachment for review. |
| [Recovery snapshots](recovery/README.md) | Historical metadata for restoring runs from old examples. |

Authoring definitions are inputs to `New-RideLibrary.ps1`, not catalogs for
`-Library`. Their original namespaces are kept deliberately. Generate one into
your own new directory, validate it and preview its explicit profile:

```powershell
.\tools\New-RideLibrary.ps1 -Path .\my-library -Definition .\examples\authoring\windows7-games.psd1
.\tools\validate.ps1 -Library .\my-library\ride-library.psd1
.\ride.ps1 apply -Library .\my-library\ride-library.psd1 -Profile .\my-library\profiles\custom.psd1 -WhatIf
```

Or copy the main library to try several operation kinds together. Its starter
selects only the inert marker; choose settings or packages explicitly. Validation
does not establish Windows behavior. Review selections and test in disposable
Windows VMs. See the [custom-library guide](../docs/CUSTOM-LIBRARIES.md) for `-Add`,
references and recovery.
