# RIDE operation catalog

Generated from `catalog/operations.psd1`. Edit catalog metadata, then run `tools/Export-RideCatalog.ps1`.

## Operations

| ID | Name | Category | Scope | Admin | Actions | Supported targets | Rollback | Description |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| package.7zip | 7-Zip | Software / Utilities | Machine | Yes | Get, Test, Install, Uninstall, Restore | Windows 11, Windows Server 2025 | Compensating | Install or remove the current 64-bit 7-Zip release. |
| package.notepadpp | Notepad++ | Software / Utilities | Machine | Yes | Get, Test, Install, Uninstall, Restore | Windows 11, Windows Server 2025 | Compensating | Install or remove the current 64-bit Notepad++ release. |
| windows.autoplay-policy | Autoplay policy | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11, Windows Server 2025 | Exact | Set the current user's Autoplay preference. |
| windows.show-known-extensions | Show known file extensions | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11, Windows Server 2025 | Exact | Show file extensions for registered file types in File Explorer. |
| windows.autorun-policy | Autorun policy | Windows settings / Security | Machine | Yes | Get, Test, Set, Restore | Windows 11, Windows Server 2025 | Exact | Set the machine policy for Autorun on removable and other drives. |
| windows.script-host-policy | Windows Script Host policy | Windows settings / Security | Machine | Yes | Get, Test, Set, Restore | Windows 11, Windows Server 2025 | Exact | Set the Windows Script Host policy or restore its default value. |

## Target defaults

Literal defaults describe the registry data or package presence expected on a clean target. Effective defaults describe the behavior Windows uses when those values are in effect.

| Operation | Target | Literal default | Effective default |
| --- | --- | --- | --- |
| package.7zip | Windows 11 | Absent | Not installed in the default Windows image |
| package.7zip | Windows Server 2025 | Absent | Not installed in the default Windows image |
| package.notepadpp | Windows 11 | Absent | Not installed in the default Windows image |
| package.notepadpp | Windows Server 2025 | Absent | Not installed in the default Windows image |
| windows.autoplay-policy | Windows 11 | <unset> | Enabled (AutoPlay is allowed by this preference) |
| windows.autoplay-policy | Windows Server 2025 | <unset> | Enabled (AutoPlay is allowed by this preference) |
| windows.show-known-extensions | Windows 11 | 1 | Disabled (known file extensions are hidden) |
| windows.show-known-extensions | Windows Server 2025 | 1 | Disabled (known file extensions are hidden) |
| windows.autorun-policy | Windows 11 | <unset> | Windows built-in AutoRun default mask: 0x91 (145) |
| windows.autorun-policy | Windows Server 2025 | <unset> | Windows built-in AutoRun default mask: 0x91 (145) |
| windows.script-host-policy | Windows 11 | <unset> | Enabled when this policy value is absent |
| windows.script-host-policy | Windows Server 2025 | <unset> | Enabled when this policy value is absent |

## Groups

| ID | Name | Category | Members, in apply order | Actions | Rollback | Description |
| --- | --- | --- | --- | --- | --- | --- |
| solution.analyst-basics | Analyst basics | Software / Groups | package.7zip, package.notepadpp | Install, Uninstall | Compensating | A small utility bundle with 7-Zip and Notepad++. |

