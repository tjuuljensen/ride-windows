# Historical example libraries for saved-run recovery

These are recovery snapshots, not alternative starting templates. The current
copyable example is [examples/library](../library/README.md).

| Original library | Retained manifest | Original identity |
| --- | --- | --- |
| Contoso starter | `contoso/0.1.0/ride-library.psd1` | `example.contoso`, version 0.1.0 |
| Operator's original games library | `games-library/0.1.0/ride-library.psd1` | `custom.games`, version 0.1.0 |
| Reconciled games example | `games-library/0.1.1/ride-library.psd1` | `custom.games`, version 0.1.1 |
| Initial consolidated library | `library/0.1.0/ride-library.psd1` | `example.library`, version 0.1.0 |

Catalogs, manifests and profiles are unchanged byte-for-byte. Games 0.1.0 retains
its placeholder license URL for identity matching; it is not a source of license
information. Library 0.1.0 retains the original games detection pattern; 0.1.1
corrects it to the observed registered product name. No payloads or saved Windows
state are stored here.

## Consolidated ID mapping

| Original entry | New main-example entry |
| --- | --- |
| `example.contoso.preference-marker` | `example.library.preference-marker` |
| `example.contoso.utilities` | `example.library.utilities` |
| `custom.games.classic-msgames` (operation and PackageId) | `example.library.classic-msgames` |
| `example.context-menu.sha256-certutil` (small authoring definition) | `example.library.sha256-certutil` |

The small [Certutil definition](../authoring/certutil-context-menu.psd1) retains its
own namespace/version. Keep any previously generated catalogs/manifests from it:
regeneration cannot guarantee the exact bytes of a catalog you edited. The same
applies to other single-operation authoring definitions.

New IDs do not retag saved runs, caches or registry state. Restore an earlier run
with its original library before applying the main example. Choose the snapshot
matching its saved version and catalog hash, for example:

```powershell
.\ride.ps1 restore -RunId <saved-run-id> -Library .\examples\recovery\games-library\0.1.0\ride-library.psd1 -WhatIf
```

Run actual recovery on the target VM after reviewing the preview. The engine
checks the library ID, version, API, catalog hash, handler and snapshot schema;
relocating unchanged files preserves that identity. Select one version of a
namespace per command. Historical metadata is not selected automatically.
