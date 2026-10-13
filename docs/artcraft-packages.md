# Artcraft standalone packages

The [Crafting Apps page](https://getartcraft.com/apps) lists twelve creative
applications and the optional ArtCraft Launcher. RIDE has one pinned x64 MSI
package for each, under `Software / Artcraft`. Source review: 2026-10-11.

| Package ID | Product | Pinned version |
| --- | --- | --- |
| `package.photocraft` | PhotoCraft | 0.7.0 |
| `package.vectorcraft` | VectorCraft | 0.9.0 |
| `package.filmcraft` | FilmCraft | 0.6.0 |
| `package.lightcraft` | LightCraft | 0.6.0 |
| `package.pdfcraft` | PdfCraft | 0.6.0 |
| `package.effectcraft` | EffectCraft | 0.8.0 |
| `package.designcraft` | DesignCraft | 0.6.0 |
| `package.wordcraft` | WordCraft | 0.5.0 |
| `package.soundcraft` | SoundCraft | 0.5.0 |
| `package.deckcraft` | DeckCraft | 0.5.0 |
| `package.cadcraft` | CADCraft | 0.5.0 |
| `package.gridcraft` | GridCraft | 0.5.0 |
| `package.artcraft-launcher` | ArtCraft Launcher | 0.2.1 |

## Full installers and offline payloads

Each pinned publisher repository's `packaging/windows/*.wxs` declares
`MediaTemplate EmbedCab="yes" CompressionLevel="high"` and includes the desktop
executable. The twelve app MSIs also include their CLI executable. These are
self-contained, compressed application installers; their smaller size than the
portable ZIPs does not indicate a web bootstrapper. For example, inspect
[VectorCraft's pinned installer source](https://github.com/storytold/vectorcraft/blob/v0.9.0/packaging/windows/vectorcraft.wxs).

The launcher MSI contains the launcher itself. Using the launcher to acquire
other apps or updates needs network access. Individual app MSIs retain the
standalone payloads without relying on the launcher. This establishes installer
payload completeness, not feature completeness or that every optional app
feature operates offline. The publisher describes these apps as early releases.

Download one package, or all thirteen, without installing anything:

```powershell
.\ride.ps1 download package.photocraft -Destination 'Z:\Artcraft'
$packages = .\ride.ps1 list packages |
  Where-Object Category -eq 'Software / Artcraft'
foreach ($package in $packages) {
  .\ride.ps1 download $package.Id -Destination 'Z:\Artcraft'
}
```

RIDE retains each MSI at `<destination>\<package-id>\<version>\<asset-name>`.
`-WhatIf` previews downloads. Pins use version-specific official
`storytold/<product>` GitHub release URLs. Each `ExpectedSha256` was checked
against that release's `SHA256SUMS.txt` and GitHub asset digest. RIDE verifies
the pin for new downloads and cached bytes. Updates require reviewed version,
URL and checksum changes; these entries do not silently resolve a newer release.

Keep downloaded publisher notices alongside the original MSI. Code is licensed
under MIT OR Apache-2.0, with separate bundled-asset notices and Artcraft branding
terms linked by `LicenseUri` and `TermsUri`. Local license-review decisions
remain in the [independent review store](package-licensing.md).

### Local acquisition verification, 2026-10-11

All thirteen pinned MSIs were downloaded to `Z:\Artcraft`, totaling 595.1 MiB.
Every acquired SHA-256 matched the pin and each Windows Authenticode check
reported `Valid`. Read-only Windows Installer database inspection confirmed
`#cab1.cab` backed by an embedded stream in every MSI, the expected product name
and desktop executable, and the CLI executable in all twelve app packages.
No installer was executed. Together with the pinned WiX source, this confirms
the retained application payloads are embedded rather than fetched at setup.

Each product/version directory also retains `SHA256SUMS.txt`,
`RIDE-acquisition.json`, `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`,
`LICENSE-brand.txt` and `README.upstream.md`. The destination root contains
`Artcraft-downloads-20261011.json` and `Artcraft-msi-inspection-20261011.json`.
These are acquisition evidence, not installation acceptance or redistribution
approval.

Repository validation passed. The Artcraft, catalog and package-evidence Pester
files passed 99 tests with the one live Windows integration test excluded.
Pester's optional registry fixture was disabled; mocked tests ran with temporary
files, without installing apps or changing Windows configuration.

## Installation acceptance and recovery

All thirteen entries declare `PendingAcceptance = $true`, no supported targets,
and Windows 11 as the candidate target. Downloads are available; state-changing
plans remain blocked until disposable Windows VM acceptance establishes support.
No Windows Server support is claimed. No apps were installed on the developer
machine during preparation.

The twelve app installers declare machine scope and require elevation. The
launcher declares current-user scope. Quiet installation/removal uses
`/qn /norestart`; PdfCraft additionally requires `ALLUSERS=1` for installation.
Exit codes 0 and 3010 are successful; 3010 reports a reboot requirement.
The `solution.artcraft-apps` group selects the twelve independent app packages
in catalog order and removes them in reverse order. The launcher remains a
separate choice.

Before changing acceptance metadata, test installation, live name/version
detection, repeated apply, removal, compensating restore, partial failures,
reboot reporting, quiet-mode launch behavior, and installation with networking
disabled in a disposable Windows 11 VM. Check application startup/graphics,
document workflows and preservation of user files separately. Saved-state
recovery uses the existing MSI compensating lifecycle and does not promise
an exact backup of application data or a previously installed version.
