# Ninite packages compared with RIDE

Snapshot checked **2026-10-16** against the [public Ninite app picker](https://ninite.com/).
Ninite provides convenient installation and updating of common Windows apps.
Eleven of its products match existing RIDE package IDs; several more overlap
with pending product reviews. A product match does not establish the same
edition, architecture, installation scope, configuration or recovery behavior.

This comparison covers the public picker, including its runtime variants. It
does not include additional Pro offerings or Nintune's WinGet catalog. The
tables together account for every app displayed in that picker on the review
date. Version families below reproduce the picker choices, not a recommendation
to deploy every listed runtime.

RIDE mappings use the [catalog](../catalog/operations.psd1),
[application review ledger](migrations/application-migration-review.md),
[confirmed review choices](migrations/application-review-rounds-2026-10-12.md),
[migration plan](MIGRATION-PLAN.md), [task list](../TODO.md) and
[supplemental candidates](candidate-tools.md). Pending review is not a committed
package implementation. This reference adds no packages or migration outcomes;
the existing [package pause and deployment decisions](migrations/package-deployment-decisions.md)
remain in effect.

## Existing RIDE packages

Each row is a product-level match. Consult the catalog for supported targets
and the [application guide](application-packages.md) for distribution behavior.

| Ninite app | Existing RIDE ID | Distribution detail relevant to the comparison |
| --- | --- | --- |
| Chrome | `package.chrome` | RIDE's declared Chrome distribution and scope apply. |
| Firefox | `package.firefox` | Browser preference migration is a separate review. |
| Thunderbird | `package.thunderbird` | RIDE selects Release x64/en-GB in current-user scope. |
| ShareX | `package.sharex` | RIDE also declares a portable variant. |
| WinDirStat | `package.windirstat` | Existing catalog package. |
| 7-Zip | `package.7zip` | Existing catalog package; included in RIDE's default profile. |
| Git | `package.git-for-windows` | Git for Windows; Git LFS is a separate RIDE package. |
| Notepad++ | `package.notepadpp` | Existing catalog package. |
| WinSCP | `package.winscp` | RIDE manages the portable distribution. |
| PuTTY | `package.putty` | RIDE manages the standalone x64 executable. |
| Visual Studio Code | `package.vscode` | Existing catalog package. |

## Pending reviews and related work

These rows distinguish intended product review from adjacent settings,
dependencies and exclusions. Legacy selector names are traceability references,
not commands supported by the new engine.

| Ninite app or picker variants | RIDE relationship | Current boundary |
| --- | --- | --- |
| Python x64 3; Python arm64 3; Python 3; Python | Pending product review: `InstallPython` | Install manager default plus a traditional installer variant selected in principle. Exact releases, architectures and integration acceptance remain open. Preserve the picker's separate `Python` label without assuming its version or equating it with the manager. |
| Wireshark | Pending product review: `InstallWireshark` | Live capture selected, with a separate interactive Npcap step and administrator-only capture. Driver licensing, ownership and recovery require separate acceptance. |
| OneDrive | Pending product review: `InstallOneDrive` / `UninstallOneDrive` | Separate package lifecycle from sync policy and user data. |
| CCleaner | Pending product review: `InstallCCleaner` / `RemoveCCleaner` | Legacy portable bundle also contains Defraggler, Recuva and Speccy; those are separate outcomes and are absent from this Ninite picker. |
| Java (AdoptOpenJDK): x64 8, unqualified 8, x64 11, x64 17, x64 21, x64 25; JDK (AdoptOpenJDK): x64 8, unqualified 8, x64 11, x64 17, x64 21, x64 25; JDK (Amazon Corretto): x64 8, unqualified 8, x64 11, x64 17, x64 21, x64 25; JRE (Amazon Corretto): x64 8, unqualified 8 | Related runtime family: `InstallOpenJDK` | RIDE's review is for **Microsoft JDK 11 x64 MSI**. Neither the publisher nor all the major versions match Ninite; no automatic substitution is planned. "Unqualified" means the picker label omits an architecture. |
| Teams | Related Office/Teams configuration and removal review | Office's bundled Teams effects, autostart, Store registration and machine-wide installer removal are tracked. This is not a planned standalone Teams installation package. |
| Edge | Related browser settings | Edge settings are tracked; no standalone Edge installation package was identified. |
| Docker Desktop | Related BloodHound container-host decision | Current BloodHound CE is selected, but its container deployment is a separate review. This does not select Docker Desktop as a RIDE package or establish Windows Server support. |
| Opera | Explicitly excluded | User decision dated 2026-10-11 removes Opera from future migration scope. Its Ninite listing does not reopen that decision. |

## Remaining Ninite apps without a RIDE package mapping

No corresponding package implementation or explicit product plan was found in
the maintained RIDE sources listed above. These are comparison gaps, not new
backlog commitments. Categories follow Ninite; apps already mapped above are
omitted here to avoid duplicate entries.

| Ninite category | Remaining apps or selectable variants |
| --- | --- |
| Web Browsers | Brave; Vivaldi |
| Messaging | Zoom; Discord; Slack; Telegram; WhatsApp; Pidgin; Trillian |
| Media | iTunes; VLC; AIMP; foobar2000; Winamp; MusicBee; Audacity; K-Lite Codecs; Spotify; CCCP; MediaMonkey; HandBrake; OBS Studio |
| .NET | .NET 4.8.1; .NET Desktop Runtime 8, 9 and 10, each in x64, arm64 and an architecture-unqualified picker entry; ASP.NET Core Runtime 8, 9 and 10, each in x64, arm64 and an architecture-unqualified picker entry; VSTO Runtime |
| Imaging | Krita; Blender; Paint.NET; GIMP; IrfanView; XnView; Inkscape; FastStone; Greenshot |
| 3D Printing | Bambu Studio; UltiMaker Cura |
| Documents | Foxit Reader; LibreOffice; SumatraPDF; CutePDF; PDF24 Creator; Ghostscript; OpenOffice |
| Security | Malwarebytes; Avast; AVG; Spybot 2; Avira; SUPERAntiSpyware |
| File Sharing | qBittorrent |
| Online Storage | Dropbox; Google Drive for Desktop; SugarSync |
| Other | Evernote; Google Earth; Steam; Epic Games Launcher; KeePass 2; 1Password; Bitwarden; Everything; NV Access; ChatGPT; Claude |
| Utilities | PowerToys; AnyDesk; TeamViewer 15; Windows App; ImgBurn; TightVNC; RustDesk; Tailscale; WireGuard; TeraCopy; CDBurnerXP; Revo; Launchy; WizTree; Glary; InfraRecorder; Open-Shell |
| Compression | PeaZip; WinRAR |
| VC++ Redistributables | VC Redist 2015+ in x64, x86 and arm64; VC Redist 2013, 2012, 2010, 2008 and 2005, each in x64 and x86 |
| Developer Tools | GitHub Desktop; Node.js 22; Node.js 24; Node.js 26; FileZilla; Sublime Text 4; WinMerge; Eclipse; Cursor |

RIDE's .NET 3.5 optional-component review is not a match for these .NET runtime
packages. Dependency references to Visual C++ runtimes likewise do not establish
standalone package coverage. Functional alternatives such as RIDE's Artcraft
apps are not counted as matches to different Ninite products.

## What Ninite avoids during installation

Ninite's documented behavior is to decline optional toolbars and extra bundled
software while installing the selected app. It describes automating installer
input, generally with the installer window hidden; defaults such as installation
location remain unchanged. This is prevention during installation, not a promise
to find and remove existing unwanted software.
See [How Ninite Works](https://ninite.com/help/how-ninite-works/).

A legitimate application can still offer another legitimate but unwanted
product during setup. For example, the FileZilla project's
[installer explanation](https://filezillapro.com/docs/v3/faq/is-filezilla-client-safe/)
says its optional sponsored offers can include Google Chrome. Declining that
offer keeps a FileZilla installation focused on FileZilla; it does not imply
that either product is inherently malicious.

The public Ninite documentation reviewed here does not provide an exhaustive
current app-by-app list of declined offers or installer switches. It therefore
does not establish a specific list of disabled services, scheduled tasks,
telemetry, startup entries or in-app advertising. Those effects need evidence
for the exact app and installer version; the toolbar claim alone is insufficient.

There is a separately documented Ninite Pro Classic
[`/disableautoupdate` option](https://ninite.com/help/features/disableautoupdate.html)
for selected applications. It is an explicit update-management feature, not the
meaning of the ordinary toolbar-avoidance claim. That help page includes legacy
products and should not be treated as the current public app inventory.

For RIDE, any desired exclusion should be declared and verified per package:
choose the appropriate publisher artifact, review its component options and
test the installed result. A silent switch by itself does not demonstrate that
optional offers, services or integrations are absent.
