# Package verification matrix

This matrix records what each upstream source makes available for the current
release. It separates publisher evidence from hosting-provider metadata and
RIDE's own observed hashes. A local observation does not prove authenticity.
Source review date: 2026-10-08.

| Package | Latest source | Exact versioned artifact | Publisher checksum/signature | Hosting metadata | Authenticode | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 7-Zip x64 | GitHub latest-release API for `ip7z/7zip`; release tag provides version | Yes; release assets are versioned (for example `7z2604-x64.exe`) | The official 7-Zip download page does not list a checksum or detached signature alongside the installer | GitHub release assets may expose a SHA-256 `digest`; this is hosting metadata, not a publisher signature | Not yet inspected by RIDE; each downloaded file observation records the local signature status and signer | Latest resolution is implemented; evidence characterization needs continued review |
| Notepad++ x64 | GitHub latest-release API for `notepad-plus-plus/notepad-plus-plus` | Yes; release tag and asset name include the version | Current releases may publish checksum lists and detached GPG signatures; confirm sidecar availability for each resolved release and validate against the official key fingerprint below | GitHub release asset digest may also be available | Not yet inspected by RIDE; each downloaded file observation records the local signature status and signer | Latest resolution is implemented; signature verification is not yet implemented |
| Git for Windows x64 | Official updater references GitHub's latest-release API; release tags identify the Git for Windows patch release | Yes; installer asset follows `Git-<version>-64-bit.exe` | No publisher-signed checksum or detached signature was identified in this review; third-party package manifests sometimes carry checksums but are not the publisher trust source | GitHub release asset digest may be available | Not yet inspected by RIDE; each downloaded file observation records the local signature status and signer | Latest resolution is implemented; independent publisher verification needs investigation |
| Sysmon x64 archive | Microsoft Sysinternals page identifies current version and links to `Sysmon.zip` | Version is extracted from the page; ZIP URL remains mutable | No publisher checksum or detached signature was identified on the download page | Microsoft-hosted direct download; no GitHub release digest | ZIP itself has no Authenticode signature; contained executable signer is not yet recorded by RIDE | Latest download and archive/service handler passed mocked and Windows 11 VM install/idempotence/uninstall checks |
| SwiftOnSecurity Sysmon XML | Latest commit history for the exact file path in `SwiftOnSecurity/sysmon-config` | Yes; the selected file is downloaded from the resolved immutable commit SHA | No detached signature or checksum identified | GitHub API reports commit identity; this does not authenticate the author or content | Not applicable to XML | Download-only artifact support added; application remains a separate explicit configuration action |

## Source notes

- 7-Zip official downloads: <https://www.7-zip.org/download.html>
- 7-Zip official release: <https://github.com/ip7z/7zip/releases>
- Git for Windows official site: <https://gitforwindows.org/>
- Git for Windows official update mechanism: <https://github.com/git-for-windows/build-extra/blob/main/git-extra/git-update-git-for-windows>
- Git for Windows releases: <https://github.com/git-for-windows/git/releases>
- Microsoft Sysmon download page: <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
- Microsoft Sysmon installation and configuration guidance: <https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon>
- Notepad++ official releases: <https://github.com/notepad-plus-plus/notepad-plus-plus/releases>
- Notepad++ official project README and GPG key fingerprint: <https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/README.md>
- Notepad++ public GPG key: <https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/nppGpgPub.asc>
- GitHub documents the release asset `digest` field as a hosting-provided digest: <https://docs.github.com/en/rest/releases/releases>

The Notepad++ signing key fingerprint published by the project is
`14BC E436 2749 B2B5 1F8C 7122 6C42 9F1D 8D84 F46E`. The project has used
GPG signatures for release verification, but signature sidecar availability
must be checked on the specific release rather than assumed. RIDE currently
records available checksum and signature sidecar URLs; it does not yet verify
detached signatures.

## Next research

1. Inspect downloaded 7-Zip and Notepad++ Authenticode signer identities on
   Windows and compare them with publisher documentation.
2. Implement provider-specific checksum and GPG verification, including key
   acquisition and trust-root review.
3. Add at least two independently routed observations for the same immutable
   artifact before using cross-path agreement as evidence.
4. Recheck these source behaviors whenever a provider adapter changes.

Sysmon is deliberately called out separately from ordinary EXE packages:
Microsoft documents `sysmon64 -i`, `sysmon64 -c`, and `sysmon64 -u`; the
download is an archive whose contained executable installs a service and
driver. The active legacy selectors also fetch separate community XML files
from mutable branch URLs. The user selected a separate download-only XML
artifact that is applied only when explicitly chosen; Sysmon installation must
not pick a community configuration implicitly. Keep the binary and XML as
separate artifact observations, and treat configuration updates as potentially
behavior-changing policy inputs. The Microsoft page currently identifies
Sysmon v15.22 (published 2026-09-10), but its download path is mutable.
[Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
also lists Windows 11 and Windows Server 2019+ as supported by Sysmon.
