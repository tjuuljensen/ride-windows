# Package verification matrix

This matrix records what each upstream source makes available for the current
release. It separates publisher evidence from hosting-provider metadata and
RIDE's own observed hashes. A local observation does not prove authenticity.
Source review date: 2026-10-08.

| Package | Latest source | Exact versioned artifact | Publisher checksum/signature | Hosting metadata | Authenticode | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 7-Zip x64 | Official `ip7z/7zip` release `26.04` | `7z2604-x64.exe` | No publisher checksum/detached signature identified on the official download page | GitHub SHA-256 digest matched | Windows 11 observation: `NotSigned` | Unsigned-artifact policy remains a decision before any strict gate |
| Notepad++ x64 | Official release `v8.9.8.1` | `npp.8.9.8.1.Installer.x64.exe` | Exact release checksum and GPG sidecar URLs recorded; detached verification remains open | GitHub digest matched | `Valid`; subject/organization `NOTEPAD++`, email `don.h@free.fr` | Confirm publisher signer expectations/rotation and implement trusted-key GPG verification |
| Git for Windows x64 | Official release `v2.56.0.windows.2` | `Git-2.56.0.2-64-bit.exe`; four-part installer names supported | Exact installer SHA-256 published in release notes is now parsed and matched. No detached signature over that checksum identified | GitHub digest matched separately as provider metadata | `Valid`; subject/organization `Johannes Schindelin`, Bruehl, DE | Git functionality/lifecycle passed; publisher signer expectations remain a trust-policy investigation |
| Sysmon x64 archive | Microsoft page version `15.22`, direct `Sysmon.zip` | Versioned cache; source ZIP URL remains mutable | No publisher checksum/detached signature identified on download page | Microsoft direct download; no GitHub digest | Root `Sysmon64.exe` reports `Valid`, signer `Microsoft Windows Publisher`, issuer `Windows Production PCA 2023`; member evidence is bound to archive SHA-256 | Actual Windows signer captured; certificate rotation/trust policy remains separate |
| SwiftOnSecurity Sysmon XML | Latest commit history for the exact file path in `SwiftOnSecurity/sysmon-config` | Yes; the selected file is downloaded from the resolved immutable commit SHA | No detached signature or checksum identified | GitHub API reports commit identity; this does not authenticate the author or content | Not applicable to XML | Download-only artifact support added; application remains a separate explicit configuration action |
| Git LFS standalone | Official `git-lfs/git-lfs` release `v3.8.0` | `git-lfs-windows-v3.8.0.exe` | `sha256sums.asc` and signature assets inventoried; detached verification not implemented | GitHub digest checked when supplied | `Valid`; subject/organization `GitHub, Inc.`, San Francisco, US | Requires Git before install and during removal; verify publisher keys separately |
| Joplin | Official `laurent22/joplin` release `v3.7.21` | `Joplin-Setup-3.7.21.exe` | Sidecar URLs collected when present; no new mandatory gate | GitHub digest matched | `Valid`; subject/organization `Joplin`, Nancy, FR | Current-user NSIS lifecycle passed on Windows 11 |
| ShareX | Official `ShareX/ShareX` release `v21.0.0` | `ShareX-21.0.0-setup-x64.exe` | Sidecar URLs collected when present; no new mandatory gate | GitHub digest matched | `NotSigned` | Machine EXE lifecycle passed on Windows 11; portable form remains separate; unsigned policy needs a decision before a strict gate |
| WinDirStat | Official `windirstat/windirstat` release `release/v2.9.2` | `WinDirStat-x64.msi`, retained under exact version | Publisher `WinDirStat-Hashes.txt` identified; parsing/verification remains open | GitHub digest matched | `Valid`; signer `Open Source Developer Bryan Berns` | Quiet no-restart MSI lifecycle passed on Windows 11 |
| PowerShell 7 | Official `PowerShell/PowerShell` release `v7.6.6` | `PowerShell-7.6.6-win-x64.msi` | Publisher checksum assets collected when present; verification remains separate | GitHub digest matched | `Valid`; signer `Microsoft Corporation` | MSI lifecycle and executable/version check passed on Windows 11; preserve Windows PowerShell 5.1 |

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

1. Windows inspection completed for all package artifacts in this matrix.
   7-Zip and ShareX are unsigned; Sysmon's executable and the other installers
   report valid signatures. Compare certificate identities and rotation
   expectations with official publisher material before using them as policy.
2. Git's release-note checksum is implemented and matched. Other publisher
   sidecar parsing and detached GPG verification remain open, including trusted
   key acquisition, expiration/revocation and mismatch tests.
3. Sysmon executable signer collection is completed. Microsoft Windows Publisher
   is the observed subject, with Microsoft Corporation organization and Windows
   Production PCA 2023 issuer. Establish accepted identities and rotation rules
   before turning observations into enforcement. The ZIP's `UnknownError`
   signature result does not describe the contained executable.
4. Obtain at least two demonstrably independently routed observations for the
   same immutable artifact. Repeated direct downloads and cache reads do not
   satisfy this requirement.
5. Recheck provider behavior when adapters/artifacts change. The agreed workflow
   is evidence-first; a future mandatory authenticity gate needs an explicit
   missing-evidence policy, accepted identities, rotation and recovery decision.
6. Add metadata-only fallback collection for cache sidecars if a VM cannot write
   its shared library. Current VM collection exports the library; the local
   sidecar survives a shared-write warning only until checkpoint reset. Preserve
   it manually before reset when investigating that failure mode.

## Retention and use workflow

Every acquisition has a new `ObservationId`, UTC time, package/artifact ID,
version, architecture, filename, product origin, resolved source/release URIs,
route, SHA-256 and size. `AcquisitionKind` distinguishes `Download` from `Cache`.
Records retain provider digest, publisher checksum/source/result, available
checksum/signature URLs, file/product versions, Authenticode status, subject,
issuer, certificate thumbprint and timestamp certificate details. New VM
observations also include the correlated `RunId`.

Sysmon `Contents` records `ArchivePath=Sysmon64.exe`, member SHA-256,
`ParentSha256` and executable signature/version evidence. ZIP and executable
hashes remain separate; XML has its own observation. Inspection never executes
a file; installation goes through the separate engine lifecycle.

1. Resolve the official source to an exact versioned artifact or immutable file
   revision. Retain bytes in the local version cache.
2. Check any supplied provider digest and supported publisher checksum before
   installation. Mismatch stops execution; failure logs and retained cache
   support investigation. Missing evidence is unavailable, not verified.
3. Write an observation and `.ride.json` sidecar alongside the artifact. The
   shared library uses an exclusive lock and atomic replacement. On shared-write
   failure, retain the sidecar and report a warning.
4. VM requests export metadata to `guest/artifact-observations.json` before
   checkpoint restore. Host results retain transcripts, source hashes, Pester
   output and state. Installer caches are excluded and vanish on checkpoint reset.
5. Review source/version/hash, signer status, archive linkage and request outcome,
   then merge metadata using the importer. A failed installation can still supply
   acquisition evidence; it does not establish lifecycle acceptance.

```powershell
.\tools\Import-RideArtifactObservations.ps1 `
    -Path 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results\<run-id>\guest\artifact-observations.json' `
    -WhatIf
# After review, repeat without -WhatIf.
```

The importer preserves existing observations, ignores identical repeated IDs
and rejects conflicting IDs or member/parent mismatch. Older schema-1 records
are preserved; records without acquisition IDs are not invented as new events.
Binaries, credentials, notebooks and tool configuration are not stored in this
version-controlled metadata library.

Compare exact version/source and content hash. A cache read is not an independent
download; repeated direct acquisitions from the same host/provider are not
independently routed evidence. Mutable Sysmon URLs require comparison of time,
archive/member versions and both hashes. Never silently replace old observations
when source bytes change.

### Reviewed Windows observations

Runs `a2a2539763bf43e4a2981404d33a39e2` and
`d1ce1d8e371241699e5d9d1d88f98c7c`, followed by passing full request
`9744844940fd4ca498ef6486092ac831`, supplied matching direct-route acquisitions.
The final request passed 128 guest tests and integration. The library now holds
30 observations; repeat imports add zero duplicates. Full records are in
`catalog/artifact-observations.json`.

| Artifact | SHA-256 | Observed Authenticode certificate thumbprint |
| --- | --- | --- |
| 7-Zip 26.04 x64 | `d54bf805f9f3704d1e8db2fa3498ae7ef2df0312b40b558e7c71c734430a665d` | None (`NotSigned`) |
| Notepad++ 8.9.8.1 x64 | `26f3bcced788fadbac4e7e577b430ea2ce6060cf3bcad993ef4612ecd7d743da` | `1E8E0D13B608BA908572C1A129FAEC5D228DF8A2` |
| Git 2.56.0.windows.2 x64 | `52188f917b378f00c70ec136bcf090005f30d44fbc4eba0bce759cc6592d60f6` | `C4BA1DE1C1B6049CF0E3FB393640685052199AEB` |
| Git LFS 3.8.0 | `aa2d69214905d6b348f1b038beb2d68e4828342f9b3fe47dae5a5f023823fe92` | `5F69F3A04D6E13E9C1C5AA26C69A7FD2878A9936` |
| Joplin 3.7.21 | `4222536c69360a30a566627b35c2e1cd8d38d0c79735ebde4e39edbcddd750cd` | `AF0C1B9451567F9AF077DD0646D2927153B05DAF` |
| ShareX 21.0.0 x64 | `f213aca04d30e0e2dc7c43bc79acae8622be291cee6014a90962ed87ea5f10cc` | None (`NotSigned`) |
| WinDirStat 2.9.2 x64 | `21fb47b7262bcd094506a14977de8db54264bd7a93db9ad2863f1eed206ba2a3` | `82802376D2DD840614CC00C6EC8AD763CEA6D33C` |
| PowerShell 7.6.6 x64 | `958838ff55091e1c8705d89efed0cc7e8245a3a6ef6c0ccfae20015227108ad8` | `AB172913A2960A224809EE8A0C371CD47A079B72` |
| Sysmon 15.22 ZIP | `00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54` | No executable-signature interpretation |
| Sysmon64.exe 15.22, inside that ZIP | `83d31f2478dc6716cfdbf69e5c384bf043072b5f0d8d7b2eea365f709fda4352` | `CDCC1456D261BC0EB00975F46DFFB2E24592EDAD` |

Thumbprints identify observed certificates; they are not permanent trust roots
or automatic approvals. Reassess rotations through the publisher.

Additional official references: [Git's exact release/checksums](https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.2),
[Git LFS releases](https://github.com/git-lfs/git-lfs/releases),
[Git LFS installer dependency behavior](https://github.com/git-lfs/git-lfs/blob/v3.8.0/script/windows-installer/inno-setup-git-lfs-installer.iss),
[Joplin releases](https://github.com/laurent22/joplin/releases),
[ShareX releases](https://github.com/ShareX/ShareX/releases),
[WinDirStat releases](https://github.com/windirstat/windirstat/releases), and
[PowerShell releases](https://github.com/PowerShell/PowerShell/releases).

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
