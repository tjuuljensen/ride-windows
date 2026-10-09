# System Tools selector reconciliation

Reviewed 2026-10-09. The System Tools family contains 25 legacy selectors.
None currently has a v3 catalog operation. A listed selector is not considered
migrated until it has an explicit disposition, source/artifact contract, and
tested lifecycle. Do not run legacy installers as part of this review.

| Legacy selector(s) | Current v3 disposition | Source behavior and remaining work |
| --- | --- | --- |
| `GetSysinternalsSuite`, `RemoveSysinternalsSuite` | Deferred: managed portable collection | Downloads Microsoft's mutable `SysinternalsSuite.zip`, copies the extracted suite into a shared tools root, and removes that whole directory. Define a versioned artifact, deterministic package directory and safe ownership/removal. Assess dual-use utilities and Defender behavior per artifact. |
| `InstallJoeWare`, `RemoveJoeWare` | Deferred: dynamic collection; AdFind alert risk confirmed | Scrapes all linked JoeWare tool pages and downloads each archive. The publisher reports Microsoft Defender blocking AdFind because it is commonly used for Active Directory reconnaissance. Select exact tools and versions before treating this as a package or planning an exception. [JoeWare report](https://blog.joeware.net/2023/02/22/6166/) |
| `InstallCCleaner`, `RemoveCCleaner` | Deferred: split into distinct products | The legacy selector fetches CCleaner Portable, Defraggler, Recuva, and Speccy, then extracts archives and installers with different mechanisms. Model supported products separately and define artifact, ownership, and removal behavior for each. |
| `InstallMitec`, `RemoveMitec` | Deferred: dynamic collection | Scrapes the MiTeC site and follows multiple product pages before downloading tool archives into one shared directory. Select and pin intended tools; do not infer presence or remove ownership from a directory name alone. |
| `InstallNtcore`, `RemoveNTCore` | Deferred: dynamic collection; alert status unknown | Crawls NTCore tool pages and downloads multiple EXE/ZIP files into one shared directory. No source-confirmed Defender alert was identified in this review. Enumerate exact intended artifacts and check their publisher evidence before migration. |
| `InstallTMOG`, `RemoveTMOG` | Deferred: conventional installer, source validation needed | Downloads a fixed TMOG Task Manager setup EXE and silently installs it; removal searches package-registration data. Resolve a versioned official artifact, signature expectations, and stable installed-package detection. |
| `InstallWireshark`, `RemoveWireshark` | Deferred: installer/dependency lifecycle | Selects the first current 64-bit non-portable EXE from the download page. Define deterministic version/architecture resolution, signature checks, optional Npcap behavior, and removal/recovery semantics. |
| `InstallZimmermanTools`, `RemoveZimmermanTools` | Deferred: mutable executable bootstrap; alert status is artifact-specific | Downloads `Get-ZimmermanTools.ps1` from a mutable GitHub `master` URL and executes it, producing a changing forensic-tool collection. The publisher says tools are signed and antivirus hits are false positives after signature verification. Pin and verify the bootstrap script and record/verify each resulting artifact before execution or exception decisions. [Official publisher guidance](https://ericzimmerman.github.io/) |
| `InstallNirsoftLauncher`, `RemoveNirsoftLauncher` | Deferred: dual-use launcher collection; alert risk confirmed | Downloads a password-protected encrypted launcher archive. The launcher exposes a changing suite of utilities. NirSoft reports frequent antivirus alerts for some password-recovery tools; choose exact utilities and versions rather than automatically importing the whole suite. [NirSoft antivirus report](https://www.nirsoft.net/false_positive_report.html) |
| `InstallNirsoftToolsX64`, `RemoveNirsoftToolsX64` | Deferred: dual-use collection; alert risk confirmed | Downloads NirSoft's password-protected x64 tools archive and extracts it into a shared directory. Exact contents vary; identify tools and hashes before choosing any package-scoped compatibility treatment. [NirSoft antivirus report](https://www.nirsoft.net/false_positive_report.html) |
| `InstallNirsoftPkgFiles`, `RemoveNirsoftPkgFiles` | Deferred: launcher metadata and collection coupling | Downloads `.nlp` launcher package files and adds a repository-supplied Zimmerman language file. This is launcher configuration, not an independently installed software package; define its ownership and relationship to the launcher and bundled tools. |
| `InstallArsenalRecon` | Deferred: gated/dynamic dual-use collection; AV interaction documented | Installs MEGAcmd and downloads every MEGA link discovered on the Arsenal Recon page. Arsenal documents antivirus exclusions and a possible `utilman.exe` alert for Arsenal Image Mounter's VM features. This establishes AV interaction, not a Defender detection for every artifact. Select an exact product/version, review licensing and drivers, and define rollback before migration. [AIM walkthrough](https://arsenalrecon.com/arsenal-image-mounter-aim-walkthrough) |
| `InstallWinget` | Deferred: Windows capability and dependency provisioning | Downloads an App Installer MSIX bundle plus VCLibs and WinUI dependencies, then registers packages. Determine supported Windows baselines and use the documented Windows package servicing model rather than ordinary EXE installer semantics. |
| `InstallWingetAutoUpdate` | Deferred: scheduled task/service behavior | Downloads the latest WAU ZIP from GitHub and runs its setup flow. Review task/service creation, update policy, persistence, and exact uninstall/restore behavior separately from WinGet itself. |

## Implementation constraints

- Package operations currently support EXE and MSI installers plus a dedicated
  Sysmon ZIP path. A portable collection needs managed-file installation,
  presence detection, version reporting, safe removal and exact rollback.
- The default workstation profile currently adds a broad Tools-directory
  Defender exclusion. That exclusion must not be mistaken for package-level
  alert evidence; a controlled alert scan must run with that exclusion absent
  from the disposable VM, inspect effective Defender exclusions, and scan exact
  versioned files without executing the tools.
- Package-specific Defender exceptions are not implemented. Before migrating
  a package with a known alert, add reviewed package metadata and make any
  exception exact to that package's directory. Never create a parent Tools or
  Downloads exclusion as a shortcut.
- No System Tools package was downloaded, executed or scanned for this
  reconciliation. The parallel AutomatedLab runbook test was not touched.
