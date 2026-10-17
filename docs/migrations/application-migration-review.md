# Application migration and individual review ledger

Reviewed 2026-10-17 for current dispositions; the grouped review history below began on 2026-10-12. Every selector in the eight package families is assigned to one batch. Install/remove pairs count once; installed and portable distributions remain distinct outcomes. Existing accepted IDs retain their earlier evidence and support declarations. New distributions declare support only after target-specific acceptance and never enter recommended profiles automatically.

The [dated decision map](application-review-rounds-2026-10-12.md) assigns the original
79 review outcomes once across 13 groups. Q17/Q20 now retire two of those outcomes,
leaving 77 pending/partial review outcomes. Historical mappings, dependencies and
individual ownership boundaries remain. First-round user choices keep both
ImageMagick distributions, GnuPG command line/Kleopatra without Explorer/Outlook
integration in current-user scope, and Wireshark live capture with a separate
interactive Npcap step without assumed OEM rights. ImageMagick's edition pairing
is confirmed; other scope/integration choices, driver terms and technical
acceptance remain open. The two explicit retirements add no native acceptance;
older publisher observations below retain their original dates.

Batch 1 covers conventional installed applications and their adjacent bundled configuration/component issues. Batch 2 covers portable files, collections, repository downloads and deployed configuration. A review disposition accounts for the outcome without claiming migration or retirement.

Source references below identify the publisher declared by the legacy implementation. Their presence is not a fresh download or license approval. Current release observations are distinguished explicitly; remaining legacy implementations are in [lib-windows.psm1](../../legacy/v2/lib-windows.psm1). Opera's removed selector is retained below solely as a dated user-policy exclusion.

| Batch | Exact selectors / component | Intended outcome / disposition | Blocker and next decision or test | Source evidence |
| --- | --- | --- | --- | --- |
| 1 | `Install7Zip`, `Remove7Zip` | Previously migrated: `package.7zip` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://www.7-zip.org/) |
| 1 | `InstallGit4Win`, `RemoveGit4Win` | Previously migrated: `package.git-for-windows` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/git-for-windows/git) |
| 2 | `GetSysmonSwiftXML` | Previously migrated: `artifact.sysmon-swift-config` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml) |
| 1 | `InstallSysmon64`, `RemoveSysmon64` | Previously migrated: `package.sysmon64` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://download.sysinternals.com/files/Sysmon.zip) |
| 1 | `InstallGitLFS`, `RemoveGitLFS` | Previously migrated: `package.git-lfs` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/git-lfs/git-lfs) |
| 2 | `InstallPSScriptTools`, `RemovePSScriptTools` | Pending source candidate: `package.psscripttools` | The [inert archive candidate](#b08-psscripttools-source-candidate-2026-10-17) retains full source/notices; no production target or deployment choice is accepted. Legacy copies a Git clone under Tools. Current inspected MIT source is module 3.2.0, PowerShell >=5.1/Desktop/Core, requiring Microsoft.PowerShell.Threadjob and System.Drawing. Choose retained Git workspace or pinned source archive; Gallery installation is a separate publisher-recommended distribution. Define dependency ownership, notices and preservation of user edits before deployment; never auto-import the module or silently replace with Install-Module. | [Exact source/initialization review](../archive/migrations/application-winscp-follow-up-2026-10-11.md#psscripttools-repository-and-module-boundary) |
| 1 | `InstallVSCode`, `RemoveVSCode` | Accepted migration: `package.vscode` | Preview, install/repeat/remove and restoration of original absence passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; application behavior and prior-version recovery remain separate limits. | [Legacy publisher reference](https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user) |
| 1 | `InstallGPGwin` | Individual review: gpgwin | User confirmed current-user scope, GnuPG command line and Kleopatra only, without Explorer/Outlook integration, on 2026-10-12. Verify current-user scope in both the outer and nested GnuPG installers and explicit component exclusions before admission. Inspected 5.1.1 installer/source hashes and certificate are recorded; nested GnuPG install/removal can affect both registry views. Resolve dependency ownership, process handling and key/configuration preservation; outer EXE presence is insufficient recovery. | [Confirmed preparation choices](application-review-rounds-2026-10-12.md#confirmed-first-round-choices); [exact integrity/certificate reference](https://gpg4win.org/package-integrity.html); [source inspection](../archive/migrations/application-installed-follow-up-2026-10-11.md#gpg4win-component-and-dependency-preparation) |
| 1 | `InstallNotepadPlusPlus`, `RemoveNotepadPlusPlus` | Previously migrated: `package.notepadpp` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/notepad-plus-plus/notepad-plus-plus) |
| 2 | `GetSysmonOlafXML` | Individual review: sysmonolafxml | Legacy root XML differs from the current template collection. Choose one template and immutable revision; acceptance must assess policy intent before applying any XML. | [Legacy publisher reference](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml) |
| 1 | `InstallVMwareWorkstation`, `RemoveVMwareWorkstation` | Individual review: vmwareworkstation | Resolve Broadcom download entitlement, supplied artifact and license acceptance; test drivers, reboot and machine recovery independently. | [Legacy publisher reference](https://www.vmware.com/go/getworkstation-win) |
| 2 | `SetVMDirUserhome` | Individual review: vmdiruserhome | VMware preference edit, not an install. Discover preferences.ini, capture the prior value and test exact current-user restore. | Legacy function defines local Windows/application state; see source. |
| 2 | `SetVMDirDocuments` | Individual review: vmdirdocuments | VMware preference edit, not an install. Resolve the Documents path, capture the prior value and test exact current-user restore. | Legacy function defines local Windows/application state; see source. |
| 1 | `InstallThunderbird` | Accepted migration: `package.thunderbird` | Confirmed Release x64/en-GB in current-user scope. Version 157.0.1 passed non-elevated install/repeat/remove, profile preservation and saved-selection recovery on Windows 11 and Server 2025 Desktop Experience. Each correlated batch passed 242 guest checks and seven lifecycles; temporary account/right cleanup and checkpoint recovery passed. Mail functionality and exact prior-version/association recovery remain separate limits. | [Correlated acceptance](../archive/migrations/application-thunderbird-follow-up-2026-10-11.md#accepted-migration-after-resumed-validation); [official release feed](https://product-details.mozilla.org/1.0/thunderbird_versions.json) |
| 1 | `InstallJoplin` | Previously migrated: `package.joplin` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/laurent22/joplin) |
| 1 | `InstallImageMagick` | Individual review: imagemagick | User confirmed keeping both distributions and selected the x64 Q16 HDRI DLL installer, all-user machine scope and machine PATH on 2026-10-12. Optional integrations, exact revision-bearing version/uninstall detection and environment recovery remain pending. | [Confirmed preparation choices](application-review-rounds-2026-10-12.md#confirmed-first-round-choices); [current publisher builds](https://imagemagick.org/download/#windows) |
| 2 | `InstallImageMagickPortable`, `RemoveImageMagickPortable` | Individual review: imagemagickportable | User confirmed this separate outcome and selected the listed x64 Q16 static portable build on 2026-10-12. Verify actual features, required files and scoped destination. Publisher uses 7z; bounded extraction and lifecycle acceptance remain technical work. | [Confirmed preparation choices](application-review-rounds-2026-10-12.md#confirmed-first-round-choices); [current publisher builds](https://imagemagick.org/download/#windows) |
| 1 | `InstallSignal` | Accepted migration: `package.signal` | Official stable x64 feed binds version/filename/SHA-512. Current-user lifecycle, repeat installation/removal, Roaming-profile preservation and compensating recovery passed on Windows 11 and Server 2025 Desktop Experience. Account linking and UI behavior remain separate. | [Correlated acceptance](../archive/migrations/application-installed-follow-up-2026-10-11.md#final-correlated-acceptance); [official update feed](https://updates.signal.org/desktop/latest.yml); [upstream uninstall-data configuration](https://github.com/signalapp/Signal-Desktop/blob/v8.30.0/package.json) |
| 1 | `InstallPython` | Individual review: python | User confirmed both selectable variants under one stable product ID on 2026-10-12: install manager default; traditional installer in all-user machine scope with unchanged machine PATH and preserved file associations; bundled/validated pip without automatic upgrade. These explicitly change legacy PATH/association/pip behavior. Manager deployment/command integration, releases, launcher coexistence and runtime/update policy remain undecided; manager-managed runtimes remain per-user even with a machine manager MSI. Verify exact installer controls, stable artifacts, dependency ownership and preservation/recovery; do not upgrade another interpreter or silently switch recorded variants. | [Publisher downloads](https://www.python.org/downloads/windows/); [confirmed integration choices](application-review-rounds-2026-10-12.md#confirmed-python-integration-choices); [manager scope](https://docs.python.org/3/using/windows.html#advanced-installation) |
| 2 | `InstallYara`, `RemoveYara` | Individual review: yara | Official stable v4.5.8 still has only source ZIP/tar.gz assets on the 2026-10-16 recheck; see the [latest availability record](#b08-yara-availability-recheck-2026-10-16). Establish a publisher-declared binary or reviewed reproducible Windows build; an older binary or YARA-X substitution requires its own decision. | [Current release evidence](https://github.com/VirusTotal/yara/releases/tag/v4.5.8); [dated availability check](../archive/migrations/application-winscp-follow-up-2026-10-11.md#yara-binary-availability-recheck) |
| 2 | `GetCyberChef`, `RemoveCyberChef` | Accepted migration: `package.cyberchef` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/gchq/CyberChef) |
| 2 | `InstallCaffeine`, `RemoveCaffeine` | Accepted migration: `package.caffeine` | Version 1.98 retains both x86/x64 files with an inspected archive hash pin. Preview, repeat install/remove, preservation and exact owned-file restore passed on Windows 11 and Server 2025 Desktop Experience. No automatic execution or startup entry. See continuation evidence. | [Current product/version reference](https://www.zhornsoftware.co.uk/caffeine/); [publisher terms](https://www.zhornsoftware.co.uk/) |
| 2 | `InstallPutty`, `RemovePutty` | Accepted migration: `package.putty` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) |
| 2 | `InstallWinSCP`, `RemoveWinSCP` | Accepted migration: `package.winscp` / `portable` | Official stable x86 6.5.7 ZIP matches publisher SHA-256. Preview, repeat install/remove, four-file ownership, executable signatures, unowned INI/registry-session preservation and exact owned-file recovery passed on Windows 11 and Server 2025 Desktop Experience. No application launch or Server Core support. | [Correlated acceptance](../archive/migrations/application-winscp-follow-up-2026-10-11.md#final-correlated-acceptance) |
| 2 | `InstallKAPE`, `RemoveKAPE` | Individual review: kape | Resolve applicable license/download terms and exact modules/targets. Current publisher clarification excludes third-party-network/paid-engagement use while allowing internal company use; retain this distinction in the corporate licensing review. Never add the legacy implicit Defender exclusion; acceptance requires a separate policy decision. | [Licensing watchlist and current publisher references](../package-licensing.md#important-to-review-licensing); [legacy publisher reference](https://s3.amazonaws.com/cyb-us-prd-kape/kape.zip) |
| 2 | `InstallVeraCrypt` | Individual review: veracrypt | Driver/reboot installation requires orchestrated reboot and retained-version recovery tests; ordinary EXE presence is insufficient. | [Legacy publisher reference](https://github.com/veracrypt/VeraCrypt) |
| 2 | `InstallVeraCryptPortable` | Individual review: veracryptportable | Portable self-extractor still loads a driver. Resolve driver ownership, cleanup/reboot and exact version recovery separately from file deployment. | [Legacy publisher reference](https://github.com/veracrypt/VeraCrypt) |
| 1 | `InstallADReplStatus`, `RemoveADReplStatus` | Individual review: adreplstatus | Latest-release endpoint returned HTTP 404, but the source repository remains available. Publisher describes an early personal rebuild targeting .NET Framework 4.8.1, not Microsoft support. Establish a licensed binary/build and domain-test prerequisites; do not infer retirement or substitute the expired original tool. | [Publisher README and dependency evidence](https://github.com/ryanries/ADReplStatus) |
| 2 | `InstallFirewallNotifier`, `RemoveFirewallNotifier` | Individual review: firewallnotifier | Latest-release lookup returned HTTP 404; publisher README still offers beta/nightly choices and says Server is not officially supported. Choose a pinned GPLv3 distribution and applicable target; capture/restore firewall policy before treating package presence as recovery. | [Publisher versions, requirements and support limits](https://github.com/wokhan/WFN) |
| 1 | `InstallWinDirStat`, `RemoveWinDirStat` | Previously migrated: `package.windirstat` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://windirstat.net/wds_current_setup.exe) |
| 1 | `InstallShareX`, `RemoveShareX` | Previously migrated: `package.sharex` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/sharex/sharex) |
| 2 | `InstallShareXportable`, `RemoveShareXportable` | Accepted migration: `package.sharex / portable` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/sharex/sharex) |
| 1 | `InstallPowerShell` | Previously migrated: `package.powershell` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/PowerShell/PowerShell) |
| 1 | `InstallAutomatedLab` | Individual review: automatedlab | Inspected machine MSI has ProductVersion 5.61.18 under release 5.61.0 and bundles Pester 5.7.1, PSFramework, SHiPS, transfer/logging and DSC modules. Define version/file collisions, dependency ownership and LabSources recovery; package-only versus host provisioning remains separate. No Hyper-V/remoting/trust action is implied. | [Exact MSI/component inspection](../archive/migrations/application-winscp-follow-up-2026-10-11.md#installed-candidates-requiring-review) |
| 1 | `DisableOneDrive`, `UninstallOneDrive`, `EnableOneDrive`, `InstallOneDrive` / OneDrive package | Individual review: onedrive | Separate OneDrive sync policy from installation/removal. Resolve built-in/updated edition and user data handling; saved settings and package state need distinct recovery. | Legacy function defines local Windows/application state; see source. |
| 1 | `DisableOneDrive`, `UninstallOneDrive`, `EnableOneDrive`, `InstallOneDrive` / OneDrive sync policy | Individual review: onedrive | Separate OneDrive sync policy from installation/removal. Resolve built-in/updated edition and user data handling; saved settings and package state need distinct recovery. | Legacy function defines local Windows/application state; see source. |
| 1 | `InstallOffice365` / Office deployment | Individual review: office365 | Q21 selects Microsoft 365 Apps for enterprise, Monthly Enterprise default/Current alternative, fresh x64/existing architecture match/explicit x86, and user sign-in with activation-pending continuation. Keep en-GB and reviewed additional/proofing intent. The [inert XML reviewer](#b10-inert-office-configuration-review-2026-10-17) exposes legacy removal/activation requests; exact versions, installed-product compatibility, terms and recovery remain open. | [ODT configuration reference](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/office-deployment-tool-configuration-options); [accepted Q21](decision-session-2026-10-17.md#q21-guided-officevisio-selection-and-separate-teams-actions) |
| 1 | `InstallOffice365` / Bundled Teams actions | Individual review: office365 | Q21 keeps Teams installation optional, existing startup unchanged, and old-version cleanup separately previewed with user data preserved. Office installation selects none implicitly. Exact distribution, detection, ownership and recovery remain pending. | [Accepted Teams boundary](decision-session-2026-10-17.md#q21-follow-up-optional-teams-installation-and-separate-cleanup) |
| 1 | `DisableTeamsAutoStart`, `ResetTeamsAutoStart` | Individual review: teamsautostart | Legacy Run/StartupApproved and classic Teams behavior differ from current Teams. Identify supported edition and exact preference restoration; do not delete application data. | Legacy function defines local Windows/application state; see source. |
| 1 | `RemoveTeamsStoreApp` | Individual review: teamsstoreapp | Resolve classic/current AppX identity and user/all-user/provisioned scope; add the applicable Windows component lifecycle and recovery. | Legacy function defines local Windows/application state; see source. |
| 1 | `RemoveTeamsWideInstaller` | Individual review: teamswideinstaller | Microsoft ended classic desktop support in 2024 and availability on 2025-07-01. Decide whether narrowly identified historical MSI cleanup remains useful or retire the outcome; resolve retained-artifact recovery and client/Outlook add-in ownership. Never substitute new Teams or reconnect legacy Win32_Product. | [Microsoft availability evidence](https://learn.microsoft.com/en-us/microsoftteams/teams-classic-client-end-of-availability); [exact legacy cleanup reconciliation](../archive/migrations/application-winscp-follow-up-2026-10-11.md#classic-teams-cleanup) |
| 1 | `InstallVisioPro` | Individual review: visiopro | Q21 retains separate Visio Professional 2016 Retail and Plan 2 choices, no automatic replacement/licence conversion. Plan 2 uses ODT and assigned-user sign-in; accepted display default is en-US with explicit da-DK, preserving Office en-GB and additional/proofing review. Existing-product/version/channel/architecture compatibility, 2016 support status, publisher route and recovery remain open. | [Accepted Visio/language choices](decision-session-2026-10-17.md#q21-follow-up-visio-en-us-default-with-explicit-danish-alternative); [inert review](#b10-inert-office-configuration-review-2026-10-17) |
| 2 | `GetSysinternalsSuite`, `RemoveSysinternalsSuite` | Source-ready pending candidates: whole reviewed Suite plus nine independent products | The 164-file Suite snapshot and complete official product archives are pinned with retained notices. Remaining member selection, native ownership/recovery and explicit tool/driver/EULA behavior remain partial. Existing installations are not adopted automatically. | [Suite inventory/candidate](#b11-sysinternals-reviewed-snapshot-candidate-2026-10-17); [latest individual product batch](#b11-sysinternals-command-line-candidates-2026-10-17) |
| 2 | `InstallJoeWare`, `RemoveJoeWare` | Individual review: joeware | Legacy crawls a changing tool collection. Select and license exact utilities; AdFind has publisher-documented AV interaction. No implicit exclusions. | [Legacy publisher reference](http://www.joeware.net/freetools/index.htm) |
| 2 | `InstallCCleaner`, `RemoveCCleaner` / CCleaner portable | Individual review: ccleaner | Four-product bundle must be split into CCleaner, Defraggler, Recuva and Speccy outcomes; select portable/installed artifacts and terms per product. | [Legacy publisher reference](https://www.ccleaner.com/ccleaner/download/portable) |
| 2 | `InstallCCleaner`, `RemoveCCleaner` / Defraggler | Individual review: ccleaner | Four-product bundle must be split into CCleaner, Defraggler, Recuva and Speccy outcomes; select portable/installed artifacts and terms per product. | [Legacy publisher reference](https://www.ccleaner.com/ccleaner/download/portable) |
| 2 | `InstallCCleaner`, `RemoveCCleaner` / Recuva | Individual review: ccleaner | Four-product bundle must be split into CCleaner, Defraggler, Recuva and Speccy outcomes; select portable/installed artifacts and terms per product. | [Legacy publisher reference](https://www.ccleaner.com/ccleaner/download/portable) |
| 2 | `InstallCCleaner`, `RemoveCCleaner` / Speccy | Individual review: ccleaner | Four-product bundle must be split into CCleaner, Defraggler, Recuva and Speccy outcomes; select portable/installed artifacts and terms per product. | [Legacy publisher reference](https://www.ccleaner.com/ccleaner/download/portable) |
| 2 | `InstallMitec`, `RemoveMitec` | Individual review: mitec | Legacy crawls changing EXE/ZIP links and filters trial/demo by filenames. Pin an explicit product list, versions and licenses; do not treat the whole website as one package. | [Legacy publisher reference](http://www.mitec.cz) |
| 2 | `InstallNtcore`, `RemoveNTCore` | Individual review: ntcore | Legacy downloads multiple linked EXE/ZIP artifacts. Identify intended tools, current versions and per-tool license/ownership; preserve independent outcomes. | [Legacy publisher reference](https://ntcore.com/?page_id=345) |
| 1 | `InstallTMOG`, `RemoveTMOG` | Individual review: tmog | Exact signed 1.0.1.0/Inno 6.7.0 payload includes notices and TMOG.scr with application/system destinations. Included free-edition license calls itself a release-candidate document requiring publisher approval and grants personal use; resolve applicable approved terms, unattended scope/screensaver controls and entitlement/configuration recovery. No activation or screen-saver execution. | [Current installer, license and component inspection](../archive/migrations/application-winscp-follow-up-2026-10-11.md#installed-candidates-requiring-review) |
| 1 | `InstallWireshark`, `RemoveWireshark` | Pending machine MSI candidate: `package.wireshark` | Q16 all-user install and separate association choice accepted. Official 4.6.9 MSI pinned with association components disabled; signature/hash and static tables verified. No supported targets. Separate interactive Npcap/admin-only capture and explicit compatibility-off default retained. Existing-installation transitions, global/user content, shared runtime, association preservation and recovery require disposable acceptance. | [Current candidate evidence](#b08-wireshark-machine-msi-candidate-2026-10-17); [historical NSIS analysis](../archive/migrations/application-installed-follow-up-2026-10-11.md#wireshark-silent-install-and-unowned-content-preparation) |
| 2 | `InstallZimmermanTools`, `RemoveZimmermanTools` | Reviewed membership accepted; pinned acquisition/helper integration pending | The decision session selects 26 members with compatible pinned maps/batch definitions and separate refresh preserving custom content. Replace the mutable execution/destructive-copy wrapper; retain useful updater intent. Immutable upstream-helper inspection, bounded failure tests and payload provenance remain pending under GitHub backoff. | [Accepted collection and helper review](decision-session-2026-10-17.md); [historical upstream source](https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1) |
| 2 | `InstallNirsoftLauncher`, `RemoveNirsoftLauncher` | Individual review: nirsoftlauncher | Collection uses 7z plus dynamic tools and package files. Define exact version/member inventory and safe bounded extraction; individual credential utilities need AV review. | [Legacy publisher reference](https://launcher.nirsoft.net/downloads/index.html) |
| 2 | `InstallNirsoftToolsX64`, `RemoveNirsoftToolsX64` | Individual review: nirsofttoolsx64 | Dynamic x64 collection needs exact utility/version/license inventory and notices. Publisher documents AV alerts for some tools; no broad exclusion. | [Legacy publisher reference](https://www.nirsoft.net/x64_download_package.html) |
| 2 | `InstallNirsoftPkgFiles`, `RemoveNirsoftPkgFiles` | Individual review: nirsoftpkgfiles | Package/config files belong to the launcher integration outcome. Pin revision and capture existing configuration before replacing or removing files. | [Legacy publisher reference](https://launcher.nirsoft.net/downloads/index.html) |
| 2 | `InstallArsenalRecon` / Arsenal products | Individual review: arsenalrecon | Legacy crawls MEGA links and also installs MEGAcmd. Select actual Arsenal products, licensed distribution, drivers and VM/AV side effects; account for MEGAcmd separately. | [Legacy publisher reference](https://mega.nz/MEGAcmdSetup64.exe) |
| 2 | `InstallArsenalRecon` / MEGAcmd helper | Individual review: arsenalrecon | Legacy crawls MEGA links and also installs MEGAcmd. Select actual Arsenal products, licensed distribution, drivers and VM/AV side effects; account for MEGAcmd separately. | [Legacy publisher reference](https://mega.nz/MEGAcmdSetup64.exe) |
| 1 | `InstallWinget` | Individual review: winget | App Installer MSIX plus dependencies needs AppX lifecycle, minimum OS and per-user/provisioned scope. Do not substitute an EXE package or enable updates implicitly. | [Legacy publisher reference](https://aka.ms/getwinget) |
| 1 | `InstallWingetAutoUpdate` | Individual review: wingetautoupdate | Automatic maintenance changes tasks/service/configuration beyond package presence. Declare update policy and capture each reversible component before admission. | [Legacy publisher reference](https://github.com/Romanitho/Winget-AutoUpdate) |
| 1 | `InstallRSAT`, `RemoveRSAT` | Individual review: rsat | Windows capabilities on client and features on Server differ. Use a Windows-component handler with edition/build applicability and exact feature-state recovery. | Legacy function defines local Windows/application state; see source. |
| 1 | `InstallOpenJDK` | Individual review: openjdk | Legacy selects Microsoft JDK 11 x64 MSI with PATH, JAVA_HOME and .jar associations. Current publisher roadmap lists earliest end of support September 2027, so no retirement or Java-major substitution is justified. Pin the current update/source; capture environment and association state. Microsoft requires one installation method per JDK major and uninstall before MSI/EXE conversion; inspect existing editions and preserve the method during recovery. | [Publisher downloads](https://learn.microsoft.com/en-us/java/openjdk/download); [current JDK 11 roadmap](https://learn.microsoft.com/en-us/java/openjdk/support); [method/features constraint](https://learn.microsoft.com/en-us/java/openjdk/install) |
| 1 | `InstallNeo4j` | Deferred by Q20 pending an independent use case: neo4j | Corrected source reading 2026-10-12: legacy downloads a Neo4j Community Windows ZIP and a separate APOC JAR, replaces the Tools destination, enables unrestricted apoc.* procedures, and installs/starts a service. It does not use APOC as a Neo4j installer. Retain deferred scope until an independent server/plugin use case is identified; verify exact Neo4j/APOC/Java compatibility and preserve database/configuration/credentials/service state. Broad procedure permissions and directory replacement are not implicitly approved. | [Legacy selector](../../legacy/v2/lib-windows.psm1); [legacy APOC publisher](https://github.com/neo4j-contrib/neo4j-apoc-procedures); [corrected contract](application-review-rounds-2026-10-12.md#corrected-neo4j-legacy-contract) |
| 2 | `GetBloodhound`, `RemoveBloodhound` | Individual review: bloodhound | User confirmed current Community Edition preparation with container deployment reviewed separately on 2026-10-12. This changes the legacy desktop distribution; implementation/data migration and target applicability remain unaccepted. Choose supported host/runtime, images, backend configuration, data/credentials/network ownership and recovery. No automatic Docker/WSL provisioning; Docker Desktop does not support Windows Server. | [Confirmed R03 preparation](application-review-rounds-2026-10-12.md#r03-preparation-review-2026-10-12); [current publisher deployment](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart); [legacy publisher reference](https://github.com/BloodHoundAD/BloodHound) |
| 2 | `GetSharphound`, `RemoveSharphound` | Individual review: sharphound | User confirmed retaining optional SharpHound for AD, matched to the chosen backend, on 2026-10-12. Inspect exact stable publisher binary/source, license/notices and scoped ownership; publisher directs compatible CE version selection through the backend. Legacy references older repository collectors; record distribution changes explicitly. No collection or service configuration is implied. | [Confirmed R03 preparation](application-review-rounds-2026-10-12.md#r03-preparation-review-2026-10-12); [current publisher/version contract](https://github.com/SpecterOps/SharpHound); [legacy publisher reference](https://github.com/BloodHoundAD/SharpHound) |
| 2 | `GetAzurehound`, `RemoveAzurehound` | Individual review: azurehound | User confirmed retaining optional AzureHound for Entra/Azure, matched to the chosen backend, on 2026-10-12. Legacy mixes release assets and a raw PowerShell collector; resolve the exact stable distribution/dependencies and record any replacement explicitly. Stable v3.1.2 x64 archive and checksum were inspected on 2026-10-17; the ZIP contains only an unsigned executable, with GPL-3.0-or-later license/notices retained separately. See the [artifact record](#b08-azurehound-stable-artifact-preparation-2026-10-17). Backend version matching and companion-notice ownership precede catalog admission; no collection, authentication or service setup is implied. | [Confirmed R03 preparation](application-review-rounds-2026-10-12.md#r03-preparation-review-2026-10-12); [current publisher distributions](https://github.com/SpecterOps/AzureHound); [legacy publisher reference](https://github.com/BloodHoundAD/AzureHound) |
| 2 | `GetImproHound`, `RemoveImprohound` | Retired by explicit user decision, 2026-10-17: planned ImproHound deployment | Q20 closes the planned deployment outcome. Preserve existing installation, license and data; do not uninstall or adopt. BloodHound CE is not asserted to replace its historical tiering-analysis workflow. | [Accepted retirement](#accepted-volatility-2-and-improhound-retirements-2026-10-17); [historical role/dependency review](../archive/migrations/application-winscp-follow-up-2026-10-11.md#improhound-role-and-dependency-reconciliation) |
| 2 | `GetPingCastle`, `RemovePingCastle` | Individual review: pingcastle | Review current license and supported distribution, pin exact edition and verify executable/dependency compatibility before deployment. | [Legacy publisher reference](https://github.com/vletoux/pingcastle) |
| 1 | `InstallVirtIOGuestTool` | Individual review: virtioguesttool | QEMU VirtIO guest drivers are inappropriate for the current Hyper-V acceptance VMs. Test on a matching disposable guest with driver/reboot recovery. | [Legacy publisher reference](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio) |
| 1 | `InstallSpiceGuestTool` | Individual review: spiceguesttool | SPICE drivers/agent require a matching QEMU/SPICE guest. Hyper-V tests cannot establish driver applicability or recovery. | [Legacy publisher reference](https://spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe) |
| 1 | `InstallSpiceWebDAV` | Individual review: spicewebdav | WebDAV daemon requires SPICE transport and service recovery. Use a matching guest; installation on Hyper-V alone is not acceptance. | [Legacy publisher reference](https://spice-space.org/download/windows/spice-webdavd/spice-webdavd-x64-latest.msi) |
| 1 | `DisableEdgePagePrediction` | Individual review: edgepageprediction | Microsoft ended Edge Legacy support on 2021-03-09. Review retirement of the old EdgeHTML outcome or explicitly choose a current policy; NetworkPredictionOptions is a different mapping, not an implicit replacement. No setting acceptance is inferred. | [Microsoft lifecycle evidence](https://learn.microsoft.com/en-us/lifecycle/announcements/edge-legacy-eos-details); [current policy reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/networkpredictionoptions); [legacy third-party explanation](https://www.kapilarya.com/how-to-enable-disable-page-prediction-in-microsoft-edge) |
| 1 | `InstallFirefox`, `RemoveFirefox` | Accepted migration: `package.firefox` | Preview, install/repeat/remove and restoration of original absence passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; application behavior and prior-version recovery remain separate limits. | [Legacy publisher reference](https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US) |
| 2 | `CreateFirefoxPreferenceFiles`, `RemoveFirefoxPreferenceFiles` | Individual review: firefoxpreferencefiles | Legacy deploys prefs.js and search data. Choose enterprise policy versus user-file intent, pin data and capture/restore existing profile files. | [Legacy publisher reference](https://developer.mozilla.org/en-US/Firefox/Enterprise_deployment) |
| 1 | `InstallChrome`, `RemoveChrome` | Accepted migration: `package.chrome` | Retains the legacy all-user enterprise stable x64 MSI. Version 155.0.8059.40 has an inspected SHA-256 pin and valid Google LLC signature. Profile-preserving installation/removal/repeat and compensating recovery passed on Windows 11 and Server 2025 Desktop Experience; browser-policy and language overrides remain separate. | [Correlated acceptance](../archive/migrations/application-installed-follow-up-2026-10-11.md#final-correlated-acceptance); [enterprise distribution](https://chromeenterprise.google/download/); [official MSI source](https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi) |
| 2 | `CreateChromePreferenceFile`, `RemoveChromePreferenceFile` | Individual review: chromepreferencefile | Legacy writes preferences from obsolete Chromium source mappings. Reconcile each current policy/key and capture existing profile data before deployment. | [Legacy publisher reference](https://src.chromium.org/viewvc/chrome/trunk/src/chrome/common/pref_names.cc) |
| 1 | `InstallOpera` | Excluded by user: Opera | User trust-policy decision on 2026-10-11: remove from the repository and future migration scope. Legacy installer/preset entry removed; no v3 package or remaining product choice. Historical selector retained solely for accounting. | [Dated exclusion](../archive/migrations/application-winscp-follow-up-2026-10-11.md#opera-exclusion-by-user-decision) |
| 1 | `InstallAutopsy` | Accepted migration: `package.autopsy` | Preview, install/repeat/remove and restoration of original absence passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; application behavior and prior-version recovery remain separate limits. | [Legacy publisher reference](https://github.com/sleuthkit/autopsy) |
| 2 | `InstallNetworkMiner`, `RemoveNetworkMiner` | Accepted migration: `package.networkminer` | Fixed-version free edition 3.2 matches publisher page SHA-256; whole nested distribution and notices retained. Preview, repeat install/remove, preservation and exact owned-file restore passed on Windows 11 and Server 2025 Desktop Experience. Runtime/forensic analysis remains separate acceptance. See continuation evidence. | [Current fixed-version distribution and checksum](https://www.netresec.com/?page=NetworkMiner); [GPLv2 reference](https://www.netresec.com/?page=NetworkMinerSourceCode) |
| 2 | `InstallAutorunner`, `RemoveAutorunner` | Individual review: autorunner | Latest-release endpoint returned HTTP 404, but source/README remain available. Publisher requires x64/.NET Framework 4.7.2 and describes privileged forensic-image access and a Sigcheck dependency. Establish a licensed binary/build, pin dependencies and keep deployment separate from investigation execution. | [Publisher README and dependency evidence](https://github.com/woanware/autorunner) |
| 2 | `InstallChainsaw`, `RemoveChainsaw` | Accepted migration: `package.chainsaw` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/WithSecureLabs/chainsaw) |
| 2 | `GetChromeParser`, `RemoveChromeParser` | Individual review: chromeparser | Pending package.chromeparser retains the complete pinned source/README/MIT archive. Python 3.12.14 syntax parsing passed without execution; interpreter, historical SQLite schema, input protection and native lifecycle acceptance remain open. See the [source batch](#b08-pinned-python-source-candidates-2026-10-16). | [Legacy publisher reference](https://raw.githubusercontent.com/marleyjaffe/ChromeSyncParser/master/ChromeParser.py) |
| 2 | `InstallCyLR`, `RemoveCyLR` | Accepted migration: `package.cylr` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/orlikoski/CyLR) |
| 2 | `InstallDejsonlz4`, `RemoveDejsonlz4` | Accepted migration: `package.dejsonlz4` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/avih/dejsonlz4) |
| 2 | `GetHex2text`, `RemoveHex2text` | Individual review: hex2text | Pending package.hex2text retains the pinned script/README/GPLv3 archive. Python 3.12.14 syntax parsing passed without execution; four-digit-group conversion/input behavior and native lifecycle acceptance remain open. No implicit interpreter install; see the [source batch](#b08-pinned-python-source-candidates-2026-10-16). | [Legacy publisher reference](https://raw.githubusercontent.com/gh05t-4/hex2text/master/hex2text.py) |
| 2 | `InstallHindsight`, `RemoveHindsight` | Accepted migration: `package.hindsight` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/obsidianforensics/hindsight) |
| 1 | `InstallSqlitebrowser` | Accepted migration: `package.sqlitebrowser` | Preview, install/repeat/remove and restoration of original absence passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; application behavior and prior-version recovery remain separate limits. | [Legacy publisher reference](https://download.sqlitebrowser.org) |
| 2 | `GetShimCacheParser`, `RemoveShimCacheParser` | Individual review: shimcacheparser | Pinned publisher revision c4772b9dc72fd50ba210b7b0636c2d20bea68bc5 still uses Python 2 exception/print syntax and cStringIO; Python 3.12.14 AST parsing rejects it. Retain Apache-2.0 source evidence and defer interpreter/port/retirement choice; no obsolete runtime installed. Current registry-format correctness remains separate. See the [source review](#b08-pinned-python-source-candidates-2026-10-16). | [Legacy publisher reference](https://raw.githubusercontent.com/mandiant/ShimCacheParser/master/ShimCacheParser.py) |
| 1 | `GetPSTViewer` | Individual review: pstviewer | Exact signed free 20.3 installer is identified and hashed. Included EULA still uses licensed-copy terms without an explicit freeware grant; resolve applicable terms and shared RICHTX32.OCX registration/ownership/recovery before admission. | [Exact installer, terms and dependency evidence](../archive/migrations/application-winscp-follow-up-2026-10-11.md#installed-candidates-requiring-review) |
| 1 | `GetOSTViewer` | Individual review: ostviewer | Exact signed free 21.1 installer is identified and hashed. Included EULA still uses licensed-copy terms without an explicit freeware grant; resolve applicable terms and shared RICHTX32.OCX registration/ownership/recovery before admission. | [Exact installer, terms and dependency evidence](../archive/migrations/application-winscp-follow-up-2026-10-11.md#installed-candidates-requiring-review) |
| 2 | `InstallLoki`, `RemoveLoki` | Individual review: loki | Current release includes scanner/signature update behavior. Define exact rules, updates and runtime dependencies; no execution or implicit Defender exclusions. | [Legacy publisher reference](https://github.com/Neo23x0/Loki) |
| 2 | `InstallSSView`, `RemoveSSView` | Individual review: ssview | Publisher distinguishes non-commercial freeware from paid commercial/Professional use. Choose intended edition and applicable terms, inspect exact ZIP version/members and pin its hash before lifecycle acceptance. No local/company license approval is inferred from research. | [Publisher features, edition and license terms](https://www.mitec.cz/ssv.html) |
| 2 | `InstallSrumMonkey`, `RemoveSrumMonkey` | Accepted migration: `package.srum-monkey` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/devgc/SrumMonkey) |
| 2 | `InstallSrumDump`, `RemoveSrumDump` | Accepted migration: `package.srum-dump` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/MarkBaggett/srum-dump) |
| 2 | `InstallThumbcacheviewer`, `RemoveThumbcacheviewer` | Individual review: thumbcacheviewer | Publisher site offers GUI 1.0.4.0 x86/x64 and CMD 1.0.2.1, but declares Visual C++ 2008 runtime dependency. Microsoft ended general v90 support in 2018; product-specific exceptions do not establish support for this tool. Choose reviewed binary/license/runtime or rebuild; no implicit obsolete dependency installation. | [Publisher binaries and requirements](https://thumbcacheviewer.github.io/); [Microsoft runtime lifecycle](https://learn.microsoft.com/en-us/lifecycle/faq/visual-c-faq) |
| 2 | `InstallSuperFetchTools2`, `RemoveSuperFetchTools2` | Individual review: superfetchtools2 | 2026-10-16: the official product page still advertises 2.2.0.0, but its linked legacy archive returns HTTP 404. No artifact acquired or mirror selected. Current-build compatibility, dependencies and bundled notices remain unverified; see the [deferred-source record](#b08-deferred-tool-source-checks-2026-10-16). | [Legacy publisher reference](https://www.tmurgent.com/download/SuperFetch_Tools2.zip) |
| 2 | `InstallUserAssist`, `RemoveUserAssist` | Individual review: userassist | Official 2.6.0 archive matches published SHA-256 F6F73F4E00905A7727ED4136DE875DD1FBCF4B90FFEE4B93D4A46E58C0314D45. Source declares public-domain dedication and targets .NET 2.0; includes separate x64/AnyCPU Debug/Release and development host executables. Choose one Release distribution and establish explicit .NET 3.5 prerequisites without silently enabling Windows components. Publisher only declares through experimental Windows 8; modern format/runtime acceptance is separate. | [Exact publisher release/checksum](https://blog.didierstevens.com/2012/07/19/userassist-windows-2000-thru-windows-8/); [runtime requirement](https://blog.didierstevens.com/programs/userassist/); [current Microsoft prerequisite routes](https://learn.microsoft.com/en-us/dotnet/framework/install/dotnet-35-windows-11) |
| 2 | `InstallThumbsviewer`, `RemoveThumbsviewer` | Individual review: thumbsviewer | Publisher site offers 1.0.3.1 x86/x64 but requires Visual C++ 2008 runtime. Microsoft ended general v90 support in 2018; exceptions for Microsoft products do not establish this application's runtime support. Choose reviewed binary/license/runtime or rebuild; do not silently install the obsolete dependency or retire the product. | [Publisher binaries and requirements](https://thumbsviewer.github.io/); [Microsoft runtime lifecycle](https://learn.microsoft.com/en-us/lifecycle/faq/visual-c-faq) |
| 2 | `InstallRegRipper`, `RemoveRegRipper` | Individual review: regripper | Pending package.regripper now stages the complete pinned 3.0 archive, including runtime and plugins; custom data preservation and exact recovery have inert-fixture evidence. Native Windows 11, runtime and parser acceptance remain open. RegRipper4.0 has different terms and is not substituted; see the [2026-10-16 record](#b08-regripper-30-distribution-candidate-2026-10-16). | [Legacy publisher reference](https://github.com/keydet89/RegRipper3.0/raw/master/rr.exe) |
| 2 | `InstallWinhex`, `RemoveWinhex` | Individual review: winhex | Legacy HTTP archive and licensed edition need official HTTPS source, terms and version evidence; no unlocked or substitute distribution. | [Legacy publisher reference](http://www.x-ways.net/winhex.zip) |
| 2 | `InstallWinPmem`, `RemoveWinPmem` | Individual review: winpmem | Memory acquisition loads a kernel driver. Review signing, Secure Boot/current-build support and exact driver unload/reboot recovery before execution. | [Legacy publisher reference](https://github.com/Velocidex/WinPmem) |
| 2 | `InstallVolatility2`, `RemoveVolatility2` | Retired by explicit user decision, 2026-10-17: planned Volatility 2 deployment | Q17 closes this planned deployment outcome. Preserve existing installations, runtime and data; do not uninstall, adopt or replace them. Volatility 3 remains separately selected with its own runtime/plugin requirements; no universal workflow equivalence is claimed. | [Accepted retirement](#accepted-volatility-2-and-improhound-retirements-2026-10-17); [historical R02/source review](application-review-rounds-2026-10-12.md#r02-preparation-review-2026-10-12) |
| 2 | `InstallVolatility3` | Individual review: volatility3 | User confirmed a managed pinned release with an isolated Python environment and core plus broader plugin dependencies on 2026-10-12. Inspected 2.28.2 declares Python >=3.8, pefile >=2024.8.26 and a full plugin extra under VSL-1.0; verify the selected release/interpreter/dependency matrix rather than assuming all later-interpreter compatibility. Cloud/development extras and driver/acquisition execution remain separate. Define scope, symbols/caches, updates and environment recovery; preserve license and user plugins. Existing bounded ZIP deployment can serve a reviewed pinned archive; no global pip install or executable-edition substitution. | [Confirmed preparation](application-review-rounds-2026-10-12.md#r02-preparation-review-2026-10-12); [publisher release](https://github.com/volatilityfoundation/volatility3/releases/tag/v2.28.2); [exact release requirements](https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/pyproject.toml); [exact license](https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/LICENSE.txt) |
| 2 | `InstallPartDiagParser`, `RemovePartDiagParser` | Individual review: partdiagparser | Latest-release lookup returned HTTP 404 but legacy uses a repository zipball. Verify repository revision, license and script runtime before admission. | [Legacy publisher reference](https://github.com/theAtropos4n6/Partition-4DiagnosticParser) |
| 2 | `InstallGglCookieCruncher`, `RemoveGglCookieCruncher` | Individual review: gglcookiecruncher | Latest-release lookup returned HTTP 404 but legacy uses a repository zipball. Verify current repository, pinned revision, license and runtime. | [Legacy publisher reference](https://github.com/mdegrazia/Google-Analytic-Cookie-Cruncher) |
| 2 | `InstallSigma`, `RemoveSigma` | Individual review: sigma | Rule repository clone is a dynamic data collection, not one executable. Pin rules revision/license, retain user rules and define explicit tooling dependencies. | [Legacy publisher reference](https://github.com/SigmaHQ/sigma) |
| 2 | `InstallHashcat`, `RemoveHashcat` | Individual review: hashcat | Official 7.1.2 release is a 7z archive. Add bounded 7z extraction and GPU/runtime applicability tests; no driver install or cracking execution implied. | [Legacy publisher reference](https://hashcat.net) |
| 2 | `InstallHashcatLauncher`, `RemoveHashcatLauncher` | Individual review: hashcatlauncher | Legacy latest-release endpoint returned HTTP 404. Verify maintained launcher release and Hashcat-version compatibility before admitting the pair. | [Legacy publisher reference](https://github.com/s77rt/hashcat.launcher) |
| 1 | `InstallLenovoVantage`, `RemoveLenovoVantage` | Individual review: lenovovantage | Store/OEM hardware-specific deployment needs AppX identity, Lenovo service dependencies and matching hardware applicability; Hyper-V is unavailable for hardware acceptance. | [Legacy publisher reference](https://www.lenovo.com/) |

## Accounting and acceptance

Inventory: 175 exact selector names, 109 outcomes/components (45 in batch 1, 64 in batch 2), including existing migrations, adjacent settings and the OEM pair outside the preset. The CCleaner bundle counts four products; Arsenal/MEGAcmd and Office/Teams count omitted components independently. These totals are reconciliation units, not newly accepted migrations.

Accepted application migrations: six installed products and twelve portable outcomes, with ShareX retaining its published product ID and installed default. The nested Chainsaw executable and licence are required; Hindsight retains the legacy GUI executable. CyLR and dejsonlz4 retain x86 distributions after inspection of official archives. SRUM Dump corrects the legacy install/remove folder-name mismatch through one stable product ID. The portable continuation adds Caffeine's mixed-architecture archive and NetworkMiner's free edition; the installed continuation adds machine Chrome and current-user Signal with explicit profile-preservation acceptance.

GitHub anonymous API throttling was observed during research. HTTP 404 at a latest-release endpoint does not prove repository removal or justify retirement. No product was silently substituted, no collector/scanner was run and no Defender exclusion was added.

Detailed target results, native verification and checkpoint recovery are recorded
in the [dated batch acceptance record](../archive/migrations/applications-batch-acceptance-2026-10-11.md).
Pending distributions declare candidate targets only; production execution has
no supported target until the applicable lifecycle evidence passes.

Batch 2 accepted nine portable distributions on both targets, with recovery and
207 passing guest Pester checks per target. Batch 1 accepted all four installed
outcomes on both targets, with recovery and
211 passing guest Pester checks per target. The continuation reran all eleven
portable distributions successfully on each target, with 212 passing guest
checks and confirmed checkpoint recovery. The installed continuation passed all
six scenarios and 224 guest checks on each target, including Chrome/Signal
profile preservation and compensating recovery. Ten earlier migrations,
nineteen newly accepted outcomes,
79 individual review items and one user-policy exclusion complete the 109-item ledger. See the
[portable continuation](../archive/migrations/application-follow-up-2026-10-11.md) and
[installed acceptance record](../archive/migrations/application-installed-follow-up-2026-10-11.md).

The WinSCP continuation accepts a twelfth portable distribution on both targets,
with 230 guest checks and twelve portable lifecycles per target. Installed viewer terms/shared
components, AutomatedLab bundled-module ownership and TMOG screensaver controls
are recorded with exact inspection evidence in the
[WinSCP follow-up](../archive/migrations/application-winscp-follow-up-2026-10-11.md).

The [Thunderbird continuation](../archive/migrations/application-thunderbird-follow-up-2026-10-11.md#accepted-migration-after-resumed-validation)
accepts a seventh installed distribution on both targets, with 242 guest checks
and seven installed lifecycles per target. The temporary standard account's
batch-logon permission, task and account were removed before checkpoint recovery.
An elevated controller refresh remains an infrastructure review item: deploy
the locked-file collector fix and synchronize Windows 11's scratch-directory
exclusion. This does not change the 79 unresolved application outcomes.

## B08 Rufus portable source candidate, 2026-10-16

Source f53ce6ab102a plus the overnight patch. The user's resumed package scope
permits preparation of the separately requested v3 Rufus addition. This is not a
legacy selector or an extra completed legacy outcome. RIDE maintainers own the
pending candidate and source checks; disposable target and operator acceptance
remain separate. The [operator contract](../application-packages.md#rufus-portable-candidate)
describes the chosen x64 portable distribution and recovery boundary.

Official [product page](https://rufus.ie/en/) and
[release](https://github.com/pbatard/rufus/releases/tag/v4.15) identify 4.15 portable
x64. Direct publisher acquisition retained 1,989,992 bytes with SHA-256
84c8a437f8af89257524478489e5c85f1edf25f761d299e2bcde46ac0afbe106,
file/product version 4.15.2396 and Valid Akeo Consulting Authenticode signature.
The [sanitized observation](../archive/evidence/rufus-portable-source-review-2026-10-16.json)
retains exact source, UTC time and certificate evidence. The hash is locally
observed, not publisher-published. Initial sandbox DNS failed; the authorized
network-enabled retry acquired the same official URL. No API polling, mirror,
installer execution, registry edit or USB access was used.

The existing File portable handler stages only rufusp.exe, keeping the publisher's
filename-based portable-mode trigger. The unmodified file retains embedded notices.
RIDE does not own rufus.ini/logs/downloaded images, create shortcuts or configure
media. Its removal/restore owns only the executable/manifest. Modified binaries
refuse overwrite and are preserved on removal. Running Rufus may create configuration
and registry state; those and media writes are outside file recovery. No shared
license approval is recorded. Existing deployment identity/state schemas unchanged.

PendingAcceptance is true, SupportedTargets empty and CandidateTargets Windows 11;
no profile inclusion or Server support. The supplemental MigrationBatch label is
not consumed by the existing all-products VM batches. A focused disposable test
must explicitly admit only this candidate rather than rerun unrelated applications.

Validation on native Windows PowerShell 5.1.26100.9711 and 7.6.5: four Rufus-specific
inert-file tests plus existing application/catalog tests, **153 passed per edition,
zero failures/skips, one WindowsIntegration excluded**. Tests preserve settings/logs,
refuse adoption/modified content, repeat and restore retained bytes. Initial catalog
tests caught missing CandidateTargets; adding the explicit pending target corrected
the metadata and both full focused runs passed. Repository validation passed on both:
341 operations, eight groups, five profiles, 153 PowerShell files. Generated reference
current; CLI download WhatIf passed without acquisition. No production activation.

Recovery: remove only this candidate and focused docs/test/evidence, regenerate
OPERATIONS and preserve other edits. Retain local reviewed bytes for subsequent
acceptance. After future staging, saved-run file restore requires intact retained
backups and cannot undo application execution or media writes. Next acceptance:
isolated Windows 11 preview/stage/repeat/remove/restore, exact hash/signature, user
config preservation and separately authorized GUI/config writable-path evidence;
do not format media merely to prove package lifecycle.

Resolved: Rufus source candidate and file-boundary tests. Retired/excluded: none.
Partial: requested addition; legacy application dispositions unchanged. Deferred:
native target/GUI acceptance and outstanding installed/portable coexistence/kit
decisions. All five ranges reviewed and unchanged: 38-58 settings, 58-73 packages,
20-25 components, 25-35 accounts/assets, 8-12 actions; rounded 150-205/about 180.
Rufus is outside the legacy counts and has no complete runtime acceptance. Continue
with the complete RegRipper distribution review; postpone WFN prerelease/runtime
selection rather than silently choosing nightly or an unsupported runtime.

## B08 RegRipper 3.0 distribution candidate, 2026-10-16

Source f53ce6ab102a plus the overnight patch. The authorized package continuation
adds pending package.regripper, preserving the legacy 3.0 product line. This is
source preparation for one unresolved legacy outcome, not native acceptance.
The [operator contract](../application-packages.md#regripper-30-portable-candidate)
defines complete distribution ownership, custom plugin preservation and recovery.

The official RegRipper3.0 repository resolved to commit
ec96dd4a6a5c3ea70d8fece9b47a374f83582335. Its exact archive contains 5,216,266 bytes,
285 entries and 282 files, including 266 plugin/profile files. Observed SHA-256:
a1a13f6742990ca413e1763b90176d22ed4a9d663c4b37cb3f66e46f296acb43.
The [sanitized source evidence](../archive/evidence/regripper-source-review-2026-10-16.json)
retains all member hashes, binary metadata and exact source; this is an observed
pin, not a publisher checksum. rr.exe, rip.exe and p2x5124.dll are x86 and NotSigned.
No downloaded code, parser, nested archive or registry hive was executed/read.

The complete pinned archive replaces the legacy rr.exe-only download boundary.
Twelve required members cover both executables, runtime, licenses, README and
representative plugin/profile files; the handler owns every extracted file, not
only that minimum. The commit-named root is retained. Unowned analyst plugins
and reports survive removal/restore; modified bundled files refuse replacement
and are preserved on removal. Upgrading revisions can leave custom data under
the old root, requiring explicit operator migration. No Perl/Python installation,
file association or automatic plugin execution. Existing snapshot schema unchanged.

The 3.0 project declares MIT; upstream notices and bundled runtime provenance
are retained. RegRipper4.0 has different personal/academic-use and distribution
restrictions and is not substituted. Its separate review is recorded in the
[licensing watchlist](../package-licensing.md). No individual/company approval
is stored in catalog or shared evidence. WFN remains deferred: its published
prerelease/runtime choices require selection; no nightly is silently admitted.

PendingAcceptance is true, SupportedTargets empty and CandidateTargets Windows 11.
IndividualPortableReview is separate from automatic existing VM batches. No
recommended profile, supported Server claim or application execution is added.

Validation: native Windows PowerShell 5.1.26100.9711 passed 74 focused tests with
zero failures (one integration test excluded). PowerShell 7.6.5 passed all 70
selected catalog tests; its first corrected combined run passed 73/74 with an
IOException during atomic fixture-manifest replacement. A sequential rerun of
all four product tests passed 4/4 without handler changes. The transient I/O
failure remains evidence, not a reason to claim a clean combined run. Initial
test setup also exposed a missing compression assembly on 5.1 and an incorrect
snapshot-backup field assumption; both fixtures were corrected. Both editions
passed repository validation: 342 operations, eight groups, five profiles and
154 PowerShell files. Tests use inert archive members only. Native runtime,
forensic parsing, transaction-log handling and GUI acceptance remain deferred.

Recovery: remove the pending declaration and focused additions, regenerate the
catalog reference and retain other work. Future staged recovery requires intact
owned-file backups and cannot undo parser execution or changes to analyst data.
Next acceptance: explicitly scoped disposable Windows 11 preview/stage/repeat/
remove/restore, retained notices/runtime evidence, custom plugin/report retention
and separately reviewed synthetic-hive/parser behavior. Do not auto-select an
obsolete dependency to make an application start.

Resolved: complete pinned 3.0 source distribution and inert ownership tests.
Retired/excluded: none. Partial: one legacy RegRipper outcome remains open.
Deferred: native/runtime/parser acceptance, RegRipper4.0 terms and WFN selection.
Settings, components, accounts and maintenance gain no new acceptance. All five
ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12; rounded 150-205/about 180.
Source readiness does not reduce outstanding legacy acceptance estimates.
Continue independent source batches; postpone questions Q01-Q31 until input.

## B08 pinned Python source candidates, 2026-10-16

Source f53ce6ab102a plus the overnight patch. The authorized continuation adds
pending package.hex2text and package.chromeparser as complete source archives,
not runnable application acceptance. Each has exactly three required owned files:
script, README and upstream license. No interpreter, association, PATH change,
source execution, database scan or evidence read. The [operator contract](../application-packages.md#pinned-python-source-candidates)
owns usage limits and recovery; [sanitized evidence](../archive/evidence/python-script-source-review-2026-10-16.json)
retains exact revisions/URLs, archive and member hashes, raw-source agreement and
syntax-only observations without personal paths or license approvals.

Hex2text revision 9715c6c26824ef05039228f16e0c47620c52fe79: archive 13,331 bytes,
observed SHA-256 aa0083da094a3320db9a97eb22c499a420187c208ed92376a662243678f083c3,
GNU GPL v3. Its fixed script converts complete four-hex-digit groups after removing
literal spaces; incomplete trailing groups are ignored. Input/Unicode behavior
must be accepted explicitly rather than described as a general UTF-8 decoder.
ChromeSyncParser revision 0f59c5702ffd03102c550ecc373ab4fefa6f810c: archive 9,305
bytes, observed SHA-256 8dff59a48d3d6ab41cf8d39154a0e05cfda5df36a1b76180a70692762854da46,
MIT. It imports standard-library modules including sqlite3, opens ordinary
connections and assumes historical SyncData/metas schema. Modern Chrome support,
forensic read-only handling and correct output are not established by acquisition.
Both sources parsed under isolated Python 3.12.14 AST inspection, without executing
or importing downloaded code. No general minimum-version claim is inferred.

ShimCacheParser remains deferred. Exact upstream revision
c4772b9dc72fd50ba210b7b0636c2d20bea68bc5 retains Apache-2.0 and Python 2 constructs;
Python 3.12.14 rejects exception syntax at line 148. cStringIO and legacy print
statements further demonstrate the port/runtime gap. README.md returned 404 at
the pinned path; this does not establish repository or product removal. No
Python 2 install, automatic port, alternate parser or retirement was selected.

Both new candidates use neutral Portable ZIP staging, Windows 11 CandidateTargets,
empty SupportedTargets, PendingAcceptance and no profile selection. Every source
and notice is owned and retained. Commit-named roots remain intact. Inert tests
refuse legacy script-only payloads, preserve unowned analyst output, repeat staging,
restore retained bytes and preserve/refuse replacement of modified owned scripts.
All eight product cases plus 70 catalog cases passed on each native PowerShell
edition: 78 passed, zero failures/skips, one integration exclusion. Both editions
passed validation: 346 operations/eight groups/five profiles/156 PowerShell files.
Generated reference is current. An initial scratch insertion expanded JavaScript
replacement syntax inside a regex value and was rejected by the catalog parser;
the exact insertion boundary was repaired before tests. Whole-catalog comparison
against the pre-overnight snapshot confirms only six pending additions and four
reviewed presentation blocks, with all other original fields/groups unchanged.

Next acceptance: isolated Windows 11 preview/stage/repeat/remove/restore with
notice/hash and analyst-file preservation checks; separately select a Python
runtime and test harmless synthetic inputs, invalid input and intended output.
For ChromeSyncParser use disposable copied/synthetic databases, never live browser
or original evidence data. Exact file recovery does not undo script execution or
data writes. Source recovery removes only these pending entries/tests/docs/evidence
and regenerates the reference, preserving other work; future runtime file restore
requires intact owned backups. No new saved-state schema or release is introduced.

Resolved: source/integrity/license packaging and inert ownership for two partial
legacy products; Python 2 blocker made concrete for a third. Retired/excluded:
none. Deferred: native/interpreter/functional acceptance and ShimCacheParser choice.
All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180. None of these partial products closes a legacy outcome, and no other group
gains runtime evidence. Continue independent batches without awaiting approval.

## B08 deferred tool source checks, 2026-10-16

SuperFetch Tools remains deferred: its official page advertises 2.2.0.0 dated
2016-04-08, with historical Windows support, while the exact linked
https://www.tmurgent.com/download/SuperFetch_Tools2.zip returned HTTP 404 during
acquisition. No binary was acquired or run; no hash, dependency or runtime pass
can be claimed. An official available artifact and current-build scope are the
next gates; do not substitute an unrelated cache tool, unofficial mirror or
retire the outcome solely from the failed route.

Read-only R06 repository review also confirms Partition-4DiagnosticParser offers
a standalone EXE and Python source with evtx/PySimpleGUI dependencies; selecting
and pinning a distribution and its bundled runtime/notices remains open.
Google Analytic Cookie Cruncher has a versioned ZIP inside its repository and no
published releases; inspect its exact revision/archive/license/runtime before
admission. These page observations are not pinned payload acceptance or answers
to Q15. No dependency, interpreter, parser or installer was run.

See [dated static evidence](../archive/evidence/media-privacy-and-deferred-tool-review-2026-10-16.json).
Resolved: sharper acquisition/dependency next gates only. Retired/excluded: none.
Deferred: all three product outcomes. No catalog/profile/package lifecycle change.
No state recovery is needed; preserve failed-acquisition evidence. Settings and
the other groups gain no acceptance from this review. All five ranges stay
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; failed/source-only
checks close no legacy outcome. Continue independent implementation.

## B08 YARA availability recheck, 2026-10-16

The publisher's latest release remains v4.5.8. Its
[expanded asset list](https://github.com/VirusTotal/yara/releases/expanded_assets/v4.5.8)
contains only source ZIP and tar.gz, dated 2026-07-28. This confirms the earlier
binary blocker rather than creating a new distribution choice. No payload,
compiler, dependency or scanner was downloaded/executed, and no catalog change.
Next gate is a publisher-provided binary or reviewed reproducible Windows build;
an older executable or YARA-X replacement remains an independent decision.

Resolved: current source-only availability confirmed. Retired/excluded: none.
Deferred: YARA binary/build and native/runtime acceptance. No legacy outcome
closes; all five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded
150-205/about 180. No state recovery required; continue independent batches.

## B08 PSScriptTools source candidate, 2026-10-17

Source f53ce6ab102a plus the overnight patch. Official main still resolves to
549fa3e3d769532320054fc0b3c8f42df0452361, manifest 3.2.0. The downloaded complete
archive is 25,031,482 bytes, SHA-256
05c86295a0846ae4f51ecfa6f38ef71ba8173be83eb0adc8627525a4c6ee72bd. It contains 374
entries/360 files, 75 function scripts and 27,486,171 expanded bytes. All 36
manifest/root reference paths were present; inspected names had no traversal or
symlinks, and no EXE/DLL/MSI/SYS members. Root manifest/module parsed in both
PowerShell editions without import. No publisher signature/checksum is claimed.
See [evidence](../archive/evidence/psscripttools-source-review-2026-10-17.json) and
[operator contract](../application-packages.md#psscripttools-source-candidate).

The pending catalog candidate pins that archive, retains MIT notices and all
source, and uses existing inert portable ownership. It has empty SupportedTargets,
Windows 11 candidate only, neutral source architecture and no profile selection.
It does not clone/edit Git history, install Gallery modules/dependencies, register
PSModulePath, import type/format data, modify profiles or run examples. Import
side effects and Microsoft.PowerShell.Threadjob/System.Drawing requirements remain
separate. Q15's snapshot/editable/Gallery choice is not resolved by preparation.

Windows PowerShell 5.1.26100.9711 passed 74 focused package/catalog tests, one
integration exclusion. PowerShell 7.6.5 initially passed 73/74: a real File.Replace
IOException occurred at final manifest replacement before the modified-source
case's assertions. Catalog checks passed. The four package tests then passed
sequentially with no changes to production/test logic. Retain the initial failure;
its cause is not established and the shared writer needs focused follow-up.
Tests stage inert fixture text, not publisher source. No upstream code executed.
Both editions passed validation of 347 operations/eight groups/five profiles/172
PowerShell files. Whole-catalog comparison admits only this pending addition on
top of the prior pending candidates and presentation/power changes. Native acceptance remains absent.

Next: retain the exact artifact, choose the deployment model at Q15, then use a
disposable current-source fixture for complete-file repeat/removal/recovery and
modified-source/user-file preservation. Dependency/import/editor/function
acceptance is distinct. Do not switch to Gallery or an editable workspace without
its ownership model. Preserve unowned/modified files and original snapshots;
no session/runtime recovery is claimed. Source rollback removes only this pending
entry/tests/evidence/guide addition and regenerates catalog documentation.

Resolved: pinned artifact and inert ownership candidate. Retired/excluded: none.
Partial: PSScriptTools legacy outcome. Deferred: Q15, native lifecycle, dependency/
runtime/import effects and manifest-replacement investigation. All five ranges
stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. No accepted
legacy closure; presentation stays 47/279, 232 open. Other groups gain no acceptance.

## Portable manifest failure recovery, 2026-10-17

Source f53ce6ab102a plus the overnight patch. Repeated File.Replace exceptions
during RegRipper/PSScriptTools fixture staging prompted a focused shared-writer
review. Their original cause remains unproven. An isolated Windows file-lock probe
returned IOException code 32 with both fixture files intact; releasing the handle
allowed replacement. This establishes one lock case, not the cause of earlier
"Unable to remove the file to be replaced" failures.

RIDE-PortablePackages 0.3.0 creates staged manifests exclusively and retains them
on commit failure. It retries only IOException codes 32/33/1175, at most twice
after 50/100 ms, requiring both paths and SHA-256 contents to remain unchanged.
Partial replacement 1176/1177, unrelated errors, missing or changed files stop.
No overwrite/copy/delete fallback or automatic journal adoption was added.
The original manifest schema and saved-run recovery remain unchanged. Review the
[operator recovery procedure](../application-packages.md#manifest-commit-failure)
before acting on retained evidence. This is not a concurrent-writer transaction.

Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 each passed 100 focused
tests: 13 manifest failure/success cases plus PSScriptTools, RegRipper and general
application lifecycle fixtures. These use inert test files and mocked system
calls; no downloaded code or installed product ran. Both editions passed parser,
catalog/profile and generated-document validation: 347 operations, eight groups,
five profiles and 173 PowerShell files. Earlier failed results remain retained.

Resolved: bounded replacement retry and preservation of proposed journal evidence.
Retired/excluded: none. Partial: existing portable package outcomes. Deferred:
original transient cause, native package/GUI/runtime acceptance and all product
choices. Preserve original backups and staged bytes for recovery; a source rollback
must not remove the evidence. Next acceptance uses a serialized disposable fixture
to exercise locked and interrupted commits with exact saved-byte recovery.

All five legacy ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded
150-205/about 180: a shared recovery repair closes no legacy feature. Presentation
remains 47/279, 232 open. No workstation setting, VM, controller or pin changed.

## B08 AzureHound stable artifact preparation, 2026-10-17

The existing R03 choice retains optional AzureHound matched to the chosen CE
backend. It does not approve independent latest-version compatibility. The
official stable v3.1.2 Windows amd64 ZIP (2026-10-07 release asset) was downloaded
without execution. Its 5,363,432 bytes match both GitHub's release digest and the
publisher's .sha256 file: 64575a30873b9fcdcebeca988e1313e28da2dac00fc8a10a90ba67939552a26e.
The initial checksum reader treated a byte-array response as text and refused;
explicit UTF-8 decoding produced the matching filename/digest. This was a review
script decoding defect, not a payload checksum mismatch or production change.

The single archive member is azurehound.exe, 14,900,736 bytes, PE amd64/0x8664,
ProductVersion v3.1.2, FileVersion 0.0.0.0 and Authenticode NotSigned. Its hash is
1322925cd0aaa61654a58f1bcf155f59ffb4d24c2b12d7ebd3a0135d4d0d65f7. No binary was
launched, including help/version. Static metadata is not runtime compatibility.
The archive omits LICENSE.md and NOTICE.md. Matching tag license, notice and
README were retained separately with hashes; NOTICE declares GPL-3.0-or-later.
See [structured evidence](../archive/evidence/azurehound-source-review-2026-10-17.json).
No individual/company license approval or redistribution approval is recorded.

No catalog candidate was added: backend version compatibility remains unresolved,
and complete notice/companion ownership must be defined before a deployable artifact.
Do not repack the executable into a synthetic publisher release, silently select
rolling builds or substitute the commented historical PowerShell collector.
Next: select the concrete backend release, verify its collector compatibility,
then prepare exact binary and notice acquisition/ownership with preserved user
configuration/logs. Native lifecycle, runtime/authentication/collection and service
setup are distinct later acceptance scopes. Preserve downloaded bytes as local
evidence; this read-only review has no account, service or system rollback.

Resolved: exact stable artifact/integrity/license observations. Retired/excluded:
none. Partial: AzureHound preparation. Deferred: matched deployment, companion
notices, native lifecycle and functional acceptance. Existing 347-operation catalog
and passed validation remain unchanged; no repeated tests were needed. All five
ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180: no
legacy outcome closed. Presentation remains 55/279, 224 open. No VM or controller
work, credentials, authentication or collection occurred.

## B08 Cookie Cruncher source backoff, 2026-10-17

The official repository still lists a versioned ZIP, without published releases.
A bounded inspection script was prepared to pin master, hash the exact official
ZIP and inspect its members/notices without execution. The sandbox DNS attempt
could not resolve the host; the permitted network attempt reached GitHub but its
commit API returned an unauthenticated rate-limit error. No revision was resolved,
payload acquired, source executed or catalog entry added. The response did not
provide a retained reset time, so no further GitHub acquisition is attempted in
this overnight window; the older paused backoff automation remains unchanged.

Next: after the service reset, perform one official commit lookup and bounded
archive/license/runtime inspection. Retain exact artifact/source digests and
notices before considering a pending candidate. Do not substitute a mirror or
assume that a versioned filename is verified product metadata. Source preparation
needs no Windows recovery. This is not product retirement or license approval.

Resolved/retired/excluded: none. Deferred: Cookie Cruncher acquisition and runtime/
license review. Partial: the application remainder. All five ranges stay 38-58 /
58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. No tests rerun because
no maintained code changed. Presentation remains 72/279, 207 open.

## B07 explicit deployment identity preparation, 2026-10-17

The separate [decision session](decision-session-2026-10-17.md) accepted Q01 named
deployment selection and Q02 existing-installation adoption, explicit replacement
and bulk adoption review with individual ambiguity resolution. These are design
choices, not permission for workstation mutation or completed legacy outcomes.
The [deployment ledger](package-deployment-decisions.md) now owns their reconciled
requirements. Q03-Q04 and ownership/recovery details remain open.

Added RIDE.DeploymentIdentity 0.1.0: schema-1 PackageDeploymentIdentity preparation,
complete supplied-record inspection and exact selection. Stable operation/product,
variant, library, scope and intended-user identities remain distinct. No automatic
default deployment is introduced. Product-only selection refuses multiple records,
including different variants/scopes/owners; an explicit deployment and operation
must agree. Duplicate names and malformed unrelated records fail before output.
Inspection returns copied metadata, with a 4096-record limit. Completion reads
that same validated collection without a state store, installer or operational
engine import. Every identity retains ReadyForMutation=false.

Both native editions passed 37 distinct focused tests. The first run passed 35
and exposed two completion failures because the completer could not resolve a
private helper from its execution context. Completion now calls the exported
read-only inspection API; those two tests passed on each edition, with initial
results retained. Full validation passed for 347 operations/eight groups/five
profiles/192 PowerShell files; the final completion-only change was exercised on
both editions. No existing engine/catalog/profile/state writer was changed.

Next: implement a versioned mapping from existing selection indexes/saved runs,
preserving original bytes and explicit operator names; do not silently reinterpret
schema-1 PackageSelections as the new identity schema. Define complete store and
machine/user binding before a writer can use selection results. For Q02, prepare
read-only supported-installation observations and per-match ambiguity, then bulk
adoption plans that own only supported identity/metadata. Adoption, replacement
and upgrade remain separate. Define portable file ownership, modified-content
conflicts and backup/rollback guarantees before any replacement. Product-specific
coexistence, live lifecycle and kit licensing/media acceptance remain required.

Source recovery removes only this new metadata API/tests and its guidance; no
runtime state was written and old selection/recovery records remain readable by
the existing engine. Resolved: Q01/Q02 intent and pure identity/selection behavior.
Retired/excluded: none. Partial: deployment integration and adoption/replacement.
Deferred: state migration, native lifecycle, ownership/recovery and kit decisions.
All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180; no accepted legacy product closure. Presentation remains 102/279, 177 open.

## B07 installed registration inventory, 2026-10-17

Implements a read-only first slice of accepted Q02 adoption discovery. Added
RIDE.InstalledRegistrationInventory 0.1.0 and exclusive JSON export. Expected
machine/build/edition/user/session plus native-process guards surround collection,
with post-read revision/architecture/identity drift refusal. Explicit Machine/User
selection reads both views on 64-bit Windows and Registry32 on 32-bit Windows.
Each source independently reports Captured/Unavailable and literal root existence;
partial failures discard that source, not unrelated successfully observed views.

Every observed key is retained separately with six bounded literal metadata fields.
Presence and registry kind remain explicit; environment variables are unexpanded
and signed .NET DWord representations retain their UInt32 bits. No uninstall command,
Win32_Product, service, executable, portable tree or other user is queried. No
entry is declared installed, owned or adoptable from this metadata. Shared/reflected
view duplicates remain visible; there is no first-match or implicit merge.

The implementation follows Microsoft's [explicit registry-view API](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registrykey.openbasekey)
and [unexpanded-value option](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvalueoptions?view=netframework-4.8.1).
The [MSI uninstall reference](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key)
explains common metadata; it does not authenticate arbitrary registration data or
extend MSI-specific semantics to every EXE registration. All handles close through
finally paths; child keys are opened read-only. Export uses exclusive CreateNew,
query-free WhatIf and an existing parent directory.

Both native editions passed 36 distinct tests. Initial runs passed 35 and failed
the output-race fixture because the preceding test reused the same TestDrive file.
Unique per-test paths fixed the fixture; all three export cases then passed on both
editions. Initial failed evidence is retained. Fake registry handles verified
read-only opens, unexpanded reads, missing roots, disappearing children and cleanup;
mocked sources verified source limits, malformed values, view separation and
identity refusal. Validation passed 347 operations/eight groups/five profiles/195
PowerShell files. No workstation registry inventory or installed-package query ran.

Next: compare complete supplied observations with catalog package/variant metadata
using bounded matching and per-candidate ambiguity. Distinguish unsupported or
unavailable sources from no match. Establish live identity/product/version/scope/
path and file/registration ownership before bulk adoption. Do not infer ownership
from a display-name match or replay an untrusted uninstall command. Native read-only
acceptance on the intended disposable target precedes adoption; replacement remains
a separate planned/backup/recovery workflow. Source recovery removes only this
new module/export/tests and guide section; no existing state format changed.

Resolved: bounded registration observation and export contract. Retired/excluded:
none. Partial: first-run adoption discovery. Deferred: catalog matching, native
provider, adoption ownership, replacement and state migration. All five ranges
stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; no native
legacy closure. Presentation remains 102/279, 177 open. GitHub backoff retained.

## B07 offline package adoption review, 2026-10-17

Added RIDE.PackageAdoptionReview 0.1.0. It compares supplied schema-1 registrations
with catalog package distributions using explicit target declarations and complete
scope/view coverage. RIDE.InstalledRegistrationInventory 0.2.0 validates/copies saved
context, source statuses, literal values and identities before review. PackageSelection
0.3.0 adds MetadataOnly resolution and direct Variant completion; normal operational
resolution is unchanged. No local configuration, environment destination, native
inventory or package handler is invoked in this offline review path.

Every possible display-name match remains visible. Multiple registrations and
cross-product/variant overlaps are ambiguous per row, leaving unrelated rows
reviewable. Missing/unavailable views prevent uniqueness/absence conclusions.
Undeclared targets and portable/service-only distributions remain separate from
covered Exe/Msi registration review. All candidates still need live target,
product/version/architecture/channel/location and ownership verification; every
ReadyForAdoption flag remains false. Regex matching has 50 ms per-match timeout
and a two-second scan budget per distribution; a failed distribution drops partial
matches without blocking independent rows. No command string is replayed.

Both native editions passed 103 review/application-selection/lifecycle tests and
one additional repository-catalog case: 104 distinct checks total, including all
current package distributions, target/variant overrides, overlap, absent views,
pathological regex and no-query completion. Validation passed 347 operations/eight
groups/five profiles/197 files. Whole focused diff review confirms only an opt-in
resolver branch/completion and the saved-data validator affect existing modules;
existing indexes, captured runs, handlers and main commands remain unchanged.

The decision session also accepted Q03 profile-driven toolkit publication to a
named host folder. Reconciled the active deployment ledger and question register:
manual transfers require no USB enrollment or persistent volume binding. Keep
normal explicit-path ownership, exact manifests/hashes/notices and local licensing
review. Air-gap installer payload repositories are a separate desired scenario,
whose package/variant/dependency/engine/profile scope remains undefined. Q04 is
still open. This design acceptance closes no legacy outcome and authorizes no
publisher acquisition, workstation adoption, overwrite, runtime or release.

Next: assemble explicit bulk adoption selections from these review rows, retaining
per-match ambiguity rather than guessing. Bind a stable deployment name and exact
registration identity/evidence before any durable state creation. Complete live
revalidation, product-specific ownership and versioned legacy record compatibility;
adoption preserves installations, replacement has a separate backup/recovery plan.
For Q03, prepare the host-folder manifest/layout independently of kit update/removal.
Native inventory/GUI/adoption and product coexistence remain acceptance work.

Recovery: this batch only prepares data. Retain observations and initial records;
source rollback removes the new review API/tests and opt-in metadata resolver
branch, leaving the existing engine lifecycle. Resolved: offline matching and
Q03 publication intent. Retired/excluded: no product outcome. Partial: adoption
integration and toolkit publication. Deferred: live ownership/state migration,
Q04, native acceptance and offline bundle scope. All five ranges unchanged:
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. Presentation
remains 102/279, 177 open; no accepted legacy closure or target expansion.

## B07 legacy selection mapping preparation, 2026-10-17

Added RIDE.LegacyDeploymentMapping 0.1.0 for PackageSelections schema-1 logical
data, with explicit deployment name and expected stable operation/product/library/
store scope. User scope requires an explicit intended SID. Current defaults,
variants and paths never replace the saved values; retired variant identities and
unknown literal fields remain retained. Deep copies preserve nulls, empty arrays,
numeric values and nested records without shared mutable references. Unsupported
objects, script properties, non-finite numbers and excessive depth/nodes/strings
fail without evaluating or changing the original source.

The version-1 mapping and reverse API validate structural identity consistency,
not source authenticity. ReadyForMigration and OriginalFileBytesPreserved remain
false: this is not the durable state migration. Existing indexes and run schemas
remain unchanged; run snapshots are explicitly refused as a different source.
No name is automatically assigned/reserved and no original bytes or store ACLs
are read. Future integration must retain exact source bytes, prevent ambiguous
parsing, bind machine/user/store provenance, reserve names and journal commits.

Both native PowerShell editions passed 20 focused tests, including old-variant
retention, JSON logical round trip, expected-identity mismatch, user/library scope,
copied data, bounds and recovery consistency. Validation passed 347 operations,
eight groups, five profiles and 199 PowerShell files. No state, package, path,
registry or workstation mutation occurred.

Q04 was also accepted in the decision session and reconciled into active ledgers:
stage and verify before modifying the named host publication; preserve unrelated
and tool-generated data; remove only unchanged managed obsolete files. Modified
managed replacements require an explicit answer; modified obsolete files are not
silently removed. Noninteractive conflicts remain deferred for that answer.
Temporary staging space is accepted, but actual commit/recovery behavior remains
implementation/acceptance work. No toolkit content was created or changed.

Next: implement strict original-byte retention and authenticated state-store binding
before any compatibility write; preserve current engine recovery for old runs.
Prepare Q03/Q04 host-folder layout and owned-file update decisions without USB
enrollment or implicit adoption. Bind every selected artifact/member to exact
version/hash/source/notices; product coexistence and local license review remain
separate. A user conflict answer is still required before modified-file replacement.

Resolved: logical selection compatibility and Q04 intent. Retired/excluded: none.
Partial: durable deployment migration and staged toolkit publication. Deferred:
source bytes/store provenance/journal, ownership conflicts, native acceptance and
offline installer-bundle scope. Source recovery removes only the new module/tests
and guidance; the in-memory API needs no Windows rollback. All five ranges stay
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; no legacy closure.
Presentation remains 102/279, 177 open. GitHub backoff and protected runtime remain.

## B07 toolkit owned-file update preparation, 2026-10-17

Added RIDE.ToolkitUpdatePreparation 0.1.0 for accepted Q03/Q04 host-folder
publication. Explicit kit/root, prior and desired schema-1 ToolkitOwnedFiles,
and a complete matching ToolkitFilesystemObservation produce in-memory decisions.
No filesystem discovery, copy, overwrite, delete, acquisition, publication or
physical-volume enrollment occurs.

StageAdd/StageReplace require future verified staging. Keep leaves owned desired
content unchanged. Only obsolete files matching prior SHA-256 and byte length
receive RemoveOwnedUnchanged; already absent obsolete files receive ForgetAbsent.
Unrelated/generated content remains PreserveUnmanaged. Modified/missing managed
content, modified obsolete content, unowned path collisions and unsafe namespace
conditions are explicit Conflict decisions. An identical unowned file is not
adopted automatically. Independent decisions remain visible but the whole result
retains ReadyForPublication=false and RecoverySupported=false.

Paths are bounded forward-slash members, with traversal/ADS/reserved names,
trailing dots/spaces, duplicate-case and file/descendant collisions refused.
Root is a chosen host subdirectory, not a drive/share root. A complete case-
insensitive non-reparse root observation is required; reparse/unavailable/file
ancestors and observed descendants block affected managed paths. No directory
tree ownership is inferred. These supplied assertions are not live proof; source
authentication and fresh filesystem guards still belong to the future writer.

Both native editions passed 37 distinct tests. Initial runs passed 36 and found
a UNC root-suffix normalization bug: GetPathRoot can omit the trailing separator,
leaving an unwanted leading slash in the relative suffix. The fix removes that
separator before member validation; the focused drive/UNC/device/traversal root
test then passed on both editions. Initial evidence is retained. Validation passed
347 operations/eight groups/five profiles/201 PowerShell files. No workstation or
VM file publication occurred; tests used supplied synthetic content digests only.

Next: implement trusted complete filesystem observation, exact artifact/version/
source/notice binding and the full profile-selected layout manifest. Verify all
staged members before commit. Add durable journal, live conflict rechecks and
interrupted commit recovery; do not claim atomicity from this comparison. Ask
before modified-file replacement, retaining conflicts during unattended runs.
Manual transferred copies stay outside automatic management. Keep toolkit deployed
content separate from the still-unspecified offline installer repository.

Resolved: three-way owned-file update rules and conflict boundaries. Retired/excluded:
no product outcome. Partial: toolkit publication. Deferred: full manifest, trusted
collection, staging/journal/recovery, license review and native acceptance. Source
recovery removes this pure API/tests and guidance; no actual rollback is needed.
All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180; no accepted legacy closure. Presentation remains 102/279, 177 open.

## B08 Wireshark machine MSI candidate, 2026-10-17

Accepted Q16 now selects all-user Wireshark installation preserving existing file
associations; selecting capture-file defaults is separate. Added pending
package.wireshark, installed MSI variant only, SupportedTargets empty and no profile
selection. The existing handler receives /qn /norestart WIRESHARK_FILE_EXTENSIONS=0.
No automatic Npcap, USBPcap or association workflow is introduced.

Official Wireshark 4.6.9 x64 MSI acquisition used declared source and license metadata
and the existing versioned acquisition/sidecar path. It retained 80,433,152 bytes,
SHA-256 1975dfc96581a9b674fda3f41ac1585963b4ba52ea9459f3b6d9cedfac3a7217,
matching the exact publisher checksum. Authenticode is Valid, Wireshark Foundation;
the checksum document's PGP signature was retained but not verified. GPLv2 and
bundled notices remain with the payload. GitHub backoff remained in force; acquisition
used Wireshark's declared hosting and source inspection its official GitLab project.

Read-only Windows Installer database queries inspected 981 File rows, 1013 Component
rows and 148 Registry rows; no installer/custom action was executed. ProductVersion
is 4.6.9.0, ALLUSERS=1 and summary template x64;1033. All 116 class-registry rows join
to 29 components conditioned on WIRESHARK_FILE_EXTENSIONS = "1". No Npcap/USBPcap
file was listed; runtime merge-module files and notices were present. Existing NSIS
launch-condition guards and publisher MSI transition/experimental limitations remain.
The [sanitized evidence](../archive/evidence/wireshark-msi-source-review-2026-10-17.json)
contains exact source hashes and relevant table rows, not local filesystem paths.

Initial local inspector attempts failed on COM reflection dispatch and the absent
Extension table; direct read-only dispatch and explicit table presence fixed them.
COM method return values were then suppressed from row output. A component-name
prefix assumption also included four unrelated harvested IDs and missed three
association IDs; the corrected check joins actual class registry rows to
their exact component IDs. These failed assertions are not runtime acceptance.
The final joined-table check and unchanged artifact hash passed; no installer ran.

Both native PowerShell editions passed eight candidate/handler tests and ten focused
catalog tests (18 per edition). All installer, driver and registered-presence calls
were mocked. Tests cover no-association/no-restart dispatch, MSI-only removal,
artifact drift, failed installation and reboot-required reporting. Static validation
passed 348 operations/eight groups/five profiles/206 maintained files. Whole-catalog
comparison permits eight pending additions and the prior 72 presentation blocks;
all other baseline fields/groups remain unchanged.

Next: disposable install/repeat/removal and failure recovery on each candidate
desktop target, with seeded prior associations and unowned global/user content,
shared-runtime ownership and NSIS/MSI transition refusal. Native driver acceptance
stays separate. Q16 compatibility mode is explicitly off by default; enabling it
requires a selected option and existing WinPcap replacement preview, never silent
workstation replacement. Source rollback removes the pending entry/test/evidence
and regenerates OPERATIONS; retain the local cache until no recovery depends on it.

Resolved: exact MSI acquisition and static argument/integrity evidence. Retired or
excluded: none in this package batch. Partial: Wireshark migration; deferred:
native lifecycle, associations, content/runtime ownership and Npcap. No legacy
closure. All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded
150-205/about 180. Presentation remains 102/279, 177 open.

## Accepted Volatility 2 and ImproHound retirements, 2026-10-17

Reconciled explicit [Q17](decision-session-2026-10-17.md#q17-retire-planned-volatility-2-deployment-retain-volatility-3)
and [Q20](decision-session-2026-10-17.md#q20-defer-standalone-neo4japoc-and-retire-planned-improhound-deployment).
Retired two planned legacy product outcomes: InstallVolatility2/RemoveVolatility2
and GetImproHound/RemoveImprohound. The exact selector mappings and historical
source/dependency evidence remain. Neither product had an active v3 catalog entry;
no code, supported target, package, runtime or data was removed or adopted.
Volatility 3 and CE are not declared universal replacements for historical workflows.

The original 109-row application ledger now accounts for ten earlier migrations,
19 accepted migrations, one exclusion, two explicit retirements and 77 pending/
partial review outcomes. The dated 79-outcome/13-group map remains historical
coverage rather than being rewritten to erase two rows. Wireshark and other pending
source candidates remain in the unresolved count until acceptance.

Q18 accepts pinned reviewed dependencies, explicitly selected extras and separate
rule/plugin updates, preserving custom content and requiring answers for modified
managed files. The broader selected Volatility 3 plugin scope is retained. Exact
dependency versions and membership remain open. Q19 prioritizes collectors with
the backend separately managed; optional backend deployment is deferred, not
retired. Q20 defers standalone Neo4j/APOC until an independent use case exists.
Those outcomes remain counted. No credentials or collector execution is implied.

Q21 now selects Microsoft 365 Apps for enterprise and retains the approved language
intent. The referenced Visio suggestion, update channel, architecture, activation
and supported product-language mapping still need explicit resolution. Teams
install/startup/old-edition cleanup remain separate. No Office entitlement or
unattended-capability claim follows from product choice.

Estimate adjustment: subtract exactly two package outcomes from 58-73 to 56-71.
The other four groups remain 38-58 settings, 20-25 components, 25-35 accounts/assets
and 8-12 maintenance. Summed endpoints change from 149-203 to 147-201; rounded
to the nearest five this becomes 145-200, about 175 for planning. Presentation
remains 102/279, 177 open. No runtime acceptance or new exclusion occurred.

Validation: verified both exact selector rows remain once, their dispositions
are explicit retirement, neither product appears in the active catalog/profiles,
and the current five ranges/rounded total match the two-outcome arithmetic. Local
links and whitespace checked; passed runtime suites were not rerun for prose.
Next: continue remaining independent batches; revisit Neo4j/backend only after
their stated use-case/scope gates. Reversing a retirement requires a new explicit
product decision while retaining this history. No OS recovery action is needed.

## B10 inert Office configuration review, 2026-10-17

Reconciled Q21 follow-ups: Microsoft 365 Apps for enterprise; Monthly Enterprise
default and explicit Current; fresh x64, existing compatible architecture matching
and explicit x86; separate approval for architecture migration; standard subscription
user sign-in with activation-pending continuation; Visio Professional 2016 Retail
and Plan 2 as separate choices without implicit replacement/conversion. Visio
display language is now explicitly en-US or da-DK, preserving Office en-GB.
Additional LanguagePack/MatchOS/ProofingTools still need product-specific validation.
Teams is optional, startup preserved, old-version cleanup separately previewed and
data-preserving. Q22 also accepts preserving OneDrive accounts, sync and all user
files; sync/folder-backup restrictions remain separate. These follow-ups supersede
the earlier partial Q21 paragraph above without erasing its chronology.

Implemented RIDE.OfficeConfigurationReview 0.1.0 as pure supplied-byte inspection.
The bounded parser disables DTD/external resolution; no source is executed or
rewritten. It records exact input SHA-256 and redacted product/language, version,
architecture/channel, removals/MSI exclusions, updates, terms and property requests.
Unknown elements/attributes/properties remain review items. Missing choices are
not replaced by defaults. Credentials/product keys, paths and AppSettings values
are omitted; parser exceptions do not echo XML. ReadyForMutation and
RecoverySupported remain false; ActivationStatus is NotObserved. This preparation
does not add an internal licence-review blocker to the future unattended runner.

Both actual legacy XML blocks were extracted as text from lib-windows.psm1 and
inspected without evaluating it. They contain RemoveMSI, Current channel updates,
Display None/AcceptEULA TRUE, AUTOACTIVATE=1 and the misspelled
FORCEAPPSSHUTDOWN. The actual ODT property is FORCEAPPSHUTDOWN; the typo is
flagged as unreviewed, never silently corrected into a potentially destructive
action. Office additionally carries AppSettings. Both omit immutable versions and
explicit architecture, and request MatchOS without a fallback. Visio requests
unsupported en-GB; the new user choice resolves its display-language direction
but does not automatically rewrite any existing deployment.

The [ODT reference](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/office-deployment-tool-configuration-options)
documents these configuration boundaries. The [Visio deployment guide](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/deployment-guide-for-visio)
supports the separately licensed subscription ODT route; a product ID alone
does not identify an existing licence edition. [Coexistence rules](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/install-different-office-visio-and-project-versions-on-the-same-computer)
require product/version/technology/architecture review. [Visio 2016 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/visio-2016)
ended in October 2025; keeping the requested choice does not assert publisher
support or authorize retirement/removal. No installer, payload, licence, account,
activation, Office/Teams/OneDrive setting or VM was changed.

Validation: 37 initial tests passed per Windows PowerShell edition, followed by
four focused removal-summary/review tests (three new, one affected). All 40 distinct
cases passed per edition; already passed unrelated cases were not rerun. Bounds,
DTD/entities/namespaces, processing instructions, redaction, raw-byte identity,
UTF-16 input, ordered languages, explicit versus omitted values, unknown syntax,
legacy typo, removal intent and the two real historical configurations were tested.
Repository validation passed for 348 operations/eight groups/five profiles/210
PowerShell files. No native/provider or installer call was used. Presentation
remains 123/279, 156 open.

Next: inventory installed Office/Visio product, technology, version, architecture,
channel and language metadata without keys; resolve publisher-supported combinations
before generating a fresh configuration. Pin ODT/payload version and sources,
verify all approved extra-language/proofing requests and MatchOS fallback without
reintroducing en-GB Visio resources. Keep migration, RemoveMSI, process closure,
terms/entitlements and specialized activation explicit; retain standard user
activation pending after successful unattended installation. Native lifecycle and
preservation/recovery need disposable acceptance. Source recovery removes the unused
review module/fixture and its guidance; original XML and runtime state are unchanged.

Resolved: configuration inspection contracts and Q21/partial Q22 design choices.
Retired/excluded: none. Partial: Office/Visio/Teams/OneDrive preparation. Deferred:
publisher acquisition, compatibility, extra languages, entitlements/activation,
native deployment/preservation and WinGet AutoUpdate choices. All five ranges
remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no legacy
product or setting outcome is accepted from XML review.

## B10 Click-to-Run observation, 2026-10-17

Implemented RIDE.OfficeInventory 0.1.0 and exclusive JSON export. The schema-1
observation uses independently expected native machine/build/edition/user/session,
checks the context again after collection, and keeps explicit registry views
separate. It reads eight values under the machine ClickToRun/Configuration root
without expansion. Missing roots/values are captured absence; source failure,
partial output, malformed or excessive data becomes Unavailable with no partial
values. All opened handles are disposed, including failure paths.

VersionToReport, ClientVersionToReport, Platform, ProductReleaseIds, ClientCulture
and AudienceId remain bounded raw tokens. CDNBaseUrl/UpdateChannel raw URLs are
always redacted; only an exact recognized Microsoft CDN channel GUID is retained.
Credentials, custom server paths, queries, fragments and unknown URL forms are
never exported. No keys, tokens, installation paths, MSI provider, executable or
activation query is used. The [Microsoft update guidance](https://learn.microsoft.com/en-us/intune/device-configuration/settings-catalog/update-office)
distinguishes initial CDNBaseUrl from dynamic UpdateChannel and explains update
timing; neither value alone proves effective policy or successful channel change.

Validation: 36 mocked tests passed on each native PowerShell edition. They cover
32/64-bit view selection, context mismatch/type drift, missing versus unavailable
metadata, raw/empty values, URL redaction, partial-source discard, exact field/read
options, handle cleanup, no-query WhatIf and exclusive/racing export preservation.
Repository validation passed for 348 operations/eight groups/five profiles/213
PowerShell files. No developer Office registry, provider, installer or VM was used.

Next: collect this observation and independent installed-registration evidence in
an authorized disposable target; verify view sharing and installed product,
technology, architecture, per-product language and policy precedence. Continue
publisher ODT/payload pinning, supported coexistence/languages, explicit removal/
migration and recovery design before execution. Activation remains NotObserved;
all verification/readiness/recovery flags remain false. Recovery is preservation
of existing/partial outputs and a fresh filename, not a claim of Office backup.

Resolved: bounded metadata observation/export. Retired/excluded: none. Partial:
Office/Visio preparation. Deferred: native acceptance, per-product identity,
licensing/activation and deployment. Presentation remains 123/279, 156 open.
All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about
175; no legacy outcome is closed by read-only preparation.

## B10 FTK source and decision reconciliation, 2026-10-17

Q22 accepts opt-in updater selection, approved sources/pins and separate scheduling
without forced closure/reboot. Q23 prioritizes VMware workstation installation,
preserving VMs/preferences and separating directory configuration and guest drivers.
Q24 prioritizes FTK Imager then KAPE; Arsenal remains an unresolved product choice.
These are preparation/design choices, not installer or native acceptance.

Acquired the exact ZIP linked by the [official FTK Imager 8.3 release page](https://www.exterro.com/ftk-downloads/ftk-imager-8-3),
retaining declared product/license/terms references and original notices. The
405,808,295-byte ZIP has observed SHA-256
`0f717d0d91c94af94107775ae37c2e330cc2a2312a8eecc91a344c8010e82afe`;
no independently published checksum was verified. Its two executables were
extracted as data into the ignored review directory, never launched. Main setup
8.3.0.27 has Valid ACCESSDATA GROUP, INC. Authenticode; CodeMeter Runtime
8.20.6539.500 has Valid WIBU-SYSTEMS AG Authenticode. Exact hashes/certificates,
source and member paths are in [shared evidence](../archive/evidence/ftk-imager-source-review-2026-10-17.json).
The x64 product uses an x86 InstallShield setup launcher; wrapper architecture is
not proof of installed runtime architecture. The publisher release notes describe
a driver update/old-driver cleanup, requiring separate recovery review.

The nested ISSetupPrerequisites CodeMeter directory is material. Existing generic
ZIP installation extracts a selected installer member; it does not establish
preservation or execution of this bundle's external prerequisites. Do not catalog
this as a simple single-EXE install, assume CodeMeter optional, invent silent
flags, or strip it and call the result portable. Exact bundle/EULA, prerequisite
conditions, service/driver/reboot, detection, removal/coexistence and data recovery
remain unresolved. The free edition's product description is not blanket approval
for dependencies or redistribution. Internal pending licence-review status alone
is not a future unattended-install blocker (Q14); real publisher requirements remain.

Validation was archive structure, member hashes, signatures/version resources and
7-Zip PE listing, with no setup/MSI action, driver loading, disk-image collection
or VM operation. No catalog/runtime change was made; previously passed suites
were not rerun. Next inspect supported prerequisite handling and exact bundled
terms without executing setup; then implement bounded layout-preserving staging
and mocked lifecycle only when actual flags/detection are evidenced. Native
acceptance requires a disposable target and explicit driver/recovery boundaries.
Preserve the original archive; inspection recovery is retaining/deleting only
review-owned copies after checking their paths, not product uninstall.

Resolved: official artifact identity and dependency finding; Q22-Q24 choices.
Retired/excluded: none. FTK deployment remains partial, KAPE follows separately,
Arsenal/VMware edition and native actions deferred. Q31 separately closes only
unsubstantiated bookkeeping, not a numeric legacy outcome. All five ranges remain
38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B10 local offline bundle preflight, 2026-10-17

Reconciled the accepted offline follow-ups: profile-selected and full external
sets, reviewed installed/portable variants on selected targets, pinned RIDE/source,
profiles/payloads/notices, clear partial omissions, complete-selected-profile gating,
no network fallback, retained old versions and optional supplied servicing sources.
Updated the former optional-future wording in AGENTS, licensing and the backlog;
the user's later scope acceptance supersedes it. Runtime and redistribution rights
remain separate. No new legacy outcome is inferred from this workflow scope.

Implemented RIDE.OfflineBundle 0.1.0 and Test-RideOfflineBundle 0.1.0. The strict
schema-1 manifest records independent file IDs/relative paths/hashes/lengths,
engine/profile identities, package variants/versions/target metadata, dependency
edges, publisher/licence references, omissions and servicing metadata. Shared
private-review fields are rejected. Before file observation it rejects unsafe
paths, duplicate/case collisions, invalid references, cycles in selected dependency
closure and byte limits. It verifies selected engine/profile/payload/notices and
declared transitive dependencies locally, retaining missing/hash/length/access/
reparse failures. Unrelated omitted artifacts leave selected complete content usable
for further review; they remain visible in the incomplete overall declaration.

Integrity is deliberately narrower than readiness. It does not discover undeclared
profile dependencies, prove engine source coverage/commit provenance, authenticate
publishers, query the target or test installer offline behavior. Servicing metadata
mismatches are reported; matching labels never establish native media compatibility.
ManifestCoverageVerified, EngineSourceCommitVerified, ProfileDependencyClosureVerified,
ActualTargetVerified and ReadyForMutation remain false. Normal install/apply do not
yet consume this preflight. No misleading air-gap-ready claim follows from hashes.
Read-only profile-ID completion uses the same supplied manifest; no Windows query.

Validation: 38 tests passed initially on each native edition; five focused follow-up
cases (three new, two affected) passed after adding testable read-handle/reparse
boundaries. All 41 distinct cases passed per edition. Coverage includes actual
temporary-file hashing, moved roots, original file preservation, partial unrelated
omissions, transitive missing requirements, source metadata, servicing mismatch,
cycle/bounds/unsafe paths, shared-key names, read failure redaction and no-follow
root/member guards. Repository validation passed on both editions for 348
operations/eight groups/five profiles/219 PowerShell files. No real payload,
installer, bundled script, network fallback, media, component or VM was executed.

Next: derive manifest coverage/dependencies from the selected catalog/profiles,
build a new pinned source version using the release/source packaging boundary,
implement exclusive assembly with recoverable staging, and integrate mandatory
full-selected-deployment preflight before any target write. Prove product offline
behavior and supplied servicing compatibility in disposable targets. Retain old
versions and omissions; failed read-only preflight requires no target recovery.
See the [operator contract](../offline-bundles.md). Assembly is not yet delivered.

Also checked the [current KAPE publisher page](https://www.kroll.com/en/services/cyber/reactive-services/kroll-artifact-parser-and-extractor-kape)
after FTK. It presents personal/company/contact fields and a publisher agreement
checkbox. No form or agreement was submitted, no old S3 route was used as a bypass,
and no payload acquired. Next provide an officially obtained artifact and retain
its applicable terms, then pin/hash/inspect it without adding the legacy Defender
exclusion. The existing internal-use versus third-party paid-engagement watchlist
remains relevant; this is a publisher interaction gate, not an internal review pause.

Resolved: offline workflow design and local declared-content preflight. Retired/
excluded: none. Partial: bundle implementation. Deferred: assembly, engine install
integration, dependency discovery, actual target/offline/media acceptance and KAPE
publisher input. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12,
rounded 145-200/about 175. No legacy product/component outcome closed.

## B10 offline profile package coverage, 2026-10-17

OfflineBundle 0.2.0 adds Test-RideOfflineProfileCoverage. Supplied catalog/profile
hash claims must match the manifest's engine catalog and selected profile records.
The function expands ordinary package groups and explicit catalog prerequisite
links, then compares only artifacts in the selected manifest dependency closure.
It detects missing/omitted/ambiguous package variants and pinned version/digest,
architecture or publisher/licence metadata mismatches. It does not query host
preferences: variant-bearing selections must be explicit. Overlaps, unknown
selection fields, unsupported Store workflows and cyclic graphs fail closed.

Thirty-six focused tests passed in native Windows PowerShell 5.1 and PowerShell 7.
The comparison is data-only; source hashes remain caller assertions until bound
to parsed bytes. File integrity, installer-hidden dependencies, non-package assets,
actual target eligibility, offline runtime behavior and removal/recovery are not
certified. Catalog prerequisites are preparation requirements, not implicit install
selections. Conditional profile fields are refused until their schema is implemented.
No installer, provider, source acquisition, host query or VM action occurred.

The latest [Q23/R10 decisions](decision-session-2026-10-17.md#q23--r10-follow-up-hashcat-cli-and-optional-launcher)
also retain Hashcat CLI plus separately selected compatible HashcatLauncher and
NVIDIA/AMD/Intel applicability review, with drivers and workloads separate. Guest
scope is VMware, Hyper-V and KVM/QEMU (including Proxmox/GNOME Boxes); detection
suggests but does not select unattended drivers. Explicit profile conflicts remain
pending. Clipboard, drag/drop, shared folders and WebDAV are individually optional
and preserve current settings; host requirements stay separate. AutomatedLab module
installation is included, preserving modules/lab definitions; host provisioning and
lab creation/removal stay explicit. Lenovo Vantage is optional and conditionally
selectable for confirmed compatible target hardware; unknown compatibility skips
with explanation, manufacturer alone is insufficient. Offline preparation includes
selected conditional payloads irrespective of preparation-host hardware. Application
installation never selects driver/firmware/BIOS updates or changes update preferences.
Exact package compatibility, installer defaults and native acceptance remain open.

Next: bind coverage to the bytes read by local preflight, implement exclusive bundle
assembly and mandatory selected-deployment checks before any target mutation. Review
hidden runtime/assets and conditional selection schemas without expanding support.
Retain failed bundles and old versions; no state recovery is needed for this read-only
comparison. Resolved: manifest package-omission detection and Q23 design reconciliation.
Retired/excluded: none. Partial: offline assembly/integration and platform/product
implementation. Deferred: actual offline/hardware/guest/driver/workload acceptance.
All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about
175. The added detail refines existing product outcomes and closes none.

## B10 byte-bound offline profile preflight, 2026-10-17

OfflineBundle 0.3.0 and Test-RideOfflineBundle 0.2.0 accept optional CatalogFileId
with manifest-driven completion. Preflight captures the selected catalog/profile
as bounded bytes, verifies those hashes, decodes strict UTF-8 and evaluates only
declarative data from that same buffer. CatalogData 0.3.0 adds mutually exclusive
Content input using the existing AST evaluator. No bundled code is imported.
ProfileCoverageStatus is Compared, SourceUnavailable or NotRequested. Only the
wrapper can set ParsedBytesBindingVerified; direct data API hashes remain claims.
SelectedPackageContentComplete combines declared-file integrity with package
coverage, not hidden dependencies, non-package resources or native readiness.

Twenty-two new tests plus affected completion passed in each native PowerShell
edition: exact byte binding, manifest omissions, changed/unavailable source,
encoding/BOM, parser bounds, malicious expressions, reparse refusal, CLI and full
current-catalog file/text parity. Earlier 36 coverage tests retain their evidence;
unaffected cases were not repeated. Both repository validations passed for 348
operations/eight groups/five profiles/220 PowerShell files. No installer, target,
VM, network acquisition or publication action occurred.

Further [decision-session choices](decision-session-2026-10-17.md) are reconciled:
Volatility 3 defaults to per-user isolation, with separate machine scope and
configurable preserved symbols/caches/plugins. Python manager preserves python/py
and associations, uses direct interpreter paths, prepares pinned runtimes and
disables implicit downloads; automatic acquisition is an explicit online choice,
with updates separate. ImageMagick portable defaults to a chosen per-user path
without PATH changes; shared scope/PATH are explicit. Its accepted x64 Q16 HDRI
DLL all-user installer keeps machine PATH, leaves other fresh integrations
unselected and preserves adopted/upgraded choices. Microsoft OpenJDK remains
independent: side-by-side selected majors and direct runtime paths, preserving
JAVA_HOME/PATH/.jar unless explicitly changed. New standalone selections default
to pinned JDK 25 LTS, with 21/17/11 compatibility choices and no automatic major
migration. Exact pins, installer preservation and native acceptance remain open.

Next: exclusive local assembly into new retained bundle versions, dependency and
conditional-profile audits, then mandatory engine preflight before any target
mutation. Preserve partial bundles and old versions. Read-only checks require no
target recovery; source recovery is a focused revert. Resolved: parsed-byte binding
and decision ambiguity. Retired/excluded: none. Partial: offline workflow and runtime
product implementation. Deferred: native installer/hardware/recovery acceptance.
All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about
175; no additional legacy outcome closes.

## B10 explicit local offline bundle assembly, 2026-10-17

OfflineBundle 0.4.0 and New-RideOfflineBundle 0.1.0 assemble explicitly mapped
local files into a new destination. Validated manifest/source mappings, whole-bundle
byte bounds, regular-file/reparse guards and ShouldProcess precede writes. Exclusive
file creation and streaming SHA-256 are followed by staged-file verification. The
manifest and completion record contain no preparation-host source paths. A final
directory move refuses an existing/competing destination. Older bundles and all
source files are preserved; no automatic deletion, resume, acquisition or installer.

Partial bundles retain explicit omission records. Failure returns phase/file/type
and retained staging path; an interruption also leaves its unique sibling stage
for inspection. Completed means copied bytes matched, not publisher authenticity,
complete engine packaging/dependencies, redistribution or native offline acceptance.
No install/apply integration or new supported target is implied.

Twenty-seven distinct tests passed in each native PowerShell edition: preview,
source/destination preservation, digest/length failure staging, partial omissions,
older versions, source-map/path rejection, bounds, metadata collisions, orphan files,
reparse refusal, concurrent destination collision, exclusive file writes, CLI and
multi-buffer/zero-byte copying. Fixtures were inert data in isolated TestDrive;
no package or bundled source was executed. Both repository validations passed for
348 operations/eight groups/five profiles/222 PowerShell files.

Latest decision reconciliation: the initial Arsenal collection contains Image
Mounter, Hibernation Recon, Registry Recon, HBIN Recon, Hive Recon, ODC Recon,
Swap Recon and LevelDB Recon, individually or together after acquisition/compatibility
review. Open-source Arsenal utilities are separate future scope. MEGAcmd stays
deferred unless a chosen official source demonstrably requires it; no implicit
helper, licensing/activation, driver or forensic execution is authorized. The exact
external BloodHound CE backend version and matching collectors are explicitly
deferred; retain collectors-first preparation without selecting a compatibility
pair. The initial Sysinternals scope is the full official Suite frozen to reviewed
members/versions/hashes, with individual/whole selection and review of future
additions. No mutable deployment-time membership or automatic Sysmon activation.
See the [accepted decision session](decision-session-2026-10-17.md).

Next: prepare official-source inventory/pins and complete dependency/engine-source
packaging, then integrate mandatory selected-profile preflight before target changes.
Use the [operator procedure](../offline-bundles.md), retain failed stages/old versions,
and never treat a completed copy as approval to run installers. Source recovery is
a focused revert; local assembly recovery is inspect-and-retain, not destructive
rollback. Resolved: explicit local assembly and preservation behavior. Retired/
excluded: none. Partial: automated planning and complete offline installation.
Deferred: native product/media/hardware acceptance and backend-version input.
All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about
175; no additional legacy outcome is complete.

## B11 Sysinternals reviewed snapshot candidate, 2026-10-17

Following accepted full-Suite membership, the official Microsoft archive was
acquired once at 05:14 UTC. Observed size is 374,742,194 bytes and SHA-256
e1e75de5cdb12116b0a4eca83725dc7c7a1645266196025cbe5ca6c167161aed. Microsoft Learn
showed an October 15 page date and 192.2 MB label; the actual downloaded size is
recorded rather than inferred from that label. No publisher archive digest is
claimed. Bounded flat-path ZIP review found 164 files, 468,112,920 expanded bytes.
All 151 PE executables had Valid Microsoft signatures: 79 x86 and 72 x64 machine
fields. Thirteen other files include help/notices. Every member has an observed
hash; no extraction/signature error or tool execution occurred.

The [source evidence](../archive/evidence/sysinternals-suite-source-review-2026-10-17.json)
retains complete members/versions/certificates and official product/license URLs.
Eula.txt SHA-256 is 8329bcbadc7f81539a4969ca13f0be5b8eb7652b912324a1926fc9bfb6ec005a.
The bundled readme claims NotMyFault is omitted, but actual notmyfault variants
are present; the publisher page also lists it. Exact archive inventory governs
this snapshot, not stale prose. No file was run or interactive terms answered.
Local acquisition is separate from publication rights and per-owner review.

package.sysinternals-suite is a pending whole-archive portable candidate, using
existing state/ownership/recovery. Its synthetic snapshot label identifies these
observed bytes, not a Microsoft version. All 164 members are required and the
archive hash is pinned; mutable upstream changes fail verification. No supported
apply targets or profile defaults were added. Individual product selection and
per-tool applicability remain partial. Sysmon portable bytes do not install or
alter the separately managed Sysmon service/configuration.

Legacy source SHA-256 4827a032607e96a2eb49bd53bb02bdeab860a5481a1ab68954480452a3f4cdea
parsed with zero native PowerShell errors. GetSysinternalsSuite at line 2111 uses
the same useful official ZIP, but unpinned acquisition and recursive replacement;
RemoveSysinternalsSuite at 2170 recursively deletes the product folder. Disposition:
replace those wrappers with pinned acquisition and owned-file lifecycle, retain
the collection intent, and do not reconnect legacy code. This is not a product
retirement. No legacy wrapper or external helper was executed.

Seven distinct focused tests passed in each native edition: inventory/pin binding,
required notice refusal, changed archive refusal, repeat staging/removal/exact
restore, unowned/modified-file preservation, no-network metadata resolution and
mocked changed-upstream digest rejection before success evidence/process execution.
PowerShell 5.1 initially lacked the test fixture's explicit Compression assembly;
that fixture import was fixed and only its four failed cases rerun. Synthetic ZIPs
contain inert text, not acquired executables. Both repository validations passed
for 349 operations/eight groups/five profiles/223 PowerShell files. Cumulative
comparison retains nine pending additions and 105 presentation blocks, with all
other baseline fields/groups unchanged. Generated OPERATIONS refreshed.

Next: review individual product/member grouping and dependencies against the frozen
inventory, then use the serialized disposable-target workflow for owned-file
repeat/restore/collision acceptance. Keep tool launch, EULA interaction, drivers,
services, credentials and workloads separately explicit. Preserve retained cache,
operator files and saved snapshots. Source recovery removes only this candidate
and regenerates OPERATIONS; runtime recovery uses the existing exact file snapshot.

Zimmerman forensic members and separately refreshed maps/batch definitions are now
accepted in the decision ledger. Preserve custom content and require decisions on
modified managed files; ordinary installation must not run a mutable updater or
sync command. The legacy wrapper/upstream-helper review remains distinct; GitHub
backoff prevents further upstream source acquisition during this window. No helper
equivalence or native behavior is inferred from the decision chat's static review.

Resolved: official Suite inventory/pin and whole-copy candidate. Retired/excluded:
none. Partial: complete collection/individual product migration. Deferred: native
target/runtime/driver/service acceptance and updater/member integration. All five
ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; a
source candidate does not complete this legacy collection outcome.

## B11 independent Sysinternals products, 2026-10-17

Three official product archives now have independent portable candidates, separate
from the whole Suite. Microsoft product pages declare Process Explorer 17.2
(2026-10-15), Autoruns 14.3 (2026-06-17) and TCPView 4.19 (2023-04-11). Actual PE
versions agree. Source records retain each official URL, acquisition time, length,
observed SHA-256, all member hashes/versions/PE machines and signature observations:

- [Process Explorer inventory](../archive/evidence/sysinternals-process-explorer-source-review-2026-10-17.json):
  3,813,190-byte ZIP, dab147316264b89ae46ae2ad7d8a94116848ef0b703bcac8de9ff22689ce9d51,
  four files, three Valid Microsoft signatures.
- [Autoruns inventory](../archive/evidence/sysinternals-autoruns-source-review-2026-10-17.json):
  3,183,752-byte ZIP, 7b3a8eed819f732a3e4c134aecaeaebb8d643a46490ccddb82cc8a1a745c4cf7,
  seven files, six Valid Microsoft signatures.
- [TCPView inventory](../archive/evidence/sysinternals-tcpview-source-review-2026-10-17.json):
  1,604,604-byte ZIP, 4fc5ceba3e1b27ad95a24df35d094b454ec5f9478e12a8ca2b1b222705b9683b,
  eight files, six Valid Microsoft signatures.

No publisher archive checksum is claimed; integrity binds the observed archive and
member signatures. Each ZIP retains its Eula.txt. Independent product payloads
include ARM64 files absent from the reviewed x86/x64 Suite. Process Explorer and
Autoruns product ZIPs omit the help files present in Suite. Exact inventories govern;
no files are silently synthesized or borrowed. These differences do not establish
ARM64 support. Candidate apply targets remain empty, with Windows 11 acceptance pending.

Each stable product ID owns an independent folder. Users may select a product without
Suite, or keep separate copies. The existing lifecycle refuses unowned collisions
and modified managed files, captures exact recovery and preserves custom files. It
does not overlay the Suite or uninstall an external product. No driver, autostart,
process control, connection closure, tool launch, EULA or VirusTotal action occurred.
The first acquisition command failed at shell parsing before download; the corrected
file-based invocation acquired each official URL once. No GitHub request/retry occurred.

Validation: 24 focused tests passed per native PowerShell edition. They cover full
inventory/notice binding, no-discovery pinned resolution, changed-download refusal,
missing notices/corrupt archive refusal, repeat/remove/exact restore, custom/modified
file preservation and sibling Suite-folder isolation using inert fixtures. Repository
validation passed in both editions for 352 operations/eight groups/five profiles/224
PowerShell files. Cumulative comparison allows twelve pending additions and 124
presentation blocks; other baseline fields/groups remain unchanged. OPERATIONS updated.

Next: use the pinned serialized disposable-target workflow for independent and Suite
coexistence, user-created files, interrupted state, exact restore and explicit tool
launch acceptance. Keep driver activation and sensitive tool actions separate. Review
the rest of Suite product groupings/dependencies before adding them. Source recovery
removes only these candidate declarations and regenerates OPERATIONS; runtime recovery
uses existing versioned owned-file snapshots. Keep retained source caches/evidence.

Resolved: three individually selectable source candidates. Retired/excluded: none.
Partial: collection migration and remaining individual members. Deferred: native
target/tool/driver/GUI acceptance. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 /
8-12, rounded 145-200/about 175; these are parts of the same legacy Suite outcome,
not three completed legacy products.

## B11 Sysinternals diagnostic and imaging candidates, 2026-10-17

Process Monitor 4.12, RAMMap 1.63 and Disk2vhd 2.02 now have independently owned
portable candidates. Their official publisher pages and actual PE versions agree.
Each acquired archive preserves all content, Eula.txt and available help:

- [Process Monitor inventory](../archive/evidence/sysinternals-procmon-source-review-2026-10-17.json):
  3,202,206 bytes, 477754bf299c9e5b311c5666f7a4a48dfdb21265eaa8f0cca70ef9d9552e3a10,
  four members and three Valid Microsoft signatures.
- [RAMMap inventory](../archive/evidence/sysinternals-rammap-source-review-2026-10-17.json):
  737,190 bytes, 6536a8107a3fb391e4443f2742366067341a7da50de89f99ca0b2390120dd0cc,
  four members and three Valid Microsoft signatures.
- [Disk2vhd inventory](../archive/evidence/sysinternals-disk2vhd-source-review-2026-10-17.json):
  578,504 bytes, c294d279bf98645f84452989f320b561bf58609e35d85de47ea19ef583880821,
  five members and three Valid Microsoft signatures.

The publisher pages were dated 2026-10-15, 2026-03-26 and 2021-10-12 respectively.
Observed pins are not publisher-provided archive checksums. Mixed x86/x64/ARM64
payloads are retained without expanding support. SupportedTargets remain empty;
Windows 11 native acceptance and every additional architecture/target stay pending.
These products reuse independent owned-folder lifecycle, not the destructive legacy
Suite wrapper. They do not overlay Suite or infer ownership of external installations.

Staging does not load drivers, enable boot logging, record traces, change memory
lists, create VSS snapshots/images, mount virtual disks, decrypt volumes or accept
application prompts. The [Disk2vhd page](https://learn.microsoft.com/en-us/sysinternals/downloads/disk2vhd)
describes conversion limitations; package selection does not authorize altering
encryption or establish Windows imaging entitlement. Tool-use workflows remain
separate from this inert source acquisition. No program or driver was executed.

Validation: another 24 focused acquisition/owned-file tests passed in each native
PowerShell edition; the six-product fixture now has 48 distinct cases. An initial
FullName filter selected zero parameterized tests and is not counted as validation.
The fixture now accepts explicit ProductIds through a Pester data container, and
the runner requires exactly 24 passes. Previously passed products were not rerun.
Both repository validations passed for 355 operations/eight groups/five profiles/
224 PowerShell files; the subsequent fixture parameter edit was parsed by both
successful test runs. Cumulative comparison permits fifteen pending additions and
124 presentation blocks, with other baseline fields/groups unchanged. OPERATIONS updated.

Next: continue remaining member grouping and native ownership/recovery acceptance
through the serialized pinned disposable-target workflow. Schedule driver/tool,
trace-data, memory and imaging behavior explicitly, with independent recovery and
entitlement checks where applicable. Preserve generated user artifacts and external
copies. Source recovery removes only these three candidates and regenerates the
catalog documentation; runtime recovery uses existing exact file snapshots.

Resolved: three further individual source candidates. Retired/excluded: none.
Partial: the whole legacy Suite outcome and remaining member selection. Deferred:
native file/tool/driver/GUI/imaging acceptance. All five ranges remain 38-58 / 56-71 /
20-25 / 25-35 / 8-12, rounded 145-200/about 175; no legacy outcome is newly complete.

## B11 Sysinternals command-line candidates, 2026-10-17

Three further independent portable candidates use complete official Microsoft ZIPs.
Each contains x86/x64/ARM64 executables and Eula.txt; all nine executable signatures
were Valid Microsoft signatures, and actual PE versions match the publisher pages.
Observed archive pins (not publisher-supplied checksums):

- [sigcheck 2.93 inventory](../archive/evidence/sysinternals-sigcheck-source-review-2026-10-17.json): 682,449 bytes; 8756099c1ce3d3f450245c0d4b39aeb5b29309f56bf77f8c18f1469c418abf12.
- [strings 2.54 inventory](../archive/evidence/sysinternals-strings-source-review-2026-10-17.json): 547,485 bytes; b1a0a3dc5f639af1c98ae5832676727646eb3d543640e65e310dff747e733a25.
- [handle 5.0 inventory](../archive/evidence/sysinternals-handle-source-review-2026-10-17.json): 747,331 bytes; 279aaf8eccb6f79147f4dcc6ba091fb895c4cb8b199a0dd186a4c76bc519d2cd.

No scan, certificate inspection/change, remote reputation request/upload, handle
enumeration/closure, driver or tool launch occurred. The source inventories record
comparison with the whole Suite, while independent product folders retain separate
ownership. No EULA/service terms were accepted automatically. License references
and notices remain separate from private review status and public redistribution.

Validation: 24 new cases passed in each native PowerShell edition; the nine-product
fixture has 72 distinct cases, without rerunning previously passed products. Both
repository validations passed for 358 operations/eight groups/five profiles/224
PowerShell files. Cumulative comparison permits eighteen pending additions and 150
presentation blocks while preserving other baseline fields/groups. OPERATIONS updated.

Next: review remaining collection members, then use the serialized pinned disposable
target workflow for native owned-file repeat/restore/collision and explicit tool
acceptance. Keep handles, drivers and external lookups/uploads separate. Source
recovery removes only these declarations and regenerates OPERATIONS; runtime recovery
uses existing exact snapshots and preserves custom/modified files and Suite copies.

Resolved: three independent source candidates. Retired/excluded: none. Partial:
remaining member selection and whole legacy Suite outcome. Deferred: native file/
tool/driver/architecture behavior and selected-service acceptance. All five ranges
remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no new legacy
outcome closed.

## B10 final staged bundle integrity check, 2026-10-17

Source review found that per-file verification could become stale: a file copied
early could change while later files were copied, yet assembly could still report
Completed. A focused Windows PowerShell regression reproduced this with a same-length
edit to the staged engine file during the later profile copy; the previous module
incorrectly returned Completed. No real engine or installed target was involved.

OfflineBundle 0.5.0 now rechecks the complete staged manifest file set after all
copies and before writing commit metadata. Failure reports ReverifyStagedFiles and
the affected File Id, retains the staging directory, creates no final destination
and writes no completion metadata. VerifiedFileIds is rebuilt from that final pass,
so the failed file is not reported as verified. The CLI header is 0.2.0; manifest
schema and prior bundle versions are unchanged. The [operator guide](../offline-bundles.md)
explains the final pass and continued need to recheck after transfer/before use.

The regression first failed against the old implementation, then all 28 assembly
checks passed in each native PowerShell edition. The assembly checks were rerun
because the shared commit path changed; unrelated passed suites were not rerun.
Both repository validations passed for 358 operations/eight groups/five profiles/
224 PowerShell files. No acquisition, installer, VM or workstation configuration ran.

Next: preserve failed staging for inspection; correct sources and retry into a new
version directory. Native interrupted-copy/filesystem-resource acceptance and
offline installation integration remain pending. A final hash pass is a point-in-time
check, not protection against arbitrary later edits; installation must still preflight.
Source recovery reverts this final-pass change without changing the schema. No existing
bundle was replaced or automatically deleted, and ReadyForMutation remains false.

Resolved: a reproduced stale-integrity success condition. Retired/excluded: none.
Partial: full offline installer/dependency/engine-source integration. Deferred: native
resource/interruption/air-gap acceptance. All five ranges remain 38-58 / 56-71 /
20-25 / 25-35 / 8-12, rounded 145-200/about 175; shared preparation repair closes no
additional legacy outcome.

## Morning application handoff, 2026-10-17

The [consolidated handoff](remaining-migrations-follow-up.md#morning-handoff-2026-10-17) closes the extended 08:00 window. Six earlier package candidates plus Suite/nine individual products remain pending runtime acceptance. Final assembly 0.5.0 passed 28 checks per edition; individual Sysinternals products have 72 distinct checks per edition and whole Suite seven. No acquired program ran. Q17/Q20 retirements are already counted; remaining collection/dependency/native scope stays partial/deferred. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; this handoff closes no additional legacy outcome.

## B10 offline declared source comparison, 2026-10-17

The user directly resumed implementation after the morning handoff, using accepted
decisions from the separate decision ledger and deferring outstanding acceptance.
This is a new direct work instruction; the expired overnight automation remains paused.
The Windows-hosted checkout and unrelated/B01 work are preserved.

OfflineBundle 0.6.0 compares the selected variant's explicit DownloadUri with the
manifest artifact source. A mismatched host, case-sensitive path or query now
reports CatalogDownloadUriMismatch, including when version and payload SHA-256
match. CatalogDownloadUriComparison records Matched, Mismatch, NotDeclared or
NotCompared. Provider-resolved sources retain their separate provenance gate;
matching metadata never sets DownloadSourceVerified or ReadyForMutation true.

Procedure: supply the pinned catalog/profile with Test-RideOfflineBundle's existing
CatalogFileId option, inspect CoverageIssues and preserve failed/incomplete inputs.
Both Windows PowerShell 5.1 and PowerShell 7 passed all 63 focused profile-coverage
tests (58 existing plus five new cases). All fixtures are inert and local; no
network resolver, installer or developer-machine setting was invoked. Schema 1
remains readable, with additive result evidence and a stricter explicit source
comparison. Recovery is a focused source revert; no bundle or target state changed.

Latest accepted decision reconciliation: standalone YARA-X with explicit classic
compatibility; frozen NirSoft/JoeWare/MiTeC/NTCore review scopes; LOKI RS beta and
separately pinned signatures; separate VeraCrypt variants; WinPmem preparation
separate from capture; pinned KAPE definitions and separately reviewed executable
dependencies; four independently selectable CCleaner-family products. Exact
CCleaner editions/distributions remain pending. These decisions do not promote
any package, expand target support or authorize runtime collection/driver actions.

Resolved: explicit catalog download-source mismatches are detected. Retired/excluded:
no additional legacy outcome in this run (the decision ledger owns product choices).
Partial: offline packaging/source/dependency coverage and engine installation gate.
Deferred: publisher provenance for dynamic providers, entitlements and native/GUI/
driver acceptance. Next: optional byte-bound package coverage during local assembly,
then remaining selected-content/runtime integration and reviewed collections.
All five ranges were reviewed unchanged: 38-58 / 56-71 / 20-25 / 25-35 / 8-12,
rounded 145-200/about 175. Shared preparation does not close a whole legacy outcome.

## B10 assembly selected-profile gate, 2026-10-17

OfflineBundle 0.7.0 and New-RideOfflineBundle 0.3.0 add paired CatalogFileId and
CoverageProfileId options. Assembly now optionally compares byte-bound staged
catalog/profile data and selected package/dependency files before success metadata
or final-directory commit. Every explicitly selected profile must pass; unrelated
omissions and unselected incomplete profiles stay visible without blocking it.
Preview validates metadata/IDs only and reports Pending, never Passed.

Procedure: use the paired IDs from the manifest (both complete read-only), preview,
then assemble into a new destination. Inspect overall Status and CoverageStatus.
A failed check reports CheckProfileCoverage, FailedProfileId and coverage reports;
staging remains for recovery and no success metadata/final directory is produced.
Correct the inputs and choose a fresh destination. Existing integrity-only assembly
and schema-1 manifests remain supported. Completed assembly records add catalog ID,
selected profile IDs and coverage status; no source paths or private assessment enter
transferable metadata. The final whole-file recheck still follows coverage.

Both native Windows PowerShell 5.1 and PowerShell 7 passed all 48 assembly tests:
28 existing plus 20 new checks for selected/multiple profiles, missing declarations,
source mismatch, unrelated omissions, parser refusal, metadata bounds, preview,
completion, CLI, and mutation during coverage. All files were inert test fixtures.
No network, installer, workstation setting or VM change occurred.

Resolved: an explicit selected-package completeness gate during preparation.
Retired/excluded: none. Partial: engine provenance, complete non-package and hidden
installer dependencies, mandatory install/apply gate and native offline lifecycle.
Deferred: unresolved product/entitlement/elevation/GUI/driver acceptance. A passed
preparation check leaves ReadyForMutation false and does not supersede revalidation
after transfer or before deployment. Next: remaining setting presentation and
reviewed collection/integration work under the direct resumed instruction.
All five ranges were reviewed unchanged: 38-58 / 56-71 / 20-25 / 25-35 / 8-12,
rounded 145-200/about 175; this shared preparation feature closes no whole legacy outcome.

## Resumed-session decision reconciliation, 2026-10-17

The [latest setting/source record](settings-post-migration-review.md#b01-scheduled-task-observation-and-readback-2026-10-17) reconciles subsequent distribution/edition choices, the superseding shared-installer/licence-tier policy, optional TMOG and WinHex scope, separate mailbox viewers, historical tool retention and explicit profile/recovery-resource deferrals. Earlier statements that edition policy is unanswered are superseded; exact artifact equivalence and native activation-preservation remain technical evidence gates. This reconciliation introduces no product/default selection, runtime acceptance or legacy-count deduction. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.
