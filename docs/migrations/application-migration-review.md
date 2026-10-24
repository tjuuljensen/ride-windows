# Application migration and individual review ledger

Reviewed 2026-10-24 for current dispositions; the grouped review history below began on 2026-10-12. Every selector in the eight package families is assigned to one batch. Install/remove pairs count once; installed and portable distributions remain distinct outcomes. Existing accepted IDs retain their earlier evidence and support declarations. New distributions declare support only after target-specific acceptance and never enter recommended profiles automatically.

The [dated decision map](application-review-rounds-2026-10-12.md) assigns the original
79 review outcomes once across 13 groups. Q17/Q20 and the 2026-10-22 decisions to
retire Paradox Data Editor, Weather Agent and Mail Checker retire five outcomes;
the 2026-10-23 decision also retires classic Teams MSI cleanup, and the
2026-10-24 decision retires the obsolete Edge Legacy page-prediction selector,
leaving 72 pending/partial review outcomes. Historical mappings, dependencies and
individual ownership boundaries remain. First-round user choices keep both
ImageMagick distributions, GnuPG command line/Kleopatra without Explorer/Outlook
integration in current-user scope, and Wireshark live capture with a separate
interactive Npcap step without assumed OEM rights. The later decisions settle
ImageMagick portable scope/PATH and installed integrations, plus Wireshark scope,
associations and Npcap compatibility defaults. Q16/R01 source and Windows 11
ImageMagick package lifecycle/feature acceptance are verified; the current-source
rerun also confirms its minimum-version runtime preflight. The RIDE-managed v14
runtime lifecycle, activation, Server acceptance, and exact versions/Npcap terms
for remaining outcomes stay open. Do not reopen selected choices. The four
explicit retirements add no native acceptance; older publisher observations
below retain their original dates.

Batch 1 covers conventional installed applications and their adjacent bundled configuration/component issues. Batch 2 covers portable files, collections, repository downloads and deployed configuration. A review disposition accounts for the outcome without claiming migration or retirement.

Source references below identify the publisher declared by the legacy implementation. Their presence is not a fresh download or license approval. Current release observations are distinguished explicitly; remaining legacy implementations are in [lib-windows.psm1](../../legacy/v2/lib-windows.psm1). Opera's removed selector is retained below solely as a dated user-policy exclusion.

| Batch | Exact selectors / component | Intended outcome / disposition | Blocker and next decision or test | Source evidence |
| --- | --- | --- | --- | --- |
| 1 | `Install7Zip`, `Remove7Zip` | Previously migrated: `package.7zip` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://www.7-zip.org/) |
| 1 | `InstallGit4Win`, `RemoveGit4Win` | Previously migrated: `package.git-for-windows` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/git-for-windows/git) |
| 2 | `GetSysmonSwiftXML` | Previously migrated: `artifact.sysmon-swift-config` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml) |
| 1 | `InstallSysmon64`, `RemoveSysmon64` | Previously migrated: `package.sysmon64` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://download.sysinternals.com/files/Sysmon.zip) |
| 1 | `InstallGitLFS`, `RemoveGitLFS` | Previously migrated: `package.git-lfs` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/git-lfs/git-lfs) |
| 2 | `InstallPSScriptTools`, `RemovePSScriptTools` | Pending source candidate: `package.psscripttools` | Q15 selects the [pinned inert archive](#b08-psscripttools-source-candidate-2026-10-17) for normal deployment; editable Git workspaces and Gallery installation remain separate. Legacy copies a Git clone under Tools and removes the whole destination. The 3.2.0 MIT snapshot retains full source/notices and owned-file recovery. Windows 11 native deployment acceptance remains pending; runtime/import compatibility and Microsoft.PowerShell.Threadjob/System.Drawing ownership remain separate. Never auto-import or silently replace with Install-Module. | [Exact source/initialization review](../archive/migrations/application-winscp-follow-up-2026-10-11.md#psscripttools-repository-and-module-boundary) |
| 1 | `InstallVSCode`, `RemoveVSCode` | Accepted migration: `package.vscode` | Preview, install/repeat/remove and restoration of original absence passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; application behavior and prior-version recovery remain separate limits. | [Legacy publisher reference](https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user) |
| 1 | `InstallGPGwin` | Individual review: gpgwin | User confirmed current-user scope, GnuPG command line and Kleopatra only, without Explorer/Outlook integration, on 2026-10-12. Verify current-user scope in both the outer and nested GnuPG installers and explicit component exclusions before admission. Inspected 5.1.1 installer/source hashes and certificate are recorded; nested GnuPG install/removal can affect both registry views. Resolve dependency ownership, process handling and key/configuration preservation; outer EXE presence is insufficient recovery. | [Confirmed preparation choices](application-review-rounds-2026-10-12.md#confirmed-first-round-choices); [exact integrity/certificate reference](https://gpg4win.org/package-integrity.html); [source inspection](../archive/migrations/application-installed-follow-up-2026-10-11.md#gpg4win-component-and-dependency-preparation) |
| 1 | `InstallNotepadPlusPlus`, `RemoveNotepadPlusPlus` | Previously migrated: `package.notepadpp` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/notepad-plus-plus/notepad-plus-plus) |
| 2 | `GetSysmonOlafXML` | Partial migration: three pinned Sysmon Modular download-only artifacts for release `configs-a45dedb13a43`, target Sysmon 15.21 | User selected Balanced, Balanced with FileDelete and Excludes only. Each exact profile is verified against the pinned release SHA256SUMS before download. RIDE does not install Sysmon or apply configuration. Local mocked lifecycle and checksum checks pass; live acquisition, file preservation/recovery and user acceptance remain. | [Pinned upstream release](https://github.com/olafhartong/sysmon-modular/releases/tag/configs-a45dedb13a43); [dated record](#sysmon-modular-pinned-profile-artifacts-2026-10-23) |
| 1 | `InstallVMwareWorkstation`, `RemoveVMwareWorkstation` | Retired from v3 by user decision, 2026-10-24 | Do not implement these legacy package install/remove selectors or substitute another virtualizer. Preserve any existing installation; no cleanup or runtime change is implied. The separate VMware preference selectors remain tracked as application configuration. | [User decision](decision-session-2026-10-17.md#detect-it-easy-vmware-workstation-and-winpmem-scope-decisions-2026-10-24); [legacy publisher reference](https://www.vmware.com/go/getworkstation-win) |
| 2 | `SetVMDirUserhome` | Individual review: vmdiruserhome | VMware preference edit, not an install. Discover preferences.ini, capture the prior value and test exact current-user restore. | Legacy function defines local Windows/application state; see source. |
| 2 | `SetVMDirDocuments` | Individual review: vmdirdocuments | VMware preference edit, not an install. Resolve the Documents path, capture the prior value and test exact current-user restore. | Legacy function defines local Windows/application state; see source. |
| 1 | `InstallThunderbird` | Accepted migration: `package.thunderbird` | Confirmed Release x64/en-GB in current-user scope. Version 157.0.1 passed non-elevated install/repeat/remove, profile preservation and saved-selection recovery on Windows 11 and Server 2025 Desktop Experience. Each correlated batch passed 242 guest checks and seven lifecycles; temporary account/right cleanup and checkpoint recovery passed. Mail functionality and exact prior-version/association recovery remain separate limits. | [Correlated acceptance](../archive/migrations/application-thunderbird-follow-up-2026-10-11.md#accepted-migration-after-resumed-validation); [official release feed](https://product-details.mozilla.org/1.0/thunderbird_versions.json) |
| 1 | `InstallJoplin` | Previously migrated: `package.joplin` | Retain prior acceptance; see existing software disposition and verification records. No new Server support inferred. | [Legacy publisher reference](https://github.com/laurent22/joplin) |
| 1 | `InstallImageMagick` | Individual review: imagemagick | User confirmed the x64 Q16 HDRI DLL installer, all-user machine scope and machine PATH on 2026-10-12; optional integrations stay unselected on fresh installs and existing choices are preserved on adoption/upgrades, with requested changes previewed. Exact revision-bearing version/uninstall detection and environment recovery remain pending. | [Confirmed preparation choices](application-review-rounds-2026-10-12.md#confirmed-first-round-choices); [ImageMagick integration decision](decision-session-2026-10-17.md#imagemagick-optional-installed-integrations); [current publisher builds](https://imagemagick.org/download/#windows) |
| 2 | `InstallImageMagickPortable`, `RemoveImageMagickPortable` | Individual review: imagemagickportable | User confirmed this separate outcome and selected the listed x64 Q16 static portable build on 2026-10-12. The pinned Q16 package has passed Windows 11 lifecycle/recovery and bounded synthetic PNG acceptance; a current-source rerun also verifies the `vcomp140.dll` minimum-version preflight with Microsoft's v14 runtime. The RIDE-managed runtime prerequisite lifecycle and recovery, ImageMagick activation, and Server acceptance remain separate gates. | [Confirmed preparation choices](application-review-rounds-2026-10-12.md#confirmed-first-round-choices); [current publisher builds](https://imagemagick.org/download/#windows); [Windows 11 acceptance](../archive/evidence/imagemagick-q16-win11-acceptance-2026-10-23.json); [versioned preflight rerun](../archive/evidence/imagemagick-q16-versioned-prerequisite-win11-2026-10-24.json) |
| 1 | `InstallSignal` | Accepted migration: `package.signal` | Official stable x64 feed binds version/filename/SHA-512. Current-user lifecycle, repeat installation/removal, Roaming-profile preservation and compensating recovery passed on Windows 11 and Server 2025 Desktop Experience. Account linking and UI behavior remain separate. | [Correlated acceptance](../archive/migrations/application-installed-follow-up-2026-10-11.md#final-correlated-acceptance); [official update feed](https://updates.signal.org/desktop/latest.yml); [upstream uninstall-data configuration](https://github.com/signalapp/Signal-Desktop/blob/v8.30.0/package.json) |
| 1 | `InstallPython` | Individual review: python | User confirmed both selectable variants under one stable product ID on 2026-10-12: install manager default; traditional installer in all-user machine scope with unchanged machine PATH and preserved file associations; bundled/validated pip without automatic upgrade. These explicitly change legacy PATH/association/pip behavior. The 2026-10-17 policy, reaffirmed 2026-10-24, requires RIDE-managed preparation of explicitly selected pinned runtimes; implicit downloads are disabled, automatic acquisition is an explicit online option, and interpreter updates remain separate. On 2026-10-24, the user chose RIDE-controlled explicit updates for the Python Install Manager; its built-in automatic self-update is not enabled. Existing python/py behavior and associations are preserved by default; RIDE uses the selected interpreter directly. Manager-managed runtimes remain per-user even with a machine manager MSI. Exact compatible release pins, architecture, installer controls, launcher coexistence and recovery remain open. Verify exact installer controls, stable artifacts, dependency ownership and preservation/recovery; do not upgrade another interpreter or silently switch recorded variants. | [Publisher downloads](https://www.python.org/downloads/windows/); [confirmed integration choices](application-review-rounds-2026-10-12.md#confirmed-python-integration-choices); [manager scope](https://docs.python.org/3/using/windows.html#advanced-installation) |
| 2 | `InstallYara`, `RemoveYara` | Classic YARA compatibility option deferred by user decision, 2026-10-22 | Preserve the earlier selection of YARA-X as the default standalone engine and classic YARA as a separate compatibility option. No older classic-YARA binary/build route or silent engine substitution is selected; the reviewed stable release had source archives but no Windows binary. | [Current release evidence](https://github.com/VirusTotal/yara/releases/tag/v4.5.8); [dated availability check](../archive/migrations/application-winscp-follow-up-2026-10-11.md#yara-binary-availability-recheck) |
| 2 | `GetCyberChef`, `RemoveCyberChef` | Accepted migration: `package.cyberchef` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/gchq/CyberChef) |
| 2 | `InstallCaffeine`, `RemoveCaffeine` | Accepted migration: `package.caffeine` | Version 1.98 retains both x86/x64 files with an inspected archive hash pin. Preview, repeat install/remove, preservation and exact owned-file restore passed on Windows 11 and Server 2025 Desktop Experience. No automatic execution or startup entry. See continuation evidence. | [Current product/version reference](https://www.zhornsoftware.co.uk/caffeine/); [publisher terms](https://www.zhornsoftware.co.uk/) |
| 2 | `InstallPutty`, `RemovePutty` | Accepted migration: `package.putty` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) |
| 2 | `InstallWinSCP`, `RemoveWinSCP` | Accepted migration: `package.winscp` / `portable` | Official stable x86 6.5.7 ZIP matches publisher SHA-256. Preview, repeat install/remove, four-file ownership, executable signatures, unowned INI/registry-session preservation and exact owned-file recovery passed on Windows 11 and Server 2025 Desktop Experience. No application launch or Server Core support. | [Correlated acceptance](../archive/migrations/application-winscp-follow-up-2026-10-11.md#final-correlated-acceptance) |
| 2 | `InstallKAPE`, `RemoveKAPE` | Individual review: kape | Resolve exact publisher artifact/source, pinned definition inventory, executable dependencies and managed-file lifecycle; a pinned KapeFiles snapshot and separate refresh were already approved. Current publisher clarification excludes third-party-network/paid-engagement use while allowing internal company use; retain this distinction in the corporate licensing review. The user authorized a Defender exclusion limited to KAPE's dedicated install directory, with prior-state capture and removal only of the exclusion RIDE adds. Defer individual-file exclusions to v3.1; do not add a broad tools-directory exclusion or file allow action. Official CISA guidance documents antivirus/host-protection blocking for KAPE run from removable media, but the sources reviewed do not establish a KAPE-specific Defender detection or false positive. | [CISA KAPE collection procedure](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/2c5011c); [KAPEDocs FAQ](https://github.com/EricZimmerman/KapeDocs/blob/master/Pages/50-Frequently-asked-questions.md); [user report: MDE Live Response module validation, not Defender detection](https://github.com/EricZimmerman/KapeFiles/issues/1099); [Microsoft exclusion guidance](https://learn.microsoft.com/en-us/defender-endpoint/navigate-defender-endpoint-antivirus-exclusions); [licensing watchlist](../package-licensing.md#important-to-review-licensing) |
| 2 | `InstallVeraCrypt` | Individual review: veracrypt | Driver/reboot installation requires orchestrated reboot and retained-version recovery tests; ordinary EXE presence is insufficient. | [Legacy publisher reference](https://github.com/veracrypt/VeraCrypt) |
| 2 | `InstallVeraCryptPortable` | Individual review: veracryptportable | Portable self-extractor still loads a driver. Resolve driver ownership, cleanup/reboot and exact version recovery separately from file deployment. | [Legacy publisher reference](https://github.com/veracrypt/VeraCrypt) |
| 1 | `InstallADReplStatus`, `RemoveADReplStatus` | Deferred by user decision, 2026-10-24 | Keep the legacy outcome in v3's deferred scope; do not retire it based only on the 404 release endpoint. Reconsider only after establishing an authorized, compatible distribution and applicable domain/lab acceptance. The available source repository describes an early personal rebuild targeting .NET Framework 4.8.1, which is not approved for RIDE deployment. | [Publisher README and dependency evidence](https://github.com/ryanries/ADReplStatus); [scope decision](decision-session-2026-10-17.md#adrepstatus-remains-deferred-2026-10-24) |
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
| 1 | `RemoveTeamsWideInstaller` | Retired by user decision, 2026-10-23 | Retire the obsolete classic Teams MSI cleanup outcome. Do not substitute current Teams or infer cleanup of Outlook add-ins or user data. | [Microsoft availability evidence](https://learn.microsoft.com/en-us/microsoftteams/teams-classic-client-end-of-availability); [scope decision](decision-session-2026-10-17.md#windows-component-and-classic-teams-scope-decisions-2026-10-23) |
| 1 | `InstallVisioPro` | Individual review: visiopro | Q21 retains separate Visio Professional 2016 Retail and Plan 2 choices, no automatic replacement/licence conversion. Plan 2 uses ODT and assigned-user sign-in; accepted display default is en-US with explicit da-DK, preserving Office en-GB and additional/proofing review. Existing-product/version/channel/architecture compatibility, 2016 support status, publisher route and recovery remain open. | [Accepted Visio/language choices](decision-session-2026-10-17.md#q21-follow-up-visio-en-us-default-with-explicit-danish-alternative); [inert review](#b10-inert-office-configuration-review-2026-10-17) |
| 2 | `GetSysinternalsSuite`, `RemoveSysinternalsSuite` | Source-ready pending candidates: whole reviewed Suite plus nine independent products | The 164-file Suite snapshot and complete official product archives are pinned with retained notices. Remaining work is exact member selection, native ownership/recovery, and technical checks for any first-run prompt, driver, or tool behavior. Existing installations are not adopted automatically. Licensing is cleared for RIDE's direct download-and-install workflow under the prior RIDE v2 specialist approval; it is not an acceptance blocker. | [Suite inventory/candidate](#b11-sysinternals-reviewed-snapshot-candidate-2026-10-17); [latest individual product batch](#b11-sysinternals-command-line-candidates-2026-10-17) |
| 2 | `InstallJoeWare`, `RemoveJoeWare` | Individual review: joeware | The frozen 41-name collection remains an exact-source and technical review batch. The publisher permits internal corporate download and deployment under its 2024 clarification, so licensing does not block RIDE's direct download-and-install workflow. AdFind's AV/PUP warning is specific to AdFind; keep any Defender-blocked binary excluded and do not treat the warning as a collection-wide exclusion. Current AdFind/AdMod versions have advanced since the 2026-10-17 page snapshot; refresh exact source pins before candidate registration. | [2026-10-23 source/terms review](../archive/evidence/joeware-internal-use-current-version-review-2026-10-23.json); [collection inventory](../archive/evidence/joeware-collection-inventory-2026-10-17.json) |
| 2 | `InstallCCleaner`, `RemoveCCleaner` / CCleaner portable | Individual review: ccleaner | Four-product bundle must be split into CCleaner, Defraggler, Recuva and Speccy outcomes; select portable/installed artifacts and terms per product. | [Legacy publisher reference](https://www.ccleaner.com/ccleaner/download/portable) |
| 2 | `InstallCCleaner`, `RemoveCCleaner` / Defraggler | Individual review: ccleaner | Four-product bundle must be split into CCleaner, Defraggler, Recuva and Speccy outcomes; select portable/installed artifacts and terms per product. | [Legacy publisher reference](https://www.ccleaner.com/ccleaner/download/portable) |
| 2 | `InstallCCleaner`, `RemoveCCleaner` / Recuva | Individual review: ccleaner | Four-product bundle must be split into CCleaner, Defraggler, Recuva and Speccy outcomes; select portable/installed artifacts and terms per product. | [Legacy publisher reference](https://www.ccleaner.com/ccleaner/download/portable) |
| 2 | `InstallCCleaner`, `RemoveCCleaner` / Speccy | Individual review: ccleaner | Four-product bundle must be split into CCleaner, Defraggler, Recuva and Speccy outcomes; select portable/installed artifacts and terms per product. | [Legacy publisher reference](https://www.ccleaner.com/ccleaner/download/portable) |
| 2 | `InstallMitec`, `RemoveMitec` | Individual review: mitec; Paradox Data Editor, Weather Agent and Mail Checker retired from v3 | Legacy crawls changing EXE/ZIP links and filters trial/demo by filenames. Pin the remaining product list, versions and licenses; do not treat the whole website as one package. The user's 2026-10-22 decision drops these three products; preserve their source/security findings as history, but do not prepare them as selectable packages or pursue their BDE/network acceptance. | [Legacy publisher reference](http://www.mitec.cz); [retirement decision](decision-session-2026-10-17.md#package-licensing-and-selection-decisions-2026-10-22) |
| 2 | `InstallNtcore`, `RemoveNTCore` | Individual review: ntcore | Legacy downloads multiple linked EXE/ZIP artifacts. Identify intended tools, current versions and per-tool license/ownership; preserve independent outcomes. | [Legacy publisher reference](https://ntcore.com/?page_id=345) |
| 1 | `InstallTMOG`, `RemoveTMOG` | Individual review: tmog | Exact signed 1.0.1.0/Inno 6.7.0 payload includes notices and TMOG.scr with application/system destinations. Included free-edition license calls itself a release-candidate document requiring publisher approval and grants personal use; resolve applicable approved terms, unattended scope/screensaver controls and entitlement/configuration recovery. No activation or screen-saver execution. | [Current installer, license and component inspection](../archive/migrations/application-winscp-follow-up-2026-10-11.md#installed-candidates-requiring-review) |
| 1 | `InstallWireshark`, `RemoveWireshark` | Pending machine MSI candidate: `package.wireshark` | Q16 all-user install and separate association choice accepted. Official 4.6.9 MSI pinned with association components disabled; signature/hash and static tables verified. A Windows 11 build 26300 batch passed absent-to-installed, repeat and saved-run restoration to absence. No supported targets promoted: the explicit removal action, existing-installation transitions, global/user content, shared runtime, association preservation and exact recovery still need separate disposable acceptance. | [Current candidate evidence](#b08-wireshark-machine-msi-candidate-2026-10-17); [2026-10-22 batch evidence](../archive/evidence/applications-batch1-acceptance-2026-10-22.json); [historical NSIS analysis](../archive/migrations/application-installed-follow-up-2026-10-11.md#wireshark-silent-install-and-unowned-content-preparation) |
| 2 | `InstallZimmermanTools`, `RemoveZimmermanTools` | Reviewed membership accepted; pinned acquisition/helper integration pending | The decision session selects 26 members with compatible pinned maps/batch definitions and separate refresh preserving custom content. Replace the mutable execution/destructive-copy wrapper; retain useful updater intent. Immutable upstream-helper inspection, bounded failure tests and payload provenance remain pending under GitHub backoff. | [Accepted collection and helper review](decision-session-2026-10-17.md); [historical upstream source](https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1) |
| 2 | `InstallNirsoftLauncher`, `RemoveNirsoftLauncher` | Authorized v3 whole-collection package preparation; member-level handling deferred to v3.1 | Use the frozen collection source and current non-restrictive package rules. Do not add automatic per-file exclusions or allow actions. The 2026-10-24 decision permits reviewed exclusions only for selected packages' RIDE-managed install directories, with prior-state capture and removal only of exclusions RIDE added; do not exclude shared roots, Downloads or individual files. If alerts remain at v3.1 file handling, submit them for the user's manual review. Safe archive lifecycle and target acceptance remain pending. | [Decision and scope](decision-session-2026-10-17.md#additional-migration-dispositions-2026-10-22); [package exclusion lifecycle](decision-session-2026-10-17.md#package-scoped-defender-exclusions-and-deferred-yarasysmon-work-2026-10-24); [legacy publisher reference](https://launcher.nirsoft.net/downloads/index.html) |
| 2 | `InstallNirsoftToolsX64`, `RemoveNirsoftToolsX64` | Authorized v3 whole-collection package preparation; member-level handling deferred to v3.1 | Use the frozen collection source and current non-restrictive package rules. Do not add automatic per-file exclusions or allow actions. The 2026-10-24 decision permits reviewed exclusions only for selected packages' RIDE-managed install directories, with prior-state capture and removal only of exclusions RIDE added; do not exclude shared roots, Downloads or individual files. If alerts remain at v3.1 file handling, submit them for the user's manual review. Safe archive lifecycle and target acceptance remain pending. | [Decision and scope](decision-session-2026-10-17.md#additional-migration-dispositions-2026-10-22); [package exclusion lifecycle](decision-session-2026-10-17.md#package-scoped-defender-exclusions-and-deferred-yarasysmon-work-2026-10-24); [legacy publisher reference](https://www.nirsoft.net/x64_download_package.html) |
| 2 | `InstallNirsoftPkgFiles`, `RemoveNirsoftPkgFiles` | Individual review: nirsoftpkgfiles | Package/config files belong to the launcher integration outcome. Pin revision and capture existing configuration before replacing or removing files. | [Legacy publisher reference](https://launcher.nirsoft.net/downloads/index.html) |
| 2 | `InstallArsenalRecon` / Arsenal products | Individual review: arsenalrecon | Legacy crawls MEGA links and also installs MEGAcmd. Select actual Arsenal products, licensed distribution, drivers and VM/AV side effects; account for MEGAcmd separately. | [Legacy publisher reference](https://mega.nz/MEGAcmdSetup64.exe) |
| 2 | `InstallArsenalRecon` / MEGAcmd helper | Individual review: arsenalrecon | Legacy crawls MEGA links and also installs MEGAcmd. Select actual Arsenal products, licensed distribution, drivers and VM/AV side effects; account for MEGAcmd separately. | [Legacy publisher reference](https://mega.nz/MEGAcmdSetup64.exe) |
| 1 | `InstallWinget` | Individual review: winget | App Installer MSIX plus dependencies needs AppX lifecycle, minimum OS and per-user/provisioned scope. Do not substitute an EXE package or enable updates implicitly. | [Legacy publisher reference](https://aka.ms/getwinget) |
| 1 | `InstallWingetAutoUpdate` | Individual review: wingetautoupdate | Automatic maintenance changes tasks/service/configuration beyond package presence. Declare update policy and capture each reversible component before admission. | [Legacy publisher reference](https://github.com/Romanitho/Winget-AutoUpdate) |
| 1 | `InstallRSAT`, `RemoveRSAT` | Individual review: rsat | Windows capabilities on client and features on Server differ. Use a Windows-component handler with edition/build applicability and exact feature-state recovery. | Legacy function defines local Windows/application state; see source. |
| 1 | `InstallOpenJDK` | User selected independent Java packages on 2026-10-23: Microsoft OpenJDK 25 default plus 21/17/11 compatibility versions | This is an independent Java use case, not a BloodHound dependency. Carry JDK 21, 17 and 11 as explicit compatibility choices alongside the previously selected JDK 25 default. Preserve side-by-side installs and existing `JAVA_HOME`, `PATH` and `.jar` associations by default. Exact patch pins, artifact sources, installer/recovery behavior and native acceptance remain open. | [Scope decision](decision-session-2026-10-17.md#package-and-profile-scope-decisions-2026-10-23); [publisher downloads](https://learn.microsoft.com/en-us/java/openjdk/download); [support roadmap](https://learn.microsoft.com/en-us/java/openjdk/support) |
| 1 | `InstallNeo4j` | Deferred by Q20 pending an independent use case: neo4j | Corrected source reading 2026-10-12: legacy downloads a Neo4j Community Windows ZIP and a separate APOC JAR, replaces the Tools destination, enables unrestricted apoc.* procedures, and installs/starts a service. It does not use APOC as a Neo4j installer. Retain deferred scope until an independent server/plugin use case is identified; verify exact Neo4j/APOC/Java compatibility and preserve database/configuration/credentials/service state. Broad procedure permissions and directory replacement are not implicitly approved. | [Legacy selector](../../legacy/v2/lib-windows.psm1); [legacy APOC publisher](https://github.com/neo4j-contrib/neo4j-apoc-procedures); [corrected contract](application-review-rounds-2026-10-12.md#corrected-neo4j-legacy-contract) |
| 2 | `GetBloodhound`, `RemoveBloodhound` | User selected BloodHound CE backend 9.8.0 on 2026-10-23; deployment contract and acceptance remain open | Keep the selected version independent of Java package scope. Docker Desktop is a separate Windows 11 package (`package.docker-desktop`) with per-user and all-users variants, enabled and ready for physical-machine RIDE review. The user reports that the latest WinGet Docker Desktop installation succeeded on a physical computer; this validates the publisher installer on that host, not RIDE state capture or recovery. Disposable Hyper-V guest runs on 2026-10-20 passed guest Pester but the per-user installer exceeded 20/60-minute limits and the all-users request exceeded 90 minutes; that VM environment is not Docker's documented supported VM/VDI configuration. RIDE install/repeat/detection, saved-run recovery and uninstall with Docker data preserved remain unverified for both scopes. Verify the selected CE 9.8.0 backend and collector compatibility before implementation. Keep WSL, Windows features, app launch, images, backend configuration, data/credentials/network ownership and recovery outside package acceptance until explicitly designed. Docker Desktop does not support Windows Server. | [Scope decision](decision-session-2026-10-17.md#package-and-profile-scope-decisions-2026-10-23); [confirmed R03 preparation](application-review-rounds-2026-10-12.md#r03-preparation-review-2026-10-12); [publisher deployment](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) |
| 2 | `GetSharphound`, `RemoveSharphound` | Selected optional collector; CE 9.8.0 pins SharpHound v2.17.0 | The official CE v9.8.0 Dockerfile pins the bundled collector to v2.17.0 and names the x86 ZIP plus `.sha256` sidecar. Prepare this exact stable version for owned portable lifecycle; do not use rolling/latest builds. No collection or backend setup is implied. | [Scope decision](decision-session-2026-10-17.md#package-and-profile-scope-decisions-2026-10-23); [CE v9.8.0 collector pin](https://raw.githubusercontent.com/SpecterOps/BloodHound/v9.8.0/dockerfiles/bloodhound.Dockerfile); [SharpHound source and license](https://github.com/SpecterOps/SharpHound/tree/v2.17.0) |
| 2 | `GetAzurehound`, `RemoveAzurehound` | Selected optional collector; CE 9.8.0 pins AzureHound v3.1.1 | The official CE v9.8.0 Dockerfile pins AzureHound v3.1.1 and checksums its platform archives before packaging them for the CE collector endpoint. Prepare the exact stable Windows amd64 release for owned portable lifecycle; do not use rolling/latest builds. GPL-3.0-or-later license and notices remain alongside the selected archive. No collection, authentication or backend setup is implied. | [Scope decision](decision-session-2026-10-17.md#package-and-profile-scope-decisions-2026-10-23); [CE v9.8.0 collector pin](https://raw.githubusercontent.com/SpecterOps/BloodHound/v9.8.0/dockerfiles/bloodhound.Dockerfile); [AzureHound source and license](https://github.com/SpecterOps/AzureHound/tree/v3.1.1); [earlier artifact observation](#b08-azurehound-stable-artifact-preparation-2026-10-17) |
| 2 | `GetImproHound`, `RemoveImprohound` | Retired by explicit user decision, 2026-10-17: planned ImproHound deployment | Q20 closes the planned deployment outcome. Preserve existing installation, license and data; do not uninstall or adopt. BloodHound CE is not asserted to replace its historical tiering-analysis workflow. | [Accepted retirement](#accepted-volatility-2-and-improhound-retirements-2026-10-17); [historical role/dependency review](../archive/migrations/application-winscp-follow-up-2026-10-11.md#improhound-role-and-dependency-reconciliation) |
| 2 | `GetPingCastle`, `RemovePingCastle` | User selected as an optional, independently selectable v3 AD assessment tool on 2026-10-24 | This does not make PingCastle a BloodHound dependency or authorize execution. Review current license and supported distribution, pin the exact edition/version, and verify executable/dependency compatibility before deployment. Domain/lab acceptance remains separate. | [Legacy publisher reference](https://github.com/vletoux/pingcastle); [scope decision](decision-session-2026-10-17.md#python-install-manager-updates-and-pingcastle-scope-2026-10-24) |
| 1 | `InstallVirtIOGuestTool` | Individual review: virtioguesttool | Virtio-win publishes Windows KVM/QEMU guest drivers and a guest-tools installer that bundles VirtIO drivers with the SPICE agent/driver. Select drivers for the devices actually exposed; verify signing, package version and recovery on a matching disposable QEMU guest. Hyper-V cannot establish applicability. | [Legacy publisher reference](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio) |
| 1 | `InstallSpiceGuestTool` | Individual review: spiceguesttool | GNOME documents spice-guest-tools for Windows guest integration; upstream SPICE says its installer includes QXL and the SPICE agent/driver. The VirtIO guest-tools bundle may already supply these, so avoid duplicate installation. Verify the exact GNOME Boxes release, guest devices and recovery on a matching QEMU guest; Hyper-V cannot establish this. | [Legacy publisher reference](https://spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe) |
| 1 | `InstallSpiceWebDAV` | Individual review: spicewebdav | The user selected this as a separate optional QEMU guest folder-sharing integration on 2026-10-23. Upstream SPICE states spice-webdavd is separate from the guest-tools installer. Do not install by default; verify exact artifact, service, sharing and recovery on a matching QEMU guest. Hyper-V is not acceptance. | [Scope decision](decision-session-2026-10-17.md#wsl-net-35-and-qemu-guest-integration-decisions-2026-10-23); [legacy publisher reference](https://spice-space.org/download/windows/spice-webdavd/spice-webdavd-x64-latest.msi) |
| 1 | `DisableEdgePagePrediction` | Retired from v3 by user decision, 2026-10-24 | The selector targeted obsolete Edge Legacy behavior. Do not replace it with the current Edge `NetworkPredictionOptions` policy; that would be new scope. No setting operation or Windows acceptance is inferred. | [Microsoft lifecycle evidence](https://learn.microsoft.com/en-us/lifecycle/announcements/edge-legacy-eos-details); [separate current policy reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/networkpredictionoptions) |
| 1 | `InstallFirefox`, `RemoveFirefox` | Accepted migration: `package.firefox` | Preview, install/repeat/remove and restoration of original absence passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; application behavior and prior-version recovery remain separate limits. | [Legacy publisher reference](https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US) |
| 2 | `CreateFirefoxPreferenceFiles`, `RemoveFirefoxPreferenceFiles` | Individual review: firefoxpreferencefiles | Legacy deploys prefs.js and search data. Choose enterprise policy versus user-file intent, pin data and capture/restore existing profile files. | [Legacy publisher reference](https://developer.mozilla.org/en-US/Firefox/Enterprise_deployment) |
| 1 | `InstallChrome`, `RemoveChrome` | Accepted current pin on Windows 11 and Windows Server 2025: `package.chrome` | Historical version 155.0.8059.40 acceptance passed on Windows 11 and Server 2025 Desktop Experience, but does not establish the newly served bytes. On 2026-10-22 the current publisher MSI was inspected as 156.0.8078.48, 170,979,328 bytes, SHA-256 `a31bd8a4746069a128bf3beefdaa246c792af5f15bbf06af0259abc895c9609b`, with valid Google LLC Authenticode. It was executed on both registered disposable VMs after the pin refresh. Windows 11 build 26300 and Server 2025 build 26100 passed install/repeat/removal, profile preservation and compensating recovery at 156.0.8078.48. The catalog now supports both targets; prior version acceptance remains historical. Browser-policy and language overrides remain separate. | [Historical correlated acceptance](../archive/migrations/application-installed-follow-up-2026-10-11.md#final-correlated-acceptance); [2026-10-22 batch evidence](../archive/evidence/applications-batch1-acceptance-2026-10-22.json); [exact refreshed MSI pin evidence](../archive/evidence/chrome-enterprise-msi-pin-2026-10-22.json); [enterprise distribution](https://chromeenterprise.google/download/); [official MSI source](https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi) |
| 2 | `CreateChromePreferenceFile`, `RemoveChromePreferenceFile` | Individual review: chromepreferencefile | Legacy writes preferences from obsolete Chromium source mappings. Reconcile each current policy/key and capture existing profile data before deployment. | [Legacy publisher reference](https://src.chromium.org/viewvc/chrome/trunk/src/chrome/common/pref_names.cc) |
| 1 | `InstallOpera` | Excluded by user: Opera | User trust-policy decision on 2026-10-11: remove from the repository and future migration scope. Legacy installer/preset entry removed; no v3 package or remaining product choice. Historical selector retained solely for accounting. | [Dated exclusion](../archive/migrations/application-winscp-follow-up-2026-10-11.md#opera-exclusion-by-user-decision) |
| 1 | `InstallAutopsy` | Accepted migration: `package.autopsy` | Preview, install/repeat/remove and restoration of original absence passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; application behavior and prior-version recovery remain separate limits. | [Legacy publisher reference](https://github.com/sleuthkit/autopsy) |
| 2 | `InstallNetworkMiner`, `RemoveNetworkMiner` | Accepted migration: `package.networkminer` | Fixed-version free edition 3.2 matches publisher page SHA-256; whole nested distribution and notices retained. Preview, repeat install/remove, preservation and exact owned-file restore passed on Windows 11 and Server 2025 Desktop Experience. Runtime/forensic analysis remains separate acceptance. See continuation evidence. | [Current fixed-version distribution and checksum](https://www.netresec.com/?page=NetworkMiner); [GPLv2 reference](https://www.netresec.com/?page=NetworkMinerSourceCode) |
| 2 | `InstallAutorunner`, `RemoveAutorunner` | Individual review: autorunner | Latest-release endpoint returned HTTP 404, but source/README remain available. Publisher requires x64/.NET Framework 4.7.2 and describes privileged forensic-image access and a Sigcheck dependency. Establish a licensed binary/build, pin dependencies and keep deployment separate from investigation execution. | [Publisher README and dependency evidence](https://github.com/woanware/autorunner) |
| 2 | `InstallChainsaw`, `RemoveChainsaw` | Accepted migration: `package.chainsaw` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/WithSecureLabs/chainsaw) |
| 2 | `GetChromeParser`, `RemoveChromeParser` | Individual review: chromeparser | Pending package.chromeparser retains the complete pinned source/README/MIT archive. Python 3.12.14 syntax parsing passed without execution. Static follow-up found Windows default discovery handles only release labels 7/XP, the README and code paths differ, SQLite opens read-write, and -f truncates its output before the database is opened; aliasing input and output can destroy the database. Do not execute against live profiles/evidence. Disposable file lifecycle may be tested independently, but parser runtime, modern schema, read-only input/output safety and target acceptance remain open. See the [source batch](#b08-pinned-python-source-candidates-2026-10-16) and [2026-10-22 static review](#chromesyncparser-static-source-safety-review-2026-10-22). | [Pinned source evidence](../archive/evidence/python-script-source-review-2026-10-16.json); [legacy publisher reference](https://raw.githubusercontent.com/marleyjaffe/ChromeSyncParser/master/ChromeParser.py) |
| 2 | `InstallCyLR`, `RemoveCyLR` | Accepted migration: `package.cylr` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/orlikoski/CyLR) |
| 2 | `InstallDejsonlz4`, `RemoveDejsonlz4` | Accepted migration: `package.dejsonlz4` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/avih/dejsonlz4) |
| 2 | `GetHex2text`, `RemoveHex2text` | Individual review: hex2text | Pending package.hex2text retains the pinned script/README/GPLv3 archive. Static review confirms literal-space removal, one code point per complete four-digit group, silent incomplete-suffix loss, and uncaught `ValueError` for invalid complete groups; it is not UTF-8 byte decoding. Surrogate/display behavior, user input and native file lifecycle remain unverified. No implicit interpreter install; see the [source batch](#b08-pinned-python-source-candidates-2026-10-16) and [2026-10-22 static review](#hex2text-static-behavior-review-2026-10-22). | [Pinned source evidence](../archive/evidence/python-script-source-review-2026-10-16.json); [legacy publisher reference](https://raw.githubusercontent.com/gh05t-4/hex2text/master/hex2text.py) |
| 2 | `InstallHindsight`, `RemoveHindsight` | Accepted migration: `package.hindsight` | Preview, install/repeat/remove, file preservation and saved-selection restore passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; runtime/forensic function remains separate acceptance. | [Legacy publisher reference](https://github.com/obsidianforensics/hindsight) |
| 1 | `InstallSqlitebrowser` | Accepted migration: `package.sqlitebrowser` | Preview, install/repeat/remove and restoration of original absence passed on Windows 11 and Server 2025 Desktop Experience. See dated acceptance evidence; application behavior and prior-version recovery remain separate limits. | [Legacy publisher reference](https://download.sqlitebrowser.org) |
| 2 | `GetShimCacheParser`, `RemoveShimCacheParser` | Retired from v3 by user decision, 2026-10-24 | Preserve the historical Apache-2.0 source and Python 2 compatibility review. Do not port, package, install or substitute another parser under this legacy outcome. No obsolete runtime is installed. | [Source review](#b08-pinned-python-source-candidates-2026-10-16); [scope decision](decision-session-2026-10-17.md#exiftool-zimmerman-hasher-and-shimcacheparser-decisions-2026-10-24) |
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
| 2 | `InstallWinPmem`, `RemoveWinPmem` | Required v3 tool preparation, reaffirmed 2026-10-24 | Include a pinned acquisition executable as a deployable tool; keep driver loading and memory capture explicit actions. Signing, Secure Boot/current-build support, driver cleanup, reboot reporting and exact recovery remain technical gates before execution or target support. | [User decision](decision-session-2026-10-17.md#detect-it-easy-vmware-workstation-and-winpmem-scope-decisions-2026-10-24); [publisher documentation](https://github.com/Velocidex/WinPmem) |
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

## B08 PSScriptTools lifecycle continuation, 2026-10-17

Q15 is settled: normal deployment uses the pinned inert 3.2.0 snapshot. The
original `InstallPSScriptTools` cloned mutable Git source into bootstrap and
replaced the entire Tools destination; `RemovePSScriptTools` removed that tree.
Neither original selector imported the module. The accepted snapshot model
replaces those acquisition/deletion semantics with retained pinned source and
owned-file preservation; it does not migrate an editable Git workspace.

The fixture now uses all 360 reviewed members instead of only ten required files.
An explicit `RIDE_PSSCRIPTTOOLS_FIXTURE_ARCHIVE` selects the already retained ZIP
only after its digest matches both the catalog and acquisition evidence. All
destinations are isolated TestDrive paths; no upstream module or script is
imported/executed and no dependency is installed. Coverage includes complete-file
repeat/remove/exact-hash recovery, unowned output, modified source, unowned
destination collisions, damaged recovery bytes and prior absence. JSON-round-trip
snapshots exercise the saved-state representation. The [source index](../archive/evidence/psscripttools-lifecycle-2026-10-17.json)
retains the exact handler/fixture baseline independently of later offline work.
Local validation passed **7/7** with zero failures/skips on Windows PowerShell
5.1.26100.9711 and PowerShell 7.6.5, using the actual retained ZIP. Durations were
811.45 and 2165.07 seconds respectively. Logs are
`.local/closure-psscripttools-powershell.log` and
`.local/closure-psscripttools-pwsh.log`. These runs loaded portable handler 0.3.0;
the later B10 offline branch and B01 presentation changes have separate recorded
checks. No acquired script/module was imported or executed.

Native Windows 11 engine/destination acceptance remains pending: the host token
is not elevated and direct Hyper-V CIM access is denied. Do not submit a broad
application suite or refresh protected controllers/pins to bypass this gate.
Next native case must stage this exact ZIP/current source in the existing serialized
disposable workflow, capture the engine run, verify repeat/owned removal/modified
preservation/exact recovery, retain evidence and restore its pinned checkpoint.
Import/dependency/function compatibility stays separate and unverified.

No legacy outcome is closed, retired or excluded. PSScriptTools remains partial;
its native acceptance is deferred on the concrete access/resource gate. All five
ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about
175**. The next independent closure candidate is B10's mandatory offline gate.

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
19 accepted migrations, one exclusion, four explicit retirements and 75 pending/
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
The acquisition record identifies the exact publisher-provided bytes; the later
RIDE v2 license-specialist approval governs RIDE's direct download-and-install
workflow. This source inventory does not create a separate publication-rights
or per-owner licensing gate for that approved workflow.

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

## B10 offline execution gate, 2026-10-17

Explicit `install`/`apply` now require `-OfflineBundle`, `-OfflineProfileId` and
`-OfflineCatalogFileId` together. The engine verifies byte-bound profile/catalog
coverage, the running source files, exact ordered plan, target/build/edition/
architecture and selected payloads/notices before state capture or any handler.
Read leases remain held through execution. Manifest-derived completion is read-only.
The initial execution subset is accepted portable packages with one inert payload
and no dependency actions. Settings/removals, servicing, executable installers,
libraries, pending candidates and unresolved dependencies fail before mutation.
No acquisition fallback is used. Offline deployment skips certificate-provider
inspection and records `NotInspectedOffline`; it makes no signature-validity claim.

Validation on Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5: **162/162**
combined offline execution/CLI/portable ownership/application checks per edition,
including **28** offline cases; **25/25** package-evidence checks per edition.
The combined suite exposed CLI-spy module unloading; its teardown now restores
the original real module exports, and both complete reruns passed. Repository
validation passed **358 operations, eight groups, five profiles and 227 PowerShell
files**, with generated documentation current. Fixtures use inert isolated files
and mocked system calls; they do not establish disconnected native acceptance.
The [source and result index](../archive/evidence/offline-execution-2026-10-17.json)
records this baseline. See the [operator procedure](../offline-bundles.md#execute-an-explicitly-selected-offline-package-bundle).

Next acceptance: stage the exact source and a complete accepted portable profile
on a disposable declared Windows target; disconnect networking; verify preview,
apply/repeat, missing/altered file refusal before changes, preserved user content
and saved-run restore. Retain results and restore the pinned checkpoint. Hyper-V
CIM access is denied to this session's non-elevated token, so that native run is
deferred; no protected controller or VM pin was changed. Extend installer and
dependency coverage only with explicit no-network execution contracts and tests.

No whole legacy outcome is resolved, retired or excluded. B10 is partial;
disconnected acceptance and broader installer/component coverage remain counted.
All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded
**145-200/about 175**. The implementation advances preparation without deducting
unfinished product outcomes. Next independent source work is the remaining
presentation review; Clipchamp remains dependent on serialized VM access.

## B11 collection continuation, 2026-10-17

The next independent collection batches advance source preparation under the
standing continuation authorization. The catalog now contains **360 operations:
58 packages, 279 settings, one artifact and 22 Store declarations**, with eight
groups and five profiles. **Eighteen continuation package candidates remain
pending; 31 packages were pending in the full catalog, including 13 Artcraft
candidates.** The later named-collection audit corrected this counting scope. All
279 setting presentations retain their prior review; this run changes no setting
metadata, profile selection or supported target. The [result index](../archive/evidence/collection-continuation-2026-10-17.json)
binds the focused source files and local validation results.

### Selected ZIP files and NTCore candidates

PortablePackages 0.5.0 supports optional `PortableMembers`: an exact file list
bound to the declared archive SHA-256. Catalog validation requires a bounded,
safe, unique list containing every required file. Extraction validates all ZIP
entry paths, links, duplicates and declared size bounds, but stages only selected
files. A missing selected member fails before product writes. Existing ownership,
modified-file preservation and saved-file recovery remain in effect. Packages
without this field retain whole-archive behavior. The catalog generator 0.16.0
renders selections in OPERATIONS; full cached archive contents are still separate
from the deployment selection and any distribution approval.

Two candidates are source-ready, with `PendingAcceptance = true` and empty
`SupportedTargets`:

- `package.ntcore-pe-detective`: pinned PE Detective 1.2.1.1, bundled Signature
  Explorer 2.0.0.0 and five signature databases; seven files, x86 executables.
  [Source evidence](../archive/evidence/ntcore-pe-detective-source-review-2026-10-17.json)
  retains the acquired archive digest, member hashes and embedded copyrights;
  its evidence does not claim a publisher-provided digest comparison.
- `package.ntcore-cff-explorer`: pinned standalone CFF Explorer 8.0.0.0, x86,
  and five signature databases. Six selected files omit ten SDK, source example,
  script and optional UPX files. This does not deliver the entire installed
  Explorer Suite. [Source evidence](../archive/evidence/ntcore-cff-explorer-source-review-2026-10-17.json)
  records both selection and omissions. Publisher freeware descriptions and
  embedded copyright are retained; neither archive supplies a separate license
  file. Individual/company distribution review remains in its independent store.

The retained archives passed isolated TestDrive file installation, repeat,
removal, exact restoration, modified-database preservation and unowned-file
collision checks. No acquired executable was launched, registered, used to patch
another file or allowed to update signatures. These are file lifecycle checks,
not native functionality acceptance. [4GB Patch evidence](../archive/evidence/ntcore-4gb-patch-source-review-2026-10-17.json)
records its inert archive/version inspection. No product-specific publisher
license grant was established. On 2026-10-22 a pinned pending package candidate
was added per the user's migration priority and marked `NeedsReview` in the
private version-specific store; this does not assert entitlement or distribution
permission. No binary was launched or target executable patched.

### NirSoft inspection stopped after protection alerts

The first NirLauncher response was an HTML referer error, retained as rejected
input. One corrected official request supplied the publisher page referer and
acquired version 1.30.26 with the published matching SHA-256. Its central directory
contains 668 entries. Installed 7-Zip 26.04 extracted the archive for inspection
using the publisher's public password; no utility or launcher was executed.
Extraction reported 668 files, but the subsequent observation found 667, with
`NirSoft/bulletspassview.exe` missing. Reading `NirSoft/chromecookiesview.exe`
then failed with Windows' virus/potentially unwanted software error. The user
reported Defender alerts for both files. This is **incomplete member verification**,
not evidence that every extracted file matched the archive. The [central inventory](../archive/evidence/nirlauncher-source-inventory-2026-10-17.json)
preserves archive-level proof and the failed inspection separately.

The separate x64 ZIP has 49 recorded files. Its [partial source inventory](../archive/evidence/nirsoft-x64-source-review-2026-10-17.json)
retains hashes/version metadata where reading succeeded and explicit unavailable
members. The user reported alerts for `ProduKey.exe` and `WirelessKeyView.exe`.
Matching NirLauncher member names do not prove identical versions or bytes;
`SameSha256 = null` means unknown, not different. Both source identities and
the unresolved overlap remain recorded. All NirSoft payload inspection has
stopped. No restoration, allow action, exclusion, protection change or
re-extraction was performed. No false-positive or safety determination is made.
Neither collection entered the catalog. Licensing, ownership/configuration,
encrypted-archive lifecycle and native acceptance remain blocked or incomplete.

The user also reported `Downloads/PowerISO9-x64.exe`, then identified the
detection as `PUADlManager:Win32/Sepdot` dated **2025-11-25 07:22**. That historical
report predates this run and is separate from the current NirSoft alerts. This
run did not open or execute that installer or query/change its protection state.
The [blocker record](../archive/evidence/collection-continuation-blockers-2026-10-17.json)
keeps the user report and its date without attributing it to this acquisition.

### Validation, remaining gates and next batch procedure

Windows PowerShell **5.1.26100.9711** and PowerShell **7.6.5** each have **191
distinct passing checks** across PortableSelection, ApplicationPackages,
PortableManifest, NtcorePackages and Catalog. The first combined run passed 100
and failed 13 because the new fixture's repository-root variable collided with
its case-root variable. The fixture was corrected; all 21 PortableSelection
checks then passed in both editions, retaining the other 92 passing checks.
NtcorePackages/Catalog added 78 passes per edition with one native integration
case excluded. Counts do not add repeated checks. Repository validation passed
360 operations, eight groups, five profiles and 229 PowerShell files in both
editions; generated documentation is current.

Zimmerman immutable source pinning remains blocked by the anonymous GitHub API
rate limit. No retry, credential request or mutable updater execution followed.
OpenSSH Client/Telnet preparation remains non-executable: matching source
completeness, policy/dependencies and durable servicing recovery are required
before writers. Previously denied non-elevated Hyper-V CIM access still blocks
VM acceptance, including Clipchamp and the NTCore candidates. No controller,
checkpoint pin or protection settings were changed. New deployment profiles and
BitLocker/recovery resource setup remain explicitly deferred.

Next independent work starts at the repository root: review the existing R05
named JoeWare/MiTeC/remaining NTCore scope and official source/license evidence,
or complete component source/dependency/recovery contracts when inputs exist.
Keep protected NirSoft files out of further inspection, acquisition retries and
deployment. Do not treat an unavailable source, API limit or VM denial as a
reason to weaken protections or execute on the workstation.

For reproducible source validation, use native Windows PowerShell/Pester 5 with
`tests/PortableSelection.Tests.ps1` and `tests/NtcorePackages.Tests.ps1`; the latter
defaults to inert fixtures. Its optional `RIDE_NTCORE_FIXTURE_DIRECTORY` accepts
only retained NTCore archives matching the catalog/evidence digests. All product
paths are isolated in TestDrive. Run `tools/validate.ps1` in each native edition.
No administrator privileges, NirSoft payload access or VM are needed for these
checks. TestDrive cleanup does not remove retained acquisition evidence.

When disposable-target access is available, follow the existing package
acceptance procedure with the exact reviewed source and a pinned checkpoint:
verify preview, selected files, repeat, modified-file refusal, removal, exact
saved restore and separately scoped product functionality on the candidate
Windows 11 target. Retain results and restore the checkpoint; promote no target
before applicable acceptance passes. A failure keeps the candidate pending.
Source recovery is a focused reversal of this batch's two catalog declarations,
selection code/tests and generated output, preserving unrelated working changes.
No installed workstation product or Windows state needs recovery from this run.

Resolved preparation: exact ZIP selection and two candidate file lifecycles.
**No whole legacy outcome is resolved, retired or excluded.** Collections,
components and native product outcomes remain partial; protection, license,
source and VM blockers are explicit. All five ranges were reviewed unchanged:
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**. Candidate
IDs and local checks do not deduct unfinished legacy feature/product outcomes.

## B11 named collections and MiTeC viewers, 2026-10-17

Three authorized source batches continued without VM access or access to blocked
NirSoft files. The [run index](../archive/evidence/named-collections-continuation-2026-10-17.json)
records sources, checks and remaining gates. No downloaded program, installer,
codec or updater was executed. No credentials, form submissions, Defender
changes, native system changes or VM actions were involved.

### Frozen named inventories

- **JoeWare:** [41 named tools](../archive/evidence/joeware-collection-inventory-2026-10-17.json)
  from the official index, with 41 retained product-page hashes, observed versions
  and explicit HTTPS form routes/ZIP names. The version list's header is dated
  2023 while some rows are later. More materially, rdp-sec-check's list entry
  disagrees with its product page. Publisher MD5/SHA1 values are observations,
  not verified archive SHA-256 pins. No download form was submitted. The general
  licence permits personal/company system use but restricts onward distribution;
  rdp-sec-check identifies separate GPLv2/source and Portcullis attribution.
  Per-artifact identity, bytes, notices and current-target acceptance remain open.
- **MiTeC:** [22 current Apps & Tools entries](../archive/evidence/mitec-collection-inventory-2026-10-17.json)
  and all 22 product pages are frozen. Mail Viewer and OLE/COM Explorer have no
  version parsed from the current page; no website script/library version was
  substituted. Older linked standalone products still need reconciliation, so
  this is not claimed as an exhaustive historical inventory. Developer component
  libraries/demos stay outside the approved collection. Current product/EULA
  information supersedes blanket assumptions based on historical freeware labels.
- **NTCore:** [16 utility entries](../archive/evidence/ntcore-collection-inventory-2026-10-17.json)
  now have explicit dispositions. Cerbero remains a separate product and the
  Sources section remains excluded from the collection. Existing PE Detective/CFF
  evidence is reused; the PE Detective digest is locally measured, whereas CFF
  also has a publisher-digest comparison. The previous prose was corrected to
  match that distinction. 4GB Patch's licence gap, Filter Monitor's historical
  compatibility limitation and the remaining utilities' artifact/licence/native
  gates remain visible. Mixed research/source bundles are not silently admitted.

This freezes review inputs; it does not add a runtime site crawler or treat
publisher page availability as tested product support. Source exclusions above
describe the accepted collection scope, not additional retired legacy outcomes.

### MiTeC JSON and XML Viewer candidates

Added `package.mitec-json-viewer` **3.2.2.0** and
`package.mitec-xml-viewer` **6.5.0.0** with exact archive SHA-256 pins and member
hashes. The [JSON evidence](../archive/evidence/mitec-json-viewer-source-review-2026-10-17.json)
and [XML evidence](../archive/evidence/mitec-xml-viewer-source-review-2026-10-17.json)
record both actual PE architectures and embedded versions/copyrights. Each
archive contains two executables and no separate licence file. `portable`
selects x64; `portable-x86` selects x86. Each deploys exactly one file through
the existing pinned ZIP selection handler. No profile chooses either package.
Both operations remain pending, with Windows 11 as a candidate and no supported
apply target. Publisher platform claims do not expand RIDE support.

Each product has one package identity across its published licence tiers;
activation is separate. Isolated file fixtures preserve synthetic unowned licence
and configuration files through repeat/remove/restore. They do not establish real
activation preservation or entitlement equivalence. The shared licensing guide
now records JoeWare distribution restrictions and MiTeC's per-product EULA/tier
review. Personal/company assessments remain in the local review store and do not
become new catalog installation gates.

[Structured Storage Viewer 4.1.2.0](../archive/evidence/mitec-structured-storage-viewer-source-review-2026-10-17.json)
was inspected without execution. Its four-file archive contains the x86 viewer,
an x86 ZLib codec, Delphi source and a sample. R05 collection and R13 SSView refer
to the same product: do not create duplicate ownership. Codec/source/sample
selection, attribution/licensing and native behavior remain a specific gate;
no SSView candidate or automatic plugin loading was introduced.

### Validation and corrected counting scope

Both native **PowerShell 5.1.26100.9711** and **PowerShell 7.6.5** pass **107
checks**: 16 viewer cases covering both products/architectures, 70 catalog checks
and 21 exact-selection checks. One integration case is excluded. Retained actual
MiTeC archives were used only for isolated file lifecycle checks. Initial catalog
generation exposed an unquoted hyphenated variant key; it was corrected before
tests. The first sandboxed 5.1 attempt failed authorization before testing, and a
read-only policy query reported registry access denied. The normal-host-access
rerun passed without policy/Defender changes. Repository validation passes in
both editions: **362 operations, eight groups, five profiles, 230 PowerShell
files**, generated documentation current. Only the two MiTeC declarations differ
semantically from this run's captured catalog baseline; all settings are unchanged.

There are now **60 packages and 33 pending packages in the full catalog**.
The earlier count of 18 described the continuation group, omitting 13 separately
pending Artcraft products. That group is now 20 after the MiTeC additions. This
is a reporting-scope correction, not newly discovered legacy work or acceptance.
Setting presentation remains **279/279**.

### Next procedure, acceptance and recovery

From the repository root, use native Windows PowerShell/Pester 5 to run
`tests/MitecViewerPackages.Tests.ps1`, `tests/Catalog.Tests.ps1` (excluding
`WindowsIntegration`) and `tests/PortableSelection.Tests.ps1`, followed by
`tools/validate.ps1`. The viewer suite defaults to inert ZIP fixtures; set
`RIDE_MITEC_FIXTURE_DIRECTORY` only to the retained, digest-matched viewer archive
directory for actual-byte file checks. TestDrive isolates writes. No acquired
program runs and no administrator privileges are required by these fixtures.

Next source batches: reconcile remaining named product artifact versions and
licences against the frozen page inventories, review JoeWare form-response
identity before adding any acquisition provider, reconcile older MiTeC standalone
entries and resolve SSView's codec/source/sample scope. Preserve per-product
unavailable or conflicting evidence; no mutable deployment-time crawling or
silent replacement. Existing Zimmerman rate limiting, 4GB Patch licensing,
component source/dependency/recovery and explicit profile/recovery-resource
deferrals remain. Do not retry protected NirSoft files or VM access in this state.

When disposable-target access is available, use the existing package acceptance
procedure and pinned checkpoint for each selected viewer architecture: preview,
apply/repeat, exact file selection, collision/modified-file refusal, removal and
saved restore; then separately verify viewer behavior and real licence/settings
preservation with authorized inputs. Retain results and restore the checkpoint.
No target is promoted before those checks pass. Source recovery is a focused
reversal of the two declarations and their fixture, followed by regeneration of
OPERATIONS; preserve earlier work and retained evidence. No installed workstation
product needs recovery from this run.

The supplied PowerISO screenshot adds historical status **Abandoned**, severity
Low, and a statement that the threat can no longer be found, with notification
and detail dates in November 2025. It establishes no present threat state; the
[historical record](../archive/evidence/collection-continuation-blockers-2026-10-17.json)
remains separate from current NirSoft alerts. Protection and VM blockers are
unchanged.

Resolved preparation: three explicit inventories and two architecture-selectable
viewer candidates with file lifecycle evidence. **No whole legacy outcome was
resolved, retired or excluded.** All five estimate ranges were refreshed and
remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**.
Partial collection, component, native and deferred outcomes remain counted;
the inventory/member/candidate counts are not legacy burndown deductions.

## Focused portable VM acceptance, 2026-10-17

Historical first attempt. The later [authorized WinRM start and rerun](#focused-portable-vm-acceptance-rerun-2026-10-17)
supersedes the host blocker and unrun lifecycle status below.

User-authorized scope: prepare and run the new package checks on the existing
**RIDE-Win11-Test** with its registered checkpoint, excluding Defender-blocked
tools. The new [focused procedure](../../tests/integration/README.md#focused-reviewed-portable-packages)
selects MiTeC JSON Viewer 3.2.2.0 and XML Viewer 6.5.0.0 (`portable` and
`portable-x86`), NTCore PE Detective 1.2.1.1 and CFF Explorer 8.0.0.0
(`portable`): **four products, six architecture cases**. The older application
batch selectors do not cover these candidates. No NirSoft or additional collection
is in the runner selection; no protected file was reopened, restored or executed.

Prepared source includes host/guest runners, a fixed selection/archive validator
and entry-point tests. The host verifies registered ownership, exact VM/checkpoint,
idle controller, empty queues, exclusive lock and catalog-pinned archives. The
guest uses real engine lifecycle operations in a guarded disposable VM, with only
selected candidate support enabled in memory. Checks cover preview, repeat,
exact member selection, removal, saved recovery and modified/unowned preservation.
Evidence collection precedes checkpoint reset; recovery failure blocks reuse.
No payload execution, GUI/parser functionality or real activation is claimed.

### Attempt and blocker

Read-only host access and the elevated launch are now available. The actual
elevated run **361729f7f6434c299eddcc40bc84069f** failed host preflight with:

> WinRM must already be running. Prepare the host in an elevated session; no services were started.

The raw result has `Status = Failed`, `Cleanup = NotStarted` and
`EvidenceCollected = false`: **zero of six guest cases ran**. No VM restore/start,
source staging or package action occurred. Post-attempt reads confirm:

| Object | Observed state |
| --- | --- |
| RIDE-Win11-Test | Off; ID `6a5c9f91-91f9-44c5-924a-d1b5f863e16f` |
| RIDE-clean-test-base | Existing checkpoint ID `a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9` |
| RIDEWin11Test controller | Ready; registration unchanged |
| VMMS | Running, Automatic |
| Host WinRM | Stopped, Manual |

This replaces the nonspecific access diagnosis for this focused attempt with a
concrete host prerequisite blocker. Later preflight gates have not run; restoring
WinRM alone is not proof that the entire host is ready. No service, remoting policy,
Defender setting or protected controller file was changed. Checkpoint recovery was
not needed and is **not** reported as tested. Earlier acceptance remains separate.
The historical PowerISO alert remains separate from current NirSoft exclusions.

### Validation, evidence and next procedure

Native Windows PowerShell **5.1.26100.9711** and PowerShell **7.6.5** each pass
**37 focused checks**: 13 selection/entry/archive guards, 16 MiTeC fixture checks
and eight NTCore fixture checks. These are inert TestDrive fixtures, not guest
acceptance. Initial use of the generic PSD1 loader and PowerShell 5.1 JSON-array
enumeration were corrected before the final successful tests. Both editions
validate **362 operations, eight groups, five profiles and 234 PowerShell files**;
generated documentation is current. No production catalog or handler changed in
this focused run. All **33 pending packages** remain pending; presentation remains
**279/279**.

The [sanitized evidence record](../archive/evidence/focused-portable-vm-acceptance-2026-10-17.json)
links the raw run ID, exact selection, checks and blocker. Raw local output is
`.local/portable-vm-acceptance-20261017/361729f7f6434c299eddcc40bc84069f/result.json`;
launcher and postcheck evidence are `.local/portable-vm-launch.log` and
`.local/portable-vm-postcheck.json`. Preserve these before cleaning local outputs.

Next, restore the existing host's required running WinRM state through its normal
administrative procedure, then use the runbook's elevated `-WhatIf` and actual
commands with the same installed configuration and retained four-archive manifest.
Do not refresh controller binaries or change checkpoint pins. Successful lifecycle
acceptance must retain all six scenario results and `ResetAndOff`, followed by
separate GUI/functionality and authorized real licence/settings acceptance.
If another host prerequisite fails, retain that concrete blocker before proceeding.
Independent artifact/licensing review can continue; Defender-protected tools,
Zimmerman API pin, 4GB Patch licensing, SSView scope and explicit resource/profile
deferrals remain open.

Resolved preparation: focused runner coverage and a concrete host diagnosis.
**No whole legacy outcome was resolved, retired or newly excluded.** All six
runtime cases remain blocked; related collection outcomes remain partial and
existing resource/profile deferrals remain deferred. All five group ranges were
refreshed unchanged at **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded
**145-200/about 175**. Runner preparation and a failed preflight do not reduce
legacy outcome counts.

## Focused portable VM acceptance rerun, 2026-10-17

The user authorized starting the existing host WinRM service and rerunning the
focused checks on **RIDE-Win11-Test** using its existing checkpoint. WinRM changed
from Stopped to Running; its **Manual startup type is unchanged**. No host remoting
policy, Defender setting, controller registration or checkpoint pin changed.
NirSoft and all other Defender-blocked tools remained outside the selection.

### Result and scope

Final run **a2cfd331a10e4f71a607a148361cdc0b** passed **all six cases**, with
**14 lifecycle assertions per case (84 total)**, in Windows PowerShell 5.1 on
**Windows 11 build 26300**. Evidence was collected before the same registered
checkpoint was restored; the runner reports **ResetAndOff**. A separate host
postcheck confirms VM Off, controller Ready, no recovery block and WinRM Running.

| Product | Variant | Native file lifecycle |
| --- | --- | --- |
| MiTeC JSON Viewer 3.2.2.0 | portable / x64 | Passed |
| MiTeC JSON Viewer 3.2.2.0 | portable-x86 | Passed |
| MiTeC XML Viewer 6.5.0.0 | portable / x64 | Passed |
| MiTeC XML Viewer 6.5.0.0 | portable-x86 | Passed |
| NTCore PE Detective 1.2.1.1 | portable / x86 | Passed |
| NTCore CFF Explorer 8.0.0.0 | portable / x86 | Passed |

Each case verifies install preview, installation, exact member selection, repeat
installation, removal preview, removal, repeat removal, restore preview, exact
removal restoration, unowned preservation, restoration of original absence,
unowned collision refusal, modified replacement refusal and modified removal
preservation. The actual retained, hash-pinned archives were staged through the
real engine/provider path. **No acquired utility was executed.** These results
do not establish GUI/parsing behavior, real licence activation or disconnected
installation acceptance. Build 26300 evidence does not expand support to other
Windows builds or Server targets.

### Corrections and retained failed attempts

- `ca4376f5a3ab43a2a5f503b9c9448825`: host prerequisites passed after WinRM start;
  the new runner called AutomatedLab's credential accessor without its required
  loaded-lab argument. Corrected to the installed provider's documented source
  call shape. Failure preceded VM mutation; cleanup was NotStarted.
- `5ad651f2bcd840c187febb0acc4097c4`: the first viewer installed correctly, then
  repeat installation failed because the engine probed its ownership manifest as
  the other architecture sharing the same product directory. The engine now
  validates current ownership using the selected variant before skipping that
  redundant probe. Invalid ownership and recorded different editions still fail.
  Evidence collected; checkpoint restored and VM Off.
- `3c2ee725c46947c1b9e52dc8341e1594`: repeat, remove and exact recovery passed, but
  the collision assertion used the first character of a scalar filename. The
  guest runner now preserves singleton member lists as arrays and records refusal
  details. Evidence collected; checkpoint restored and VM Off.
- `a2cfd331a10e4f71a607a148361cdc0b`: all six corrected cases passed; evidence
  collected and checkpoint restored. No cleanup failure occurred in this rerun.

Engine version **0.21.1** contains the focused shared-destination correction;
host and guest runner versions are **0.1.1**. The regression uses an inert owned
file/manifest in TestDrive to cover repeat, removal preview, invalid ownership
and recorded different-edition refusal. Both native PowerShell **5.1.26100.9711**
and **7.6.5** pass **93 checks** across ApplicationPackages and
PortableAcceptanceAutomation. The final guest-fixture correction also reran all
13 entry/selection/archive guards per edition; those are included in the 93
distinct checks, not additional coverage. Both editions validate **362 operations,
eight groups, five profiles and 234 PowerShell files**, with generated docs current.

### Evidence, next acceptance and estimates

The [sanitized rerun record](../archive/evidence/focused-portable-vm-rerun-2026-10-17.json)
contains all four attempts, six scenario results, source/payload hashes, saved run
IDs, test summaries and postcheck. Raw output is retained under
`.local/portable-vm-acceptance-20261017/<run-id>/`; preserve the final source and
payload manifests, result, guest scenarios/log/summary, observations and saved
state before local cleanup. Earlier blocked evidence remains available separately.
VM/checkpoint IDs remain `6a5c9f91-91f9-44c5-924a-d1b5f863e16f` and
`a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9` respectively.

The focused host-access and file-lifecycle blockers are resolved for this run.
Next acceptance is GUI/parser functionality on suitable synthetic/copied samples,
plus real licence/settings activation and preservation with authorized inputs.
Use the same [checkpoint-backed procedure](../../tests/integration/README.md#focused-reviewed-portable-packages)
when repeating lifecycle acceptance; verify controller idle, retain evidence and
require ResetAndOff. Catalog support remains unchanged: **33 pending packages**,
including all four products here. Other collection artifact/licensing questions,
SSView scope, Zimmerman API pin, 4GB Patch licence grant, Defender exclusions and
explicit profile/recovery-resource deferrals remain open. This result does not
retroactively accept unrelated settings, components or controller/PAT scenarios.

Resolved: authorized host prerequisite and six native file-lifecycle subgates.
**No whole legacy outcome was resolved, retired or newly excluded.** Product
functionality/activation and collection outcomes remain partial; existing
profile/resource scope remains deferred. All five ranges were refreshed unchanged:
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**. Partial
acceptance increases evidence without deducting a whole legacy outcome.

## Next authorized acceptance batches, 2026-10-17

The continuation selected B03 user-bin startup, B08 PSScriptTools and B10 offline
portable execution, using RIDE-Win11-Test and the existing registered checkpoint.
VM/checkpoint IDs remain `6a5c9f91-91f9-44c5-924a-d1b5f863e16f` and
`a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9`. Defender-blocked NirLauncher/NirSoft x64
payloads were excluded; protections and quarantine were not changed.

| Batch | Dated result | Remaining gate |
| --- | --- | --- |
| B03 UserBinPath | `be21c647ec6247d0be626b4ddd45e019`: guest prerequisite failed before startup checks; installed PowerShell 7 was absent. ResetAndOff. | Supply the runtime through a scoped disposable prerequisite workflow, then repeat the existing scenario. No runtime was installed and no checkpoint was replaced. |
| B08 PSScriptTools | `62c045acec124c7eb57aecba30dacba8`: all 14 lifecycle checks and exact 360-file selection passed on Windows 11 build 26300. Host result Failed because saved-state evidence copying exceeded a Windows PowerShell path limit. Evidence partially collected; ResetAndOff. | Guest runner 0.2.1 archives each saved-state directory and checks its file count; complete native rerun and collection remain pending. Runtime/function/dependency ownership remains separate. |
| B10 OfflineCaffeine | Prepared a source-bound private fixture using the retained, pinned Caffeine 1.98 archive. Intended coverage is 16 disconnected/preflight/CLI lifecycle assertions. | No native run started: the subsequent Windows elevation launch was canceled. Broader installers, dependencies, servicing and interruption remain open. |

PSScriptTools used the full pinned source snapshot at revision
`549fa3e3d769532320054fc0b3c8f42df0452361`; no upstream module was imported or
executed. Its scenario verifies preview/install/repeat, exact members,
preview/remove/repeat, preview/restore, exact recovery, unowned preservation,
original absence recovery, collision refusal and modified-file preservation.
Passing the scenario does not override the failed collection/host result.
The offline fixture uses a private test profile, not a newly proposed deployment
profile or redistribution approval. No Caffeine executable ran.

### Preregistered continuation instead of repeated elevation

The user requested reuse of preregistration after repeated Windows prompts.
Read-only inspection confirmed the existing scheduled task, but its protected
controller predates these two focused batches. Both later direct elevation
launches (an optional progress read and the sequential rerun launcher) returned
"The operation was canceled by the user." No further UAC launch was attempted.
This was a Windows elevation cancellation, not an automatic approval-review denial.

Prepared task client/controller **0.6.0**, registration **0.3.0**, and focused host
runner **0.3.0**. The `FocusedPortableV1` capability adds only `PSScriptTools` and
`OfflineCaffeine` to the registered Local queue. The protected child derives its
source, fixed archive-manifest and result paths from registration/request identity;
queue requests accept no arbitrary scripts or payload paths. It validates the
running request and worker-held lock, checks the same VM/checkpoint pins, transfers
only verified selected payloads with PowerShell Direct and requires collected
evidence plus ResetAndOff. Existing timeout/termination/recovery blocking remains.
An already-running VM is refused before mutation. The general suites, active
settings fixture, controller/PAT RC gate and support declarations remain separate.

**Prepared, not installed:** one elevated refresh of the idle existing controller
is required to deploy these protected files. Afterward ordinary task submissions
need no per-batch UAC. The current client was checked against the installed old
configuration: it refused before creating a request or prompting. Follow the
[preregistration procedure](../../tests/integration/README.md#focused-reviewed-portable-packages),
using the existing installed configuration, owning account and unchanged pins.
Submit PSScriptTools first, inspect its correlated result/recovery, then submit
OfflineCaffeine. The local handoff `.local/refresh-and-run-focused-acceptance.ps1`
performs the single refresh and serial requests when explicitly run in elevated
Windows PowerShell 5.1; it does not open UAC itself. Its manifests are prepared at
`.local/acceptance-input/<batch>.json`. First registered dispatch remains unverified.

### Validation, evidence and estimates

Both editions passed the initial **44** focused portable/offline checks. The final
controller, portable and offline set passes **136 checks on Windows PowerShell 5.1**
and **134 on PowerShell 7**, with two intended Desktop-only host-preflight skips on
PowerShell 7. Tests cover fixed dispatch without RunAs, old-controller refusal,
CI/path rejection, already-running VM preservation, result mismatch/incomplete
recovery refusal and existing timeout/recovery behavior. Both editions validate
**362 operations, eight groups, five profiles and 235 PowerShell files**. These
local checks do not establish native registration or disconnected acceptance.

The [sanitized record](../archive/evidence/next-authorized-acceptance-2026-10-17.json)
retains run results, source/payload hashes, all 360 file observations, local tests
and blockers. Raw results remain under `.local/user-bin-vm-acceptance-20261017/`
and `.local/portable-vm-acceptance-20261017/`. Preserve them before local cleanup.
The last completed VM runner confirms the existing checkpoint restored and VM
Off; a later independent Hyper-V postcheck was not run after elevation cancellation.
The task itself was observed Ready by unelevated read-only inspection.

Resolved: concrete startup prerequisite diagnosis, partial PSScriptTools lifecycle
evidence and a prepared path through preregistration. **No whole legacy outcome
was resolved, retired or newly excluded.** B03/B08/B10 remain partial; existing
Defender exclusions, runtime/GUI/activation and Server acceptance remain open.
New deployment profiles and BitLocker/recovery resources remain deferred. All
five ranges are refreshed unchanged: **38-58 / 56-71 / 20-25 / 25-35 / 8-12**,
rounded **145-200/about 175** (exact endpoints 147-201). Preparation and failed or
partial acceptance do not justify a whole legacy-count deduction.

## Preregistered acceptance and deferred elevation, 2026-10-17

The user approved one attended controller refresh and instructed that all later
scenarios needing a fresh UAC prompt be saved for a later session. The refresh
installed `FocusedPortableV1` on the existing RIDEWin11Test task. All ten protected
files match the reviewed source. VM/checkpoint IDs remain
`6a5c9f91-91f9-44c5-924a-d1b5f863e16f` and
`a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9`; no new checkpoint or controller identity
was introduced. Registration/client versions are 0.3.0/0.6.0 and the focused host
runner is 0.3.0. No additional UAC launch occurred after the approved refresh.

| Registered request | Result and evidence | Recovery |
| --- | --- | --- |
| PSScriptTools `c3f65b2ab9f643b2b84510aff987dd4d` | Passed all 14 lifecycle checks, exact 360-file selection and complete saved-state ZIP collection on Windows 11 build 26300. This resolves the earlier long-path collection failure. | ResetAndOff; collected evidence. |
| OfflineCaffeine `ee094143fc904dc692760a3de0b248fc` | Failed before installation. The adapter was disabled, but positive preflight rejected the catalog's `neutral` archive as an architecture mismatch. Its four negative assertions are not independent acceptance evidence because the positive bundle was invalid. | ResetAndOff; failure evidence retained. |
| OfflineCaffeine `efca4ec56f604cee840c28d31f11e622` | Passed all 16 checks after the focused correction. Submitted from ordinary Windows PowerShell through the existing task, without RunAs or another UAC prompt. | ResetAndOff; collected evidence. |

OfflineBundle **0.7.1** now recognizes the catalog's neutral archive declaration,
alongside manifest `any`; explicitly architecture-specific content and declared
targets still must match. Catalog/manifest architecture equality remains required.
The guest fixture **0.1.1** now retains and requires a valid positive preflight
before interpreting negative cases. This correction is guest source delivered by
the registered runner, so it required no protected-controller refresh. Both native
PowerShell editions pass **87** OfflineBundle/OfflineExecution/portable-runner
checks, including neutral x64/x86 coverage and retained target mismatch refusal.
Both validate **362 operations, eight groups, five profiles and 235 PowerShell
files**. The preceding controller regression remains 136 passes on Windows
PowerShell 5.1, and 134 with two Desktop-only skips on PowerShell 7.

The successful offline run records the Hyper-V adapter changing from Up to
Disabled, with no Up adapter at completion. Positive package preflight passed
with no requirement issues or offline gates. Missing payload, changed digest,
omission and wrong actual target were refused without state mutation. CLI install
preview/install/repeat, original-absence restore, profile apply/repeat, removal,
exact removal restore and profile-absence restore passed. Both Caffeine files
retained `NotInspectedOffline` signature observations. No upstream PSScriptTools
code or acquired executable was launched. This establishes portable file
deployment/recovery on this build, not application functionality, broad installer
coverage or public redistribution approval.

The [sanitized record](../archive/evidence/preregistered-acceptance-2026-10-17.json)
contains all three requests, source/payload hashes, scenario/file observations,
network transitions, archive hashes, tests and final queue state. Raw evidence is
retained at `%ProgramData%/RIDE/TestAutomation/RIDEWin11Test/results/<request-id>/`;
preserve `focused/evidence`, source and payload manifests, controller logs and
result records. Final read-only inspection found task Ready, no pending/running
requests, no recovery block and WinRM Running. Final VM Off is established by
the successful focused recovery result; no fresh elevated Hyper-V inspection was
launched solely to repeat it. The earlier attended postcheck is retained separately.

Next: use the [registered task procedure](../../tests/integration/README.md#focused-reviewed-portable-packages)
for supported authorized batches. Keep B03's missing installed PowerShell 7 and
standalone profile workflow, interactive Store/settings setup, and any further
protected-controller/host changes in the [deferred elevation list](../../TODO.md#deferred-elevation-sessions).
Do not open fresh UAC prompts for them until a later attended session. This is
the user's instruction, not an approval-review rejection. Defender-blocked tools
remain excluded; no exclusions, restoration or protection changes were made.

Resolved: native preregistered dispatch, PSScriptTools file-lifecycle collection
and the focused disconnected portable execution subgate. **No whole legacy
outcome was resolved, retired or newly excluded.** B08 runtime/function/dependency
work and B10 broader installers/dependencies/servicing/interruption remain partial.
B03 remains blocked by its guest prerequisite; GUI/activation/Server and broader
controller/PAT RC gates stay open. New deployment profiles and BitLocker/recovery
resources remain deferred. All five ranges were refreshed unchanged:
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**, exact
endpoints 147-201. Closing these subgates does not deduct a whole legacy outcome.

## No-UAC source continuation, 2026-10-17

Continued three source batches under the instruction to save every fresh-UAC
scenario for later. The installed focused queue exposes PSScriptTools and
OfflineCaffeine, whose file acceptance already passed. B03 prerequisites, new
portable selections and interactive Store workflows are not added by renaming a
request or changing protected files. No VM request or new UAC launch occurred.
The [read-only controller record](../archive/evidence/no-uac-controller-status-2026-10-17.json)
confirms Ready, empty pending/running queues, no recovery block, WinRM Running
and unchanged VM/checkpoint IDs. VM power was not queried; the previous run's
ResetAndOff evidence remains the latest runtime observation.

### Batch 1: NTCore member artifacts

[Driver List and Rebel.NET](../archive/evidence/ntcore-member-source-follow-up-2026-10-17.json)
now have official-source archive SHA-256 pins, exact member hashes and PE machine
observations. Archives were read in memory without extraction or execution.
Driver List contains x64, x86 and IA64 executables; IA64 is not an ARM64 or x64
variant. Rebel.NET contains an x86 PE and a file-format header. Publisher page
versions are 1.0.2 and 1.6.0.1 respectively; embedded versions remain unverified.
Neither archive includes a licence file, and no explicit use/distribution grant
was located on the two reviewed product pages. Explorer Suite terms cannot be
inherited. Both remain outside the catalog pending product-specific licence
evidence, version/selection checks and owned deployment/acceptance. No publisher
digest verification or target support is claimed.

### Batch 2: historical MiTeC reconciliation

The current site's link to its retired main page exposed **13 additional
standalone products** beyond the frozen 22 current Apps & Tools entries:
Internet History Browser, E-mail History Browser, Instant Messaging History
Browser, Windows File Analyzer, Database Documentation/Code Generator, MSA Query,
ADO Query, Weather Agent, DirList, Network Meter, PhotoView, Icon Explorer and
Mail Checker. The [reconciliation](../archive/evidence/mitec-historical-reconciliation-2026-10-17.json)
retains all 13 page hashes, historical index versions and exact download routes.
The bounded union is **35 product review identities**, not 35 admitted packages
or an exhaustive inventory of all historical releases. Eleven linked developer
component pages remain outside the standalone collection scope. No historical
product payload was acquired. Existing SSView identity is reused across R05/R13.

Ten old product pages explicitly describe private/commercial free use. Internet
History Browser, Icon Explorer and Windows File Analyzer instead restrict free
use to private, educational and non-commercial purposes; WFA directs other use
to a commercial licence. Reconcile these exact product statements with current
terms before admission. Neither historical labels nor this review approve
distribution or record a personal/company licence assessment. DAO/ADO/database
clients, installer behavior and data ownership remain per-product gates.

### Batch 3: SSView ownership and codec prerequisites

The retained SSView archive still matches its recorded SHA-256. Text review of
`ZLibCodec.dpr` and the publisher description confirms DLL discovery in the
viewer directory through `EncodeIStream`/`DecodeIStream`. The
[ownership record](../archive/evidence/ssview-ownership-follow-up-2026-10-17.json)
separates the viewer, optional codec, reference source and sample without adding
catalog operations. The source imports Delphi units and references a resource
file absent from the archive; a reproducible build is not established. It has no
explicit source licence grant. Algorithm naming alone does not settle plugin
licensing. Native tests must use an isolated directory and disposable sample
copies, preserve unowned configuration/activation/plugins, and verify viewer-only
behavior before codec round trips. No DLL, viewer or source was executed.

AdFind remains page-only: its publisher describes a password-protected executable
and antivirus interaction. No download, password handling or allowlisting was
attempted. The existing Defender-blocked NirSoft paths were not read, restored,
re-extracted or included in any batch. Defender settings remain unchanged.

### Validation, next procedure and estimates

Validation checked the two archive member sets and hashes, retained SSView pin,
13 historical product routes/page hashes, JSON readability, local evidence links
and the focused documentation diff. No engine/catalog change was made, so prior
Pester/native results remain dated evidence rather than rerun claims. Initial
sandbox DNS access failed; ordinary host network access fetched only the declared
review inputs without Windows elevation.

From the repository root, continue the frozen collection review one product at a
time: resolve exact official terms and artifact versions, inspect bounded member
sets, then prepare isolated file-lifecycle fixtures. Keep raw pages/archives in
the local review store and sanitized hashes in the linked evidence. Source review
needs no administrator rights and makes no system change; retain previous evidence
if a publisher artifact changes. Do not run a newly selected product through an
unrelated registered suite. Save a concrete controller delta and native procedure
for the [later attended session](../../TODO.md#deferred-elevation-sessions).

Resolved subgates: two NTCore artifact inventories, historical MiTeC scope and
SSView source/ownership analysis. **No whole legacy outcome closed, retired or
newly excluded.** The 13 historical products are reconciliation within the
already-counted collection outcome, not 13 new deductions or additions. Packages
remain 60 with 33 pending; setting presentations remain 279/279. Native behavior,
licensing, dependencies, Server/UI/activation and broader offline coverage remain
partial. B03, protected-controller changes and desktop handoffs remain deferred
for fresh elevation; Defender and resource blockers stay separate. All five
ranges were refreshed unchanged: **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded
**145-200/about 175**, exact endpoints 147-201.

## Utility and database source batches, 2026-10-17

Three more authorized batches reviewed **nine artifacts for eight products**:
eight ZIPs with 16 members and one MSI with five cabinet files. The
[run record](../archive/evidence/source-review-batches2-2026-10-17.json) retains
official source URLs, input hashes and the three evidence records. No downloaded
application, DLL, database or installer custom action was executed. No UAC prompt,
VM request, controller change or Defender change occurred. The previously
recorded controller/power state was not rechecked and is not a new runtime claim.
Defender-blocked NirSoft payloads and page-only AdFind remain excluded.

### Batch 1: MiTeC directory, network and image utilities

[Artifact evidence](../archive/evidence/mitec-utility-artifact-review-2026-10-17.json)
records exact files, archive/member SHA-256 values, PE machine fields and embedded
versions. DirList **1.3.0.0** and Network Meter **2.5.0.0** each contain one x86
executable. PhotoView **1.4.0.0** contains an x86 executable, three language files
and Microsoft's x86 `gdiplus.dll` **5.1.3102.1360**. The latter is a dependency
review gate: retain its provenance, establish applicable redistribution notices
and verify supported loading behavior before omitting or replacing it. An old
version observation alone is not a vulnerability assessment.

The historical product pages describe private/commercial free use. Exact artifact
terms and current-EULA reconciliation remain distinct from local licence-owner
assessments and shared-kit approval. Prepared acceptance uses synthetic directory
trees/images, isolated guest counters, separate export directories and exact
owned-file restore. Language resources, user configuration, original images and
unowned exports must be preserved. No product was admitted or declared supported.

### Batch 2: MiTeC database utilities

[Database evidence](../archive/evidence/mitec-database-artifact-review-2026-10-17.json)
distinguishes **DDG_IBFB 1.0.0.0** from **DDG_MSSQL 1.2.0.0**. The historical shared
product version 1.2.0 must not be copied onto both artifacts. The Interbase/Firebird
archive also contains `EMPLOYEE.GDB`, `EMPLOYEE.ini` and CSS; the SQL Server archive
contains its own CSS. Sample data/configuration was hashed as data, not opened in
a database or used for a connection. Its content is not published in evidence.

MSA Query **2.1.0.0** and ADO Query **1.9.0.0** each contain one x86 executable.
Publisher requirements identify DAO and installed ADO support respectively;
concrete provider versions/bitness, database clients and target compatibility
remain unverified. All four archives have exact pins/member inventories and no
standalone licence file. Later acceptance needs synthetic databases, explicit
test credentials, provider-absence refusal, query/import/export checks and
preservation of connections, history, CSS, generated files and databases.
No database/provider was installed, connected or modified.

### Batch 3: NTCore managed utilities

[NTCore evidence](../archive/evidence/ntcore-managed-utility-source-review-2026-10-17.json)
pins VirtualReg Manager **1.0.0.1** and its single x86 PE. The publisher expressly
permits inclusion in freeware; that narrow statement is retained without
claiming unrestricted commercial or shared-kit redistribution. Actual CLR
requirements, synthetic virtual-registry round trips and separate ownership of
output XML/configuration remain acceptance gates.

ScreenWriter's publisher/executable version is **1.1.0.1**, while MSI
`ProductVersion` is **1.0.0** and `ProductCode` is
`{0D75586D-610A-41E3-9278-9D4860DFA99F}`. Keep installer identity and application
version separate in future detection/recovery. Read-only MSI tables identify
framework **2.0.50727**, `VSDAllowLaterFrameworkVersions=False`, six custom actions,
shortcuts/registry metadata and five files. The executable's embedded version
matches the MSI File table. The cabinet contains two sample scripts, an icon and
a readme alongside the program. The readme describes free software without
warranty and credits Daniel Pistelli; an explicit redistribution grant was not
located. Preserve sample provenance and resolve their terms before bundling.

MSI inspection used `OpenDatabase` mode 0, never an installation session. The
initial COM property read produced empty metadata; explicit property access and
required-table/count checks corrected that before evidence was accepted. 7-Zip
extracted only the named embedded cabinet and its five validated file identifiers.
No custom-action binary was extracted or loaded. Framework servicing, installer
scope, actual custom-action behavior, application function and uninstall/rollback
remain for a reviewed disposable-guest scenario in a later attended session.

### Validation, next instructions and estimates

Validation rechecked all nine artifact pins, exact ZIP member sets, nine staged
PE hashes/version observations, five MSI cabinet sizes/hashes, evidence JSON,
linked files and the focused documentation diff. No engine/catalog code changed;
no new Pester or native acceptance claim is made. Raw source material and inspection
scripts are retained in `.local/source-review-batches2-20261017/`; sanitized
evidence contains no personal credentials, sample connection values or payloads.

Next source work: finish the remaining historical MiTeC artifacts and NTCore
member-specific terms; prioritize the explicit PhotoView dependency, DDG variant
identity, DAO/ADO providers and ScreenWriter framework/custom-action gates. From
the repository root, compare retained hashes before review, keep each artifact's
version/selection independent and prepare exact inert file fixtures only after
selection and terms are understood. Source review requires no elevation. Preserve
the original evidence on publisher changes and record a new pin instead of
silently replacing it. Do not install prerequisites on the host. Save any new
registered scenario/controller delta in [deferred elevation](../../TODO.md#deferred-elevation-sessions)
before a later attended session; retain the existing checkpoint and recovery
procedure. Do not submit these products under an unrelated registered suite.

Resolved: artifact identity/member/version subgates for eight products, with
explicit dependency and licensing gaps. **No whole legacy outcome closed, retired
or newly excluded.** These products remain within the existing collection scope;
60 catalog packages/33 pending and 279/279 setting presentations are unchanged.
Fresh-UAC work, native/UI/Server/function/activation gates, Defender exclusions,
Zimmerman pin, 4GB Patch grant, SSView and resource/profile deferrals remain.
All five estimates were refreshed unchanged: **38-58 / 56-71 / 20-25 / 25-35 /
8-12**, rounded **145-200/about 175**, exact endpoints 147-201. Source inspection
reduces uncertainty but does not establish complete deployment or user outcomes.

## Remaining MiTeC and NTCore source review, 2026-10-17

The authorized continuation needed no fresh UAC. The [run record](../archive/evidence/remaining-collection-batches-2026-10-17.json)
pins **35 additional official artifacts**: 26 MiTeC and nine NTCore. Static
inspection covers **122 embedded files** (110 members in 28 ZIPs, five Phoenix
MSI cabinet files and seven nested SNSRemover ZIP files). Six installer wrappers
have outer hashes/metadata only. All 41 artifact/page requests returned HTTP 200;
no new Defender/access failure was recorded. Acquired programs, libraries,
drivers and installer custom actions were not executed. No VM, controller,
checkpoint, Windows configuration or Defender policy changed; prior runtime
status was not rechecked. Existing Defender-blocked NirSoft files were untouched.

The [coverage reconciliation](../archive/evidence/mitec-ntcore-source-coverage-2026-10-17.json)
assigns all **35 MiTeC and 16 NTCore** frozen review entries to existing/new
evidence or a page-only/excluded disposition. Zero entries are unassigned.
This closes the unassigned source-review queue, not product admission, complete
licensing, opaque-payload inspection or native acceptance. Explorer Suite's full
installer is a follow-up within the existing product outcome; variants and
bundled files are not new legacy outcomes.

### MiTeC current and historical batches

[MiTeC evidence](../archive/evidence/mitec-remaining-source-review-2026-10-17.json)
covers the remaining 19 current apps and seven historical products. Archive and
member hashes, PE machine fields, versions, dependency/helper files and exact
per-product acceptance gaps are retained. Notable distinctions:

- DFM Editor's Delphi 11 executable is **8.3.1.0**, while Delphi 12 is **8.4.0.0**.
  Each has eight matching BPLs. Keep the variants/runtime families separate and
  review Embarcadero redistribution and user-package loading.
- Mail Viewer **2.5.1.0** and OLE/COM Explorer **1.4.0.0** resolve the missing
  parsed page-version observations through embedded metadata. Mail Viewer also
  carries 21 language files and localization guidance.
- SQLite Query includes SQLite **3.35.5**; Internet History Browser's renamed
  DLL identifies the same version, while ICQ/MSN History Browser's identifies
  **3.8.10.2**. Upstream public-domain status does not independently establish
  these binaries' provenance or the surrounding product's licence.
- System Information eXtra/GetSys are **16.0.0.0**. SMBIOS Explorer **1.8.0.0**
  has a **1.0.0.0** helper; Task Manager DeLuxe **5.1.1.0** has **2.0.0.0**
  DeskExp helpers. Preserve distinct file ownership and version detection.
- Project Maker's page lists **2.0.0**, but its outer installer FileVersion is
  **1.9.0**. Actual installed version is unverified. No build/signing action ran.

InfoBar, Paradox Data Editor, Project Maker, Weather Agent and Mail Checker
remain opaque installer payloads. Installed 7-Zip exposes only PE resources for
four wrappers and cannot open Mail Checker as an archive; listing success does
not establish a payload inventory. No reviewed alternative static extractor was
available on PATH. Record this source-tool limitation separately from elevation.
Paradox Data Editor's BDE, database clients/providers, TAPI/TSP resources, weather
services and isolated mail infrastructure remain concrete dependency gates.

Current product pages distinguish non-commercial free use and paid tiers;
historical terms retain their exact per-product scope. See the updated
[licensing watchlist](../package-licensing.md#important-to-review-licensing).
No private individual/company review or distribution approval was recorded.

### NTCore utilities and installer batch

[NTCore evidence](../archive/evidence/ntcore-remaining-source-review-2026-10-17.json)
records NETUnpack's x86/x64 **1.0.0.1** variants and DynLogger's matched
three-file sets. Target-process architecture, hook/dump behavior and current
Windows compatibility need synthetic owned targets; no process was inspected.

Explorer Suite's downloaded SHA-256 matches the publisher's published digest.
The full installer is the sixth opaque payload. Prior standalone CFF lifecycle
acceptance does not cover suite installation, integrations or uninstall.

Phoenix has three distinct identities: page **1.8.0.1**, MSI ProductVersion
**1.7.1**, and contained Phoenix Protector executable **1.9.0.1**. ProductCode
is `{32A1C684-C199-4DD2-9F89-8F44C655D4EC}`. Read-only MSI tables identify
framework **2.0.50727**, later-framework acceptance disabled, six custom actions
and five cabinet files. The latter include Phoenix Merger **1.0.0.0**, help,
bitmap and `Phoenix License.rtf`. Its limited single-user development/testing
grant and no-transfer/component-separation/commercial-hosting restrictions need
exact intended-use review; the page's freeware label is insufficient. The EULA
hash is published, not its full text. Inspection used `OpenDatabase` mode 0 and
bounded cabinet extraction, never an installation session or custom action.

NoDel's 16-file source/project/binary archive includes an x86 driver, and reviewed
`Drivers.cpp` creates a `SERVICE_KERNEL_DRIVER` service. No compilation/loading
occurred. Grant, signing and current-build support remain open. WIM Installer's
single x86 **1.0.0.1** executable still needs imaging dependencies, exact disk/image
destinations and a recovery procedure; no image was opened or applied.

SNSRemover includes a separately pinned nested PE Detective archive, with
**PE Detective 1.0.0.1**, **Signature Explorer 1.0.0.0** and five signature XMLs.
Its hash and versions differ from the previously reviewed standalone candidate;
do not silently replace or co-own it. An initial root-only guard rejected the
signature subdirectory; the explicit eight-entry set was reviewed before bounded
inspection of seven leaf files. No target binary was processed by these tools.

Filter Monitor remains page-only: the publisher describes an unsigned driver
and disabling signature enforcement, with Vista/Windows 7 support claims.
Vista4Experts also remains page-only; its UAC/Defender/update changes are not
adopted. Neither payload was acquired. AntiMida's existing mixed research/source
exclusion is retained, not a new retirement. These are publisher/support/scope
dispositions, not new Defender detections.

### Validation, saved acceptance and next procedure

Validation rechecks all 41 retained inputs, 110 ZIP members, 66 staged PE members,
five MSI cabinet files and seven nested ZIP members against the evidence. It
also checks unique 35+16 coverage, evidence links/JSON, documented counts and the
focused documentation diff. No engine/catalog changes or new Pester/native
acceptance claim. Raw material and inspection scripts are retained under
`.local/remaining-collections-20261017/`; published evidence contains hashes and
observations, not payloads, real-user data or credentials.

From the repository root, the next source-only procedure is:

1. Verify retained artifact hashes against the linked records. For each of the
   six named wrappers, select a reviewed static extractor that supports its
   actual installer format; extract only bounded paths to a new local review
   directory. Do not invoke an installer, even for help or extraction switches.
   Preserve prior pins and record changed publisher bytes as a separate input.
2. Reconcile actual payload versions/architecture, bundled notices and dependency
   ownership. Prior PhotoView GDI+, DDG samples, DAO/ADO, ScreenWriter, SSView and
   NTCore grant gaps remain linked from earlier entries. Product review and local
   owner assessment remain separate from shared-kit distribution approval.
3. Prepare exact synthetic fixtures and expected outputs for each admitted
   selection: test certificates, mail/history stores, databases, hives and PE
   files; explicit isolated endpoints for network/process checks. Preserve
   unowned files, outputs, configuration and activation. Kernel/imaging/service
   changes require their own compatibility and recovery evidence.
4. Save new registered selections, installer/prerequisite setup and protected
   controller changes in [deferred elevation](../../TODO.md#deferred-elevation-sessions).
   The installed focused controller permits PSScriptTools/OfflineCaffeine only;
   do not submit unrelated products under those names. Later acceptance must
   verify install/repeat/status/function/remove/exact recovery, collect evidence
   and restore the existing checkpoint. No fresh UAC is authorized now.

Source acceptance is exact identity, complete bounded member inventory where
available and explicit unresolved terms/dependencies; runtime acceptance is
separate. Recovery in this pass consists of retaining original artifacts and
evidence; no application/system state was changed. Do not delete the prior raw
evidence or restore Defender-blocked files. No VM recovery was needed this run.

Resolved: 35 artifact pins and remaining frozen-entry dispositions, with version,
dependency and ownership uncertainty narrowed. **No whole legacy outcome closed,
retired or newly excluded.** Filter Monitor/Vista4Experts stay page-only and the
prior AntiMida exclusion remains. Six opaque payloads and all recorded
licensing/native/UI/activation/Server gaps remain partial/deferred work. Catalog
362 operations/60 packages/33 pending and setting presentation 279/279 are unchanged.
All five estimate ranges were refreshed unchanged: **38-58 / 56-71 / 20-25 /
25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**. The scoped
source-review queue is assigned, but complete legacy deployment and user outcomes
are still unverified; no estimate deduction is justified by file inspection alone.

## Six-installer static extraction, 2026-10-17

The authorized no-UAC continuation resolves all **six outer installer extraction
blockers** from the preceding entry. [Dated evidence](../archive/evidence/installer-static-extraction-2026-10-17.json)
records unchanged input pins, **85 extracted files**, **14 nested SDK ZIP files**,
**20 nested MSI cabinet files**, their SHA-256 hashes and the remaining dependency
gates. A further embedded BDEFILES resource is pinned but still opaque. This is
source evidence only: no installer, extracted program/DLL, script, driver or
custom action ran; no VM/controller/checkpoint or Defender change occurred.
Defender-blocked NirSoft payloads remained untouched. All 51 frozen collection
entries retain their prior dispositions; no new product was admitted.

### Extractor provenance and bounded procedure

The six retained inputs contain Inno Setup 5.5.x data markers; the extractor
interprets four MiTeC headers as 5.6.0 and Mail Checker/Explorer Suite as 5.5.0
(Unicode for Explorer Suite). The portable Windows **innoextract 1.9** came from
the [official publisher](https://constexpr.org/innoextract/). Its archive matches
the published MD5 and has SHA-256
`6989342c9b026a00a72a38f23b62a8e6a22cc5de69805cf47d68ac2fec993065`.
The detached OpenPGP signature verifies against the publisher's HTTPS key,
fingerprint `ADE9653703D4ADE0E997758128555A66D7E1DEC9`. This establishes that
cryptographic match, not independent web-of-trust certification. Tool/dependency
licences remain beside the local executable; nothing was installed system-wide.

Sandbox DNS/MSYS startup restrictions and an extractor DLL-relocation startup
error were resolved using ordinary host execution, not Windows elevation. GPG
used an isolated review keyring and disabled agent startup for verification.
These were tooling/environment errors, not reported Defender detections. The
successful extractor ran at ordinary user privilege; no RunAs/UAC was requested.

From the repository root, the local scripts under
`.local/installer-static-20261017/` first verified each retained installer hash
against the preceding evidence. `list.ps1` captured names/sizes/internal hashes;
`extract.ps1` rejected unsafe/duplicate paths and bounded member count and size
before extraction to separate new directories. The reviewed
[extractor options](https://constexpr.org/innoextract/innoextract.1) combine
`--extract --test --no-extract-unknown --no-gog-galaxy`, explicit output directories
and collision handling. No installer extraction/help switch was used.

MiTeC used `--collisions error`. Explorer Suite initially refused duplicate
destinations, then used `--collisions rename-all` after review, retaining four
pairs independently. `$0`/`$1` suffixes are inspection names, not installation
names or architecture declarations; PE machine fields establish x86/x64.
All six extraction/checksum tests passed. Independent file rehashing matched
the installer SHA-1 values; new SHA-256 inventories supplement those checks.
Temporary BDE helpers were retained as data rather than silently omitted.

### Product findings and remaining acceptance

| Installer | Extracted files | Source finding / remaining gate |
| --- | ---: | --- |
| InfoBar | 29 | InfoBar x86/x64 **4.6.2.0**, DeskExp x86/x64 **1.4.0.0**, language/data files. TMX's separately reviewed DeskExp is 2.0.0.0; do not merge helpers by filename. Startup, desktop/UI, API behavior and recovery remain. |
| Paradox Data Editor | 4 | PDE **3.7.0.0**, TUTIL32.DLL **5.0.0.38**, temporary MiniReg.exe and BdeInst.dll **5.1.1.1**, all x86. BDE registration/redistribution/current-build behavior remain; no loader was invoked. |
| Project Maker | 3 | Both x86/x64 payloads are **1.9.0.0**, plus CHM. The page lists **2.0.0**: this is now a verified page/payload mismatch, not merely an outer-wrapper observation. Do not label this pin 2.0.0. Build/compiler/signing integrations still need synthetic fixtures. |
| Weather Agent | 10 | x86 **3.6.0.0**, data, seven languages and localization guidance. Service/API availability, startup/configuration and functional behavior remain; no keys or service calls used. |
| Mail Checker | 12 | x86 **7.2.0.0**, three OpenSSL-identified **1.0.1e** DLLs, six languages, localization and sample CSV. libssl32.dll/ssleay32.dll are byte-identical. Exact notices/provenance and isolated mail-server/TLS/send/delete acceptance remain. No real mailboxes or sample contents published. |
| Explorer Suite IV | 27 | Both CFF **8.0.0.0**, Task Explorer **2.2.0.1**, PE Detective **1.2.1.1** and DriverList **1, 0, 2, 1** variants; Signature Explorer **2.0.0.0**, UPX extension **1, 0, 0, 1**, UPX **3.08**, SDK, scripts and common-documents signatures. Component ownership, exact conditional destinations and suite install/uninstall remain. |

Explorer Suite's x86 CFF, both DriverList binaries, x86 installed UPX extension
and UPX executable match prior reviewed hashes. The suite's PE Detective files
do not match the prior standalone hash despite matching version text. Neither
version text nor byte matches extend prior standalone VM acceptance to the full
suite. Common-documents signatures and app scripts need explicit ownership and
preservation rules. The suite readme describes free software without warranty;
it does not supply an explicit redistribution grant.

### Nested components and saved blockers

`nested.ps1` inventories all 14 files in `UPX_Utility.zip`, including source/project
files and distinct x86/x64/Itanium extension builds. Those source-package DLLs
differ from the installed extension DLLs; no build, extension loading or UPX
operation occurred. No separate licence file was found in that ZIP. UPX's own
version-specific grant remains distinct from the NTCore extension and SDK.

The nested Extension Wizard MSI was opened with `OpenDatabase` mode 0. It has
ProductVersion **1.0.0**, ProductCode
`{D35C17BC-044C-4A61-98DD-9ED1D05CE565}`, four custom-action entries and 20
template/script/image assets. Only its exact named cabinet and File-table IDs
were extracted with existing 7-Zip. `vcprojects`/`VCWizards` destinations need a
specific Visual Studio fixture and recovery plan. Generic MSI .NET/IIS message
strings are not prerequisite evidence; no LaunchCondition table was found.
JavaScript, HTML, project files and MSI actions were never executed.

Exact extraction of `.rsrc/RCDATA/BDEFILES` from BdeInst.dll produced a
**3,548,843-byte** resource with SHA-256
`cc4c87a57391cf6c283ba212bae3a0fbbcd3346e53ac640c7819319db0b70d25`.
7-Zip cannot open it as an archive. Its internal BDE file set remains a concrete
source-format blocker; do not use MiniReg, DLL registration or an installer as
an extraction fallback. No protection setting was relaxed.

The [licensing watchlist](../package-licensing.md#important-to-review-licensing)
now records exact OpenSSL/SSLeay, UPX and BDE dependency review needs. Payload
inventories do not reconstruct embedded installer agreements, conditional file
selection, scripts, registry/tasks/shortcuts or post-install behavior. Those
surfaces remain open, as do existing Phoenix, DFM, SQLite, SSView and other terms
gates. No private licensing assessment was written on the user's behalf.

### Validation, recovery, next instructions and estimates

Validation checks six original pins, exact output sets, all 85 SHA-1/SHA-256
pairs, 27 outer PE metadata records, 14 nested ZIP hashes, 20 MSI cabinet file
sizes/hashes and the BDE resource pin. Evidence JSON, documentation links and
the focused diff/whitespace are checked. There were no engine/catalog changes;
no new Pester or native acceptance is claimed. Original artifacts, tool notices,
signature logs and output records remain in the local review directories.
No system/application state needs rollback, and no original evidence is deleted.

Next: resolve Project Maker's publisher/version discrepancy; identify a reviewed
static decoder for BDEFILES; reconcile exact bundled notices and installer
agreements/action metadata. Prepare synthetic fixtures and per-component
ownership/recovery before native proposals. Save BDE registration, prerequisites,
Visual Studio/SDK setup and new protected-controller selections in the
[deferred queue](../../TODO.md#deferred-elevation-sessions) for an attended session.
Keep the existing checkpoint and do not submit these products as an unrelated
registered suite. Defender exclusions and resource/profile deferrals persist.

Resolved: **six outer extraction subgates**, complete bounded output inventories
and specific version/helper/dependency observations. Partial: nested BDE data,
installer actions/terms and functional installation/recovery. Deferred: fresh
UAC and native/UI/activation/Server acceptance. **No whole legacy outcome closed,
retired or newly excluded.** All five ranges refreshed unchanged: **38-58 /
56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**.
The file-level progress does not yet establish a complete legacy user outcome;
362 operations/60 packages/33 pending and 279/279 setting presentations remain.

## Nested BDE and version/licence reconciliation, 2026-10-17

The authorized source-only continuation resolves the nested BDE extraction
blocker and corrects the prior Project Maker version conclusion. [Evidence](../archive/evidence/bde-version-license-follow-up-2026-10-17.json)
records **29 decoded BDE files**, five focused version checks, five licensing
checks, 22 rehashed frozen MiTeC pages and six newly retained publisher references.
Three direct Embarcadero guide requests returned HTTP 403 and remain recorded
access limits. No fresh UAC, installer/payload execution, VM/controller/checkpoint
change or Defender change occurred. Defender-blocked tools remained untouched.

### BDE data-format review and result

The resource pin remains
`cc4c87a57391cf6c283ba212bae3a0fbbcd3346e53ac640c7819319db0b70d25`,
3,548,843 bytes. A bounded read found a 32-bit count followed by 29 records, each
containing a byte-length ASCII filename, expanded/compressed lengths, an
uninterpreted 32-bit metadata word and a zlib stream. This is an inference from
this exact resource, not a published format specification or general decoder
support claim. All record boundaries consume the input exactly; metadata words
are retained without inventing timestamp or flag semantics.

The local `decode-bde.ps1` under `.local/bde-terms-20261017/` validates the input
hash, count, unique safe leaf names, header/buffer bounds and aggregate output
limit before accepting any result. .NET ZLibStream and a separate raw Deflate
read produce identical SHA-256 output; an explicit Adler-32 calculation matches
each stored checksum. Both paths use the platform compression implementation,
so this is not an independent decompression-library comparison. All 29 expanded
lengths match; **8,189,528 output bytes** are retained under the new review root.
No original file was overwritten, and no decoded DLL/EXE/CPL was loaded.

There are **18 x86 PE files**. Core engine/driver/admin files report **5.1.1.1**;
the set also contains **BLW32.DLL 3.05**, **bantam.dll 01.008** and
**DBCLIENT.DLL 5.0.1.32**. Do not assign one version indiscriminately to every
dependency. Remaining members include translation/data tables, help/index files
and `IDAPI32.CFG`. They were hashed, not opened as live database configuration or
help applications. No standalone licence file is present in the 29-file set;
this does not establish that all installer-embedded agreement surfaces are absent.

The former opaque-resource blocker is resolved. Registration and alias/config
coexistence, dependency/provider availability, rights and Windows compatibility
remain separate. This inventory is review data, not a supported portable BDE
installation. Do not use MiniReg, BdeInst/IDAPINST registration, BDEADMIN or a CPL
loader on the workstation to fill those acceptance gaps.

### Version reconciliation and explicit correction

**Correction to the preceding two source reviews:** Project Maker **2.0.0** is
explicitly marked **under development**, while **1.9.0** is dated **12 September
2025** in the [publisher history](https://www.mitec.cz/wp/pm/). The original
hash-verified frozen page already contained both labels; this was a review
interpretation error, not a changed publisher download. Both extracted
**1.9.0.0** executables agree with the dated release. The mismatch blocker is
removed, with prior evidence preserved as history. Compiler/build/signing and
licensing/runtime gates remain; unreleased 2.0.0 is not selected.

The context audit rehashed all **22** frozen current MiTeC pages. DFM Editor's
history explicitly distinguishes Delphi 11/12 variants, consistent with retaining
their individual **8.3.1.0/8.4.0.0** observations and matching BPL families.
InfoBar's current **4.6.2** dated entry matches **4.6.2.0** payloads; an older
history row also says under development. Do not classify an entire page using
that phrase or blindly select its first numeric version.

Phoenix's fresh page still reports **1.8.0.1**, the retained MSI ProductVersion
is **1.7.1**, and its File table/executable both report **1.9.0.1**. That identity
discrepancy remains unresolved. Explorer Suite's page says **III (18/11/2012)**,
while the retained installer identifies **IV**; the page's SHA-256 still matches
the exact installer. Keep suite labels and individual component versions distinct.
No artifact was re-downloaded, and no same-version binary was substituted.

### Licensing checks and remaining inputs

| Subject | Checked evidence | Remaining gate |
| --- | --- | --- |
| BDE and DFM BPLs | Official search-indexed Embarcadero licence guidance points to version-specific DEPLOY/README/product agreements and third-party vendor terms. Direct page and two BDE guide requests returned 403. | Applicable publisher-supplied edition/version documents or clarification for these exact files; generic guidance is not distribution permission. |
| MiTeC apps/components | Fresh support page separates application EULA and component/class terms. Named-user/build-machine, team and site scope are distinct. | Exact intended use and historical/current applicability; component development rights do not establish blanket app/shared-kit rights. |
| Mail Checker OpenSSL 1.0.1e | Retained and hashed the version-specific upstream OpenSSL/SSLeay terms. | Exact binary provenance and supplied notices/acknowledgements; modern TLS behavior and replacement compatibility remain unverified. |
| Explorer Suite UPX 3.08 | Retained and hashed its version-specific GPL-2.0-or-later licence and compressed-executable exception. | UPX source/notices/distribution obligations plus separate NTCore extension/source/SDK grants. |
| Phoenix/NTCore | Fresh freeware descriptions compared with the prior bundled EULA and suite readme observations. | No explicit replacement of Phoenix's restrictive EULA or blanket suite/component redistribution grant located in those sources. |

The [licensing watchlist](../package-licensing.md#important-to-review-licensing)
links the precise upstream references. The six successful HTTP responses and
three 403 outcomes are retained with hashes where content was acquired. No access
bypass, publisher message, licence purchase, entitlement assertion or private
individual/company review was performed. These findings do not convert pending
internal review status into a new unattended-installation approval gate; actual
terms, required entitlements/responses and shared-distribution review remain
separate under the accepted workflow.

### Validation, recovery and next instructions

Validation checks all resource/member offsets and lengths, complete input
consumption, checksums, saved output hashes, 18 PE observations, all 22 frozen
page hashes, six retained reference hashes and the correction's original-page
context. JSON, documentation targets/anchors, LF preservation and the focused
diff/whitespace are checked. No engine/catalog edit or Pester/native acceptance
claim. Raw data, scripts, original evidence and new outputs remain in their
review directories; no Windows/application state requires recovery.

Next source work: obtain accessible, exact publisher deployment/notice documents;
review remaining installer agreements/actions and the Phoenix/suite version
identities; prepare synthetic Paradox/database and existing-alias/configuration
fixtures with explicit dependency and ownership expectations. Keep source-ready,
activation and verified behavior distinct. Save BDE registration, prerequisites,
IDE setup and protected-controller changes in the [deferred queue](../../TODO.md#deferred-elevation-sessions)
for later attended acceptance against the existing checkpoint. No fresh UAC now.

Resolved: nested BDE format/member inspection and the erroneous Project Maker
mismatch blocker. Partial: exact rights, installer action semantics, dependency
coexistence and complete functional lifecycle. Deferred: UAC/native/UI/activation/
Server and existing resource/profile work. Defender exclusions remain. **No whole
legacy outcome closed, retired or newly excluded.** All five ranges refreshed
unchanged: **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Source clarification does not yet complete installation,
use or recovery outcomes; 362 operations/60 packages/33 pending and 279/279 setting
presentations are unchanged.

## Phoenix/Explorer Suite version and licence follow-up, 2026-10-17

The authorized no-UAC source continuation rechecked both current NTCore product
pages against retained artifacts and EULAs/readme material, then examined three
publisher monthly archive pages. [Evidence](../archive/evidence/ntcore-phoenix-suite-version-license-follow-up-2026-10-17.json)
records the exact hashes, distinct version fields, page/archive observations and
remaining product/use gates. No installer or extracted payload was run, no
download was substituted, and no user-specific or company licence approval was
made. There was no UAC, VM, controller/checkpoint or Defender change. Defender-
blocked tools remained excluded and untouched.

### Phoenix Protector

The publisher page still reports **1.8.0.1** and calls the application freeware.
The retained publisher-linked MSI remains hash
`15a7dbbf90ce66fb302a322c6809fafd897808096069dfecededf78e51b16369`; its MSI
ProductVersion is **1.7.1**, while the contained executable's file version is
**1.9.0.1**. The page has no release history mapping those fields. Keep all three
as different identities; the version relationship is unresolved.

The MSI contains `Phoenix License.rtf` with the previously recorded limited
single-user development/testing grant, nontransfer condition, restriction on
separating components, and commercial-hosting restriction. The live page's
freeware statement does not say it replaces that EULA. No publisher clarification
or intended-user entitlement was obtained. Do not treat freeware wording as an
EULA supersession or as permission to distribute a shared bundle.

### Explorer Suite

The current publisher page still labels the suite **III (18/11/2012)** and
publishes SHA-256
`94f4348ec573b05990b1e19542986e46dc30a87870739f5d5430b60072d5144d`. That hash
matches the retained **3,613,174-byte** installer whose internal product label is
**Explorer Suite IV**. This confirms the retained file matches the publisher's
currently linked download, but does not reconcile the page/installer labels.
The reviewed May 2025, March 2025 and June 2022 monthly archive pages contain no
Explorer Suite release announcement that explains the mismatch. Preserve the
publisher page's suite identity separately from the components observed in the
artifact: CFF Explorer 8.0.0.0 x86/x64, Task Explorer 2.2.0.1 x86/x64, and
Signature Explorer 2.0.0.0 x86.

The page calls the suite freeware; its retained readme says free software without
warranty. Neither reviewed source states an explicit redistribution grant.
Bundled UPX 3.08 is governed separately by its retained GPL-2.0-or-later terms
and compressed-executable exception; that does not grant rights for the NTCore
extension or SDK. No owner-specific use or redistribution decision was made.

### Migration disposition and next steps

Resolved: provenance linkage between the exact retained Explorer Suite installer
and the publisher's currently linked SHA-256. Partially clarified: the three
recent archive pages do not provide the missing Suite IV release history.
Unresolved: Phoenix version chronology; whether its freeware notice changes the
bundled EULA; Explorer Suite label chronology; intended-user rights, component
notices and redistribution; installer action/dependency review and native
acceptance. Deferred: both installers' functional and recovery acceptance until
a separately prepared, authorized attended session. These are artifact/licence
subquestions, not whole legacy outcomes. No whole outcome closed or retired and
no new exclusion was added. The existing Defender-blocked NirSoft tools remain
excluded and untouched.

Next: request exact publisher-supplied version and licence clarification through
the existing later-attended workflow; keep exact artifacts and notices pinned;
finish Phoenix framework/custom-action review and prepare disposable install,
repeat, removal and exact-restore checks before a future authorized acceptance
session. Do not run either installer now. Save any new UAC-dependent setup or
controller change for that session.

All five estimates were refreshed unchanged: **38-58 / 56-71 / 20-25 / 25-35 /
8-12**, exact **147-201**, rounded **145-200/about 175**. This source-only batch
adds evidence but resolves no complete legacy feature/product outcome, so no
range was deducted. The current inventory remains 362 operations/60 packages/33
pending and 279/279 setting presentations. JSON structure, the new evidence
hashes/links, LF endings and focused whitespace were checked; no runtime test or
Windows acceptance is claimed.

## NTCore installer-action static review, 2026-10-17

The next authorized no-UAC batch reviewed the retained MSI table records for
Phoenix Protector and Explorer Suite Extension Wizard, then inspected the
wizard's hashed template/script sources as text. [Evidence](../archive/evidence/ntcore-installer-action-static-review-2026-10-17.json)
contains the artifact pins, action sequencing, paths, script hashes, findings,
and remaining acceptance gates. No installer, extracted script or payload was
executed; no user or system state changed. There was no fresh UAC, VM,
controller/checkpoint or Defender action. Defender-blocked files remained
excluded and untouched.

### Phoenix Protector MSI

The retained MSI is 1,357,312 bytes with SHA-256
`15a7dbbf90ce66fb302a322c6809fafd897808096069dfecededf78e51b16369`. Its
serialized tables contain DLL-backed custom actions `DIRCA_CheckFX` and
`VSDCA_VsdLaunchConditions`, both sourced from `MSVBDPCADLL`. Properties record
.NET Framework **2.0.50727** and `VSDAllowLaterFrameworkVersions=False`. The
action table names and properties identify the framework gate but do not reveal
the exact DLL implementation or prove behavior on any Windows build. The
`LaunchCondition` table has no direct rows; the `VsdLaunchConditions` custom
action is sequenced before installation. The default target directory combines
Program Files, Manufacturer and ProductName. Three shortcuts and one RemoveFile
row are recorded; the MSI declares no registry or service-install/control rows.

The bundled custom-action DLL/source, exact checks and rollback/restore effects
remain unverified. Keep the previously recorded Phoenix version and EULA blockers.
Do not run the MSI or stage Framework prerequisites on the workstation.

### Explorer Suite Extension Wizard MSI and source

The retained nested MSI is 224,256 bytes, ProductVersion **1.0.0**, ProductCode
`{D35C17BC-044C-4A61-98DD-9ED1D05CE565}`. Its default destination is
`[ProgramFilesFolder]Microsoft Visual Studio 8\VC`, under both `vcprojects` and
`VCWizards\AppWiz\Generic\Explorer Suite Extension` with template and script
subdirectories. Its custom actions set a default directory/property and report
newer-version/advertised-install errors. No DLL-backed custom action,
`LaunchCondition`, Registry, service, shortcut or RemoveFile rows were recorded.
Generic .NET/IIS message strings are present, but without corresponding condition
rows they do not establish runtime prerequisites. In particular, the MSI does
not establish that Visual Studio 8 is present or identify an acceptable IDE
revision; installing it could place files in an unused Visual Studio directory.

The **20-file** MSI payload is mainly wizard templates and project assets. Static
inspection of `default.js`, `default.htm`, `.vsz`, `.vsdir` and `Templates.inf`
shows the wizard uses Visual Studio automation and the user's selected project
path to create a Unicode DLL project and render/add seven listed source/project
files. It creates a temporary rendered INF through
`Scripting.FileSystemObject` and deletes it on the normal path. The reviewed
script/HTML has no shell/process, registry or network invocation; the HTTP URI
in the HTML is a Microsoft target-schema declaration. This static observation
does not verify wizard-host behavior, generated project integrity, temp-file
cleanup under failure, collisions, or preservation of an existing project.

### Disposition and next procedure

Resolved: the MSI table-level destinations and action records, plus the wizard
script's intended project-file effects, are now explicit. Partial: exact
custom-action code, framework detection, Visual Studio prerequisite semantics,
file collision/rollback behavior and product terms. Deferred: isolated native
acceptance of both installers and the generated wizard in the exact framework/
IDE fixtures. No whole outcome closed or retired and no new exclusion was added.
Existing Defender-blocked NirSoft tools remain excluded.

Next: preserve the exact custom-action DLL and its notices/source; determine
whether a disposable registered VM has the required Visual Studio 8 fixture;
prepare a synthetic project folder with collision and recovery cases; then
prepare bounded install/repeat/remove/exact-restore acceptance in a later
attended session. Do not invoke MSI, Visual Studio wizard scripts, BDE loaders or
SDK helpers on the host. Any prerequisite/controller work requiring fresh
elevation stays in the [deferred queue](../../TODO.md#deferred-elevation-sessions).

All five estimates refreshed unchanged: **38-58 / 56-71 / 20-25 / 25-35 /
8-12**, exact **147-201**, rounded **145-200/about 175**. Static semantics do not
complete a legacy product outcome, so no count was deducted. The repository
inventory remains 362 operations/60 packages/33 pending and 279/279 setting
presentations. JSON structure, retained MSI/source hashes, estimate summary,
links, LF endings and focused whitespace were checked; no Pester, runtime test
or Windows acceptance is claimed.

## JoeWare rdp-sec-check version and licence follow-up, 2026-10-17

The next authorized no-UAC source batch reconciled the frozen JoeWare product
page with the collection's versions list, checked the publisher's version
history/announcement, and reviewed the separate original-source reference and
licence files. [Evidence](../archive/evidence/joeware-rdp-sec-check-version-license-follow-up-2026-10-17.json)
retains snapshot hashes, exact row values, source attribution and remaining gates.
The optional download form was not submitted; no archive was acquired and no
code or network probe was executed. A read-only `Get-VM -Name RIDE-Win11-Test`
check failed because the non-elevated client lacked access to a CIM resource.
No elevation was requested, and no VM, checkpoint, controller, Defender or
Windows state changed. Defender-blocked tools remain excluded and untouched.

### Version-list clarification

The product page explicitly advertises **0.9-beta (JoeWare V02.00.00)** dated
November 17, 2014. Its history says V02.00.00 updates the Portcullis 0.9-beta
base and adds IPv6 capability. The JoeWare versions list still has a
**01.00.00 / 2011.02.11** row. The page therefore identifies the current
publisher-advertised release; the 2011 row is not evidence for that release.
That row's origin/date is not reconciled with the page history's V01.00.00
entry, and no archive was fetched to establish exact contents or byte version.
Treat the page-level release label as clarified, while retaining archive/source
identity as a blocker. The [publisher product page](https://www.joeware.net/freetools/tools/rdp-sec-check/index.htm)
and [2014 publisher announcement](https://blog.joeware.net/2014/11/17/5553/)
both describe the V02.00.00/0.9-beta update.

### Source and licensing

The JoeWare page describes an AutoState PerlApp executable, says source Perl is
included in the ZIP under GPLv2, and attributes the original script to
Portcullis. The publisher's 2024 clarification permits internal corporate users
to share downloaded copies within their company; distribution outside that
internal-use scope, especially in a solution sold to others, remains separate.
That clarification removes a license blocker for RIDE's direct download-and-
install workflow. The exact ZIP, source, compiled executable and CPAN/dependency
notices remain uninspected; the 2026-10-17 publisher versions-list snapshot
provides MD5/SHA-1 rows only, not a verified SHA-256 pin.

The [CiscoCXSecurity source reference](https://github.com/CiscoCXSecurity/rdp-sec-check)
identifies the Perl source and GPL-2.0. Its repository also has a
`COPYING.RDP-SEC-CHECK` file with an additional legal-use-only condition. The
JoeWare page points to the Portcullis original source, but without the JoeWare
ZIP this reference does not prove those exact files/terms are bundled or how
they map to JoeWare's executable. Keep this as a provenance/terms question, not
a concluded legal interpretation. No owner-specific entitlement assessment was
made. The publisher's general internal-company-use clarification is recorded
separately from distribution in third-party commercial solutions.

### Disposition and later acceptance

Clarified: the publisher page's current release is V02.00.00 / 0.9-beta rather
than the older versions-list row. Partial: no exact archive, source/binary
relationship, notices, entitlement or runtime behavior is verified. Deferred:
artifact acquisition/inventory and any functional test. This command-line tool
opens TCP connections to RDP services on port 3389, so any later test requires
an explicitly owned isolated endpoint; no live-network scan is authorized here.
The host could not inspect RIDE-Win11-Test through non-elevated Hyper-V CIM, and
that VM-access blocker is saved in the [deferred queue](../../TODO.md#deferred-elevation-sessions).
No whole legacy outcome closed or retired, and no new exclusion was added.

Next: retain the exact official ZIP/source and record SHA-256, file versions,
notices and module attribution. Preserve the publisher's internal-company-use
scope and GPL obligations as separate product/source fields. No license gate
blocks RIDE's direct download-and-install workflow; archive identity and runtime
acceptance remain pending. See the [2026-10-23 scope and version review](../archive/evidence/joeware-internal-use-current-version-review-2026-10-23.json).
Use only the registered VM workflow once non-elevated access is available; do
not try to elevate or probe any network target.

All five estimates refreshed unchanged: **38-58 / 56-71 / 20-25 / 25-35 /
8-12**, exact **147-201**, rounded **145-200/about 175**. One page/manifest
version subquestion is clarified, but no complete legacy product outcome closed,
so no estimate range was reduced. Inventory remains 362 operations/60 packages/
33 pending and 279/279 setting presentations. Evidence JSON, local source-page
hashes, estimate summary, links, LF endings and focused whitespace were checked;
no installer, Pester test, VM acceptance or network behavior is claimed.

## Docker Desktop focused all-users setup and interrupted retry, 2026-10-20

Added `ApplicationsBatch3AllUsers` to isolate Docker Desktop's elevated
system-wide lifecycle from the limited-user installer path. The existing
`ApplicationsBatch3` continues to cover both variants. Guest dispatch, suite
validation, request validation, CLI help and the integration runbook now include
the focused suite. Repository validation passed for 363 operations, eight groups,
five profiles and 235 PowerShell files. A local run of
`tests/TestAutomation.Tests.ps1` passed 56 tests and failed 40 when the restricted
execution environment denied fixture writes; disabling Pester's unused
`TestRegistry` plugin did not remove those filesystem denials. This is not a
passing focused Pester result.

The already-active request `d68b653e1d034f6a9c0e8d0b640553bb` was submitted as
`ApplicationsBatch3` at 12:52:58 UTC and ended Failed at 13:40:49 UTC. The guest
connection to `192.168.11.3` was interrupted and AutomatedLab's reconnect attempt
failed. The run returned no guest summary; partial evidence collection also
failed because the remoting session was unavailable. The controller task returned
to Ready, the VM was Off, pending/running queues were empty, and no cleanup block
was recorded. No per-variant result can be inferred from this run; it does not
validate the all-users installation.

The local shell is not elevated and cannot refresh the protected controller.
After the controller is idle, an administrator must refresh it from the checkout
root with:

```powershell
.\tests\integration\Register-RideVmTestTask.ps1 -ConfigurationPath 'C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\configuration.json'
```

Then submit the focused suite with `Invoke-RideVmTestTask.ps1` using
`-IntegrationSuite ApplicationsBatch3AllUsers -TimeoutMinutes 90`. Keep catalog
support pending until guest validation/Pester and the all-users preview,
install/repeat/detection, saved-run recovery, and uninstall with Docker resources
preserved all pass. Per-user acceptance remains independently pending. This run
resolved, retired or excluded no legacy outcomes; all five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**.

Follow-up acceptance attempt `bff525a225ee4aeca7dc8db9399395d8` was dispatched
from elevated PowerShell after controller registration. Guest validation passed
and Pester passed 272/272 tests. The focused batch then failed before any package
installer ran: a `foreach ($variant ...)` loop reused the case-insensitive
`$Variant` parameter, whose `ValidateSet` accepts only `all-users`. The evidence
copy completed, the controller reported no cleanup error, and the result recorded
no collection error; this is a harness failure and not package acceptance. Renamed
the colliding loop variables in `Invoke-RideApplicationBatch.ps1`. The protected
controller must be refreshed from the updated checkout before another dispatch;
the all-users lifecycle remains pending. This run resolved, retired or excluded
no legacy outcomes and all five estimate ranges remain unchanged.

The fixed focused all-users retry `1256ae69b1a2470b8024f776f128eb41` passed
272/272 Pester tests, captured prior machine package state as absent, and acquired
Docker Desktop 4.96.0 (650,507,696 bytes; SHA-256
`3f75d46a07ff7c7adcc42e55b2bab862e25a459351723ac2633de9ad22a5b4b6`; valid
Docker Authenticode signature). It exceeded the 90-minute controller timeout
before producing a guest summary. The guest transcript was still locked during
partial evidence collection, so the install result and hang cause are unknown.
The controller recorded no cleanup or collection error; the request moved out of
the running queue and no runtime block marker remained. This is not successful
package acceptance. Both per-user and all-users variants remain pending. No
legacy outcome was resolved, retired or excluded; all five estimate ranges remain
unchanged.

## Docker Desktop ready for physical RIDE review, 2026-10-22

Completed the catalog package for both `per-user` and `all-users` installation
variants and enabled its Windows 11 operation so the owner can run the physical
RIDE acceptance. The package pins Docker Desktop 4.96.0 and its verified SHA-256,
uses the official direct installer, requires elevation only for `all-users`, and
preserves Docker resources on uninstall with the publisher's `--keep-data` option.
It does not configure WSL/backend, accept Docker terms, launch Docker Desktop or
provision containers. Generated operation docs and the operator package guide were
updated. Catalog support here enables the requested owner review; it does not
claim the RIDE lifecycle has passed.

The user reports installing the latest Docker Desktop through WinGet on a physical
computer without issues. The 2026-10-20 disposable Windows 11 Enterprise Hyper-V
attempts remain inconclusive for RIDE: the per-user install exceeded 20 and 60
minutes, and the all-users run exceeded 90 minutes after passing 272/272 Pester
checks and acquiring/verifying the installer. Docker documents Enterprise, Pro
and Education Windows editions as supported, while VM/VDI execution has separate
virtualization and Business-subscription constraints; see the [Windows install
requirements](https://docs.docker.com/desktop/setup/install/windows-install/) and
[VM/VDI guidance](https://docs.docker.com/desktop/setup/vm-vdi/). The Hyper-V
timeout does not establish a defect in the package or justify longer blind runs.

For physical review, run `ride.ps1 install package.docker-desktop -WhatIf` from
unelevated PowerShell for the default per-user mode, or add
`-Variant all-users` from elevated PowerShell. Remove `-WhatIf` to apply. Review
the RIDE plan and applicable Docker terms before applying. Acceptance should check
install, repeat detection, status/version, saved-run recovery and uninstall while
confirming Docker data remains. Both modes' RIDE lifecycle acceptance remains
open pending the user's test report. This run resolves, retires or excludes no
legacy outcomes; all five estimate ranges remain unchanged.

## SSView codec failure-path static review, 2026-10-20

Rechecked the retained `SSView.zip` and `ZLibCodec.dpr` pins without executing
the viewer, DLL or source. The source confirms same-directory plugin discovery
by `EncodeIStream` / `DecodeIStream` exports; the publisher describes the codec as
optional and says selected codecs participate in stream load/save. The sample's
exception handler rewinds the input and appends it to the output memory stream
without clearing partial output first. If a codec operation writes partial data
before raising, the returned output can contain partial transformed bytes followed
by the original stream, and no explicit error is propagated. The nil/empty path
also exits before assigning an output stream. These are source-level control-flow
observations; actual behavior depends on the bundled Delphi runtime and remains
unverified.

The publisher page lists SSView 4.1.2 dated 31 October 2022, documents the
same-directory DLL interface, and identifies ZLibCodec as a Delphi sample. Its
current support page says unregistered software is freeware for non-commercial
use and lists named-user/build-machine, team and site license types. The exact
source/plugin/sample grant, the sample `test.ss` terms, ZLib dependency provenance
and local intended-use/redistribution approval remain open. No legal conclusion
or owner-specific entitlement is inferred from those pages.

The [static evidence](../archive/evidence/ssview-codec-failure-path-review-2026-10-20.json)
records source/archive hashes and acceptance gates: isolated viewer-only opening,
valid round trip, malformed and partially decoded streams, empty input, save
behavior, and exact preservation of a disposable structured-storage copy. No
catalog change, payload execution, UAC, VM, controller, Defender action, or native
acceptance occurred. Existing Defender-blocked NirSoft files were not touched.
Resolved, retired and newly excluded whole legacy outcomes: **zero**. All five
estimate ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**. SSView terms, plugin behavior and
activation remain partial/deferred; Docker Desktop acceptance and the VM/controller
access blockers are unchanged.

## MiTeC SQLite Query static dependency and licensing review, 2026-10-20

The frozen `SQLiteQ.zip` pin and all three member hashes were checked without
extracting or executing the payload. The archive contains `SQLiteQuery.exe`,
`sqlite3.dll` and `sqlite3.exe` only; it has no license, notice, README, changelog
or source member. Static PE metadata reports SQLiteQuery FileVersion 3.2.0.0 and
ProductVersion 3.0.0.0, while the publisher page identifies product 3.2.0
(2021-05-18). Both bundled SQLite files report version 3.35.5 and the SQLite
Development Team copyright URL. These metadata match the inventory but do not
prove binary origin or compile options.

The official SQLite project states its deliverable code and documentation are
public domain and its 3.35.5 release is dated 2021-04-19. That project statement
is separate from MiTeC's SQLite Query application EULA. MiTeC's current support
page says trial/unregistered use is non-commercial and lists named-user/build-
machine, team, site and trial license types; the product page lists paid single
and site licenses. No personal/company entitlement or distribution decision is
inferred. Exact binary-to-upstream provenance/build options and any local legal
review remain open.

The publisher describes arbitrary SQL execution, table edits, import/export and
BLOB editing. Therefore later behavior acceptance must use disposable synthetic
database copies, cover edits/import/export/history and exact file recovery, and
never open production or personal databases. The [static evidence](../archive/evidence/mitec-sqlite-query-static-dependency-review-2026-10-20.json)
records all pins and gates. No payload, database, installer, UAC, VM, controller
or Defender action occurred, and existing Defender-blocked files were untouched.
Resolved, retired and newly excluded whole legacy outcomes: **zero**. All five
estimates remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**,
rounded **145-200/about 175**. MiTeC entitlement, SQLite binary provenance,
synthetic-database acceptance, SSView behavior, Docker Desktop acceptance and VM
controller access remain partial or deferred.

## MiTeC DFM Editor runtime-package and licensing review, 2026-10-20

The frozen `DFMEdit.zip` outer pin and all 18 file-member hashes match the
inventory; the two additional ZIP entries are empty directory markers. The
Delphi 11 folder contains `DFMEdit.exe` 8.3.1.0 and eight x86 BPLs with 280
suffix/version family. The Delphi 12 folder contains `DFMEdit.exe` 8.4.0.0 and
eight x86 BPLs with 290 suffix/version family. Keep the editions and package
families separate. The publisher page's 8.4.0 release history explicitly says
separate versions were added for Delphi 11 and 12.

The publisher describes editing/creating binary and text DFM files, extracting
forms from compiled PE files, and registering user packages. Package loading
executes code, so later tests must use isolated DFM, synthetic PE and disposable
BPL fixtures; no arbitrary user packages should be registered. Embarcadero's
RAD Studio 11/12 guidance says some files have redistribution limits, directs
reviewers to each version's installed DEPLOY, README and license documents, and
states that third-party redistribution rights come from the vendor. Runtime
packages require the correct matching versions. Those exact installed documents
are not in the retained archive. MiTeC's unregistered non-commercial terms and
paid single/site tiers remain separate; no local entitlement or redistribution
conclusion is made.

The [static evidence](../archive/evidence/mitec-dfm-editor-runtime-package-review-2026-10-20.json)
records the hashes, version families, publisher terms and acceptance gates. No
archive payload or BPL was executed, no user package was registered, and no UAC,
VM, controller or Defender change occurred. Existing Defender-blocked files were
untouched. Resolved, retired and newly excluded whole legacy outcomes: **zero**.
All five estimate ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**. Exact redistribution rights, local
MiTeC entitlement, DFM save/extraction preservation and package-loading behavior
remain partial/deferred.

## MiTeC EXE Explorer and HexEdit static source review, 2026-10-20

The frozen EXE Explorer and HexEdit archive pins and all three member hashes
match the inventory. EXE Explorer 3.7.5 has separate x86 and x64 executables;
HexEdit 7.1.0 is x86. Neither archive contains a license, README or notice file
by filename. The publisher describes PE/NE/VxD/.NET inspection, resource export
and text reports in EXE Explorer, and file editing/comparison plus memory and
disk dumpers in HexEdit. EXE Explorer's VirusTotal report/API-key feature is
listed, but exact request and data handling remain unspecified.

MiTeC's current support page says unregistered software is freeware for
non-commercial usage and lists paid license types. No local entitlement or
redistribution determination is inferred. Future parser/export tests need
synthetic, non-sensitive PE files and exact resource-export paths. HexEdit
editing must use disposable copies with byte-exact recovery; live memory and raw
disk features remain outside default acceptance until an isolated target and
recovery plan exist.

The [static evidence](../archive/evidence/mitec-exe-explorer-hexedit-source-review-2026-10-20.json)
records pins, features, terms and gates. No payload or analyzed file was opened;
no memory/disk target, UAC, VM, controller or Defender action occurred, and
Defender-blocked files were untouched. Resolved, retired and newly excluded
whole legacy outcomes: **zero**. All five estimate ranges remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Local terms, VirusTotal behavior, edit/recovery, UI and
activation remain partial/deferred.

## MiTeC system information and TAPI static review, 2026-10-20

The frozen MSIX archive/page hashes and all four viewer/helper member hashes
match the inventory. System Information eXtra 16.0.0 includes separate x86/x64
viewer and GetSys helper files, all versioned 16.0.0.0. The publisher describes
brief text, full XML and structured-storage reports, based on the MiTeC System
Information Component Suite. The page does not specify every report field or
redaction behavior. Its separate freeware demonstration grant does not establish
development or redistribution rights to the component suite.

The TAPI Monitor 1.2.0 archive and single x86 member hash also match. Its page
describes live TAPI line/provider monitoring and controls to make, answer, drop,
redirect and transfer calls. Version history adds TSP provider and line/phone
configuration management. The publisher lists a EUR 30 lifetime single-user
license; the support EULA separately describes non-commercial unregistered use.
No local entitlement or redistribution determination is made. The no-install/
no-traces claim is publisher-stated and remains unverified.

No system report may be created from a real profile or host; any later report
test needs synthetic guest data, an explicit field/redaction review and cleanup.
No real TAPI line, call, provider, history or configuration may be accessed; any
later behavior check must use simulated resources. The [static evidence](../archive/evidence/mitec-system-information-tapi-static-review-2026-10-20.json)
records pins and gates. No payload or report was created, no telephone resource
or call control was accessed, and no UAC, VM, controller or Defender action
occurred. Defender-blocked files were untouched. Resolved, retired and newly
excluded whole legacy outcomes: **zero**. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Report privacy/redaction, suite rights, TAPI configuration,
local terms, UI and activation remain partial/deferred.

## MiTeC InfoBar installer and data-effect static review, 2026-10-20

The pinned `InfoBar_Setup.exe` hash and product-page snapshot match the frozen
inventory. The installer PE has product version metadata 4.6.2 but blank file
version metadata. Its prior bounded listing has 18 entries; the installer
payload remains opaque because it was not extracted or executed. The publisher
describes an auto-hide taskbar-like system monitor, process/network views,
RSS/weather tools, location selection, coding tools, delayed logon startup and
Explorer-crash recovery. The page does not establish exact startup changes,
network requests, data retention, installer scope, removal behavior or recovery
guarantees. Its freeware terms are limited to private, educational and
non-commercial use; no local entitlement or redistribution conclusion is made.

This feature set can expose system, process, interface, location, RSS and
credential data. Any future acceptance requires an isolated guest with
synthetic host data; do not configure real feeds, API keys or locations. Review
exact installer actions and component notices before proposing activation.

The [static evidence](../archive/evidence/mitec-infobar-static-behavior-review-2026-10-20.json)
records current sources, pins and open gates. The installer was neither
extracted nor executed, no network request or host-data query occurred, and no
UAC, VM, controller or Defender action occurred. Defender-blocked files were
untouched. Resolved, retired and newly excluded whole legacy outcomes: **zero**.
All five estimate ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**. Installer actions, network/data
handling, terms, startup/removal, UI and activation remain partial/deferred.

## MiTeC Network Scanner network and data-risk review, 2026-10-20

The frozen `NetScanner.zip` pin, page snapshot and both executable hashes match
the inventory. The publisher page identifies version 6.1.0 and separate x86
and x64 files; both PE files report FileVersion 6.1.0.0 and ProductVersion
6.0.0.0. It describes ICMP/port/IP/NetBIOS/Active Directory/SNMP discovery,
service/share scans, SSDP/UPnP, WS-Discovery and mDNS. Published result fields
include device/user identity, services, shares, open files, running processes,
terminal sessions, event logs, installed software, SAM accounts and WMI queries.
Results can be edited and exported to CSV. The page does not establish exact
traffic, authorization, credentials, CSV handling or VirusTotal behavior.

The product page listed a EUR 30 lifetime single-user license on the review
date; the support EULA separately describes non-commercial unregistered use and
other license types. No local entitlement or redistribution decision is
inferred. Any later behavior test must use an isolated owned network, disposable
synthetic endpoints/accounts, explicit port/traffic bounds and disposable CSVs.
Do not scan a real local range, query production directory/SAM data, or use real
credentials/endpoints.

The [static evidence](../archive/evidence/mitec-network-scanner-static-risk-review-2026-10-20.json)
records the hashes, published fields and gates. No payload or network scan was
run, no host/directory data was queried, and no UAC, VM, controller or Defender
action occurred. Defender-blocked files were untouched. Resolved, retired and
newly excluded whole legacy outcomes: **zero**. All five estimate ranges remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Entitlement, network/credential/CSV behavior, UI and
activation remain partial/deferred.

## MiTeC certificate tools static source review, 2026-10-20

The frozen `CG.zip` and `CertInfo.zip` pins and executable member hashes match
the inventory. Certificate Generator 1.0.0 is x64 and creates self-signed
X.509 PEM/CER or PKCS#12 PFX certificates. Certificate Information 1.5.0 is
x86; its publisher page lists PEM/CRT/CER/P7B/P7C/DER/PFX/P12, signed portable
executables, MSI, XML and PDF as inputs, and PEM/DER export. Both pages state
freeware terms limited to private, educational and non-commercial use. The
support EULA is distinct; no owner-specific intended-use entitlement or
redistribution conclusion is recorded.

Certificate material is sensitive. Any later functional acceptance must use
synthetic or public certificates and a disposable test-only private key, verify
exact output cleanup, and never import generated certificates into trust stores
or open personal/production key containers. The current pages list Windows
XP-11 and Server 2003-2025 as publisher claims only; this is not RIDE support
evidence.

The [static evidence](../archive/evidence/mitec-certificate-tools-static-review-2026-10-20.json)
records sources, pins and acceptance gates. No payload or certificate was
opened, no certificate store changed, no UAC or VM run occurred, and neither
Defender nor its blocked-file set was changed. Resolved, retired and newly
excluded whole legacy outcomes: **zero**. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Local terms, synthetic parsing/generation/export,
cleanup, UI and activation remain partial/deferred.

## MiTeC UUID Generator host-identifier review, 2026-10-20

The frozen `UUID.zip` pin and its single executable member hash match the
inventory; the x86 PE metadata reports 1.0.0.0. The current product page says
UUID Generator creates UUID v4 (Windows GUID), UUID v7 (RFC 9562), ULID and
Snowflake Int64 identifiers, decodes UUIDs, and displays live UEFI, SMBIOS
System, Machine and Device UUIDs. Its freeware terms are limited to private,
educational and non-commercial purposes; the support EULA separately describes
license types. No local intended-use entitlement or redistribution conclusion
is inferred.

Live hardware/system identifiers can be persistent and sensitive. Later
acceptance is limited to generation and decoding with synthetic values; do not
query, capture, log, screenshot or export identifiers from the host or guest.
The product page's operating-system list is a publisher claim, not RIDE target
acceptance.

The [static evidence](../archive/evidence/mitec-uuid-generator-static-review-2026-10-20.json)
records the source, pin and privacy gate. The payload was not executed and no
live identifier was queried. No UAC, VM, controller or Defender action
occurred, and Defender-blocked files were untouched. Resolved, retired and
newly excluded whole legacy outcomes: **zero**. All five estimate ranges remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Entitlement, privacy-safe synthetic behavior, UI and
activation remain partial/deferred.

## MiTeC database utilities static review, 2026-10-20

The frozen `IBQ.zip` archive, both Interbase Query executable hashes, the
Paradox Data Editor installer and both product-page snapshot hashes match the
inventory. Interbase Query 9.5.0 offers arbitrary SQL/scripts and history,
metadata extraction including table data, user/role and privilege management,
database validation, shutdown/online/offline controls, and registered-version
import/export and index rebuilding. The page lists EUR 99/299/799 single/team/
site lifetime prices. The binaries report FileVersion 9.5.0.0 and ProductVersion
9.0.0.0; preserve this metadata distinction. It uses IBX and has an optional
client DLL path, but exact client version, bitness and redistribution are open.

Paradox Data Editor 3.7.0 uses BDE and can edit tables, remove password
protection, repair, convert levels 4/5/7, manage indexes, and import/export
multiple formats. Its pinned setup PE has blank version metadata and a prior
18-entry listing; installer actions remain opaque because it was not extracted
or executed. Exact BDE version/provider/bitness, registry/coexistence effects,
and rights remain unresolved. Product pages list EUR 30 single-user lifetime
license for Paradox and current Interbase Query tiers; the support EULA is
separate. No owner-specific entitlement or redistribution decision is made.

All later data tests require synthetic disposable databases, backups and
byte-exact recovery. No real user database, live InterBase/Firebird service,
database credentials, SQL changes, user/privilege changes, shutdown or BDE
registration may be used in this acceptance. The
[static evidence](../archive/evidence/mitec-database-tools-static-review-2026-10-20.json)
records versions, pins and gates. No database or service was opened or changed,
and no installer, UAC, VM, controller or Defender action occurred. Defender-
blocked files were untouched. Resolved, retired and newly excluded whole legacy
outcomes: **zero**. All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 /
8-12**, exact **147-201**, rounded **145-200/about 175**. Entitlement,
dependencies, installer actions, synthetic database behavior, recovery, UI and
activation remain partial/deferred.

## MiTeC OLE/COM Explorer and Project Maker static review, 2026-10-21

The frozen OLE/COM archive, Project Maker installer and both product-page
snapshot hashes match the inventory. OLE/COM Explorer's current page describes
an object explorer/type-library viewer but provides no version history or
release number; its single x86 executable reports FileVersion 1.4.0.0 and
ProductVersion 1.0.0.0. Use of arbitrary registered COM servers remains out of
scope until inspection-versus-activation behavior is known.

Project Maker's pinned x86 installer is 1.9.0 by both outer FileVersion and
ProductVersion; its prior bounded listing has 18 entries but the installer
payload/actions remain unknown. The current product page distinguishes released
1.9.0 (2025-09-12) from 2.0.0, which is labeled under development. This corrects
the earlier inventory's `PageVersion: 2.0.0` as a conflation; installed version
is still unverified. The page describes Delphi batch builds, arbitrary before/
after actions, version patching, code signing and third-party protection. Any
later build test needs an isolated synthetic project/output directory, bounded
actions and a disposable signing key. No real project or production key may be
used.

OLE/COM Explorer's page lists freeware limited to private, educational and
non-commercial use. Project Maker offers a trial and paid license tiers; the
support EULA is separate. No owner-specific entitlement or redistribution
conclusion is made. The [static evidence](../archive/evidence/mitec-olecom-project-maker-static-review-2026-10-21.json)
records pins and gates. No payload, COM object, project, compiler or signing key
was accessed. No UAC, VM, controller or Defender action occurred, and blocked
files were untouched. Resolved, retired and newly excluded whole legacy
outcomes: **zero**. All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 /
8-12**, exact **147-201**, rounded **145-200/about 175**. COM activation,
installer actions, build isolation, dependencies, terms, UI and activation
remain partial/deferred.

## MiTeC Registry Recovery and SMBIOS Explorer sensitive-data review, 2026-10-21

The frozen WRR/SMBE archive pins, both Registry Recovery executable hashes,
three SMBIOS Explorer executable hashes and page snapshots match the inventory.
Registry Recovery 3.1.3 reads offline registry hives and can expose product
keys/IDs, part of SYSKEY, machine SID, user/group accounts, installed software,
startup entries, services/drivers, network/firewall settings, environment and
Outlook Express account settings; it also exports REGEDIT4 and has a Registry
Backup tool. SMBIOS Explorer 1.8.0 can read firmware data through registry,
WMI, ROM or API, and save plain/compressed captures; its identification view
collects serial/asset numbers and the page history says System UUID is included.
The separate `SMBIOS.exe` helper is x86 version 1.0.0.0, distinct from the
1.8.0 main app.

Product pages list paid options; local entitlement and redistribution are not
resolved. All later checks must use synthetic offline hives and synthetic
SMBIOS fixtures only. Do not read/export host product keys, SYSKEY, SIDs,
accounts, network/firewall settings, email settings, firmware serials, asset
tags or UUIDs; do not run Registry Backup on a real hive. The
[static evidence](../archive/evidence/mitec-registry-recovery-smbios-static-review-2026-10-21.json)
records hashes and gates. No payload, hive, report, registry backup, WMI or ROM
data was accessed, and no UAC, VM, controller or Defender action occurred.
Defender-blocked files were untouched. Resolved, retired and newly excluded
whole legacy outcomes: **zero**. All five estimates remain **38-58 / 56-71 /
20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**.
Entitlement, export privacy, backup/recovery, UI and activation remain
partial/deferred.

## MiTeC SQLite Query upstream source-ID follow-up, 2026-10-21

The retained SQLite Query archive and all three member hashes were rechecked
against the prior frozen inventory. Without extracting or loading either
SQLite binary, printable-string inspection found the exact upstream SQLite
3.35.5 source-ID string in both `sqlite3.dll` and `sqlite3.exe`. SQLite's
official 3.35.5 release record publishes the same source ID and a SHA3-256 for
`sqlite3.c`.

Both binaries also expose static compile-option strings. Each names
`COMPILER=gcc-5.2.0`; the DLL lists `THREADSAFE=1` while the CLI lists
`THREADSAFE=0`. Their extension sets differ: the DLL lists column metadata,
FTS4/5, Geopoly, JSON1, math, pre-update hooks, RTree and session support; the
CLI additionally lists bytecode, DBSTAT, FTS3, statement-table and unknown-SQL
function options. Treat these as embedded build metadata, not runtime queries.

This strengthens the release-identity and build-configuration record, but does
not prove every compiled byte derives only from canonical SQLite source, reveal
all local patches, or provide a reproducible build recipe. No SQLite source
archive was matched byte-for-byte to either binary. The official public-domain
status applies to SQLite's deliverable code; MiTeC SQLite Query remains under
separate publisher terms, and local entitlement/redistribution is unresolved.
No database or SQL statement was opened, executed or modified.

Any functional check still requires disposable synthetic databases and exact
input/output recovery. No binary was executed, no UAC/VM/controller action
occurred, and Defender-blocked files remain untouched. The
[source-ID evidence](../archive/evidence/mitec-sqlite-query-source-id-follow-up-2026-10-21.json)
records exact strings, hashes and limits. Resolved, retired and newly excluded
whole legacy outcomes: **zero**. All five ranges remain **38-58 / 56-71 /
20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**.
Release identity is stronger, while reproducible provenance, terms and
database behavior/recovery remain partial/deferred.

## MiTeC Task Manager DeLuxe process and data-flow review, 2026-10-21

The frozen `TMX.zip` pin, page snapshot and all four executable hashes match
the inventory. TMX 5.1.1 is shipped as separate x86/x64 files with FileVersion
5.1.1.0 and ProductVersion 5.0.0.0; DeskExp x86/x64 companions are 2.0.0.0.
The publisher page describes process/service/driver, network, session, startup,
hardware and performance monitoring; VirusTotal reputation links; session
journaling; and system information. Its version history also lists service and
process termination, start/stop/restart, optional suspended-process cleanup,
minidumps, update checks and journal/account CSV export. Exact outbound query
data, dump contents, persistence and no-trace behavior remain unspecified.

The product page lists a EUR 30 lifetime single-user license; the support EULA
separately describes non-commercial unregistered use. No owner-specific
entitlement or redistribution decision is inferred. Do not query VirusTotal,
create a minidump, export account/session data, terminate processes or change
services. Future acceptance is limited to read-only viewing in an isolated
guest with synthetic data and persistence/cleanup review.

The [static evidence](../archive/evidence/mitec-task-manager-deluxe-static-risk-review-2026-10-21.json)
records pins and gates. No payload, live process/service, network request or
reputation query occurred; no UAC, VM, controller or Defender action occurred,
and Defender-blocked files were untouched. Resolved, retired and newly excluded
whole legacy outcomes: **zero**. All five estimates remain **38-58 / 56-71 /
20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**.
Process/service action semantics, data flow, persistence, local terms, UI and
activation remain partial/deferred.

## MiTeC Mail and History Viewers static review, 2026-10-21

The retained MailView, EHB, IHB and IMHB archives and executable/dependency
member hashes were recomputed and match the frozen inventory. Mail Viewer
2.5.1.0 can read email databases and EML, display bodies/HTML, extract addresses
and attachments, save messages and print. E-mail History Browser 1.2.0 exposes
communication metadata but says it omits bodies and attachments. Internet
History Browser 2.5.0 exposes visited URLs with dates, times and browser names;
Instant Messaging History Browser 1.2.1 can expose chats, calls and transfers
for legacy clients. The latter three publisher pages currently show no release
number; retained inventory and executable versions remain the pins. Current
publisher target lists for EHB, IHB and IMHB end at Windows 10 (IHB also lists
Server 2019); this does not establish RIDE support for newer releases.

Mail Viewer and IHB publisher pages limit free use to private, educational and
non-commercial purposes. EHB and IMHB pages currently state free private and
commercial use, while the general MiTeC support EULA says unregistered freeware
is non-commercial. Treat EHB/IMHB commercial use and distribution as unresolved
until product-specific terms are confirmed. IHB and IMHB contain renamed SQLite
binaries; metadata and SQLite's public-domain status do not establish exact
binary provenance or rights to the surrounding products.

No real mailbox, message, attachment, browser history, chat, call, transfer,
profile or account was opened. Future behavior checks must use synthetic data
and verify source immutability, output ownership and cleanup. The
[static evidence](../archive/evidence/mitec-mail-and-history-viewers-static-review-2026-10-21.json)
records publisher observations, rechecked pins and gates. No payload, UAC, VM,
controller, network or Defender action occurred; Defender-blocked files were
untouched. Resolved, retired and newly excluded whole legacy outcomes: **zero**.
All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**. Entitlement, distribution, target
support, SQLite provenance, output/persistence behavior, UI and activation
remain partial/deferred.

## MiTeC Windows File Analyzer and Icon Explorer static review, 2026-10-21

The retained WFA and Icon Explorer archives and executable-member hashes were
recomputed and match the frozen inventory. Windows File Analyzer 2.10.0 reads
thumbnail databases, Prefetch files, shortcuts, browser Index.dat and Recycle
Bin records and can print results. Icon Explorer 5.3.0 recursively searches a
selected path, extracts icons/images/bitmaps and creates 32-bit icon-library
DLLs; its 16-bit ICL/NE support was removed. Both publisher target lists end at
Windows 10 and do not establish Windows 11 or current Server support.

WFA can expose browsing activity, deleted-file names, user paths, timestamps and
image previews. Icon Explorer can traverse more files than intended when given
a broad root and writes extracted outputs. Any later check must use a narrow
synthetic directory, preserve inputs, write to a distinct disposable output
folder and verify collision and cleanup behavior. Do not inspect or print host
forensic data. Both publisher pages limit free use to private, educational and
non-commercial purposes; local entitlement and distribution remain unresolved.

The [static evidence](../archive/evidence/mitec-file-analyzer-icon-explorer-static-review-2026-10-21.json)
records pins, page observations and gates. No payload, host file, forensic
artifact or personal result was opened or printed, and no output was written.
No UAC, VM, controller, network or Defender action occurred; Defender-blocked
files were untouched. Resolved, retired and newly excluded whole legacy
outcomes: **zero**. All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 /
8-12**, exact **147-201**, rounded **145-200/about 175**. Entitlement, output
semantics, target support, UI and activation remain partial/deferred.
## MiTeC Weather Agent and Mail Checker static review, 2026-10-21

The frozen Weather Agent and Mail Checker outer-installer hashes were
recomputed and match the inventory. Weather Agent's pinned page version is
3.6.0, but the outer installer has no version fields and its prior bounded
listing exposed only PE resources. The page describes current conditions,
forecasts up to 16 days, selected locations and a MiTeC weather component; the
provider, location precision, API-key need, outbound data, persistence, startup
and installer actions remain unknown. Its listed targets end at Windows 10.

Mail Checker 7.2.0's outer installer also has blank version metadata and did
not parse as a 7-Zip archive; no payload was extracted. The page describes
multiple mailbox monitoring, spam recognition, deletion, message viewing,
Gmail SSL retrieval, SMTP replies/new messages, portable operation and a task
journal. Exact protocols, credential requirements, send/delete controls,
persistence and installer actions remain unverified. Its listed targets end
at Windows 7. Any future test needs an isolated mail sink, synthetic accounts,
messages and recipients, and explicit no-send/no-delete defaults with recovery.

Both pages state that private and commercial use is free, while MiTeC's general
support EULA says unregistered freeware is non-commercial. Resolve this
product-specific discrepancy and distribution rights before commercial use or
bundling. No location, API key, mailbox, credential or message was accessed;
no network request, installer extraction or execution occurred. The
[static evidence](../archive/evidence/mitec-weather-agent-mail-checker-static-review-2026-10-21.json)
records pins and gates. No UAC, VM, controller or Defender action occurred;
Defender-blocked files were untouched. Resolved, retired and newly excluded
whole legacy outcomes: **zero**. All five ranges remain **38-58 / 56-71 /
20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**.
Installer actions, service protocols/data flow, local rights, persistence,
recovery, current targets, UI and activation remain partial/deferred.
## NTCore .NET Generic Unpacker and DynLogger static follow-up, 2026-10-21

The current NTCore product pages report version 1.0.0.1 for both tools. The
.NET Generic Unpacker dumps/unpacks packed .NET applications. DynLogger logs
loaded modules and dynamically retrieved function names and writes its log when
the monitored process exits. Both pages direct x86/x64 selection by target
process architecture; DynLogger reports testing only on Windows XP/Vista. These
claims do not establish current Windows compatibility, exact injection/dump
mechanics, output paths or persistence.

All four retained ZIP hashes were recomputed and match the frozen inventory.
Each archive has the expected architecture; each DynLogger package includes its
matching executable, logger DLL and hook-engine DLL. No license/redistribution
notice was recorded in their archive member inventories. The NTCore download
page's statement that there are no license restrictions is specifically about
DisasMSIL and does not grant rights for these two tools. Do not dump or
instrument any real process. A later check requires an owned synthetic target,
matched files, isolated output, explicit compatibility review and product-
specific terms clarification.

The [static evidence](../archive/evidence/ntcore-unpacker-dynlogger-static-review-2026-10-21.json)
records current page observations, rechecked pins and gates. No target process,
memory dump, log, payload, UAC, VM, controller, network or Defender action
occurred; Defender-blocked files were untouched. Resolved, retired and newly
excluded whole legacy outcomes: **zero**. All five ranges remain **38-58 /
56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Licensing, distribution, hook/dump behavior, runtime,
output ownership, current-target support, UI and activation remain
partial/deferred.
## NTCore NoDel kernel and service static review, 2026-10-21

The frozen `NoDel.zip` hash was recomputed and matches the inventory. Its
retained source confirms the selected-folder boundary: the GUI resolves a
volume/device path and passes it to an x86 kernel driver, which hooks
`ZwSetInformationFile` and rejects `FileDispositionInformation` requests with
delete enabled when the object name starts with the selected path (case-
insensitive comparison). Other requests are forwarded to the original system
call. This is an unsupported legacy service-table hook approach, not a file-
system minifilter; source alone does not establish all deletion paths or
bypasses.

The client opens the Service Control Manager with `SC_MANAGER_ALL_ACCESS`,
creates a demand-start kernel-driver service named `nodel`, starts it and sends
the path. Its stop/close handler closes the device, stops the driver and deletes
the service. Some setup/cleanup calls ignore return values, so partial-failure
recovery, service residue, signing, architecture and current-kernel compatibility
remain unverified. NTCore's listing does not provide a specific redistribution
grant or current supported Windows targets.

The [static evidence](../archive/evidence/ntcore-nodel-source-risk-review-2026-10-21.json)
records the reviewed source members and boundaries. Source was read from the
pinned archive without extraction; no build, service, driver, file operation,
UAC, VM, controller, network or Defender action occurred, and Defender-blocked
files were untouched. Do not build/load the driver or use it on real files.
Future acceptance would require explicit attended elevation, a disposable VM,
a signed compatible driver and synthetic files, with service and file-state
recovery checks. Resolved, retired and newly excluded whole legacy outcomes:
**zero**. All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**,
exact **147-201**, rounded **145-200/about 175**. Licensing, driver support,
compatibility, failure recovery, UI and activation remain partial/deferred.
## NTCore SNSRemover and WIM Installer static review, 2026-10-21

The frozen SNSRemover and WIM Installer archive hashes were recomputed and
match the inventory. NTCore's utility listing describes SNSRemover as removing
strong-name signatures from .NET assemblies; exact input-mutation versus
separate-output behavior, signature/key effects and recovery are unspecified.
Its bundle contains a nested `PE_Detective.zip` whose hash differs from the
separately reviewed PE Detective candidate. Keep the nested older artifact
separate; do not substitute it for the pinned candidate. No assembly was
modified.

The same listing dates WIM Installer to 2007 and describes a GUI for WIM-based
setups from any publisher. Its retained x86 executable reports version 1.0.0.1.
The page does not describe destination selection, partition/boot effects, image
validation or rollback. Treat future use as potentially destructive image
deployment. No image, disk or destination was opened, mounted or changed.
Neither product has an explicit product-specific redistribution grant or current
Windows target list in the reviewed publisher listing/member inventory.

The [static evidence](../archive/evidence/ntcore-snsremover-wim-installer-static-review-2026-10-21.json)
records pins and gates. No installer/payload was executed, assembly modified or
image mounted/applied. No fresh UAC, VM, controller or Defender action occurred;
Defender-blocked files were untouched. An attempted browser navigation to a
publisher download endpoint returned a cache miss; no artifact download
completed. Resolved, retired and newly excluded whole legacy outcomes: **zero**.
All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**. Licensing, output/recovery, image
and disk effects, target support, UI and activation remain partial/deferred.

## MiTeC installer extraction reconciliation, 2026-10-21

The active queue and latest-run summary previously described the Weather Agent
and Mail Checker installers as opaque. That status was stale: the retained
2026-10-17 signed-tool extraction record shows all six pinned MiTeC installers
were statically extracted and inventoried, with no opaque outer installer left.
The later BDE review also decoded the nested BDE resource. This reconciliation
does not claim that any installer or payload ran.

The extracted payloads identify InfoBar 4.6.2.0 and DeskExp 1.4.0.0; Paradox
Data Editor 3.7.0.0 with TUTIL32.DLL 5.0.0.38 and BdeInst.dll 5.1.1.1; Project
Maker 1.9.0.0; Weather Agent 3.6.0.0; Mail Checker 7.2.0.0 with bundled
OpenSSL-identified 1.0.1e libraries; and Explorer Suite IV with its separately
versioned utilities. These resolve outer extraction, payload-version and
nested-BDE-format subgates. They do not establish installer registry/service,
task, shortcut or uninstall behavior, product-specific grants, current Windows
support, UI, dependencies, activation or recovery.

Weather Agent's network/API data flow remains unknown. Mail Checker can send or
delete messages and needs an isolated local mail sink; never use a real mailbox.
Exact OpenSSL binary provenance/notices, Phoenix custom-action behavior,
Explorer Suite component ownership, BDE registration/coexistence and synthetic
acceptance remain open. The six outer-installer statements in the frozen
2026-10-17 inventory are historical and superseded only for extraction status.

The [reconciliation evidence](../archive/evidence/mitec-installer-extraction-reconciliation-2026-10-21.json)
links the original pins and records remaining gates. No installer, payload,
service, database, network operation, UAC prompt, VM, controller or Defender
setting was touched; Defender-blocked files remain excluded. Resolved, retired
and newly excluded whole legacy outcomes: **zero**. All five ranges remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175** because only partial extraction/version subgates were
resolved. Current acceptance and licensing blockers remain.

## NTCore Filter Monitor and Vista4Experts page review, 2026-10-21

Current official publisher pages confirm why these two frozen NTCore entries
remain page-only. Filter Monitor page version 1.1.0 can list and unregister
kernel-mode filters, including registry and process/thread notifications. The
publisher claims x86/x64 availability and support from Vista RTM through
Windows 7 RTM only, disclaims later compatibility because it relies on system
internals, and states that its driver is unsigned and requires booting with
driver-signature enforcement disabled. Do not disable that protection or
unregister security filters.

Vista4Experts page version 1.2.0.1 describes changes to UAC, automatic Defender
scanning, automatic updates and other Vista security settings. The page says
these changes can be discarded, enabled or reversed and broadly claims it
works on every platform, but does not identify per-setting values, exact prior
state or restore semantics. It explicitly acknowledges that many fixes lower
Vista's default security. No Defender, UAC, update or other protection change
is accepted for migration.

These current page claims confirm the existing frozen page-only statuses; they
do not justify acquiring either payload or accepting a legacy behavior. The
[page-review evidence](../archive/evidence/ntcore-filter-monitor-vista4experts-page-review-2026-10-21.json)
records the source links and disposition. No payload was acquired or executed,
no filter/driver or Windows setting was changed, and no UAC, VM, controller or
Defender action occurred. Defender-blocked files remain untouched. Resolved,
retired and newly excluded whole legacy outcomes: **zero**. All five ranges
remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175** because the page review clarifies an exclusion without
closing either whole legacy outcome.

## NTCore Driver List and Rebel.NET source follow-up, 2026-10-21

Current NTCore pages still report Driver List 1.0.2, which lists loaded drivers
and can write a report, and Rebel.NET 1.6.0.1, which creates a reconstruction
report from a .NET assembly and can rebuild an assembly with selected method or
stream changes. The retained DriverList.zip and RebelDotNET.zip pins were
recomputed and match the frozen source evidence. The three Driver List builds
are x86, x64 and IA64; the IA64 binary is for Itanium and does not imply ARM64
support. The earlier embedded-version check remains incomplete.

The official Rebel.NET guide says commercial use goes against its licensing
terms. This resolves the prior blanket “no terms found” description only to
that extent: it does not establish who qualifies for noncommercial use or grant
redistribution. The bundled RebelDotNET.h documents a file format and is not a
source-code license. The guide also documents report/rebuild command-line
paths and a format flag that can delete every method from an input assembly.
Any later use must be limited to owned synthetic assemblies and separate
outputs, with input-preservation and signature/recovery checks.

Driver List's product page does not state a product-specific license or
distribution grant. A generated report enumerates loaded drivers and should
be treated as potentially sensitive inventory. No system driver list was read
and no report was generated. Neither archive was extracted during this review;
no payload, assembly, host, UAC, VM, controller or Defender setting was
changed. Defender-blocked files remain untouched.

The [source-review evidence](../archive/evidence/ntcore-driver-list-rebelnet-source-review-2026-10-21.json)
records page observations, pins and gates. Resolved, retired and newly
excluded whole legacy outcomes: **zero**. All five ranges remain **38-58 /
56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Rebel.NET commercial-use restriction is explicit, but
applicable user scope and redistribution remain unsettled; Driver List terms,
architecture/version, sensitive report output and both tools' runtime,
recovery and Windows support remain partial/deferred.

## NTCore 4GB Patch page and backup behavior follow-up, 2026-10-21

The current NTCore page still reports 4GB Patch 1.0.0.1. It says the x86 tool
sets the PE large-address-aware flag so a 32-bit executable can use up to 4 GB
of virtual address space on x64 Windows, accepts GUI or command-line use, and
automatically creates a backup of the original executable. The publisher's
separate CFF scripting guide shows the corresponding header operation: OR the
`IMAGE_FILE_LARGE_ADDRESS_AWARE` bit into the PE `Characteristics` field; that
example offers overwrite or Save As. The script is documentation for CFF
scripting and does not grant rights for the separate 4GB Patch executable.

The retained outer and member SHA-256 hashes were recomputed and match the
2026-10-17 evidence. Its x86 executable metadata reports version 1.0.0.1 and
2007 copyright with “all rights reserved.” Neither the current product page nor
the retained single-file archive evidence supplies a product-specific license
or redistribution grant. Do not infer permission from the CFF script or other
NTCore products. The page does not specify backup naming/location/collision,
signature/checksum handling, already-set flag behavior or exact Windows builds.

Any later acceptance must use an owned synthetic x86 PE, separately hashed
original and output, and verify the exact flag, backup content/path and
restoration. Do not patch third-party or production executables. No payload or
target was run or modified, and no UAC, VM, controller or Defender action
occurred. The [evidence](../archive/evidence/ntcore-4gb-patch-page-follow-up-2026-10-21.json)
records pins and remaining rights/recovery gates. Defender-blocked files remain
untouched. Resolved, retired and newly excluded whole legacy outcomes: **zero**.
All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**; version and backup documentation
clarify behavior without resolving rights or full acceptance.

## MiTeC SSView current terms and targets follow-up, 2026-10-21

The current MiTeC product page continues to report Structured Storage Viewer
4.1.2 dated 2022-10-31. It claims Windows XP-11 and Windows Server 2003-2025
support. This is publisher-stated compatibility, not RIDE runtime evidence or a
support declaration for a future catalog operation.

The page confirms that SSView searches its own directory for DLLs exporting
`EncodeIStream` and `DecodeIStream`, and that selected codecs participate in
view, save and load paths. It calls the included ZLIB codec Delphi source a
sample for writing third-party codecs. The 2026-10-20 static review remains
material: its exception handler can return partial transformed output followed
by original bytes, empty inputs return without assigning output, and the
reproducible source build is unresolved because the referenced resource is not
included. No codec was loaded, built or executed here.

The product page lists lifetime single, single-professional and site-professional
license options. The current support page says trial/unregistered software is
freeware only for non-commercial use and provides named-user/build-machine,
team and site EULA terms. The EULA's one-backup allowance and restrictions on
transferring license rights do not establish a product or codec redistribution
grant. No local owner or organization entitlement was assessed. The publisher
does not state separate terms or attribution for `ZLibCodec.dpr`,
`ZLibCodec.dll` or `test.ss`; do not treat the sample label as a source license.

Any later test needs an isolated SSView directory, separately identified
synthetic structured-storage fixtures and exact original/output hashes. Verify
empty and malformed inputs, codec partial-write failure, save/load round trips,
plugin search/loading, and byte-exact recovery in a registered guest. No
structured-storage document was opened or changed; no UAC, VM, controller or
Defender action occurred. Defender-blocked files remain untouched.

The [current-source evidence](../archive/evidence/mitec-ssview-current-terms-targets-follow-up-2026-10-21.json)
records the page claims and remaining gates. Resolved, retired and newly
excluded whole legacy outcomes: **zero**. All five ranges remain **38-58 /
56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. Product targets and license structure are clearer, but
codec/sample rights, local entitlement and integrity behavior remain
partial/deferred.

## MiTeC PhotoView GDI+ dependency follow-up, 2026-10-21

The retained PhotoView archive, executable and bundled DLL hashes were
recomputed and match the frozen 2026-10-17 evidence. PhotoView.exe is PE32 x86
version **1.4.0.0** and its import table directly names `gdiplus.dll`. The staged
x86 DLL is **5.1.3102.1360**, 1,645,320 bytes, has a valid Authenticode signature
from Microsoft Windows XP Publisher, and matches the frozen member hash. This
confirms a declared DLL load dependency; static inspection cannot determine the
actual file Windows resolves or whether replacing/omitting the bundled copy is
compatible.

Microsoft's [MS04-028 bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-028)
lists the same version and size for Platform SDK Redistributable: GDI+ and says
that version was not vulnerable to the specific 2004 JPEG-processing issue.
That is a version/size and release-family match, not a cryptographic package
match, proof of PhotoView's source package, a current security assessment, or a
redistribution grant. Microsoft's [GDI+ overview](https://learn.microsoft.com/en-us/windows/win32/gdiplus/-gdiplus-gdi-start)
documents the general graphics API and its lack of support in Windows services;
it does not establish PhotoView's current Windows 11/Server compatibility or
runtime DLL search behavior.

No whole legacy outcome is resolved, retired or newly excluded. PhotoView's
historical/current terms, local entitlement, redistribution rights for the
executable, DLL and three language files, Windows 11/Server behavior, and a
supported DLL replacement/omission path remain open. The Czech, Polish and Greek
resources still require deliberate selection and terms review. A future test
must use synthetic images in a disposable guest and verify the actual resolved
DLL, launch/view/save behavior, and exact file recovery before changing the
bundle. No application or DLL was executed or loaded; no image was opened; no
fresh UAC, VM, controller or Defender action occurred. The [evidence record](../archive/evidence/mitec-photoview-gdiplus-static-follow-up-2026-10-21.json)
contains the pins and scoped findings. All five ranges remain **38-58 / 56-71 /
20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**;
dependency provenance is stronger, but terms and compatibility remain partial.

## MiTeC DDG variants and terms follow-up, 2026-10-21

The current MiTeC [Database Documentation/Code Generator page](https://www.mitec.cz/ddg.html)
describes support for Interbase 6+/Firebird 1.5+ and MS SQL. It says the product
generates customizable HTML documentation, can emit SQL to update database
object descriptions, and generates Pascal table-access source. Its published
target list stops at Windows 10. The page supplies no variant-specific version.

The retained `DDG_IBFB.zip` and `DDG_MSSQL.zip` hashes and their executable
member hashes were recomputed and match the frozen evidence. Their executable
versions remain distinct: **DDG_IBFB 1.0.0.0** and **DDG_MSSQL 1.2.0.0**. The
shared historical product/index version **1.2.0** must not be projected onto the
Interbase/Firebird executable. The product page gives no explanation of this
version split. Keep separate pins, versions, providers and recovery for the two
variants.

The current product page says “Free to use for both private and commercial
users.” MiTeC's [current support/EULA page](https://www.mitec.cz/wp/support/)
also says any trial or unregistered version is freeware only for non-commercial
usage and describes named-user/build-machine, team and site licenses. These
statements conflict for unregistered commercial use. The exact historical
builds, intended local user and applicable terms have not been resolved; the
review does not infer commercial entitlement or redistribution permission. The
Interbase/Firebird archive also includes `EMPLOYEE.GDB`, `EMPLOYEE.ini` and a
CSS file; the SQL Server archive has its own CSS. Their ownership and reuse
terms remain open.

Future acceptance requires disposable synthetic databases and explicit
credentials, separate output directories and exact file/database recovery. Test
provider absence before connection, generated HTML/CSS ownership, connection
failure, description-file behavior and generated SQL against disposable copies;
inspect every SQL effect and prove restore. No live database or supplied sample
database may be opened. No whole legacy outcome is resolved, retired or newly
excluded. No executable ran, no database was opened and no credentials were
used; no UAC, VM, controller or Defender action occurred. The [evidence](../archive/evidence/mitec-ddg-variants-terms-follow-up-2026-10-21.json)
records exact pins, claims and blockers. All five ranges remain **38-58 / 56-71 /
20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**;
behavior and version distinctions are clearer, but terms, providers, target
support and database/write recovery remain partial.

## MiTeC MSA Query and ADO Query provider follow-up, 2026-10-21

Current MiTeC pages confirm **MSA Query 2.1.0.0** is based on the Microsoft DAO
Engine and **ADO Query 1.9.0.0** requires installed Microsoft ActiveX Data
Objects. Both pages describe SQL editors that can run arbitrary statements or
scripts, editable objects and table data, BLOB editing, import/export and saved
SQL history. MSA Query also manages database users and object rights. These are
write-capable database clients, not read-only inspection tools; no query or
account operation belongs on a live database during migration acceptance.

The MSA Query page lists Windows 2000 through Windows 7; the ADO Query page
lists Windows 2000 through Windows 10, including Server 2008/R2. Neither claims
Windows 11 or newer Server support. Both product pages say free for private and
commercial users, while MiTeC's [current support/EULA page](https://www.mitec.cz/wp/support/)
says trial or unregistered software is freeware only for non-commercial use.
Applicability to these retained builds and the intended user is unresolved, as
are redistribution rights. The pages do not identify the DAO/ADO provider
release, architecture, bitness or installation/redistribution requirements.

ADO Query's page overview says CSV import and CSV/XML export, while its SQL
Editor section describes CSV/SQL import and export. Retain this as a publisher
documentation discrepancy; do not assume format direction or equivalence.
The archive and executable hashes were rechecked against frozen evidence; PE
resource versions remain **2.1.0.0** for MSA Query and **1.9.0.0** for ADO Query.

Any later acceptance needs synthetic database copies, explicit test
credentials, pinned provider/runtime versions and exact database, history,
connection and export recovery. Verify missing-provider refusal, query preview
where available, non-destructive connection behavior, write/query rollback,
BLOB preservation and MSA user/rights restoration. No application ran, database
opened or credential used; no UAC, VM, controller or Defender action occurred.
No whole legacy outcome was resolved, retired or newly excluded. The [source
evidence](../archive/evidence/mitec-msa-ado-provider-source-follow-up-2026-10-21.json)
records page observations, pins and remaining gates. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**; dependencies and write behavior are clearer, but terms,
provider entitlement, current targets and isolated recovery remain partial.

## MiTeC DirList and Network Meter publisher-page follow-up, 2026-10-21

Current official pages say DirList **1.3.0.0** browses connected disks, lets a
user select files/folders for a listing and exports CSV or layout-defined HTML.
The page also says files can be “listed by content” but does not define what
that mode reads or emits. Treat directory names and any content-derived output
as potentially private; later acceptance must use an owned synthetic tree and
separate export paths.

Network Meter **2.5.0.0** is described as enumerating installed local network
interfaces/adapters and showing interface details, traffic statistics and a
graphical history. The page does not describe remote scanning or packet capture;
do not expand its scope by inference. Later acceptance must preserve adapter
configuration and identify any history/configuration files exactly.

Both pages list targets only through Windows 10. Each says “Free to use for both
private and commercial users,” while the [current MiTeC support/EULA page](https://www.mitec.cz/wp/support/)
says trial or unregistered software is freeware for non-commercial use. Exact
applicability to these retained builds, intended-user entitlement and
redistribution rights remain unresolved. The retained archive and executable
hashes were recomputed and match frozen evidence. No whole legacy outcome is
resolved, retired or newly excluded; no target/runtime support is promoted.
The [evidence](../archive/evidence/mitec-dirlist-network-meter-page-follow-up-2026-10-21.json)
records exact pins, claims and gates. No payload ran, private content was read,
or network state changed; no UAC, VM, controller or Defender action occurred.
All five estimates remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**. Feature scope is clearer, but
terms, selection, outputs, Windows 11/Server behavior and isolated acceptance
remain partial/deferred.

## MiTeC Mail Checker bundled OpenSSL static follow-up, 2026-10-21

The retained `MAILCHECKER_Instal.exe` pin was rechecked against the frozen
inventory. Its statically extracted **Mail Checker 7.2.0.0** application and
three bundled SSL libraries were inspected without loading them. `libeay32.dll`,
`libssl32.dll` and `ssleay32.dll` carry version/company resources identifying
OpenSSL **1.0.1e** and are unsigned. `libssl32.dll` and `ssleay32.dll` are
byte-identical by SHA-256. The app's PE import table names `wininet.dll` and
`wsock32.dll` but has no direct import of the OpenSSL DLL names; a bounded ASCII
scan found no such names in the app image. This does not rule out dynamic loading
or establish the TLS path.

OpenSSL's official [release timeline](https://www.openssl-library.org/news/timeline/)
dates 1.0.1e to 2013-02-11. The official [1.0.1 lifecycle page](https://www.openssl-library.org/news/vulnerabilities-1.0.1/index.html)
says that branch has been out of support since 2017-01-01 and no longer receives
updates. Its vulnerability record lists CVE-2014-0160 as affecting 1.0.1 before
1.0.1g, so the bundled 1.0.1e version predates that fix. This is a concrete
network-security blocker for any intended TLS use; the app's actual exposure
remains unproven because no application, mail account or network path was run.
Do not describe the product as safe based on its version string or the presence
of SSL-named libraries.

OpenSSL's [license guidance](https://openssl-library.org/source/license/index.html)
says all pre-3.0 releases, including unsupported releases, use the dual OpenSSL
and SSLeay license. This identifies the upstream license family, not the exact
source/build provenance or compliance of these unsigned Windows DLLs. The
retained application file list contains no separate OpenSSL `LICENSE` file;
binary/version metadata alone does not establish redistribution compliance.
Mail Checker publisher terms and local entitlement remain independently open.

Any future Mail Checker acceptance requires an isolated mail sink, synthetic
accounts/messages/recipients, controlled send/delete defaults, exact recovery,
and an explicit resolution of the obsolete TLS dependency (replacement or
network-disabled scope) before any network test. Do not use a real mailbox or
credentials. No payload or DLL ran, no network request or mail action occurred,
and no fresh UAC, VM, controller or Defender action occurred. No whole legacy
outcome is resolved, retired or newly excluded. The [evidence record](../archive/evidence/mitec-mail-checker-openssl-static-follow-up-2026-10-21.json)
contains exact pins, version observations and limits. All five ranges remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**; the obsolete dependency and notice gate are clearer but
mail behavior, rights, activation and full acceptance remain partial.

## MiTeC Weather Agent OpenWeatherMap endpoint static follow-up, 2026-10-21

The retained `WA_Setup.exe` hash matches the frozen inventory. Its statically
extracted Weather Agent executable is signed by the MiTeC publisher, file
version **3.6.0.0**, product version **3.0.0.0**, and hash-pinned in the
[evidence record](../archive/evidence/mitec-weather-agent-endpoint-static-follow-up-2026-10-21.json).
Bounded ASCII/UTF-16 string inspection found compiled request templates for
OpenWeatherMap location search, current weather, forecast and daily forecast.
Each template uses `http://api.openweathermap.org/data/2.5/...`, an `APPID`
query parameter with a format placeholder, an opaque selected-location
placeholder, XML mode, and applicable units/count/language parameters. UI
strings include “API key,” “Get API Key,” location ID, latitude and longitude.
No key value or private location was recorded.

OpenWeatherMap's current [weather API documentation](https://openweathermap.org/api/current)
shows HTTPS for the current-weather endpoint and describes `appid` as a required
unique API key. Its [API-key guidance](https://openweathermap.org/appid) says
the key is sent as an `appid` request parameter. The provider currently says
built-in city-name, ZIP and city-ID lookup/geocoding are deprecated, although
still available without further bug fixes or updates. This does not prove what
the historical application sends at runtime or whether its HTTP requests are
redirected. If these compiled templates are used as written, the API key and
selected location travel over plaintext HTTP. Keep network acceptance blocked
unless HTTPS use or an isolated non-secret/non-personal test path is established.

This resolves the earlier “endpoint/data flow unknown” subgate only to the
compiled templates. Key source/storage, location encoding, endpoint selection,
redirects, current-service compatibility, startup/persistence, terms and
Windows 11/Server behavior remain open. The historical page's commercial-use
claim still conflicts with the general unregistered non-commercial terms; no
entitlement or redistribution permission is inferred. No application or
service ran, no location/key was entered and no network request occurred. No
UAC, VM, controller or Defender action occurred. No whole legacy outcome was
resolved, retired or newly excluded. All five ranges remain **38-58 / 56-71 /
20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**; the
network path is clearer but the security and acceptance blockers remain.

## NTCore Phoenix Protector custom-action identity and license follow-up, 2026-10-21

The retained Phoenix Protector MSI hash matches its frozen inventory. Opening
the MSI database read-only and reading the `Binary` table's `MSVBDPCADLL` stream
revealed a 227,320-byte PE image with SHA-256
`ba56a2fa13e5dae48b6d74a8fa40f2f44473b386e71ba1e7ec2ded90ad56bb8b`.
Its version resources identify **Microsoft Visual Studio 2008** custom-actions
library `DPCA.DLL`, version **9.0.21022.8**. Authenticode validation reports a
valid Microsoft Corporation signature. Static imports are ADVAPI32, KERNEL32,
OLEAUT32, OLE32, USER32, SHELL32 and MSI.DLL. Bounded strings include the two
MSI entry points `CheckFX` and `VsdLaunchConditions`, plus framework property
names. These identify the library but do not establish the exact runtime
predicate or side effects. A string mentioning `aspnet_regiis.exe` is not proof
that the action launches it. The exact stream identity, signature and limits
are recorded in the [evidence file](../archive/evidence/ntcore-phoenix-custom-action-license-follow-up-2026-10-21.json).

The MSI also bundles `Phoenix License.rtf`. Its terms grant an individual a
personal, nonexclusive, nontransferable license to use copies on computers on
the individual's premises for designing, developing and testing software
products. Section 3 prohibits reverse engineering, decompilation and
disassembly except where applicable law expressly permits it; the terms also
restrict transfer, rental, lending and commercial hosting. NTCore's current
[Phoenix Protector page](https://ntcore.com/phoenix-protector/) calls the
product freeware and lists **1.8.0.1**, but does not say that this page replaces
the MSI EULA. The retained MSI version is **1.7.1** and its executable resource
version is **1.9.0.1**. Intended-user entitlement, redistribution and the
relationship between the page statement and bundled terms remain unresolved.
The EULA restriction and the difference between the EULA and publisher-page
wording are recorded for owner-specific review. Per the user's migration
direction, this open question does not pause package implementation or
technical acceptance; it does not claim rights clearance. Continue the focused
installer lifecycle and framework-behavior checks in an isolated VM without
expanding into unnecessary reverse-engineering work.

Keep the MSI and application out of host execution. Exact framework-check
behavior and presence/absence/later-version cases still need isolated
acceptance; the `NeedsReview` marker is not a technical or implementation gate.
No installer session, executable, DLL, database, framework installer or VM ran;
no fresh UAC, controller or Defender action occurred. No whole legacy outcome
was resolved, retired or excluded. All five ranges remain **38-58 / 56-71 /
20-25 / 25-35 / 8-12**, exact **147-201**, rounded **145-200/about 175**;
custom-action provenance and the publisher terms discrepancy are documented,
while runtime behavior and native acceptance remain unresolved.

## MiTeC Paradox Data Editor bundled BDE publisher deployment follow-up, 2026-10-21

The retained BDE evidence identifies 29 files totaling 8,189,528 expanded
bytes; core components including `IDAPI32.DLL`, `IDPDX32.DLL`, `IDDBAS32.DLL`
and `BDEADMIN.EXE` report version **5.1.1.1**. No version-specific deployment
notice was present in that extracted set. Current official Embarcadero
[BDE guidance](https://docwiki.embarcadero.com/RADStudio/Florence/en/Borland_Database_Engine)
marks BDE deprecated, says it will not be enhanced and advises against new
development. It points readers to the product's `DEPLOY` document for BDE
redistribution rights. Embarcadero warns that improper installation can break
other BDE applications and that BDE registry setup/removal must be handled
correctly. Its [license requirements](https://docwiki.embarcadero.com/RADStudio/Athens/en/Software_License_Requirements)
page says version-specific deployment material is supplied with the product
and third-party component rights remain with their vendor.

Those documents establish the evidence needed, not a grant for the retained
BDE 5.1.1.1 copy bundled by MiTeC with Paradox Data Editor. Direct access to the
DocWiki pages returned HTTP 403; official search-indexed content was used, and
no access-control workaround was attempted. Obtain the applicable BDE
5.1.1.1 `DEPLOY`/`README` and MiTeC bundle terms from an authorized source
before considering distribution or activation. Keep BDE registration out of
the host because incorrect shared configuration can disrupt other applications.

Provider/bitness compatibility, aliases, registration coexistence, exact
install/repeat/uninstall recovery and synthetic Paradox-table behavior remain
deferred. No BDE DLL/admin utility loaded, no database opened, and no installer,
UAC, VM, controller or Defender action occurred. No whole legacy outcome was
resolved, retired or excluded. The [evidence record](../archive/evidence/mitec-bde-publisher-deployment-follow-up-2026-10-21.json)
records the official claims, source-access limit and required follow-up. All
five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**,
rounded **145-200/about 175**; the correct rights source and shared-install
risk are clearer, while version-specific rights, entitlement and acceptance
remain open.

## Local acceptance preflight, 2026-10-22

The catalog documentation was regenerated and the repository validator passed
for 363 operations, eight groups, five profiles and 235 PowerShell files. Focused
Pester discovery found 210 checks across offline bundle/execution, PSScriptTools
and user-bin suites, but Pester 5.7.1 failed during framework setup for every
case because the restricted process could not create its temporary
`HKCU\Software\Pester` key. No test body or assertion ran. This does not replace
the earlier registered-VM evidence for the PSScriptTools file lifecycle or
OfflineCaffeine's disconnected acceptance.

VM access was rechecked read-only: `Get-VM -Name RIDE-Win11-Test` failed with
`Access to a CIM resource was not available to the client`. No registered task,
controller, VM, installer, Defender or UAC action was attempted. B03 startup
still needs guest PowerShell 7 and native startup acceptance; PSScriptTools
runtime/function compatibility and dependency ownership remain separate; B10
installer/dependency and broader disconnected acceptance remain; Docker Desktop
per-user installation still stalls and all-users acceptance remains pending.
The ignored checkout-local license store now marks Docker Desktop 4.96.0,
MiTeC JSON Viewer 3.2.2.0, MiTeC XML Viewer 6.5.0.0, NTCore CFF Explorer
8.0.0.0 and PE Detective 1.2.1.1 as `NeedsReview`; all reviewers are currently
unassigned. No entitlement or redistribution approval is implied. No whole
legacy outcome was resolved, retired or excluded. See the [dated
estimate entry](../MIGRATION-PLAN.md#local-migration-acceptance-preflight-2026-10-22);
all five ranges and the rounded total remain unchanged.

## Registered PSScriptTools acceptance rerun, 2026-10-22

Request `8c0b33994d28476e852735c78e89170f` passed the registered
`PSScriptTools` suite on RIDE-Win11-Test, Windows 11 build 26300. The guest
evidence records all 14 portable lifecycle checks over 360 files, seven saved-
state ZIPs, and recovery to the original absent state. Repeat install/removal,
exact removal restoration, preservation of unowned content, and modified-file
collision/refusal behavior passed. The runner reports `ToolExecuted=false`;
functional and activation acceptance remain pending. The VM was restored to the
existing checkpoint `a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9` and left Off. The
registered request used no fresh UAC prompt or controller refresh.

The raw correlated result, scenario evidence, file observations and saved-state
archives remain at
`%ProgramData%/RIDE/TestAutomation/RIDEWin11Test/results/8c0b33994d28476e852735c78e89170f/`.
The [sanitized evidence record](../archive/evidence/psscripttools-registered-rerun-2026-10-22.json)
retains the exact check names and acceptance limits. The earlier local Pester
run still failed in framework setup before its test bodies because its temporary
registry fixture was denied; this guest acceptance is independent evidence.

Resolved: PSScriptTools registered portable file lifecycle. Partial: runtime
function compatibility and dependency ownership. No whole legacy outcome was
resolved, retired or excluded; estimate ranges remain unchanged. Defender-alerted
tools remain excluded and fresh-UAC/controller work remains deferred.

## Phoenix Protector package candidate preparation, 2026-10-22

Added `package.phoenix-protector` for the retained publisher-linked MSI 1.7.1,
with `ExpectedSha256` pinned to
`15a7dbbf90ce66fb302a322c6809fafd897808096069dfecededf78e51b16369`. The
publisher page lists 1.8.0.1 and the contained executable reports 1.9.0.1;
these identities remain distinct. The catalog describes the bundled individual
development/testing license alongside the publisher's freeware claim. The
checkout-local version-specific review record is `NeedsReview` and has no
assigned reviewer. Per the migration decision, this status records uncertainty
for later review rather than acting as a general package-preparation gate.

The package is a Windows 11 candidate with empty supported targets and
`PendingAcceptance=true`. Offline execution now accepts hash-bound MSI payloads
when the artifact is explicitly `DeclaredNoNetwork`, has no dependencies and the
catalog target has passed native acceptance. The focused 31-test OfflineExecution
suite passes, including the MSI preflight and installer-dispatch cases; the
separate 43-test OfflineBundle suite also passes. A combined Pester invocation
caused two data-only assertions to see `RIDE.Engine` imported by an earlier file;
the isolated OfflineBundle rerun passed all 43. The
registered VM queue still does not include MSI execution. The MSI's .NET
2.0.50727 launch condition, actual network behavior, install/repeat/uninstall,
exact state recovery and offline operation remain untested. No MSI, DLL or
application was run and no host or Defender state changed. A dedicated
disconnected guest acceptance suite is required before support promotion; any
fresh controller update stays in the deferred attended session.

Resolved: pinned package/source identity and review-store record. Partial:
installer and offline implementation, user-scope review, and native behavior.
No legacy outcome was resolved, retired or excluded; all five migration ranges
remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**.

## ApplicationsBatch1 VM acceptance, 2026-10-22

The registered Local controller ran `ApplicationsBatch1` on the pinned
`RIDE-Win11-Test` VM and checkpoint. Guest validation passed all 272 Pester tests.
Seven of eight package scenarios passed: Thunderbird 158.0.1, VS Code 1.143.0,
Firefox 158.0.1, DB Browser for SQLite 3.13.1, Autopsy 4.23.1, Wireshark
4.6.9.0 and Signal 8.32.0. Their absent-to-installed, repeat and saved-run
restoration-to-absence steps reported success. Thunderbird and Signal also
exercised explicit removal/recovery and preserved their synthetic profile
fixtures. This reconfirms already accepted product outcomes and adds only partial
lifecycle evidence for Wireshark.

Chrome 155.0.8059.40 failed before installer launch because the provider's
SHA-256 digest differed from the catalog pin
`32ba438dea18f0fed1ec621bfb274a2669adec67be2aa91d96b3cc6c64779276`. The
collected artifact observation says the downloaded 169,652,224-byte MSI had a
valid Google LLC Authenticode signature, but did not retain its actual SHA-256.
The digest gate correctly prevented installation. The current source was
subsequently inspected and pinned; see the dated refresh below. The MSI was not
executed, so repeat Windows 11 and Server 2025 acceptance before treating its
version as supported.

Wireshark's batch scenario passed clean-absence installation, repeat and
saved-run restoration to absence. It did not exercise an explicit removal action
or the separately listed existing-installation transition,
association/shared-runtime preservation, or all required exact recovery cases. Keep the candidate's target
pending. Do not treat the seven batch passes as seven newly resolved legacy
outcomes.

The controller returned a Failed result for the suite, with no cleanup or
collection error, no collection omissions, and no blocked marker; the request
moved to the finished queue. The sanitized [run evidence](../archive/evidence/applications-batch1-acceptance-2026-10-22.json)
preserves the scenario outcomes and Chrome integrity gate. No whole legacy
outcome was resolved, retired or excluded; Wireshark remains partial and Chrome
current-source runtime acceptance remains pending. All five estimate
ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**,
rounded **145-200/about 175**.

## Chrome stable MSI pin refresh, 2026-10-22

The current official stable enterprise MSI was downloaded from the declared
Google HTTPS endpoint to an ignored local review directory. Read-only Windows
Installer property inspection identified Google Chrome 156.0.8078.48,
ProductCode `{FC681062-00FC-3E42-98D1-2B1A9AF642A3}`, and Google LLC as
manufacturer. The 170,979,328-byte file has SHA-256
`a31bd8a4746069a128bf3beefdaa246c792af5f15bbf06af0259abc895c9609b` and a
valid Google LLC Authenticode signature. The sanitized [pin evidence](../archive/evidence/chrome-enterprise-msi-pin-2026-10-22.json)
records the source and inspection; the MSI was not run.

Updated `package.chrome` to this exact version/hash and reset it to candidate
status for Windows 11 and Windows Server 2025. The catalog export and repository
validator passed. Submission through the existing RIDE-Win11-Test controller
failed before dispatch because this unelevated session could not write its
protected pending queue; no request or VM run was created. RIDE-Win11-Test and
RIDE-S25-Test acceptance therefore remain pending. Do not refresh controller
files or prompt for elevation while unattended; resume through the already
registered controller when its authorized queue writer is available.

This source-pin repair closes no legacy outcome and validates no runtime
behavior. Historical version 155.0.8059.40 acceptance remains historical only.
Wireshark remains partial. No outcomes were resolved, retired, or excluded, and
all five estimates remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**.

## ApplicationsBatch1 current-pin Windows 11 rerun, 2026-10-22

The registered Local controller completed run
`3e0dee246f2e48c5af664890887afe47` on RIDE-Win11-Test, Windows 11 Enterprise
Evaluation build 26300. Guest validation passed 285 Pester tests, failed 0 and
skipped 1. All eight scenarios passed: Thunderbird 158.0.1, VS Code 1.143.0,
Firefox 158.0.1, DB Browser for SQLite 3.13.1, Autopsy 4.23.1, Chrome
156.0.8078.48, Wireshark 4.6.9.0 and Signal 8.32.0. Chrome acquired the pinned
170,979,328-byte MSI with SHA-256
`a31bd8a4746069a128bf3beefdaa246c792af5f15bbf06af0259abc895c9609b` and a valid
Google LLC signature. Its install/repeat/removal, profile-marker preservation
and compensating recovery passed. Thunderbird and Signal also verified profile
preservation; the package suite reported recovery for every scenario.

This confirms current-pin Windows 11 lifecycle behavior for Chrome. Wireshark's
acceptance remains partial: its existing-installation transition,
association/shared-runtime preservation and broader recovery are not covered by
the clean-absence scenario. The controller restored the VM checkpoint and left
it Off. No whole legacy outcome was resolved, retired or excluded; all five
ranges remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**,
rounded **145-200/about 170**. See the [sanitized evidence](../archive/evidence/applications-batch1-acceptance-2026-10-22.json).

## ApplicationsBatch1 current-pin Server 2025 rerun, 2026-10-22

The registered Local controller completed run
`91190a3b18f14c0f9830d62d024556a9` on the verified RIDE-S25-Test VM, Windows
Server 2025 Standard Evaluation build 26100. Guest validation passed 285 Pester
tests, failed 0 and skipped 1. All eight package scenarios passed at the same
versions as the Windows 11 run: Thunderbird 158.0.1, VS Code 1.143.0, Firefox
158.0.1, DB Browser for SQLite 3.13.1, Autopsy 4.23.1, Chrome 156.0.8078.48,
Wireshark 4.6.9.0 and Signal 8.32.0. Chrome's pinned MSI digest and Google LLC
signature matched; install/repeat/removal, profile-marker preservation and
compensating recovery passed. All scenarios reported recovery. The controller
restored the checkpoint and left the VM Off.

Chrome current-pin Windows 11 and Server 2025 lifecycle acceptance is complete;
the catalog now supports both targets. Paired runs also reconfirm the other six
packages' existing target declarations. Wireshark remains pending its
existing-installation transition, association/shared-runtime preservation and
broader recovery checks. No whole legacy outcome was resolved, retired or
excluded. All five ranges remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**,
exact **144-198**, rounded **145-200/about 170**. See the [sanitized batch
evidence](../archive/evidence/applications-batch1-acceptance-2026-10-22.json).

## ApplicationsBatch2 Server 2025 acceptance rerun, 2026-10-22

Run `19f6e52b9e284ee5ac16b466eceaf90a` passed on the registered RIDE-S25-Test
VM, Windows Server 2025 Standard Evaluation build 26100. Guest validation
passed 285 Pester tests, failed 0 and skipped 1. All 12 portable scenarios
passed: ShareX 21.0.0, Chainsaw 2.17.1, Hindsight 2026.06, CyberChef 11.5.0,
PuTTY 0.85, SRUM Dump 3.2, SrumMonkey 1.0.0, dejsonlz4 1.1, CyLR 2.2.0,
Caffeine 1.98, WinSCP 6.5.7 and NetworkMiner 3.2. Every scenario reported exact
owned-file recovery. WinSCP also preserved its synthetic session fixture; its
WinSCP.exe and WinSCP.com signatures were valid with the expected common
publisher thumbprint.

The clean checkpoint was restored and the VM left Off. All packages already
declare Windows 11 and Server 2025, so this rerun adds Server 2025 evidence
without changing target metadata or closing a whole legacy outcome. The five
current estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact
**144-198**, rounded **145-200/about 170**. See the [sanitized run evidence](../archive/evidence/applications-batch2-server2025-acceptance-2026-10-22.json).

## NTCore 4GB Patch candidate preparation, 2026-10-22

Added `package.ntcore-4gb-patch` as a Windows 11 portable candidate using the
retained 1.0.0.1 ZIP, SHA-256
`1e13c263dc55e85cf62e3e30c6b2ce936d4c7e16e3bba3e311a5a8bed4be16ca`, and
selected member `4gb_patch.exe`. The digest was recomputed against the retained
21,464-byte archive; the current publisher URL was not downloaded again, and
the hash is not claimed to be publisher-provided. Catalog support targets stay
empty until acceptance. Staging would place the single tool in RIDE's managed
portable directory and does not launch it or patch user files.

Following the user's migration priority, the package and static source review
proceed with unresolved rights recorded instead of treating them as a package
preparation gate. The ignored local `.local/license-reviews.json` store now has
a version-specific `NeedsReview` record for 1.0.0.1 with owner `Unassigned` and
the known copyright/rights limitation. No entitlement, commercial-use grant or
redistribution permission is inferred. See the [candidate record](../archive/evidence/ntcore-4gb-patch-candidate-preparation-2026-10-22.json),
[publisher-page findings](../archive/evidence/ntcore-4gb-patch-page-follow-up-2026-10-21.json)
and [catalog source record](../archive/evidence/ntcore-4gb-patch-source-review-2026-10-17.json).

The fixed NTCore portable acceptance selection now includes this candidate, and
the host-local `.local/acceptance-input/NTCore.json` manifest contains all three
retained NTCore archives with catalog-matching digests. The focused selection
tests pass 17/17, and the source task-dispatch suite passes 95 tests with two
skipped while TestRegistry is disabled. The catalog export and validator pass,
checking 365 operations, eight groups, five profiles and 236 PowerShell files.

The focused guest runner now executes the installed 4GB Patch only on a generated,
non-runnable x86 PE fixture. It records whether the large-address-aware flag is
set, validates the exact original-byte backup, challenges the discovered backup
path with an owned collision sentinel, and restores the synthetic file exactly.
Its guard requires the correlated Windows 11 virtual guest, guest elevation, and
the installed executable hash captured by the package ownership manifest; cleanup
is limited to its unique fixture directory. Selection/version/boundary tests pass
18/18, including in-memory validation of the generated PE32/x86 header and its
initially clear flag, while the fixture's actual tool behavior remains
untested. The publisher
documents command-line use and an automatic backup
([NTCore 4GB Patch](https://ntcore.com/4gb-patch/)), but backup naming and
collision behavior have not yet been observed in execution. No utility ran in
this preparation turn.

These source checks do not establish VM acceptance. The installed protected
controller still predates this source change and permits only
PSScriptTools/OfflineCaffeine; one elevated controller refresh is needed before
NTCore can use its registered task route. The current queue request also fails
at this session's low integrity level. Both are deferred to the attended
elevation session; no task was dispatched and no prompt was requested.

No package lifecycle or utility execution ran. Required next acceptance is
focused portable install/repeat/remove/exact restoration plus the prepared
synthetic owned x86 PE test for exact flag, backup content/path/collision and
recovery behavior on the disposable Windows 11 VM. No stable legacy
selector mapping was found for this product, so candidate admission closes no
whole legacy outcome.
All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**.

## Offline package and license-review regression rerun, 2026-10-22

Reran the local Windows package regressions with Pester 5.7.1 and the unused
TestRegistry plugin disabled. `OfflineExecution.Tests.ps1` passed 37/37,
`OfflineBundle.Tests.ps1` passed 43/43, `OfflineProfileCoverage.Tests.ps1` passed
63/63, and `LicenseReviews.Tests.ps1` passed 9/9 with each store created in a
unique workspace-local temporary directory.
The earlier file-replacement failure was specific to Pester TestDrive's ACL;
the replacement logic succeeded against the local temporary store, and its
probe data was removed. The review test now uses bounded cleanup of its own
temporary directory instead of relying on TestDrive for the store file.

These checks validate local handler logic, bundle behavior and version-specific
review persistence only. No package or installer ran on Windows, and no VM
request was created. No legacy outcome was resolved, retired or excluded. All
five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact
**147-201**, rounded **145-200/about 175**.

## Wireshark Npcap local license review recorded, 2026-10-22

Added a version-specific `NeedsReview` record for `package.wireshark` 4.6.9 to
the checkout-local license review store, with reviewer `Unassigned`. Its note
tracks the separate Npcap terms, applicable exception and intended consumers;
Wireshark's GPL does not grant Npcap rights. The record is informational and
does not approve internal entitlement, driver installation or redistribution.
The sanitized [review evidence](../archive/evidence/wireshark-local-license-review-2026-10-22.json)
records the scope and links this bookkeeping update to the prior Windows 11
partial lifecycle result. No installer, Npcap component or VM ran in this
review. Existing Wireshark removal, already-installed transition, shared
runtime/content and exact recovery acceptance remain pending.

No whole legacy outcome was resolved, retired or excluded. All five estimates
remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**. The local review count is eight; the added record changes
neither package acceptance nor the legacy-outcome estimate.

## License-review workspace regression correction, 2026-10-22

The first rerun of `LicenseReviews.Tests.ps1` stopped in Pester's optional
`TestRegistry` setup because this session cannot write the Pester registry key.
With that plugin disabled, six tests then exposed an ACL limitation in the
sandbox temporary directory: atomic `File.Move` could not replace the review
store or export. Updated the fixture so each store and atomic export is created
inside its own generated direct-child directory under the ignored
`.local/pester-license-review` root. Cleanup verifies that exact root and GUID
child and removes only direct files from that directory; Pester TestDrive remains
limited to read-only import fixtures.

The focused rerun passed all **9/9** tests with the optional registry plugin
disabled. The evidence and review-store JSON checks also pass, as does the
repository validator. These are local persistence and documentation checks; no
package or VM ran. No legacy outcome was resolved, retired or excluded. All five
ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**,
rounded **145-200/about 175**.

## RIDE-Win11-Test read-only access recheck, 2026-10-22

The current session retried the read-only `Get-VM -Name RIDE-Win11-Test`
preflight. Hyper-V returned `Access to a CIM resource was not available to the
client`, so VM state and checkpoint identity remain unverified from this
session. The sanitized [access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-22.json)
records the result. No task submission or queue write was attempted, no VM or
controller state changed, and no UAC prompt or host-service change occurred.

Acceptance stays deferred until the existing authorized Hyper-V and registered-
controller workflow is available. Then verify the known VM/checkpoint identity
before dispatching an already authorized scenario. No package or feature ran;
no legacy outcome was resolved, retired or excluded. All five ranges remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, exact **147-201**, rounded
**145-200/about 175**.

## User migration decisions, 2026-10-22

The user selected Q16/R01 application review as the next decision batch. Continue
with unresolved product-specific integrations, installer options and recovery
questions in the existing ledger; accepted product scope remains settled. Chrome
156.0.8078.48 is first in the next available registered VM acceptance session.
The current session still cannot access the VM through Hyper-V CIM or write the
protected controller queue.

The user authorized package candidate implementation with unresolved license
entitlement when the description states the known terms and uncertainty; a
version-specific local `NeedsReview` record is optional. This does not establish
entitlement or redistribution permission. Native acceptance and publication
remain separate gates.

Paradox Data Editor, Weather Agent and Mail Checker are retired from v3. Retain
their 2026-10-20/21 source, network and dependency findings as historical evidence;
do not prepare packages or pursue BDE registration or network acceptance for
these products. This retires three outcomes from the original 79-item application
review. Together with Q17/Q20, the ledger now records 19 accepted migrations, one
exclusion, five retirements and 74 pending/partial outcomes. Packages decrease
from 56-71 to 53-68; exact total endpoints decrease from 147-201 to 144-198.
Other four group ranges are unchanged; the rounded total remains 145-200, about
170. This is a scope disposition, not native acceptance.

NirSoft launcher and x64 whole-collection package implementation is authorized
under the v2.x non-restrictive package approach. The user confirmed on
2026-10-24 that individual file assessment is postponed to v3.1 and is not part
of v3. If alerts remain at v3.1 file-level work, present them for the user's
manual review. This does not authorize restoring or re-extracting quarantined files
before review. The frozen NirSoft review evidence records user-reported alerts
for `NirSoft/chromecookiesview.exe`, `NirSoft/bulletspassview.exe`,
`ProduKey.exe` and `WirelessKeyView.exe`; no threat classification or
false-positive determination was supplied. Keep these members out of selected
file-level review/acceptance batches until manual user review. The exact paths
and dates are in the [frozen alert evidence](../archive/evidence/collection-continuation-blockers-2026-10-17.json).
The user decided 2026-10-22 not to carry forward the v2.x broad
`C:\Tools` Defender exclusion. This is separate from
non-restrictive v2.x package approach; package implementation
does not authorize any other directory-wide exclusion or Defender allow action.

## ImageMagick portable Q16 source discovery, 2026-10-22

The official ImageMagick Windows download page currently lists
`ImageMagick-7.1.2-34-portable-Q16-x64.7z` as a portable Win64 static build.
The publisher archive index lists the 7z at 11 MB with matching `.asc` and
CycloneDX `.cdx.json` sidecars. The official license allows personal, internal
and commercial use; redistribution requires a copy of the license and retained
attribution notices. The package description must state these terms and any
remaining entitlement uncertainty. These are publisher-page observations, not
inspection of the archive contents or license of this user's use.

Attempted to retrieve the archive and sidecars from the official publisher host
into `.local/imagemagick-source-review-20261022`; the host did not resolve from
this session (`No such host is known`). No artifact or sidecar was acquired, so
there is no observed SHA-256 or detached-signature verification. No files were
extracted, no executable ran, and no Defender, VM, UAC or PATH action occurred.

The current portable lifecycle supports ZIP archives and single files, not 7z.
The accepted portable destination/scope/PATH choices are unchanged, but a safe
7z extraction and ownership path is not implemented. Do not create a runnable
package candidate or claim native support until the exact publisher bytes and
digest are available and the archive format is handled with the existing
collision, ownership and saved-state recovery guarantees.

Resolved/retired/excluded: none. Partial: Q16/R01 ImageMagick portable choice.
Deferred: exact source acquisition/hash/signature, safe 7z lifecycle support,
distribution feature verification and native acceptance. All five estimates
remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized source-discovery record](../archive/evidence/imagemagick-portable-q16-source-discovery-2026-10-22.json).

Official references: [Windows downloads and build variants](https://imagemagick.org/download/#windows),
[publisher archive index](https://download.imagemagick.org/archive/binaries/) and
[ImageMagick license](https://imagemagick.org/license/).

## NTCore 4GB Patch licence metadata clarification, 2026-10-22

Replaced the candidate catalog's non-descriptive `License = 'Unknown'` with the
evidence-backed statement that its 2007 copyright notice says all rights
reserved, no product-specific licence grant was found, and terms/redistribution
rights remain unresolved. Regenerated `docs/OPERATIONS.md` from the catalog. The
private version-specific review record remains `NeedsReview` with owner
Unassigned; this does not establish entitlement or redistribution permission.
The candidate remains pending Windows 11 lifecycle and synthetic-fixture
acceptance, with no supported targets.

No archive or utility ran, and no executable, VM, Defender, UAC, or controller
state changed. The current read-only `Get-VM -Name RIDE-Win11-Test` recheck
returned CIM access denied. No legacy outcomes were resolved, retired or
excluded. Partial: transparent rights metadata for a prepared candidate.
Deferred: rights review, fresh source verification and all native acceptance.
Estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**,
rounded **145-200/about 170**; metadata did not change implementation or
legacy-outcome counts.

## MiTeC UUID Generator candidate preparation, 2026-10-22

Added `package.mitec-uuid-generator` as a pinned portable candidate for
publisher version 1.0.0, selecting only `UUID.exe`. Rechecked the retained ZIP
SHA-256, length and executable member SHA-256 by streaming the member bytes;
neither file was extracted or executed. The archive digest is retained-source
evidence, not a publisher-provided digest. The publisher describes generation
and decoding of UUID v4/v7, ULID and Snowflake values and also displays persistent
UEFI, SMBIOS, machine and device identifiers. Candidate acceptance is restricted
to synthetic identifiers and must not capture, log or export live values.

The package has no supported targets and remains pending Windows 11 acceptance.
The product page's private/educational/non-commercial freeware wording and the
general support EULA's separate non-commercial/paid-tier language leave local
entitlement and redistribution unresolved. The ignored local license store now
records version 1.0.0 as `NeedsReview`, owner Unassigned; no rights are inferred.
The new inert-archive portable lifecycle test passed **2/2** on Windows
PowerShell 5.1 and **2/2** on PowerShell 7. It verifies catalog/evidence pins,
exact selected-member staging, repeat install, saved snapshot, uninstall and
recovery while preserving a user-created file. It does not test UUID behavior,
activation, UI, or Windows support.

No live identifier was queried, and no VM, UAC, Defender, host or controller
state changed. Resolved/retired/excluded legacy outcomes: none. Partial: UUID
Generator candidate package preparation. Deferred: synthetic generation/decode,
privacy-safe UI, native support/activation, and intended-user license review.
The catalog now has **64 packages, 37 pending**. The five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**; the candidate was already represented in the remaining
outcome range, so no estimate deduction is justified. See the [sanitized
candidate evidence](../archive/evidence/mitec-uuid-generator-candidate-preparation-2026-10-22.json).

## MiTeC certificate tools candidate preparation, 2026-10-22

Added pinned portable candidates for Certificate Generator 1.0.0 (`CG.exe`, x64)
and Certificate Information 1.5.0 (`CertInfo.exe`, x86). Rechecked each retained
publisher archive's length and SHA-256 and each selected executable member's
length and SHA-256 by streaming bytes from the ZIP; neither source payload was
extracted or executed. The archive hashes are retained-source evidence, not
publisher-provided digests. Current official product pages still show these
versions and the private/educational/non-commercial freeware wording. The
current support EULA separately defines unregistered freeware as non-commercial
and lists license tiers, so local entitlement and redistribution remain
unresolved; both ignored local records are `NeedsReview`, owner Unassigned.

Both candidates have empty `SupportedTargets` and remain pending. The catalog
descriptions state that staging opens no certificate files or stores and creates
no keys. Certificate Generator acceptance is limited to disposable test keys
and certificates with exact output cleanup and no trust-store import.
Certificate Information acceptance is limited to synthetic certificates and
signed public fixtures, including a disposable test-only PFX; production private
keys must not be opened or exported.

The new inert-archive package tests passed **4/4** on Windows PowerShell 5.1 and
**4/4** on PowerShell 7. They verify catalog/source metadata, exact-member
staging, repeat install, snapshot, uninstall, recovery and user-file preservation.
No certificate behavior was exercised. No live certificate, key, store, VM,
Defender, UAC, host or controller state was touched. The catalog now contains
**66 packages, 39 pending**. Resolved/retired/excluded legacy outcomes: none.
Partial: both candidate package lifecycles. Deferred: synthetic generation,
parsing, export, malformed input, exact certificate cleanup, UI, Windows target,
activation and owner-specific license review. All five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**; both candidates were already represented in pending
outcomes, so no estimate deduction is justified. See the [sanitized candidate
evidence](../archive/evidence/mitec-certificate-tools-candidate-preparation-2026-10-22.json)
and current publisher pages for [Certificate Generator](https://www.mitec.cz/wp/cg/),
[Certificate Information](https://www.mitec.cz/wp/mci/) and [MiTeC support terms](https://www.mitec.cz/wp/support/).

## Slack and Discord current-user package candidates, 2026-10-22

By user direction, add Slack and Discord as current-user x64 EXE package
candidates. Slack 4.52.182 uses its versioned official `SlackSetup.exe` URL;
Discord 1.0.9264 uses its versioned official `DiscordSetup.exe` URL. The artifact
SHA-256 pins come from the matching Microsoft WinGet community manifests; they
are independently recorded hashes, not vendor checksum sidecars. Slack's MSI
deployment installers were retired, and Slack recommends MSIX for managed
deployment. RIDE has no MSIX or WinGet package handler, so the selected route is
the legacy direct-download EXE. Discord's publisher documents its setup EXE.
The matching [Slack](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/s/SlackTechnologies/Slack/4.52.182/SlackTechnologies.Slack.installer.yaml)
and [Discord](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/d/Discord/Discord/1.0.9264/Discord.Discord.installer.yaml)
WinGet manifests document the versioned installer URLs and computed SHA-256
pins. See the vendor [Slack deployment guide](https://slack.com/help/articles/212475728-Deploy-Slack-for-Windows)
and [Discord installation guide](https://support.discord.com/hc/en-us/articles/360034561191-Desktop-Installation-Guide).

Both records are `PendingAcceptance` candidates for Windows 11 with no supported
targets yet. Package metadata does not establish silent execution, successful
presence detection, exact uninstaller behavior, or roaming-data preservation.
Verify install, repeat, detection, removal, retained user data, and saved-run
recovery on a disposable Windows 11 VM before declaring them installable. No
account sign-in, application launch, organization policy, or profile selection
is part of package acceptance. These additions do not resolve a legacy selector
or change the migration outcome estimates.

## ImageMagick Q16 portable source-verification recheck, 2026-10-22

Rechecked Q16/R01 against the publisher's current [Windows download page](https://imagemagick.org/download/#windows)
and [license](https://imagemagick.org/license/). The page still identifies
7.1.2-34 portable Q16 x64 as a static Windows build that makes no installer or
registry changes. The license permits personal, internal, and commercial use;
redistribution requires a license copy and attribution. The shell could not
resolve either `download.imagemagick.org` or the publisher-linked `github.com`
release host. The web fetch of the exact release URL returned a cache miss. No
archive or sidecar bytes were obtained, so no digest, detached signature, or
package candidate was added. Safe 7z extraction, ownership/recovery, feature
verification, and target acceptance remain deferred; the package must remain
non-runnable. No legacy outcome was resolved, retired, or excluded. All five
estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**,
rounded **145-200/about 170**. See the [updated source evidence](../archive/evidence/imagemagick-portable-q16-source-discovery-2026-10-22.json).

## Slack and Discord manifest digest recheck, 2026-10-22

The matching Microsoft WinGet manifest supplies a valid 64-character SHA-256
for Slack 4.52.182; the catalog pin was corrected to that exact value. The
matching Discord 1.0.9264 manifest supplies a 65-character value, which cannot
be a SHA-256. No installer bytes were retrieved, so no digest was guessed or
derived by truncating the manifest. The Discord catalog entry now carries an
acquisition-block reason, and package resolution fails before any network
request until a valid digest is verified. Both packages remain unsupported
pending Windows 11 install/repeat/detection/removal/data-preservation/recovery
acceptance. No legacy outcome was resolved, retired, or excluded. The catalog
validates **370 operations, eight groups, five profiles, and 239 PowerShell
files**, with **68 packages and 41 pending**. Focused source-pin and fail-closed
tests passed **3/3** on Windows PowerShell 5.1 and PowerShell 7. The first
default Pester run could not initialize its `TestRegistry` plugin because the
sandbox denies registry access. The complete suite later passed **25/25** on
both editions with that unused plugin disabled; see the dated fixture-regression
entry below. All five estimates remain **38-58 / 53-68 / 20-25 / 25-35 /
8-12**, exact **144-198**, rounded **145-200/about 170**. See the [sanitized
evidence](../archive/evidence/slack-discord-manifest-digest-recheck-2026-10-22.json)
and the current [Slack](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/s/SlackTechnologies/Slack/4.52.182/SlackTechnologies.Slack.installer.yaml)
and [Discord](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/d/Discord/Discord/1.0.9264/Discord.Discord.installer.yaml)
manifests.

## Package evidence fixture regression, 2026-10-22

The earlier direct Pester attempt was blocked by sandbox registry access because
Pester's `TestRegistry` plugin was enabled. With that unused plugin disabled, the
full package evidence suite passed **25/25** on Windows PowerShell 5.1 and **25/25**
on PowerShell 7. The file-moving fixtures now use uniquely named directories
directly under the repository's `.local` directory; cleanup verifies the resolved
direct parent, expected name and non-reparse-point root before removing each
fixture. The run left no package evidence fixture directories behind.

This is local acquisition, provenance, archive-member and removal-preservation
coverage only. It does not establish package runtime or VM acceptance, and no
legacy feature or product outcome was resolved, retired or excluded. The latest
catalog remains **370 operations, eight groups, five profiles and 239 PowerShell
files**, with **68 packages and 41 pending**. All five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized regression evidence](../archive/evidence/package-evidence-fixture-regression-2026-10-22.json).

## Discord artifact digest recheck, 2026-10-22

Rechecked the current Microsoft WinGet manifest for Discord 1.0.9264. Its
`InstallerSha256` still contains 65 hexadecimal characters, so it cannot be a
SHA-256. The versioned publisher artifact host did not resolve in the shell, and
the browser fetch tool could not retrieve the installer. No bytes or signature
were verified. The previously asserted 64-character catalog value therefore has
no available primary byte evidence and has been removed; `package.discord` now
fails before any network request with an explicit acquisition-block reason.
Slack 4.52.182 retains its matching 64-character manifest pin.

Discord remains a partial current-user package candidate pending independent
digest verification, followed by Windows 11 install, repeat, detection, removal,
data-preservation and saved-run recovery acceptance. No package was installed,
no VM was used, and no legacy outcome was resolved, retired or excluded. The
catalog remains **370 operations, eight groups, five profiles and 239 PowerShell
files**, with **68 packages and 41 pending**. All five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized recheck evidence](../archive/evidence/discord-artifact-pin-recheck-2026-10-22.json)
and the [current manifest](https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/d/Discord/Discord/1.0.9264/Discord.Discord.installer.yaml).
This acquisition-blocked status was superseded by the later [ApplicationsBatch4 acceptance run](#slack-and-discord-applicationsbatch4-windows-11-acceptance-2026-10-22), which measured and signature-verified the publisher artifact; install/remove recovery still prevents full lifecycle acceptance.

## User decisions on deferred packages and guest integrations, 2026-10-22

The user decided not to carry the legacy broad `C:\Tools` Defender exclusion
into the NirSoft migration; the disposition and v3.1 per-file manual-review
boundary are recorded in the [System Tools ledger](system-tools-dispositions.md).
The user also decided to keep standalone OpenJDK deferred unless an independent
use case is identified; BloodHound CE backend needs do not establish that use
case. For QEMU/GNOME Boxes, the requested full guest experience includes both
VirtIO and SPICE integrations when they are required. Whether the guest needs
VirtIO drivers, SPICE agent and SPICE WebDAV as a complete set still requires
technical verification on a matching QEMU guest. Hyper-V acceptance cannot
establish QEMU guest behavior.

These scope decisions close no package or component outcome: no catalog entry,
installer, Defender setting or VM state changed. All five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. Hyper-V CIM access remains denied and the protected VM
queue remains unavailable; QEMU/SPICE-specific acceptance also requires a
matching guest.
## QEMU guest integration source review, 2026-10-22

GNOME's Windows guest-tools guide directs users to spice-guest-tools for its
documented guest integration. SPICE upstream says that installer includes QXL
video drivers and the SPICE agent, while spice-webdavd is separate and needed
for Windows guest folder sharing. The upstream virtio-win guest-tools installer
combines VirtIO drivers with SPICE agent/driver components, so the migration
should not blindly install duplicate SPICE components. Select drivers by the
virtual devices the guest actually uses.

This evidence is for the documented SPICE-based GNOME Boxes path. GNOME's newer
experimental Boxes implementation may use a different guest communication path;
identify the exact Boxes release before treating this as universal. No installer
bytes, digest, signature, license review or Windows guest behavior were verified.
The QEMU/SPICE package candidates remain unpinned and unsupported until exact
publisher artifacts and the matching guest's install/repeat/detection/remove/
recovery behavior are verified. Version-specific license markers can be recorded
as `NeedsReview` without blocking implementation or technical acceptance. No
legacy outcome was resolved, retired or excluded. Estimates stay
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**.

Primary sources: [GNOME Boxes guest-tools guide](https://gnome-boxes-d203b0.pages.gitlab.gnome.org/install-guest-tools.html), [SPICE Windows guest tools and WebDAV](https://www.spice-space.org/download.html), [virtio-win Windows guest drivers](https://github.com/virtio-win/kvm-guest-drivers-windows#readme), [virtio-win guest-tools installer contents](https://github.com/virtio-win/virtio-win-guest-tools-installer#readme).

## QEMU guest-tools source and acquisition follow-up, 2026-10-22

The official virtio-win guest-tools installer README confirms that its MSI
combines VirtIO drivers with the SPICE guest agent and driver; SPICE's own
Windows installer also includes QXL and the SPICE agent. Avoid installing both
bundles blindly. GNOME's documented SPICE route uses separate `spice-webdavd`
only when Windows guest folder sharing is required. The target Boxes release
and virtual devices still determine the appropriate set.

Publisher indexes expose mutable `latest` aliases, so they are not version pins.
The SPICE index lists x64 `spice-webdavd` 2.4 and `latest` entries, last modified
2020-03-16. A second direct request for the exact 2.4 MSI failed with Windows
`curl.exe` exit 6 (`Could not resolve host: www.spice-space.org`); no output
file, bytes, digest, or signature were produced. VirtIO/SPICE guest-tool
versions and their signatures remain unverified. License uncertainty is not a
migration blocker: after selecting the exact release, record any owner-specific
review as `NeedsReview` and continue source preparation and acceptance work.

No catalog entry, installer, Defender setting, or VM state changed. This run
resolved no legacy outcome, so all five ranges remain **38-58 / 53-68 / 20-25 /
25-35 / 8-12**, exact **144-198**, rounded **145-200/about 170**. See the
[source follow-up evidence](../archive/evidence/qemu-guest-tools-source-followup-2026-10-22.json).

## PSScriptTools isolated runtime acceptance probe preparation, 2026-10-22

Prepared a guest-only probe for the pinned PSScriptTools 3.2.0 module. The
portable package lifecycle now invokes it after staging the exact reviewed
manifest. Fresh child processes cover Windows PowerShell 5.1 and PowerShell 7
when installed, first with dependencies available, then with an isolated empty
`PSModulePath` to verify the declared ThreadJob requirement fails before the
module's CIM/TEMP side effect. Present-dependency checks exercise the CIM
enumeration job, `System.Drawing`-backed color conversion and a
ThreadJob-backed runspace cleanup function. Each child receives a unique
run-owned TEMP/TMP directory beneath its correlated evidence folder; the probe
deletes only the known `CimNamespaceList.txt` file and an empty owned temp
directory. It does not install dependencies, execute module code on the host,
or change package deployment metadata.

Windows PowerShell 5.1 and PowerShell 7 parsers accepted the runner, guest
integration changes and boundary tests. Focused Pester passed 20/20 tests in
PowerShell 7; catalog export check and repository validation passed for 370
operations, 8 groups, 5 profiles and 240 PowerShell files. `git diff --check`
passed. These checks validate the harness only. The VM could not be queried
through Hyper-V CIM and the protected registered queue remains inaccessible, so
no runtime probe, package import, dependency test or VM acceptance ran. A
missing PowerShell 7 edition is reported as partial acceptance; a failed runtime
probe prevents the PSScriptTools batch summary from passing even if file
lifecycle checks pass.

No legacy outcome was resolved, retired or excluded. The five estimate ranges
remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. Next: use the existing clean Windows 11 checkpoint when
controller access is restored, run the PSScriptTools batch, inspect the runtime
summary and isolated child logs, then record actual import/function results and
checkpoint recovery. Dependency ownership, compatibility, global/editor side
effects and the module's actual CIM/TEMP behavior remain unverified.
## PSScriptTools runtime dependency static review, 2026-10-22

A read-only scan of the pinned 3.2.0 archive confirmed the observed archive
SHA-256 and reviewed all 75 function files without extracting, importing or
executing upstream code. The manifest declares both
`Microsoft.PowerShell.Threadjob` under `RequiredModules` and `System.Drawing`
under `RequiredAssemblies`, so both are module-import requirements even though
source references are localized: `Start-ThreadJob` appears in
`functions/CimMember.ps1` and `functions/Utilities.ps1`; the direct
`System.Drawing.ColorTranslator` reference appears in
`functions/Convert-HTMLtoANSI.ps1`. The module dot-sources its function files and loads types/formats, then
unconditionally starts a ThreadJob that recursively calls Get-CimInstance to
enumerate CIM namespaces, writes results to the fixed `%TEMP%\CimNamespaceList.txt`
path and registers argument completers that read that file. It sets global
variables; VS Code/ISE editor integration is conditional. Import is therefore
not inert.

This resolves the static location and import-boundary question, not dependency
ownership or runtime compatibility. RIDE does not install either dependency
with the inert snapshot. Next acceptance must run import only in a disposable Windows 11 guest with
TEMP/TMP redirected to a unique run-owned directory, then test dependencies
present and absent in Windows PowerShell 5.1 and
PowerShell 7, then exercise representative dependency-using functions and
review global/editor side effects. Do not add silent dependency installation.
No legacy outcome was resolved, retired or excluded. All five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized static evidence](../archive/evidence/psscripttools-runtime-dependency-static-review-2026-10-22.json).

## PSScriptTools runtime-probe cleanup guard, 2026-10-22

Review of the isolated guest probe found that its `MissingDependency` failure
path did not clean jobs if the module unexpectedly imported despite its required
ThreadJob dependency being hidden. The probe now snapshots child job IDs before
either mode and stops/removes only later-created jobs in `finally`, protecting
any pre-existing child jobs. It also removes only empty, direct, non-reparse
`empty-modules` and TEMP directories, leaving unexpected files and non-empty
folders intact.

The focused portable-acceptance suite passed **26/26** on PowerShell **7.6.5**;
repository validation and catalog export check passed. Pester TestRegistry was
disabled because the sandbox denies registry access. These are harness checks:
no package source was imported, no probe ran, and no VM or Windows state was
changed. PSScriptTools runtime compatibility and dependency ownership remain
partial; no whole legacy outcome was resolved, retired or excluded. All five
estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**,
rounded **145-200/about 170**. The native probe remains blocked by unavailable
Hyper-V CIM and protected controller queue access. See the [sanitized evidence](../archive/evidence/psscripttools-runtime-probe-cleanup-2026-10-22.json).

## MiTeC SQLite Query portable candidate preparation, 2026-10-22

Added `package.mitec-sqlite-query` as a portable, pending-acceptance candidate
for the retained MiTeC SQLite Query 3.2.0 ZIP. Read-only ZIP inspection in
memory reverified the 3,791,645-byte archive SHA-256 and all three recorded
member hashes; no file was extracted. Static PE inspection identifies
`SQLiteQuery.exe` as x86. The candidate stages exactly `SQLiteQuery.exe`,
`sqlite3.dll` and `sqlite3.exe`, has no supported targets, and is not included in
any profile. Its package version follows the publisher's 3.2.0 product page;
the executable's FileVersion 3.2.0.0 and ProductVersion 3.0.0.0 are recorded
separately.

Both SQLite binaries contain the official SQLite 3.35.5 source-ID string and
embedded compile-option metadata, but neither confirms a reproducible MiTeC build
or all local patches. The ZIP contains no license/notice file. SQLite's
public-domain terms for its deliverable code do not resolve MiTeC's separate
non-commercial EULA, owner-specific use entitlement, or redistribution. A
version-specific private `NeedsReview` record was added with owner Unassigned.
No entitlement or distribution permission is inferred.

The new local test passed **2/2** in Windows PowerShell 5.1 and **2/2** in
PowerShell 7. It binds the exact evidence and exercises only an inert synthetic
three-file ZIP through exact-member staging, repeat, snapshot recovery and
preservation of an unrelated user file. Catalog generation and validation pass
at **371 operations, 69 packages, 42 pending packages, 8 groups, 5 profiles,
and 241 PowerShell files**. No retained binary was loaded or executed, no
database was opened or modified, and no SQL was run.

This advances SQLite Query from source review to a pinned package candidate but
does not complete its legacy behavior or acceptance. Resolved: exact retained
archive/member identity and app architecture. Retired/excluded: none. Partial:
portable staging candidate. Deferred: owner-specific MiTeC entitlement and
redistribution, reproducible SQLite build provenance and applicable notice
retention, synthetic SQL/edit/import/export/history behavior and exact database
recovery, activation and Windows target support. All five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**, because staging does not close the legacy database-tool
outcome. Acceptance must use disposable synthetic database copies only; never
open personal or production databases. The existing authorized VM/controller
access remains unavailable.

See the [sanitized candidate-preparation evidence](../archive/evidence/mitec-sqlite-query-candidate-preparation-2026-10-22.json),
[static dependency/licensing review](../archive/evidence/mitec-sqlite-query-static-dependency-review-2026-10-20.json)
and [upstream source-ID follow-up](../archive/evidence/mitec-sqlite-query-source-id-follow-up-2026-10-21.json).

## MiTeC SQLite Query focused runner preparation, 2026-10-22

The protected portable acceptance path now has an explicit `SQLiteQuery` batch
for the pinned three-file candidate. Its local manifest points only to the
retained `SQLiteQ.zip`; exact archive SHA-256 and package-selection preflight
passed. The case's three expected member paths come from the catalog pin; the
prior candidate-preparation evidence records their in-memory hashes. The guest selection will cover managed-file install/repeat/remove,
saved-run restoration and preservation boundaries. It will not launch the app,
open a database or execute SQL. The candidate remains unsupported with no
supported Windows targets.

Focused Pester passed **120 tests with two skipped in PowerShell 7** and
**122/122 in Windows PowerShell 5.1** across the portable-selection and
task-automation suites. Catalog export check and repository validation pass;
validation covers 371 operations, 8 groups, 5 profiles and 241 PowerShell
files. A read-only `Get-VM` query on 2026-10-22 at 12:46 UTC failed because this
session cannot access the CIM resource. The existing protected controller must
be refreshed while idle before it recognizes this new batch, and this session
cannot submit to its protected queue. No elevation, task submission, VM or
checkpoint change, database access, or Defender action occurred. The new guest
batch has **not** run.

No legacy outcome was resolved, retired or excluded. The runner adds no setting,
package support or legacy feature completion. All five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. Functional database behavior, synthetic data recovery,
SQLite provenance/notices, owner-specific MiTeC terms and Windows target
acceptance remain separate gates. See the [sanitized runner-preparation evidence](../archive/evidence/mitec-sqlite-query-focused-runner-preparation-2026-10-22.json)
and [operator procedure](../../tests/integration/README.md#focused-reviewed-portable-packages).

## ImageMagick portable Q16 format and source follow-up, 2026-10-22

The official [Windows download page](https://imagemagick.org/download/#windows)
continues to identify `ImageMagick-7.1.2-34-portable-Q16-x64.7z` as the
portable Win64 static build with no installer or registry changes. The official
[Windows release index](https://download.imagemagick.org/windows/releases/)
lists this 7z archive as 9.7 MB and its detached `.asc` as 833 bytes. Direct
browser retrieval of both returned cache misses; the earlier shell attempt was
blocked by host DNS resolution. No bytes, SHA-256 or signature verification
were obtained.

That index also lists a generic 16 MB `ImageMagick-7.1.2-34.zip` and detached
signature. The official download page does not label this archive portable, so
it cannot replace the selected build without further inspection. No candidate
or catalog metadata was added. The 7z extraction/lifecycle gap and native
feature acceptance remain. No legacy outcome was resolved, retired or excluded;
all five estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact
**144-198**, rounded **145-200/about 170**. See the [sanitized evidence](../archive/evidence/imagemagick-portable-q16-format-follow-up-2026-10-22.json).

## MiTeC UUID and certificate utility file-lifecycle runner preparation, 2026-10-22

The protected portable runner now has a separate `MiTeCUtilityFiles` batch for
the pinned MiTeC UUID Generator 1.0.0, Certificate Generator 1.0.0 and
Certificate Information 1.5.0 candidates. The retained archives are still
present and match their catalog SHA-256 pins. A local three-ID manifest passed
the exact digest and selection preflight. The guest batch checks only portable
managed-file lifecycle/recovery and preservation boundaries. It does not query
hardware identifiers, create or inspect certificates, open user files, import
certificates, or run any of the tools. Each package remains unsupported with
its local version-specific `NeedsReview` license record.

The focused portable-selection and task-automation suites passed **123 tests
with two skipped in PowerShell 7** and **125/125 in Windows PowerShell 5.1**.
No guest acceptance ran. The protected controller needs an idle attended
refresh before this suite can be accepted; Hyper-V CIM and protected queue
access remain unavailable in this session. No fresh UAC prompt, task, utility,
VM or checkpoint change occurred. No legacy outcome was resolved, retired or
excluded. All five estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**,
exact **144-198**, rounded **145-200/about 170**. See the [sanitized evidence](../archive/evidence/mitec-utility-files-focused-runner-preparation-2026-10-22.json)
and [operator procedure](../../tests/integration/README.md#focused-reviewed-portable-packages).
## HashCheck idrassi 2.6.3 release source review, 2026-10-22

The official [idrassi repository](https://github.com/idrassi/HashCheck) and
[v2.6.3 release page](https://github.com/idrassi/HashCheck/releases/tag/v2.6.3)
identify the current requested fork, release version, and BSD-3-Clause license.
The release notes describe the Explorer integration and checksum creation and
verification changes; the upstream README names the WinGet package ID
`idrassi.HashCheckShellExtension`.

A third-party Chocolatey page reports the version-specific publisher GitHub
asset URL and SHA-256, but that digest is not a verified pin. The shell could
not resolve `github.com` when retrieving the exact publisher asset, and browser
retrieval did not expose the asset bytes. No installer bytes, digest validation,
or Authenticode result are available. No installer was executed, and no
Defender-blocked tool, VM, or checkpoint was touched.

Resolved: current fork, release identity and license family. Partial: proposed
asset URL and third-party digest lead. Deferred: acquire the exact publisher
bytes, verify digest and signer, inspect silent installation/removal and
Explorer registration/recovery, and perform disposable Windows 11 acceptance
before declaring any target. Owner-specific use and distribution remain for
license review. No package operation or supported target was added, and no
legacy outcome was resolved, retired, or excluded. All five ranges remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized source evidence](../archive/evidence/hashcheck-idrassi-release-source-review-2026-10-22.json).

## Artcraft package license reviews recorded, 2026-10-22

The checkout-local license store now has version-specific `NeedsReview`
records, owner `Unassigned`, for the following 13 pinned catalog entries:

| Package | Version | Pending review |
| --- | --- | --- |
| PhotoCraft | 0.7.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| VectorCraft | 0.9.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| FilmCraft | 0.6.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| LightCraft | 0.6.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| PDFCraft | 0.6.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| EffectCraft | 0.8.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| DesignCraft | 0.6.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| WordCraft | 0.5.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| SoundCraft | 0.5.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| DeckCraft | 0.5.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| CADCraft | 0.5.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| GridCraft | 0.5.0 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |
| ArtCraft Launcher | 0.2.1 | Owner-specific use/distribution assessment for bundled assets and Artcraft brand terms |

The catalog identifies MIT OR Apache-2.0 for code, bundled notices, and
separate brand terms. The local records flag an unresolved owner-specific
review; they do not grant entitlement or redistribution permission. All 13
packages remain unsupported with Windows 11 candidate targets and pending
lifecycle acceptance. The repository validator passed for 371 operations,
eight groups, five profiles, and 241 PowerShell files; the focused license
review suite passed 9/9 with Pester's optional registry fixture disabled after
the sandbox denied its HKCU test-key setup. A fresh read-only `Get-VM` query for
`RIDE-Win11-Test` failed with `Access to a CIM resource was not available to the
client`. No installer, launcher, VM, or Windows state was touched.
No legacy outcome was resolved, retired, or excluded. The estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**: license-review bookkeeping does not complete package
acceptance or close a legacy outcome. See the [sanitized evidence](../archive/evidence/artcraft-package-license-review-2026-10-22.json).

## ChromeSyncParser static source safety review, 2026-10-22

Read the retained pinned `ChromeParser.py` without executing it. Its SHA-256
matches the prior source-review evidence. `GetDatabases` assigns its Windows
default path only for `platform.release()` values `7` and `XP`; on current
Windows 10/11 default discovery reaches `glob.glob(databasePath)` without an
assignment. The README's Windows Vista-or-later path also differs from the
script's path. `SyncFile` calls `sqlite3.connect` without read-only URI mode;
the inspected query methods use `SELECT`, but the connection does not enforce
read-only access. `CheckFile` opens an existing `-f` output with mode `w`, and
`main` opens that output before opening the selected database. There is no
input/output collision check, so using one path for both truncates the database
before SQLite opens it.

The repository validator and generated-operation check passed. The focused
package-evidence Pester run passed 24 tests and failed one unrelated test that
updates the shared artifact-observation fixture; .NET `File.Replace` could not
remove its existing target under the sandbox, and the artifact remained
retained. This test failure does not establish ChromeSyncParser behavior or
change its candidate status.

Resolved: exact static source behavior and the associated execution-safety
blockers. Partial: pinned source-only package and syntax compatibility under
Python 3.12.14. Deferred: managed-file lifecycle acceptance, modern Chrome
database discovery/schema, read-only input, collision-safe non-overwriting
output, parser correctness, and Windows target support. Do not execute this
script against live browser profiles or evidence. No Python process, database,
browser data, output path, VM, or Windows state was accessed or changed. No
legacy outcome was resolved, retired, or excluded. The ranges remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized static evidence](../archive/evidence/chromesyncparser-static-source-safety-review-2026-10-22.json)
and [operator-facing package boundaries](../application-packages.md#pinned-python-source-candidates).

## Hex2text static behavior review, 2026-10-22

Read the retained pinned hex2text.py without executing it; its SHA-256 matches
the earlier source archive evidence. The script removes literal spaces, uses
only complete four-character groups, parses each group as base-16, and maps the
result to one Python character. An incomplete one-to-three-character suffix is
silently ignored. Invalid complete groups raise an uncaught ValueError. This is
code-point conversion, not UTF-8 byte decoding. The source imports no modules
and uses stdin/stdout only; surrogate/display behavior remains unverified.

Resolved: exact static input/transform/output boundary. Partial: pinned
source-only candidate and earlier Python 3.12.14 syntax check. Deferred:
synthetic-input behavior checks for invalid values, incomplete groups,
control/surrogate characters and console encoding, plus disposable Windows 11
managed-file lifecycle acceptance. No source execution, user input/file access,
VM or Windows change occurred. No legacy outcome was resolved, retired, or
excluded. All five ranges remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**,
exact **144-198**, rounded **145-200/about 170**; source behavior clarification
closes no feature or package acceptance. See the [sanitized evidence](../archive/evidence/hex2text-static-behavior-review-2026-10-22.json)
and [package boundaries](../application-packages.md#pinned-python-source-candidates).

## Sysinternals license review markers, 2026-10-22

**Superseded for RIDE's direct download-and-install workflow by the following
RIDE v2 license-specialist approval record.** This dated entry preserves the
interim review-marker state and must not be read as a current licensing blocker.

Microsoft's Sysinternals terms permit installation and use on the user's
devices but prohibit publishing the software for others to copy, renting,
leasing, lending, or transferring copies. Microsoft's licensing FAQ states
that no distribution licenses are offered, even for free third-party
distribution. This matters separately from local package installation because
RIDE's deployment model also supports preparing shared or offline toolkits.

The checkout-local version-specific review store now marks the full-suite
snapshot and nine individual catalog candidates `NeedsReview`, each at its
exact package version with owner Unassigned. The records identify the
owner-specific intended-use and publication question; they do not grant or deny
an individual's entitlement, authorize publication, or block local package
implementation. No user-specific assessment was inferred.

No files were acquired or executed, no terms were accepted, and no VM or Windows
state changed. The 9-test local license-review suite passed; an exact catalog
join verified one `NeedsReview`/Unassigned record for each of the ten pinned
package versions and 35 total records in the local store. Pester TestRegistry
was disabled because the sandbox denied registry access. No legacy outcome was
resolved, retired, or excluded; package license follow-up and portable lifecycle/native acceptance remain partial. The
local review store now has **35 `NeedsReview` records**. All estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [official terms](https://learn.microsoft.com/en-us/sysinternals/license-terms),
[licensing FAQ](https://learn.microsoft.com/en-us/sysinternals/license-faq),
and [sanitized evidence](../archive/evidence/sysinternals-license-review-2026-10-22.json).

## Sysinternals Suite focused runner preparation, 2026-10-22

Added a fixed `SysinternalsSuite` acceptance selection for the exact reviewed
`package.sysinternals-suite` snapshot. The selector resolves to one case with all
164 required members, the recorded snapshot version and SHA-256, no supported
targets, and `PendingAcceptance = true`. It does not select individual tools or
Defender-blocked NirSoft files. The registered lifecycle runner would check install,
repeat, removal, exact saved-run restoration, unowned/modified-file preservation,
and collision refusal without executing a utility.

The retained archive SHA-256 matches the catalog pin, and the fixed local manifest
selects exactly the one pending suite case. Both focused Pester suites passed: 128
passed, 0 failed, and 2 host-preflight tests skipped. Pester temporary files were
rooted inside the workspace with registry/result storage disabled. `Get-VM -Name
RIDE-Win11-Test` again returned CIM access denied. The protected controller still
needs an idle refresh for `FocusedPortableV1` before this batch can be submitted.
No elevation, task submission, package acquisition, Windows/Defender change, or guest
run occurred.

Resolved, retired, excluded: none. Deferred: guest file-lifecycle/checkpoint
acceptance, individual products' technical applicability and dependency checks,
runtime acceptance, and tool execution.
Partial: the whole-Suite source candidate and its test selection. The RIDE v2
license-specialist approval covers the direct download/install workflow, so licensing
is not a blocker. This preparation closes no legacy outcome, so the estimates remain
38-58 / 53-68 / 20-25 / 25-35 / 8-12, exact 144-198, rounded 145-200/about 170.
See the [sanitized evidence](../archive/evidence/sysinternals-suite-focused-runner-preparation-2026-10-22.json).
## Sysinternals RIDE v2 license-specialist approval, 2026-10-22

The prior review-marker entry treated Microsoft's general restrictions on
publishing or transferring copies as an unresolved RIDE use question. That was
too broad for the product's actual workflow. The user clarified that RIDE v2 was
reviewed by a license specialist and approved for Sysinternals, and that RIDE is a
download-and-install tool: it obtains the utilities from Microsoft and installs
them on devices supported by the user. RIDE does not publish or transfer copies.
There is no license blocker for Sysinternals use or package migration in that
approved scope. The specialist approval and user's reaffirmation govern this
migration decision; the linked Microsoft terms and FAQ are references, not a
separate license gate for RIDE's download-and-install workflow.

The ten exact suite/product versions in the checkout-local store are now marked
`Reviewed`. The original specialist's name and approval date were not retained;
the store records that limitation and the user's 2026-10-22 reconfirmation rather
than inventing reviewer details. The local store now has 25 `NeedsReview` records;
the ten Sysinternals records are no longer among them. No legal issue or licensing
blocker remains for Sysinternals use in RIDE or its package migration.

Resolved: RIDE v2 download-and-install license review. Retired/excluded: none.
Deferred: package file lifecycle, checkpoint recovery and runtime/target acceptance
only. No estimate range changes because native package acceptance remains pending.
See the [corrected disposition evidence](../archive/evidence/sysinternals-license-disposition-correction-2026-10-22.json),
[Microsoft terms](https://learn.microsoft.com/en-us/sysinternals/license-terms),
and [Microsoft licensing FAQ](https://learn.microsoft.com/en-us/sysinternals/license-faq).

## Sysinternals migration decision reaffirmed, 2026-10-23

The user reaffirmed the prior RIDE v2 license-specialist approval for RIDE's
direct publisher-download and install workflow, and stated that there are no
legal issues using Sysinternals in RIDE. RIDE does not publish or transfer
Sysinternals copies. Do not use a generalized redistribution concern to block
this package migration. All ten exact version records remain `Reviewed`;
licensing is not a blocker. Only technical lifecycle, recovery and target
acceptance remain open. This decision closes no additional legacy outcome, so
estimates remain unchanged. See the [dated evidence](../archive/evidence/sysinternals-license-reaffirmation-2026-10-23.json).

## Sysinternals license scope reaffirmed, 2026-10-23 10:13 UTC

The user again clarified that the prior RIDE v2 license-specialist approval covers
Sysinternals in RIDE. RIDE downloads from Microsoft and installs on devices supported
by the user; RIDE does not publish or transfer copies. There are no legal issues for
this use, and licensing must not be used to block package migration. The ten exact
suite/product versions remain `Reviewed` in the local store. Do not schedule another
license review for this scope. The only remaining Suite migration gate is technical:
Windows lifecycle, exact recovery and target acceptance, which remain deferred while
the registered VM/checkpoint cannot be accessed. No legacy outcome closed and all
five estimates remain unchanged. See the [reaffirmation evidence](../archive/evidence/sysinternals-license-scope-reaffirmation-2026-10-23-1013.json).

## Sysinternals Suite focused regression, 2026-10-23

`SysinternalsSuitePackage.Tests.ps1` passed **7/7** on PowerShell 7.6.5 and
**7/7** on Windows PowerShell 5.1, both with Pester 5.7.1 and the TestRegistry
plugin disabled. The initial default-temp run
hit the sandbox's protected temporary-directory boundary during package staging
and manifest replacement; its staged evidence was retained. Repeating with
`TEMP` and `TMP` directed to repository `.local` passed all seven tests. No VM,
installer, Sysinternals executable, network or Defender setting was touched.
The read-only VM access recheck at 2026-10-23 05:55 UTC remains CIM-denied, so
guest lifecycle, exact recovery and target acceptance are still deferred. No
legacy outcome closed; ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**,
exact **142-196**, rounded **145-200/about 170**. See [focused regression
evidence](../archive/evidence/sysinternals-suite-focused-regression-2026-10-23.json)
and [VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0555.json).

## Microsoft Visual C++ runtime candidate target validation, 2026-10-23

Repository validation initially rejected the pending `package.vcredist-v14-x64`
candidate because it had no explicit candidate target. Added Windows 11 as its
candidate target; `SupportedTargets` remains empty and `PendingAcceptance` remains
true, so no install support is declared before the runtime's own lifecycle,
shared-runtime impact, recovery and target checks pass. The catalog was
regenerated and `tools/validate.ps1` passed in Windows PowerShell 5.1 and PowerShell
7.6.5 for **376 operations, 71 packages (41 pending), 8 groups, 5 profiles and
247 PowerShell files**. `git diff --check`
passed. No VM or installer ran. This package is an additional runtime prerequisite, not an extra legacy
outcome; no legacy outcome closed and estimates remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [candidate
validation evidence](../archive/evidence/vcredist-candidate-target-validation-2026-10-23.json).

## RIDE-Win11-Test access recheck, 2026-10-23 06:13 UTC

The read-only `Get-VM -Name RIDE-Win11-Test` check again returned `Access to a
CIM resource was not available to the client`. VM and checkpoint state remain
unknown; no queue submission, VM change or package action occurred. B03, Q08,
PSScriptTools, offline execution, Sysinternals, Visual C++ runtime, and prepared
NTCore/MiTeC guest batches remain deferred. Local work can continue. No legacy
outcome closed and all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See the
[timestamped access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0613.json).

## Local regression after Sysinternals disposition correction, 2026-10-22

The Windows-native catalog export check and repository validator passed (371
operations, 8 groups, 5 profiles and 241 PowerShell files). A broad local Pester
run across 90 files discovered 2,309 tests: 2,306 passed, 0 failed, 2 were
skipped and 1 was not run. Pester reported a container-level error for
`LibraryAuthoring.Tests.ps1` after its test body completed; an isolated rerun
passed all 42 tests. Six slower files were excluded from this broad run and had
passed in the earlier full run. The TestRegistry plugin was disabled. No legacy
outcome or acceptance status changed, so all five estimate ranges remain
38-58 / 53-68 / 20-25 / 25-35 / 8-12, exact 144-198, rounded 145-200/about 170.
VM acceptance is still blocked by Hyper-V CIM access and protected controller
queue access. See the [dated regression evidence](../archive/evidence/local-regression-2026-10-22.json).

## ImageMagick portable Q16 SevenZip lifecycle implementation, 2026-10-22

The official Windows download page still identifies 7.1.2-34 portable Q16 x64
static as a no-installer/no-registry archive. The direct release asset URL was
verified from the official page link, but its bytes and detached `.asc` signature
remain unavailable through the current source channels; SHA-256 and signature
verification are still required before acquisition can be enabled.

RIDE now supports a bounded `SevenZip` portable format using the Microsoft-signed
Windows inbox `System32\tar.exe`. The handler validates the complete path and
verbose type/size listings before extracting into a unique staging directory,
rejects unsafe/duplicate paths and non-file/non-directory entries, enforces
10,000-entry, 512 MiB per-file, 2 GiB total and five-minute process bounds, and
verifies the extracted file set and sizes before product writes. The existing
portable ownership manifest supplies repeat/removal and exact saved-run recovery.
Synthetic text-only 7z integration passed on the local Windows host; it does not
establish target support or ImageMagick behavior.

Added `package.imagemagick-portable-q16` as an unsupported Windows 11 candidate
using the exact official asset URL. Catalog acquisition is blocked until the
artifact bytes and signature are verified. Its version-specific checkout-local
license record is `NeedsReview`/Unassigned; this is informational and not a
license blocker. Preserve archive notices. No artifact or ImageMagick binary was
acquired, extracted or run; no VM, UAC, PATH or Defender change occurred.

The portable package suite passed 84/84. Catalog tests passed 70/71; the single
failure was the existing test that writes a registry security descriptor, denied
by sandbox permissions. Catalog export and repository validation passed for 372
operations, 8 groups, 5 profiles and 241 PowerShell files. No legacy outcome
closed; all five ranges remain 38-58 / 53-68 / 20-25 / 25-35 / 8-12, exact
144-198, rounded 145-200/about 170. See the [dated evidence](../archive/evidence/imagemagick-portable-q16-sevenzip-implementation-2026-10-22.json).

A follow-on focused run under Windows PowerShell 5.1 passed all four selected
SevenZip tests (80 other tests were not run). This confirms the archive handler's
fixture coverage in both installed PowerShell editions; native Windows package
acceptance and exact publisher artifact verification remain pending.

## ImageMagick portable Q16 official source acquisition recheck, 2026-10-22

The official download page still links version 7.1.2-34 portable Q16 x64 as a
no-installer/no-registry archive. The publisher binary index opened successfully
and lists the selected 7z at 11 MB, with an 833-byte `.asc` and a CycloneDX sidecar.
The direct shell download then failed DNS resolution for `download.imagemagick.org`;
no artifact or signature bytes were obtained. The direct release URL remains
confirmed by the official page, but its digest and detached signature cannot be
verified here. The package stays unsupported pending exact-source verification
and disposable-VM lifecycle/feature acceptance; license review is informational,
not a blocker. No artifact was extracted and ImageMagick, Defender, PATH, UAC or a
VM were not touched. No legacy outcome closed and estimates remain unchanged. See
the [structured acquisition evidence](../archive/evidence/imagemagick-source-acquisition-recheck-2026-10-22.json).

## ImageMagick portable Q16 exact source acquisition follow-up, 2026-10-22

After the preceding DNS failures, the exact 7.1.2-34 archive was acquired from
the official release URI and its detached-signature sidecar from the publisher
archive. The archive is 12,022,003 bytes and its measured SHA-256 is
`52cc6a441c7884f5ff4274b410c9b90c4b7d54245dcdf4d32988bb4e4df4e5d1`; that
digest is now pinned as `ExpectedSha256`. A read-only tar listing was inspected.
The publisher digest RDF was acquired but contains no entry for this selected
archive. The detached signature is retained but was not independently verified,
so the evidence does not claim signature verification. Candidate acquisition is
no longer blocked: future downloads must match the pinned digest. The package
remains unsupported pending disposable Windows 11 lifecycle, exact recovery and
feature acceptance. A read-only listing found 23 regular members and no unsafe
paths; bounded static extraction into the ignored review directory found
`magick.exe`, `LICENSE.txt` and `NOTICE.txt`. All eight executable members have
valid Authenticode signatures from ImageMagick Studio LLC, and none was run. The
version-specific `NeedsReview` license marker remains informational, not a
migration blocker. No Defender change, UAC action or VM test occurred. No legacy
outcome closed; all five ranges remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**,
exact **144-198**, rounded **145-200/about 170**. See the [structured acquisition evidence](../archive/evidence/imagemagick-source-acquisition-recheck-2026-10-22.json).

## ImageMagick portable Q16 artifact integrity recheck, 2026-10-22

Recomputed the retained 7.1.2-34 portable Q16 archive SHA-256 as
`52cc6a441c7884f5ff4274b410c9b90c4b7d54245dcdf4d32988bb4e4df4e5d1`, matching
the catalog pin. Read-only Authenticode inspection of the eight extracted
executables returned `Valid` for all eight, each signed by ImageMagick Studio
LLC. No executable ran. The 833-byte detached signature remains unverified:
Git for Windows `gpg.exe` could not start in this sandbox (`NtCreateDirectoryObject
... 0xC0000022`). This optional signature check remains a confidence follow-up;
it does not block implementation. The exact archive pin and valid executable
signatures remain the available integrity evidence.

No package or target metadata changed, and no legacy outcome closed. License
review remains `NeedsReview` metadata without an implementation gate. Windows 11
lifecycle, recovery and feature acceptance still require the disposable VM.
Estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**,
rounded **145-200/about 170**. See the [sanitized integrity evidence](../archive/evidence/imagemagick-artifact-integrity-recheck-2026-10-22.json).

## ApplicationsBatch1 Chrome acceptance submit retry, 2026-10-22

Retried the already-authorized `ApplicationsBatch1` suite for the pinned Chrome
156.0.8078.48 package through the existing registered client. The client failed
while writing its temporary pending-queue request: `Set-Content` was denied
access to the protected queue path. It returned before reporting a submitted
request or guest result, and no UAC prompt appeared. The preceding read-only
`Get-VM` check also returned CIM access denied; current VM and checkpoint state
remain unknown. No installer ran, no controller/VM/Defender state changed, and
no legacy outcome closed. Chrome Windows 11 acceptance remains pending; Server
2025 is not inferred. All estimates remain **38-58 / 53-68 / 20-25 / 25-35 /
8-12**, exact **144-198**, rounded **145-200/about 170**. See the [sanitized
submission evidence](../archive/evidence/ride-win11-test-applicationsbatch1-submit-retry-2026-10-22.json).

## HashCheck idrassi 2.6.3 source follow-up, 2026-10-22

The official release page lists v2.6.3 as Latest, published 2026-10-07, and shows
four assets. It describes the Windows 11 separate checksum command, safer
verification-load failure behavior, and the PowerShell 7 installer/uninstaller
lookup fix. The official repository README names the
WinGet identity `idrassi.HashCheckShellExtension`, documents Windows Vista and
later, and exposes command-line checksum creation/verification through
`HashCheckPackageHost.exe`. The publisher identifies BSD-3-Clause. No license
blocker is inferred for RIDE download/install; owner-specific local review stays
informational.

The official release page's four assets did not render in the available browser
view, and the host could not resolve GitHub's API or download host. A current
Chocolatey community record provides an x86 installer URL, SHA-256 and `/S`
switch lead, plus a test report for that Chocolatey package. These are useful
acquisition leads, not verified publisher bytes or RIDE acceptance; the x86 hash
does not pin the x64 artifact. The browsable publisher `master` installer source
still identifies itself as 2.6.2.0, so it cannot prove the selected 2.6.3
installer's exact install, uninstall, reboot or Windows 11 sparse-package
behavior.

Resolved: current release, product identity and license family. Partial:
Explorer/Windows 11 behavior and community x86 installer leads. Deferred: exact
x64 publisher bytes/digest/signer, exact-release installer effects and recovery,
and disposable Windows 11 acceptance. No package operation was added and no
legacy outcome closed; estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**,
exact **144-198**, rounded **145-200/about 170**. See the [structured source
follow-up](../archive/evidence/hashcheck-idrassi-release-source-follow-up-2026-10-22.json).

## Package license-review markers and migration blockers, 2026-10-22

User direction is to prioritize completion of package migration work and record
unresolved licensing questions in the checkout-local review store. A `NeedsReview`
marker is a follow-up record, not an automatic blocker to source review, package
implementation, local tests or acceptance preparation. It does not claim that
rights are resolved or approve a distribution model. Keep any concrete publisher
download/entitlement restrictions, security alerts, source-integrity failures and
technical acceptance gaps as their own evidence-based blockers. Sysinternals
remains separately resolved for RIDE's direct download-and-install workflow under
the prior RIDE v2 license-specialist approval.

Resolved: migration blocker interpretation and separate review tracking. Retired,
excluded, partial and deferred product outcomes do not change; estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**.

## Application package and installer-inspection local regression, 2026-10-22

The focused `ApplicationPackages.Tests.ps1` and `InstallerInspection.Tests.ps1`
run passed **99/99** on PowerShell 7.6.5 with Pester 5.7.1. Pester's optional
TestRegistry fixture was disabled because sandbox policy denied its HKCU setup;
`TEMP` and `TMP` were redirected under `.local/pester-temp-package-tests` after
the OS temp location denied portable-manifest replacement. No installer or VM
was run and Windows state did not change. This validates local package helper
behavior only; native activation, package-specific recovery and VM acceptance
remain separate. No legacy outcome closed and all five estimate ranges remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized run evidence](../archive/evidence/application-package-installer-focused-regression-2026-10-22.json).

## Phoenix Protector retained MSI installation-boundary review, 2026-10-22

The ignored retained MSI's measured SHA-256 matches the catalog pin. Read-only
Windows Installer database inspection found five files, three shortcuts, no
service or Registry table rows, a Program Files target directory, and custom
launch actions for the .NET **2.0.50727** requirement. The MSI itself is not
Authenticode-signed; its `Binary`-table custom-action DLL was separately found
Microsoft-signed in the earlier static review. The package declares machine
scope, while the all-users folder action is in the UI sequence, so its quiet
installer arguments now explicitly pass `ALLUSERS=1`. A new catalog regression
test protects this scope contract. No MSI action ran and the candidate remains
unsupported pending Windows 11 install/repeat/remove/recovery acceptance, exact
shortcut/path behavior and the .NET launch check. Its local `NeedsReview`
license marker remains separate from technical migration work. No legacy
outcome closed and estimates are unchanged. `PhoenixPackage.Tests.ps1` passed
3/3, including a mocked handler-dispatch check for the `ALLUSERS=1` MSI arguments;
no process was launched. Catalog export and validation passed for 374 operations,
8 groups, 5 profiles and 244 PowerShell files. See the [sanitized metadata
evidence](../archive/evidence/phoenix-msi-static-install-boundary-2026-10-22.json).

## Slack and Discord ApplicationsBatch4 Windows 11 acceptance, 2026-10-22

The first controller request exposed a guest fixture defect: 25 package-evidence
tests assumed the ignored `.local` directory already existed. The fixtures now
create that directory when absent while retaining the reparse-point guard and
GUID-scoped cleanup. The follow-up guest run passed Pester with 0 failures.

Runs `13d9a039f2ef4307b31bdf605b84a6de`, `f22dfd9847fb42e4b1e800c0b488e799`
and `bf0e0f310e554dfd89661699391d0184` recorded initial fixture and vendor
uninstaller failures. For run `e0d0ee2b58eb4bb2ac6d66242020c115`, RIDE's custom
Roaming-directory move-aside metadata was removed so each vendor uninstaller
could operate in place. On Windows 11 Enterprise Evaluation build 26300, the
guest acquired Slack 4.52.182 and Discord 1.0.9264 from their declared HTTPS
publishers; both measured SHA-256 values matched the catalog pins, and both
Authenticode signatures were valid for their named publishers. Install,
repeat-install, removal, repeat-removal and compensating recovery passed for both
packages. The test wrote a marker into each existing Roaming profile before
installation and verified that its bytes remained unchanged after vendor
uninstall and recovery. Both packages are now supported on Windows 11 only;
Windows Server support is not inferred.

The controller restored the disposable VM's clean checkpoint and left it Off.
No Defender alert was reported in the captured artifacts; Defender event logs
were not exported, so the run does not establish that no Defender event was
recorded. No legacy product outcome closed. The five estimate ranges remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. Four correlated request records are summarized in the
[batch 4 evidence](../archive/evidence/applications-batch4-acceptance-2026-10-22.json).

## Hex2text synthetic input runtime probe, 2026-10-22

Verified the retained archive and script hashes against the pinned catalog
candidate, then ran the source with Python 3.12.14 using only synthetic strings
on stdin. Five cases confirmed ordinary four-digit code-point conversion,
literal-space removal and ignored incomplete suffixes, an uncaught `ValueError`
for an invalid complete group, raw U+0001 output, and `UnicodeEncodeError` for
an isolated surrogate under strict UTF-8 stdout. The tool is a code-point
converter, not a UTF-8 byte decoder. `SourceScriptPackages.Tests.ps1` also
passed 8/8 with Pester 5.7.1, the optional HKCU `TestRegistry` fixture disabled
and temporary files confined to `.local`; its default invocation had failed
before assertions when sandbox policy denied that fixture.

No user file, network, or Windows state was accessed or changed. The probe ran
on the local host, not in the disposable VM; it does not establish Windows
console/code-page behavior, package file lifecycle, recovery, or target support.
`package.hex2text` remains unsupported pending those technical checks. No legacy
outcome closes, so the five estimates remain **38-58 / 53-68 / 20-25 / 25-35 /
8-12**, exact **144-198**, rounded **145-200/about 170**. See the
[sanitized runtime evidence](../archive/evidence/hex2text-synthetic-input-runtime-2026-10-22.json).

## HashCheck publisher download retry, 2026-10-22

Retried the versioned HashCheck 2.6.3 installer URL identified during release
review. Windows `curl.exe` returned exit code 6 because this host could not
resolve `github.com`; no output file or downloaded bytes were produced. The
third-party Chocolatey record's SHA-256 remains an acquisition lead only and is
not used as a package pin. The official release page still identifies v2.6.3;
its BSD-3-Clause license creates no RIDE download/install blocker.

No package operation or VM run occurred. Exact bytes, measured digest,
Authenticode signer, installer effects, recovery and target acceptance remain
open. No legacy outcome closed, so all five estimates remain **38-58 / 53-68 /
20-25 / 25-35 / 8-12**, exact **144-198**, rounded **145-200/about 170**. See the
[sanitized acquisition evidence](../archive/evidence/hashcheck-publisher-download-retry-2026-10-22.json),
[publisher release](https://github.com/idrassi/HashCheck/releases/tag/v2.6.3),
and [third-party URL/hash lead](https://community.chocolatey.org/packages/hashcheck/2.6.3).

## HashCheck publisher download retry, 2026-10-23

Rechecked the official v2.6.3 release page and retried the exact versioned
installer URL. The official page confirms the release and feature notes, but its
asset list is not available through the current retrieval path. Windows
`curl.exe` again returned exit code 6 because this host could not resolve
`github.com`; the destination was absent before the request and no output file
or bytes were produced. The third-party digest remains unverified and is not a
package pin. No package operation was added. BSD-3-Clause remains a non-blocking
license status for RIDE's download/install use.

Exact artifact verification, installer behavior, recovery and Windows target
acceptance remain open. The current read-only `Get-VM` check also returned CIM
access denied, so no guest test was run. No legacy outcome closed and all five
estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**,
rounded **145-200/about 170**. See the [sanitized acquisition evidence](../archive/evidence/hashcheck-publisher-download-retry-2026-10-23.json)
and [official release](https://github.com/idrassi/HashCheck/releases/tag/v2.6.3).

## PSScriptTools Windows 11 runtime dependency acceptance, 2026-10-22

The registered `PSScriptTools` suite on Windows 11 Enterprise Evaluation build
26300 passed the portable lifecycle and exact file restoration. The isolated
runtime probe did not pass. In Windows PowerShell 5.1, import with dependencies
present failed because `Microsoft.PowerShell.Threadjob` was not installed; the
declared missing-dependency case passed and confirmed failure before module
side effects. The VM does not have PowerShell 7, so that edition was unavailable.
No dependencies were installed; no CIM namespace data was collected. The initial
run exposed a null parent-process exit code; the corrected rerun now records the
child exit code and distinct module error. Local portable automation Pester passed
28/28 with the unused `TestRegistry` plugin disabled.

Keep `package.psscripttools` unsupported and pending. Windows 11 file staging is
accepted, but runtime/dependency ownership and PowerShell 7 behavior remain open.
No whole legacy outcome is closed. The five estimates remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized runtime evidence](../archive/evidence/psscripttools-runtime-dependency-failure-2026-10-22.json).

## NTCore 4GB Patch Windows 11 functional rejection, 2026-10-22

The focused `NTCore` VM suite ran on Windows 11 Enterprise Evaluation build
26300. PE Detective and CFF Explorer passed their portable lifecycle checks.
4GB Patch's synthetic x86 PE functional acceptance failed in three controller
runs (`abd3f2e12f124bdb9780f2c2dd964f77`,
`bf8c4d208194456697a136f88037c962`, and
`1edf0da98ac742919d3b75d2913b3087`).

The final run verified that the tool sets the large-address-aware flag and
creates an exact `.Backup` for the initial patch. With a sentinel occupying
that backup path, however, the tool returned exit code 0, patched the target,
preserved the sentinel, and created no additional copy of the original bytes.
The runner restored its generated fixture from an in-memory original before
recording the rejected behavior. No real executable was opened or changed.
The final controller summary now reports `FunctionalAcceptance: Failed`; the
VM clean checkpoint was restored and the VM left Off.

Keep `package.ntcore-4gb-patch` unsupported and pending. The functional behavior
is unsafe under a backup collision, and the local version-specific license
review remains `NeedsReview`; a retained archive hash is not publisher-provided.
No whole legacy outcome is resolved, retired or excluded. The five estimates
remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized acceptance evidence](../archive/evidence/ntcore-4gb-patch-functional-failure-2026-10-22.json).

## ImageMagick portable Q16 VM-runner preparation, 2026-10-22

Added a fixed Windows 11 acceptance batch for the retained ImageMagick 7.1.2-34
Q16 archive. Its checks cover exact archive ownership and notices, executable
signature, install/repeat/remove/recovery and preservation of an unowned package
file. The only feature commands report the pinned version and create/identify a
synthetic 1x1 PNG; no user image is opened. The task client/controller route,
regression assertions, operator instructions and ignored local archive manifest
are prepared. Focused regression Pester passed 132 tests with two host-preflight
skips.

The protected Windows 11 controller is still on module 0.9.0 and guest runner
0.4.0. Its refresh was not completed because the available PowerShell command
host failed the registration script's administrator check. No ImageMagick VM
request was submitted and the VM state was not verified by this command host.
Refresh the controller from the owning elevated Windows PowerShell session,
then run the fixed `ImageMagick` suite. Keep the package unsupported and pending
Windows 11 lifecycle, recovery and feature acceptance. No legacy outcome is
resolved, retired or excluded; the five estimates remain **38-58 / 53-68 /
20-25 / 25-35 / 8-12**, exact **144-198**, rounded **145-200/about 170**. See
the [runner preparation evidence](../archive/evidence/imagemagick-q16-vm-runner-preparation-2026-10-22.json).

## PSScriptTools ThreadJob dependency source follow-up, 2026-10-23

Microsoft's PowerShell Gallery lists `Microsoft.PowerShell.ThreadJob` 2.2.0
with a minimum PowerShell version of 5.1. Microsoft documents ThreadJob as
included in PowerShell 7.6 under the renamed module. The guest's Windows
PowerShell 5.1 therefore needs a separately staged module for the dependency
present probe; PowerShell 7.6 needs no extra module install.

One exact request to the official Gallery package endpoint failed before
transfer because this host could not resolve `www.powershellgallery.com`. No
bytes or digest were produced, and no dependency operation was added. The
read-only `Get-VM -Name RIDE-Win11-Test` check also returned CIM access denied.
No module was installed or imported and no CIM data was collected. Once source
and VM/controller access are available, acquire and verify the exact package,
then rerun the Windows PowerShell 5.1 dependency-present probe and the PowerShell
7.6 built-in-module probe in the disposable guest. No legacy outcome was closed;
all five ranges remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact
**144-198**, rounded **145-200/about 170**. See [structured evidence](../archive/evidence/psscripttools-threadjob-source-followup-2026-10-23.json).

## ImageMagick portable Q16 Windows 11 acceptance, 2026-10-23

The refreshed registered controller ran request
`d044a9243ddf461b92d035e0cdaf9418` on Windows 11 build 26300. Focused local
Pester passed 134/134 tests across catalog, package prerequisite, package
evidence and portable automation checks. The guest had no `vcomp140.dll`, so
the fixed runner downloaded Microsoft's x64 v14 redistributable from its
official aka.ms endpoint, verified the Microsoft Authenticode signature, and
installed it only inside the disposable VM. The installer exited 0; the
resulting signed runtime was version 14.51.36247.0. Evidence includes both
artifact hashes and signer thumbprints.

ImageMagick 7.1.2-34 Q16 executed successfully: version reporting and synthetic
1x1 PNG encode/identify passed. Whole-archive ownership, notices, executable
signatures, repeat install, removal, repeat removal, exact saved-run recovery,
unowned-file preservation, and refusal to overwrite colliding or modified
files all passed. No user image was opened. The controller collected evidence,
restored its clean checkpoint and left the VM Off. See the
[sanitized acceptance evidence](../archive/evidence/imagemagick-q16-win11-acceptance-2026-10-23.json).

This accepts the ImageMagick package lifecycle and bounded feature behavior on
Windows 11, which is now the package's sole supported target. The separate local
`NeedsReview` disposition does not assert entitlement. Server support and
activation remain open; detached archive signature verification is optional.
No legacy outcome was
resolved, retired or excluded; all five estimates remain **38-58 / 53-68 /
20-25 / 25-35 / 8-12**, exact **144-198**, rounded **145-200/about 170**.


## Sysinternals install-planning regression, 2026-10-23

The focused license-review Pester suite now explicitly covers all ten Sysinternals suite/product package IDs. Each install plan remains available with desired state Present, while PendingAcceptance stays true. This protects the prior RIDE v2 specialist approval for direct download/install from being turned into a legal migration gate, without implying native lifecycle acceptance.

The suite passed **20/20** on Windows PowerShell 5.1 and **20/20** on PowerShell 7 with TestRegistry disabled. No installer, package download, Sysinternals tool, Defender setting, VM, or Windows state was touched. Resolved: plan coverage for the approved scope. Retired/excluded: none. Deferred: guest lifecycle, exact recovery and target acceptance remain blocked by current VM/CIM access. Partial: no legacy runtime outcome closed. All five estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded **145-200/about 170**. See [sanitized regression evidence](../archive/evidence/sysinternals-install-planning-regression-2026-10-23.json).

## Classic Teams MSI cleanup retired, 2026-10-23

The user retired `RemoveTeamsWideInstaller` from v3 scope. Preserve the historical
mapping, but do not substitute current Teams or claim Outlook add-in/data cleanup.
This retires one legacy application outcome and changes no Windows state. The
application review queue now has 73 pending/partial outcomes. See the
[authoritative decision](decision-session-2026-10-17.md#windows-component-and-classic-teams-scope-decisions-2026-10-23).
## Docker Desktop and ImageMagick package acceptance reconciliation, 2026-10-23

A fresh read-only `Get-VM -Name RIDE-Win11-Test` check at 2026-10-23 04:59:04 UTC again returned `Access to a CIM resource was not available to the client`; VM/checkpoint state remains unverified and no batch was submitted. The catalog keeps Docker Desktop 4.96.0 as a Windows 11 candidate with no
supported targets and pending RIDE acceptance. Both per-user and all-users
variants still need RIDE lifecycle, detection and exact recovery evidence; a
physical WinGet install does not prove the RIDE handler path. Its local
`NeedsReview` record is separate from technical acceptance.

ImageMagick portable Q16 7.1.2-34 passed Windows 11 acceptance on build 26300,
including archive ownership, the signed Microsoft runtime prerequisite, Q16
version checks, synthetic PNG encode/identify, repeat install, exact removal and
restore, and preservation of unowned files. Windows 11 is its only supported
target. Server and activation remain unsupported; detached archive-signature
verification remains optional. Its local `NeedsReview` record is informational,
not an installation blocker.

Resolved: ImageMagick Windows 11 acceptance. The five-file Pester run passed 189/189 in PowerShell 7 and 189/189 in Windows PowerShell 5.1 with one WindowsIntegration case excluded and the TestRegistry plugin disabled. Repository validation passed for 374 operations, eight groups, five profiles and 246 PowerShell files; generated operation documentation is current. Retired/excluded: none. Partial:
Docker Desktop remains a candidate. Deferred: Docker variant lifecycle/recovery,
ImageMagick Server/activation and unrelated VM acceptance. No installer or VM
ran in this documentation reconciliation. No legacy product outcome closed;
all five estimates remain **38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact
**144-198**, rounded **145-200/about 170**. See the [ImageMagick acceptance
evidence](../archive/evidence/imagemagick-q16-win11-acceptance-2026-10-23.json)
and [VM access record](../archive/evidence/ride-win11-test-access-recheck-2026-10-23.json).

## PSScriptTools ThreadJob package acquisition retry, 2026-10-23

The official PowerShell Gallery page identifies Microsoft.PowerShell.ThreadJob
2.2.0 with minimum PowerShell 5.1 support and no package dependencies. The exact
publisher API package request was retried at 2026-10-23 05:01 UTC and failed
before transfer because this host could not resolve
`www.powershellgallery.com`. A 05:52 UTC page check reconfirmed the version,
minimum PowerShell and empty declared dependency list; its manual-download link
redirected to Microsoft Learn, which the browser retrieval could not fetch. No
artifact bytes, digest, extraction or installation resulted. PSScriptTools and
ThreadJob were not imported or executed; no CIM data or Windows state was touched.

Resolved: current publisher metadata reconfirmed. Retired/excluded: none. Partial:
the dependency version and runtime role are identified, but no exact artifact pin
is available. Deferred: acquire and verify the official 2.2.0 package, then probe
Windows PowerShell 5.1 with the module and PowerShell 7.6 with its built-in
module in the disposable guest. The read-only `Get-VM -Name RIDE-Win11-Test` check at 2026-10-23 05:03 UTC again returned CIM access denied; VM/checkpoint state remains unverified and no queue submission occurred.
No legacy outcome closed; all five estimates remain **38-58 / 53-68 / 20-25 /
25-35 / 8-12**, exact **144-198**, rounded **145-200/about 170**. See [source
retry evidence](../archive/evidence/psscripttools-threadjob-source-retry-2026-10-23.json)
and the [publisher page](https://www.powershellgallery.com/packages/Microsoft.PowerShell.ThreadJob/2.2.0).

## WSL, .NET 3.5 and QEMU guest integration decisions, 2026-10-23

The user kept Debian, Ubuntu and Kali as separate opt-in WSL outcomes, including
Debian when available as a WSL distribution; no automatic install or unregister
is authorized, and the unmatched Fedora removal selector remains retired. .NET
Framework 3.5 remains a conditional explicit compatibility outcome; exact build
selects the feature or standalone route, with matching local servicing sources
and no network fallback. SPICE WebDAV is a separate optional guest folder-sharing
integration and is not installed by default. These choices resolve scope only;
source, data recovery and native acceptance remain pending. No package/component
outcome closed and no estimate changed. See the
[authoritative decision](decision-session-2026-10-17.md#wsl-net-35-and-qemu-guest-integration-decisions-2026-10-23).

## Microsoft Visual C++ v14 runtime package scope, 2026-10-23

The user approved adding dependency-driven Microsoft Visual C++ Redistributables
to v3 after asking whether RIDE should include Ninite's multiple VC++ packages.
The initial implementation adds only the current x64 v14 runtime, version
14.51.36247.0, from Microsoft's `vc_redist.x64.exe` endpoint, pinned to the SHA-256
and Microsoft Authenticode result already observed in the ImageMagick Windows 11
acceptance VM. The scope does not install every historical x86/x64/ARM64 runtime.
The `v14` family is cumulative; older 2013-and-earlier redistributables remain
separate and are deferred until a selected application demonstrates need.

ImageMagick remains accepted on Windows 11. Its preflight now requires
`vcomp140.dll` version 14.50.35710.0 or later and directs an operator to install
the new RIDE package if that runtime is absent or too old. The standalone runtime
package remains pending RIDE-managed install, detection, removal and recovery
acceptance and currently has no supported targets; automatic prerequisite ordering
in plans is not implemented, so the runtime must currently be installed directly
from Microsoft and selected explicitly after RIDE support is accepted. The
package-licensing
watchlist records Microsoft's redistribution terms for bundle review. Explicit
runtime removal can affect other applications and must remain an intentional
operator action.

Resolved: v14 x64 package metadata and ImageMagick's minimum runtime check are
implemented. Retired/excluded: none. Partial: automatic prerequisite plan
ordering, runtime lifecycle acceptance and owner-specific license review.
Deferred: x86, ARM64 and legacy VC++ packages.
No legacy outcome closed; all five estimate ranges remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. No
installer or VM ran during this source change.

## VM access and Defender alert reconciliation, 2026-10-23

The read-only `Get-VM -Name RIDE-Win11-Test` again failed with
`Access to a CIM resource was not available to the client`, so the checkpoint
query was not issued. VM/checkpoint state remains unknown; no controller
submission, VM action, installer, package, or Defender change occurred. The bundled PowerShell runtime exposes
`Microsoft.PowerShell.ThreadJob` 2.2.0, but no Gallery package archive or digest
was available, so it is not accepted as the dependency's publisher source and
PSScriptTools runtime acceptance remains deferred.

The active NirSoft source-review summary was corrected against the frozen
evidence: four user-reported Defender alerts are present for
`NirSoft/chromecookiesview.exe`, `NirSoft/bulletspassview.exe`, `ProduKey.exe`
and `WirelessKeyView.exe`. No classification or false-positive determination is
recorded. Keep those members out of selected file-level review/acceptance batches
pending manual review; do not restore/re-extract quarantined files, create
per-file exclusions, or add allow actions. The whole-collection package scope
remains. The 2026-10-24 decision permits reviewed exclusions only for
selected packages' RIDE-managed install directories; it retains the rejection
of a shared v2 broad `C:\Tools` exclusion.

Resolved: corrected the active alert list and refreshed the VM blocker evidence.
Retired/excluded: no whole legacy outcome. Partial: the matching ThreadJob module
exists in the local test runtime, but the exact Gallery artifact is not acquired.
Deferred: guest lifecycle/recovery/target acceptance and PSScriptTools dependency
acceptance. All five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**,
exact **142-196**, rounded **145-200/about 170**. See [structured recheck evidence](../archive/evidence/ride-win11-and-threadjob-recheck-2026-10-23-0627.json)
and the [frozen Defender alert evidence](../archive/evidence/collection-continuation-blockers-2026-10-17.json).

## PSScriptTools ThreadJob exact package retry, 2026-10-23

The official PowerShell Gallery page confirms Microsoft.PowerShell.ThreadJob
2.2.0, a Windows PowerShell 5.1 minimum, no declared dependencies, Microsoft
copyright, and a package file list containing `.signature.p7s`. The exact
official package endpoint again failed before transfer because
`www.powershellgallery.com` did not resolve (curl exit 6); no artifact or digest
was created. The Gallery's manual-download link also redirected to a Microsoft
Learn page the browser fetch could not access. The 2.2.0 copy in the bundled
PowerShell runtime remains runtime-only evidence, not a substitute package
source. No module import, dependency installation, VM action or UAC prompt
occurred.

Resolved: official package metadata/source identity reconfirmed. Retired/excluded:
none. Partial: dependency version and compatibility are known, but exact bytes
are not acquired or pinned. Deferred: dependency-present PSScriptTools runtime
acceptance. No legacy outcome closed; estimates remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See the
[retry evidence](../archive/evidence/psscripttools-threadjob-source-retry-2026-10-23-0633.json)
and [official Gallery package page](https://www.powershellgallery.com/packages/Microsoft.PowerShell.ThreadJob/2.2.0).

## MiTeC UUID Generator bounded static interface review, 2026-10-23

The retained UUID Generator 1.0.0 archive and `UUID.exe` member were read in
memory and their SHA-256 values still match the recorded pins. A bounded ASCII
and UTF-16LE printable-string scan found MiTeC firmware/SMBIOS type names and
UUIDv7/ULID implementation references, but did not expose a clear command-line
functional-test interface or a safe UI automation contract. This static result
does not prove that no such interface exists. The payload was not extracted or
executed, and no live host identifiers were queried, captured or exported.

The accepted product scope remains synthetic UUID v4/v7, ULID and Snowflake
generation/decoder checks, plus privacy-safe UI observation that never records
the live UEFI, SMBIOS, machine or device values. This source review does not
resolve those behaviors; run them only through a disposable Windows guest once
VM access returns. The exact-version `NeedsReview` marker remains local and does
not block package implementation or technical acceptance.

Resolved: archive/member pins and the limits of printable-string inspection
rechecked. Retired/excluded: none. Partial: static interface review only; no
legacy package outcome closed. Deferred: synthetic generation/decoding, UI and
privacy acceptance on Windows 11. The read-only VM access check at 2026-10-23
07:18 UTC returned CIM access denied; no checkpoint query or guest run occurred.
All five ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**142-196**, rounded **145-200/about 170**. See the [bounded scan evidence](../archive/evidence/mitec-uuid-generator-static-string-review-2026-10-23.json)
and [VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0718.json).

## All pending package plans remain available with NeedsReview, 2026-10-23

The focused license-review regression now iterates every catalog Package
operation marked `PendingAcceptance`: all **41** receive a synthetic, version-matched
local `NeedsReview` record and retain one install plan whose desired state remains
`Present` and whose `PendingAcceptance` flag remains true. This confirms that local
license-review metadata does not become an implementation/planning gate; it does
not waive the independent technical acceptance requirement or execute a package.
The engine and package handlers do not read local license-review statuses; catalog
validation only prevents those user/company fields from entering shared catalog
data or package variants.

`LicenseReviews.Tests.ps1` passed **21/21** on PowerShell **7.6.5** with Pester
**5.7.1** and TestRegistry disabled. Windows PowerShell **5.1.26100.9711** parsed
the changed test with zero errors, but Pester could not be imported because the
host's AuthorizationManager rejected Pester's format files. No installer, package
download, VM, Defender setting or Windows state was touched. The synthetic review
fixture was isolated under `.local` and removed after the test.

Resolved: planning coverage for all 41 current pending package declarations.
Retired/excluded: none. Deferred: technical package lifecycle/target acceptance
remains independent. Partial: no legacy package outcome closed. All five ranges
remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See the [structured regression evidence](../archive/evidence/pending-package-needsreview-plan-regression-2026-10-23.json).

## License-plan regression and VM access recheck, 2026-10-23

The focused `LicenseReviews.Tests.ps1` rerun passed **21/21** on PowerShell
7.6.5 with Pester 5.7.1 and TestRegistry disabled. Coverage includes all 41
pending package install plans with version-matched synthetic `NeedsReview`
records and all ten Sysinternals plans; the approved Sysinternals download-and-
install workflow has no licensing blocker. A fresh read-only
`Get-VM -Name RIDE-Win11-Test` check at **07:31 UTC** again returned CIM access
denied. No checkpoint query or guest run occurred, and no package, installer,
Defender setting or Windows state changed.

Resolved: current local planning-regression evidence. Retired/excluded: none.
Deferred: package, setting and component guest acceptance that requires the VM;
the VM/checkpoint state remains unknown. Partial: no legacy outcome closed.
All five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**142-196**, rounded **145-200/about 170**. See the [structured evidence](../archive/evidence/license-review-and-vm-access-recheck-2026-10-23-0731.json).

## B06 restore-guard regression, 2026-10-23

Expanded the unregistered client-component lifecycle suite to **10/10 passing**
on PowerShell 7.6.5. The added tests prove refusal after target servicing-revision
drift and no state/snapshot mutation during `-WhatIf` restore. PowerShell 7 and Windows PowerShell 5.1 parser validation passed for both candidate
modules and the test file. The PowerShell 5.1 parser ran through
`powershell.exe -Command`, parsing source without executing it. No DISM, catalog
registration, supported-target declaration or Windows state change occurred.
The 07:39 UTC read-only VM query again returned CIM access denied; no checkpoint
query or guest run occurred.

Resolved: two additional local recovery-safety regression cases. Retired/excluded:
none. Partial: B06 remains an unregistered candidate. Deferred: matching-source and
no-network proof, servicing dependencies/policy, native apply/repeat/restore and
payload/version recovery. No legacy outcome closed; estimates remain **38-58 /
52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**.
See [candidate evidence](../archive/evidence/b06-component-guarded-lifecycle-candidate-2026-10-23.json).
## Deferred package decisions, 2026-10-23

The user decided to keep NTCore 4GB Patch deferred after the synthetic-target
functional test showed that an occupied backup path did not prevent target
modification and no recoverable original-byte copy was made. Do not retire the
legacy outcome or implement the package based on this failure. Reconsider only
after establishing a safe recovery path; retain the [functional rejection evidence](../archive/evidence/ntcore-4gb-patch-functional-failure-2026-10-22.json).

The user chose RIDE-managed ownership for PSScriptTools' Windows PowerShell 5.1
`Microsoft.PowerShell.ThreadJob` dependency, version 2.2.0. The exact official
Gallery package bytes and digest are still unavailable because publisher DNS
resolution failed. The copy present in the bundled PowerShell runtime is not a
substitute source. Acquire and pin the official package, implement its managed
lifecycle and dependency ordering, then complete dependency-present PSScriptTools
acceptance. Until then the PSScriptTools candidate remains unsupported. See the
[source retry record](../archive/evidence/psscripttools-threadjob-source-retry-2026-10-23-0633.json)
and [official package page](https://www.powershellgallery.com/packages/Microsoft.PowerShell.ThreadJob/2.2.0).

These are scope and ownership decisions only. No package was acquired or run, no
legacy outcome closed, and the five migration estimate ranges remain unchanged.

## MiTeC SQLite Query synthetic GUI acceptance preparation, 2026-10-23

The pinned MiTeC SQLite Query 3.2.0 archive and executable member hashes matched when read from the retained ZIP in memory. The executable was not extracted, loaded or run, and no database was opened or created. Bounded printable ASCII/UTF-16LE strings include form identifiers for BLOB editing, export, history, import and triggers; these corroborate names only and do not prove runtime behavior.

The [publisher's version page](https://www.mitec.cz/wp/msqliteq/) describes SQL, table, trigger and history modules, CSV/XML/SQL export and CSV/XML DataPacket 2.0 import. New fixtures under [tests/fixtures/mitec-sqlite-query](../../tests/fixtures/mitec-sqlite-query/README.md) define a synthetic-only VM path covering query and table edits, trigger/history behavior, CSV import/export, SQL/XML export and exact restoration of the run-owned database. The SQL seed and CSV semantics passed an additional local check using Python 3.12 standard-library sqlite3 3.49.1 against an in-memory database: schema creation, Unicode/quotes, NULL versus empty text, BLOB sentinels, the update trigger, and all three CSV rows were verified; no database file was created. XML import is deferred until its DataPacket fixture contract is documented. The test must stop if the application requests an account, license activation, online update or external connection. No personal or production database may be used.

Local `NeedsReview` metadata remains separate from implementation and technical acceptance and is not a migration blocker. Separate technical follow-up remains for disposable Windows GUI results, exact database recovery, SQLite build provenance/compile options and upstream notices, owner-specific entitlement, and Windows 11 target acceptance. The candidate remains unsupported. The 08:32 UTC read-only VM query again returned CIM access denied before checkpoint inspection; see the [access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0832.json). Focused Pester passed 2/2 on PowerShell 7.6.5 with Pester 5.7.1 and TestRegistry disabled. A Windows PowerShell 5.1 rerun could not import Pester because AuthorizationManager rejected its format files. The local checks do not substitute for Windows GUI acceptance. No legacy outcome closed; estimates remain unchanged. See the [structured preparation evidence](../archive/evidence/mitec-sqlite-query-synthetic-acceptance-preparation-2026-10-23.json).

## Cross-group catalog, package and component regression, 2026-10-23

The repository validator passed for 376 operations, 8 groups, 5 profiles and
251 PowerShell files. Focused Pester passed 318/318 executed tests across
catalog, application-package, package-evidence, client-component
preparation/lifecycle, license-review and remaining-setting suites on PowerShell
7.6.5. TestRegistry was disabled, WindowsIntegration was excluded and temporary
files were directed under `.local`; one registry integration test was not run.
The 243-test focused batch and a standalone detailed RemainingSettings rerun
(75/75 in 139.5 seconds) make up the combined result. A stale assertion for
ImageMagick's runtime description was updated to match the current catalog
wording; package behavior did not change.

The broader 3,072-test attempt found that assertion, then emitted no output at
normal verbosity while `RemainingSettings.Tests.ps1` was active. It was stopped
before that file completed and without a complete result. The standalone
detailed rerun passed that file. No package or VM ran, and no legacy outcome
closed; migration estimates remain unchanged. See the [structured regression
evidence](../archive/evidence/cross-group-catalog-package-component-regression-2026-10-23-0937.json).

## RIDE-Win11-Test access recheck, 2026-10-23 09:55 UTC

The read-only `Get-VM -Name RIDE-Win11-Test` query again returned CIM access
denied, before checkpoint inspection. The VM and checkpoint remain unknown; no
acceptance task was queued, and no DISM, Defender or guest/Windows operation
ran. Sysinternals has no licensing blocker under the prior RIDE v2 specialist
approval for direct download/install; its prepared lifecycle and target checks
remain technically pending. B06 OpenSSH Client/Telnet Client and other prepared
guest batches also remain deferred for the same VM access blocker.

Resolved, retired, excluded: none. Deferred: disposable-VM acceptance for
prepared package, setting and component batches. Partial: no legacy outcome
closed. All estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**142-196**, rounded **145-200/about 170**. See the [sanitized access
evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0955.json).

## PSScriptTools ThreadJob exact source retry, 2026-10-23 09:56 UTC

Retried the exact official PowerShell Gallery package endpoint for
`Microsoft.PowerShell.ThreadJob` 2.2.0. DNS resolution failed before transfer;
no bytes, digest or partial file were produced. No local bundled runtime copy is
being treated as publisher package evidence. The dependency was not installed,
PSScriptTools was not imported, and no CIM data, VM, Defender or Windows state
was touched.

Resolved, retired, excluded: none. Deferred: exact dependency artifact acquisition
and dependency-present Windows guest acceptance. Partial: the source endpoint
was retried but remains unavailable by DNS. All estimates remain **38-58 /
52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See the [sanitized retry evidence](../archive/evidence/psscripttools-threadjob-source-retry-2026-10-23-0956.json).

## Separate package license-review status from candidate names, 2026-10-23 10:04 UTC

Removed the shared-catalog display suffix `licence review pending` from the
NTCore 4GB Patch, MiTeC UUID Generator, Certificate Generator, Certificate
Information and SQLite Query candidate names. Their exact version-matched
`NeedsReview` records remain in `.local/license-reviews.json`; catalog review
status is not added to shared defaults. All five operations remain
`PendingAcceptance` with empty `SupportedTargets`, so this correction clears no
technical acceptance gate. It makes package identity independent from the local
license-review workflow and avoids presenting that review marker as the reason
these packages are not supported.

`Catalog.Tests.ps1` passed **72/72 selected tests**; one WindowsIntegration test
was excluded. The catalog exporter and repository validator passed, checking 376
operations, 8 groups, 5 profiles and 251 PowerShell files. No package ran and no
Windows or Defender state changed. Resolved: shared names no longer encode local
review status. Retired/excluded: none. Deferred: package lifecycle, recovery and
target acceptance. Partial: no legacy outcome closed. Estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See the [structured evidence](../archive/evidence/candidate-license-status-catalog-separation-2026-10-23.json).
## Package-plan regression and RIDE-Win11-Test access, 2026-10-23 10:08 UTC

After removing local license-review status from five shared candidate display
names, `LicenseReviews.Tests.ps1` passed 21/21. All 41 packages still marked
`PendingAcceptance` retained install plans when exact-version `NeedsReview`
records were present; all ten Sysinternals plans also remained available under
the prior RIDE v2 specialist approval. `Catalog.Tests.ps1` passed 72/72 selected
tests, with one WindowsIntegration test excluded. Catalog export and repository
validation passed for 376 operations, 8 groups, 5 profiles and 251 PowerShell
files.

The read-only `Get-VM -Name RIDE-Win11-Test` query returned CIM access denied at
10:08:16 UTC before checkpoint inspection. The VM/checkpoint remains unknown; no
queue submission, package run, Defender change or Windows mutation occurred.
Sysinternals licensing remains cleared for RIDE's direct download-and-install
workflow. Prepared guest acceptance is still deferred. Resolved: package
planning remains available with local `NeedsReview` markers. Retired, excluded:
none. Deferred: Windows package, setting and component acceptance under the
current CIM blocker. Partial: no legacy outcome closed. Estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See the [structured evidence](../archive/evidence/license-plan-labels-vm-access-2026-10-23-1008.json).

## B06 LocalSource mode naming and boundary regression, 2026-10-23 10:18 UTC

Renamed the unregistered component candidate's source mode from `Offline` to `LocalSource` in the preparation and lifecycle modules. This name means that RIDE supplies an explicit local source path. DISM `LimitAccess` blocks Windows Update lookup; configured-source fallback is `NotInspected`, so the mode does not establish network isolation. `SourceValidated` and `NetworkBoundaryVerified` remain false, and the lifecycle candidate remains unregistered with no supported targets.

The focused component preparation and lifecycle tests passed **39/39** on PowerShell 7.6.5 with TestRegistry disabled. Windows PowerShell 5.1 parsed both candidate modules and test files. No DISM, network, VM, checkpoint, Defender or Windows-state action occurred.

Resolved: accurate naming and regression coverage. Retired/excluded: none. Deferred: complete matching source/media, configured-source and dependency network behavior, payload/version recovery, and Windows target acceptance. Partial: no legacy component outcome closed. All five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See the [structured evidence](../archive/evidence/b06-local-source-mode-regression-2026-10-23-1018.json).

## RIDE-Win11-Test access recheck, 2026-10-23 10:22 UTC

The read-only `Get-VM -Name RIDE-Win11-Test` query again returned `Access to a CIM resource was not available to the client` before checkpoint inspection. The VM and checkpoint state remain unknown. No task was submitted, no fresh UAC prompt was requested, and no VM, guest, Defender or Windows state changed. Prepared package, settings and component acceptance remains deferred until the existing Hyper-V/registered-controller access path is available. The Sysinternals license decision is settled for RIDE direct download/install; only technical acceptance remains. No legacy outcome closed. All five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See the [structured access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-1022.json).

## Sysinternals Suite preregistered dispatch access, 2026-10-23 10:29 UTC

The RIDEWin11Test controller configuration advertises `FocusedPortableV1`; the
SysinternalsSuite local-source request passed that preflight. The unprivileged host
then received access denied while atomically staging the temporary request file in
the protected ProgramData queue. It stopped before enqueue or task launch. The
10:22 UTC Hyper-V CIM query was also denied, so VM/checkpoint state remains unknown.
No UAC prompt was requested, no suite or tool ran, and no Defender-blocked file was
selected. Sysinternals licensing remains settled for RIDE's prior specialist-
approved direct download-and-install workflow. Lifecycle, exact recovery and target
acceptance remain technical blockers. No legacy outcome closed; estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [structured dispatch evidence](../archive/evidence/sysinternals-suite-dispatch-access-2026-10-23-1029.json).
## PSScriptTools ThreadJob exact source retry, 2026-10-23 10:34 UTC

Retried the exact Microsoft PowerShell Gallery API URI for the pinned
`Microsoft.PowerShell.ThreadJob` 2.2.0 package. DNS resolution for
`www.powershellgallery.com` failed before transfer; no bytes, digest or partial
file were produced. No local runtime copy or mirror was substituted. No dependency
was installed, PSScriptTools was not imported, and no VM, CIM data, Defender or
Windows state was touched. The source and dependency-present Windows PowerShell
5.1 probe remain deferred. No legacy outcome closed; estimates remain **38-58 /
52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**.
See [structured retry evidence](../archive/evidence/psscripttools-threadjob-source-retry-2026-10-23-1034.json).
## Existing VM/controller focused-suite access recheck, 2026-10-23 10:35 UTC

The current RIDEWin11Test configuration is readable and advertises
`FocusedPortableV1`, but the SysinternalsSuite dispatch at 10:29 UTC failed while
writing its protected atomic queue request before enqueue. The RIDESrv2025Test
configuration is readable but is schema 1 with no advertised focused portable
capabilities; no request was submitted to that controller. A read-only `Get-VM`
inventory query returned CIM access denied, leaving VM/checkpoint state unknown.
No UAC prompt, controller-file change, task submission, VM/package/Defender or
Windows change occurred. Focused VM acceptance remains deferred until authorized
queue and Hyper-V access return. No legacy outcome closed; all ranges remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [structured access evidence](../archive/evidence/vm-controller-capability-access-2026-10-23-1035.json).
## NTCore Driver List and Rebel.NET package candidates, 2026-10-23 10:47 UTC

The retained `DriverList.zip` and `RebelDotNET.zip` archive hashes match their
source-review records. Static executable metadata verified Driver List x86/x64
file version 1.0.2.1, its additional IA64 member (excluded from the Windows x64
candidate), and Rebel.NET unsigned x86 version 1.6.0.1. Added two portable package
operations with exact retained-archive SHA-256 pins and `PendingAcceptance`; both
have empty `SupportedTargets` and Windows 11 as the candidate target. The Driver
List operation stages but does not query loaded drivers or generate reports.
Rebel.NET staging does not open assemblies; future functional tests are restricted
to an owned synthetic .NET assembly and separate output.

The official Rebel.NET guide says commercial use goes against its terms. The
Driver List product page/archive provide no product-specific use or distribution
grant. Added exact-version `NeedsReview` records owned by `Unassigned` to the local
review store as requested; these markers do not block candidate implementation or
package planning and do not claim entitlement. The local store now has 38 records
(28 `NeedsReview`, 10 `Reviewed`).

Pester passed **108/108** across ApplicationPackages and LicenseReviews with
TestRegistry disabled. Repository validation passed **378 operations, 8 groups,
5 profiles and 251 PowerShell files**, and the catalog export is current. No
executable ran, no VM or package was used, and Defender/Windows state was not
changed. Resolved: exact source metadata and candidate preparation. Retired or
excluded outcomes: none; IA64 is omitted from the Windows 11 package variant.
Deferred: native portable lifecycle and recovery, sensitive Driver List report
behavior, and synthetic-only Rebel.NET functional recovery. No whole legacy outcome
closed; estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See [structured candidate evidence](../archive/evidence/ntcore-driver-list-rebelnet-candidate-2026-10-23-1047.json),
[package guidance](../application-packages.md#ntcore-driver-list-and-rebelnet-portable-candidates),
and [license guidance](../package-licensing.md#local-usercompany-reviews).
## PSScriptTools ThreadJob publisher metadata and transfer recheck, 2026-10-23 11:29 UTC

The official Gallery package page confirms `Microsoft.PowerShell.ThreadJob` 2.2.0, Windows PowerShell 5.1 minimum, Microsoft Corporation publisher attribution, and the package file list including `LICENSE`, `ThirdPartyNotices.txt` and `.signature.p7s`. The linked PowerShell/ThreadJob project identifies its MIT license. A fresh exact-version request to the official Gallery API failed DNS resolution before transfer; no package file, bytes or digest were produced. No mirror or local substitute was used.

RIDE-managed ownership of this PSScriptTools dependency remains selected. Before adding the package operation, acquire and verify the exact nupkg, calculate its digest, inspect the signed payload and retain the upstream notices. This leaves PSScriptTools partial and closes no legacy package outcome. See [structured evidence](../archive/evidence/psscripttools-threadjob-publisher-metadata-and-transfer-recheck-2026-10-23-1129.json), the [official Gallery package page](https://www.powershellgallery.com/packages/Microsoft.PowerShell.ThreadJob/2.2.0), and [upstream project](https://github.com/PowerShell/ThreadJob).

## PSScriptTools offline source-lifecycle fixture follow-up, 2026-10-23 12:03 UTC

The pinned local PSScriptTools archive SHA-256 still matches the 360-file source
review and catalog pin. Updated `PSScriptToolsPackage.Tests.ps1` to pass `-Offline`
to portable staging and check that staged PowerShell scripts are marked
`NotInspectedOffline`, avoiding certificate-provider network checks in local
fixture runs. The selected metadata and incomplete-source Pester tests passed
2/2 on PowerShell 7.6.5 with TestRegistry disabled; the other five tests were not
selected in that focused run.

A full-source TestDrive attempt staged all 360 files and wrote its ownership
journal, but the repeat/removal/recovery test did not return within the bounded
workspace run. It was stopped without a test result; no full-source host pass is
claimed. The module was not imported or executed and no package was installed.
The earlier registered Windows 11 run's 14 file-lifecycle checks remain the
native file-staging evidence. Runtime acceptance remains partial: Windows
PowerShell 5.1 lacks the declared ThreadJob dependency, the exact Gallery package
transfer still fails DNS before bytes, and VM/controller access remains denied.

Resolved: offline behavior is explicit in the local lifecycle fixture and the
two selected preflight tests pass. Retired/excluded: none. Deferred: complete
local 360-file repeat/removal/recovery regression, dependency-present runtime
acceptance, exact dependency acquisition, and remaining guest acceptance. Partial:
no legacy package outcome closes. All five estimates remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[structured evidence](../archive/evidence/psscripttools-offline-lifecycle-fixture-follow-up-2026-10-23-1203.json),
[prior registered file-lifecycle evidence](../archive/evidence/psscripttools-registered-rerun-2026-10-22.json),
and [latest VM access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1124.json).

## MiTeC System Information eXtra and TAPI Monitor package candidates, 2026-10-23

Added unsupported Windows 11 candidates `package.mitec-system-information` 16.0.0 and `package.mitec-tapi-monitor` 1.2.0 using the retained MiTeC publisher archives. The System Information eXtra candidate stages only the four reviewed x86/x64 viewer/helper executables; TAPI Monitor stages only `TAPIMon.exe`. Archive and selected-member hashes match the static review. Each candidate has a local version-specific `NeedsReview` record with owner Unassigned. Those markers support owner-specific license administration and do not block package planning, implementation, or technical acceptance preparation.

Focused package and license-plan tests passed 25/25; repository validation passed for 381 operations, eight groups, five profiles and 252 PowerShell files; a later catalog recount corrected the pre-follow-up total to 75 packages (45 pending). Synthetic ZIP tests covered repeated offline staging, owned-file snapshot/removal/recovery and preservation of an unowned note. No publisher executable was run, no host report or identifier was collected, and no TAPI provider, line, call or call history was accessed. No VM, Defender-blocked tool, UAC prompt or Windows state change was involved.

Resolved: source/version/member selection and inert package file-lifecycle preparation. Retired/excluded: none. Partial: neither user-visible application behavior nor a legacy package outcome is accepted. Deferred: System Information eXtra report field/redaction review using synthetic guest data; TAPI behavior against a simulated provider; owner-specific review; and disposable Windows 11 acceptance and recovery. The package outcome was already counted in the remaining estimate, so all five ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured evidence](../archive/evidence/mitec-system-information-tapi-package-candidates-2026-10-23-1218.json), [static review](../archive/evidence/mitec-system-information-tapi-static-review-2026-10-20.json), and [current VM access blocker](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1124.json).

## MiTeC Windows File Analyzer and Icon Explorer package candidates, 2026-10-23

Added unsupported Windows 11 candidates `package.mitec-windows-file-analyzer` 2.10.0 and `package.mitec-icon-explorer` 5.3.0 from the retained MiTeC archives. Archive pins and selected member hashes were rechecked: `WFA.exe` is 2.10.0.0 (ProductVersion 2.0.0.0), and `IconExplorer.exe` is 5.3.0.0 (ProductVersion 5.0.0.0). Both publisher target lists end at Windows 10; `SupportedTargets` therefore remains empty.

Each package has a version-specific local `NeedsReview` record with owner Unassigned. The product pages describe private, educational and non-commercial free use. These local markers support owner-specific use administration and do not block package migration, install planning or acceptance preparation.

Focused portable staging, snapshot, removal and restore fixtures plus package/license-plan regressions passed **112/112** on PowerShell 7.6.5. Repository validation passed for **383 operations, 77 packages (47 pending), eight groups, five profiles and 253 PowerShell files**. No executable ran; no real forensic data was opened, no path was recursively scanned, no icons were extracted, and no VM, Defender-blocked tool or Windows state was touched.

Resolved: exact candidate source/member selection and inert managed-file lifecycle preparation. Retired/excluded: none. Partial: no user-visible behavior or whole legacy outcome is accepted. Deferred: synthetic-only report and icon extraction/collision checks, output cleanup, and Windows 11 lifecycle/recovery acceptance. A full catalog recount found 75 packages/45 pending before this pair, correcting the prior overview's 73/43 count; the current catalog has 77/47. The package estimate remains within **52-67**; all group ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. The 12:26 UTC read-only VM recheck failed CIM access for both RIDE test VMs before checkpoint inspection. See [candidate evidence](../archive/evidence/mitec-file-analyzer-icon-explorer-candidates-2026-10-23-1230.json), [count correction](../archive/evidence/catalog-package-count-reconciliation-2026-10-23-1230.json), [static source review](../archive/evidence/mitec-file-analyzer-icon-explorer-static-review-2026-10-21.json), and [VM access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1226.json).
## MiTeC OLE/COM, Registry Recovery and SMBIOS Explorer candidates, 2026-10-23

Added unsupported Windows 11 package candidates `package.mitec-ole-com-explorer` (selected binary FileVersion 1.4.0.0), `package.mitec-windows-registry-recovery` 3.1.3, and `package.mitec-smbios-explorer` 1.8.0. The OLE/COM product page has no release number; the exact binary version is recorded. The registry archive selects the reviewed x86/x64 viewers; the SMBIOS archive selects the x86/x64 viewers and its distinct x86 helper. All archive and selected-member hashes match retained static evidence.

Each exact version has a local `NeedsReview` record with owner Unassigned. The markers support owner-specific license administration and do not block candidate implementation, package install planning or acceptance preparation. Publisher pages describe current versions and distinct terms; RIDE target support stays empty pending applicable acceptance.

Focused candidate, package-plan and ApplicationPackages suites passed **114/114** on PowerShell 7.6.5. Windows PowerShell 5.1 parser checks passed for the candidate and license tests. Repository validation passed for **386 operations, eight groups, five profiles and 254 PowerShell files**; the full catalog loader reports **80 packages (50 pending)**. No publisher payload ran, no real hive was opened/exported, no COM server was activated, and no firmware/WMI/registry/system API was queried. No VM, Defender-blocked tool, UAC prompt or Windows state change occurred.

Resolved: exact source/member selections and inert file-lifecycle preparation. Retired/excluded: none. Partial: no user-visible product behavior or full legacy outcome accepted. Deferred: a synthetic inert COM/type-library check; offline synthetic registry hives and disposable exports; synthetic SMBIOS file parsing with live sources disabled; and Windows 11 lifecycle/recovery acceptance. The three products remain inside the package estimate, which stays **52-67**; all ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. The repeated 12:26 UTC `Get-VM` checks failed at CIM for both RIDE test VMs before checkpoint inspection. See [candidate evidence](../archive/evidence/mitec-review-data-tools-candidates-2026-10-23-1236.json), [count correction](../archive/evidence/catalog-package-count-reconciliation-2026-10-23-1230.json), [OLE/COM source review](../archive/evidence/mitec-olecom-project-maker-static-review-2026-10-21.json), [Registry Recovery/SMBIOS source review](../archive/evidence/mitec-registry-recovery-smbios-static-review-2026-10-21.json), and [VM access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1226.json).
## MiTeC DFM Editor Delphi variant package candidate, 2026-10-23 12:58 UTC

Added one pinned portable package with explicit `delphi-11` and `delphi-12` variants. The 16,714,229-byte publisher ZIP SHA-256 is `189386a7b43e835c936d0858a7e47d0e7840d0031f991d50f4abc55d391783aa`; all 18 member hashes and PE version resources were recomputed from the retained ZIP. Each selection stages only its own DFM Editor executable and eight matching BPLs: version 8.3.1.0 with the 280 family, or 8.4.0.0 with the 290 family. The default selection is Delphi 12. Both exact versions have local `NeedsReview` markers for owner-specific license administration; these do not block package implementation or install planning.

The new inert fixture verifies both versions, archive/member pins, selected family isolation, repeat staging, ownership, removal and snapshot recovery. No editor, BPL, DFM or PE file was run/opened; no terms were accepted. The first combined test attempt exposed Pester TestRegistry setup denied by host sandbox; after disabling Pester TestRegistry, the DFM variant lifecycle tests passed. The license-review data-driven test exposed that it must select the exact version when both variants have separate records; the corrected DFM variant, explicit install-plan and license-review rerun passed 26/26 on PowerShell 7.6.5 with Pester TestRegistry disabled, and Windows PowerShell 5.1 parsing passed. VM access remains blocked at host CIM inventory, so DFM/PE behavior and Windows 11 acceptance remain deferred.

Resolved: pinned candidate metadata and explicit variant separation. Retired/excluded: none. Partial: package preparation only; no legacy outcome closes. Deferred: synthetic DFM/PE behavior and Windows 11 lifecycle acceptance. Package count increases by one catalog entry, but legacy outcome estimates remain unchanged at 38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196 and rounded 145-200/about 170. See [structured evidence](../archive/evidence/mitec-dfm-editor-candidate-2026-10-23.json).

## MiTeC DFM Editor candidate verification, 2026-10-23 12:58 UTC

The corrected DFM variant, explicit install-plan and license-review focused run passed **26/26** on PowerShell 7.6.5 after disabling Pester TestRegistry, which cannot create its HKCU hive in this sandbox. Windows PowerShell 5.1 parser validation passed. The full package-specific ApplicationPackages.Tests.ps1 container also completed without a failure in the combined run; the single combined-run failure was the license test's former assumption that one product ID returns one version record, and that test now filters the requested exact version. Repository validation passed for **387 operations, 8 groups, 5 profiles and 255 PowerShell files**; the catalog loader reports **81 packages (51 pending)**. No legacy outcome closed. All five estimate ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. Windows acceptance remains deferred while host CIM denies VM inventory. See [structured DFM evidence](../archive/evidence/mitec-dfm-editor-candidate-2026-10-23.json).

## MiTeC EXE Explorer and HexEdit candidate packages, 2026-10-23 13:05 UTC

Added `package.mitec-exe-explorer` 3.7.5 with its exact x86 and x64 executables and `package.mitec-hexedit` 7.1.0 with its exact x86 executable. The archive and selected-member hashes were recomputed from retained publisher ZIPs and match the frozen source review. The current publisher pages list EXE Explorer 3.7.5 and HexEdit 7.1.0, each supporting Windows 11 and Server 2025. Both operations remain unsupported pending RIDE target acceptance, with Windows 11 as a candidate target.

Each exact version has a local `NeedsReview` marker for owner-specific license administration; these markers do not block implementation or install planning. EXE Explorer's synthetic behavior boundary excludes VirusTotal uploads/API keys and requires disposable PE files and isolated export paths. HexEdit's file editing requires disposable copies and exact recovery; its memory/raw-disk features were not accessed. The focused suite passed 27/27 on PowerShell 7.6.5 with Pester TestRegistry disabled. Windows PowerShell 5.1 parsing and repository validation passed (389 operations, 8 groups, 5 profiles, 256 PowerShell files); the catalog loader reports 83 packages/53 pending. No tool ran, no real file was opened, and no VM/Defender/UAC action occurred.

Resolved: exact candidate source/member pins, package planning and inert synthetic lifecycle/recovery coverage. Retired/excluded: none. Partial: no whole legacy outcome closes. Deferred: EXE Explorer synthetic PE/resource viewing and isolated export behavior, HexEdit file edit/compare/recovery behavior, and Windows 11 package acceptance when VM access is available. Estimates remain 38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded 145-200/about 170. See [structured evidence](../archive/evidence/mitec-analysis-tools-candidates-2026-10-23.json), [official EXE Explorer page](https://www.mitec.cz/exe.html), [official HexEdit page](https://www.mitec.cz/wp/mhex/), and [latest VM access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1226.json).

## MiTeC Mail and History Viewer package candidates, 2026-10-23 13:10 UTC

Added pinned portable candidates for Mail Viewer 2.5.1.0, E-mail History Browser 1.2.0, Internet History Browser 2.5.0 and Instant Messaging History Browser 1.2.1. Retained ZIP and selected-member hashes are recorded in the candidate evidence. Each exact version has an owner-specific local `NeedsReview` marker; these records are informational and do not block package implementation or install planning. All four operations remain unsupported pending Windows 11 acceptance.

The focused runner rehashes each retained publisher archive and selected member, checks the plan remains available, and tests repeated staging/removal/snapshot restoration with inert synthetic ZIP contents. It does not launch a viewer or access real mail, attachments, browser profiles, messages, calls or transfers. Product behavior remains deferred to synthetic stores and Windows acceptance remains blocked by unavailable VM/checkpoint access. No legacy outcome closes; package estimates remain 52-67 and all five ranges remain 38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded 145-200/about 170. See [candidate evidence](../archive/evidence/mitec-mail-history-viewer-candidates-2026-10-23.json), [package guidance](../application-packages.md#mitec-mail-and-history-viewer-candidates), and [license guidance](../package-licensing.md#local-usercompany-reviews).

## PSScriptTools batched portable ownership journal, 2026-10-23 13:38 UTC

The portable package handler now commits its complete validated `Installing` ownership/hash journal once before the first staged file copy, then commits `Installed` after copy and obsolete-file cleanup. This replaces the previous growing-manifest rewrite for every member while retaining the full write-ahead recovery set. A 24-member interruption test proves all expected file hashes are journaled before the first copy fails, and original absence is recoverable.

The exact retained PSScriptTools 3.2.0 archive (360 files; SHA-256 `05c86295a0846ae4f51ecfa6f38ef71ba8173be83eb0adc8627525a4c6ee72bd`) passed the full-source install/repeat/remove/snapshot/restore case in 717.12 seconds; the unowned analyst output was preserved. Six other compact inert failure-boundary tests passed 6/6. The broader `ApplicationPackages.Tests.ps1` regression passed 87/87. Windows PowerShell 5.1 parsing passed for the changed module and both test files, and repository validation passed for 393 operations, eight groups, five profiles and 257 PowerShell files. No upstream code was imported or executed.

The PSScriptTools test file was not completed in one uninterrupted run: the expensive full-source case was run separately and passed, then the six boundary cases passed with compact fixtures. Deferred work remains the dependency-present Windows PowerShell 5.1 runtime, exact ThreadJob 2.2.0 acquisition and Windows target acceptance; VM access is still blocked at Hyper-V CIM. No legacy outcome closes, so the package range remains 52-67 and all five estimates remain 38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded 145-200/about 170. See [structured regression evidence](../archive/evidence/psscripttools-batched-portable-journal-regression-2026-10-23.json).

## B10 offline byte-bound preflight description and regression, 2026-10-23 13:45 UTC

Corrected the `RIDE.OfflineBundle` help to describe its current integration: explicit offline `install`/`apply` consume the byte-bound whole-plan preflight, and normal online commands do not. Offline execution, manifest integrity and selected-profile coverage passed **143/143** focused Pester checks with Pester TestRegistry disabled and a repository-local temporary directory. Windows PowerShell 5.1 parsing passed; repository validation passed for 393 operations, eight groups, five profiles and 257 PowerShell files. An initial test attempt using the host's restricted AppData temporary directory failed one staging check on access denied; the repository-local rerun passed all checks.

No legacy product or outcome closed. Disposable disconnected deployment remains deferred: the current read-only inventory query for `RIDE-Win11-Test` and `RIDE-Srv2025Test` failed at Hyper-V CIM access before checkpoint inspection. All five migration estimates remain 38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded 145-200/about 170. See [structured evidence](../archive/evidence/offline-byte-bound-preflight-description-regression-2026-10-23.json).
## B06 client-component captured-state restore recovery gate, 2026-10-23 13:54 UTC

The local OpenSSH Client/Telnet Client lifecycle candidate previously allowed captured-state `Restore` to bypass the user-approved removal gate: restoring a prior OpenSSH `NotPresent` state calls capability removal, and restoring prior Telnet `DisabledWithPayloadRemoved` discards its payload. Neither path has validated matching-source identity/completeness, so both now fail before DISM and retain the saved snapshot. Restoring Telnet to `Disabled` remains supported without removing its payload.

The focused client-component lifecycle and preparation suites passed **42/42** with Pester TestRegistry disabled. Windows PowerShell 5.1 parsing passed for the candidate and both test files; repository validation passed for 393 operations, eight groups, five profiles and 257 PowerShell files. All native calls were mocked. The runner remains unregistered; source identity/completeness, dependency and configured-network-source behavior, exact payload recovery, engine/catalog wiring and disposable Windows acceptance remain open. A follow-up read-only `Get-VM` inventory for both RIDE test VMs at 2026-10-23 13:56 UTC again failed at Hyper-V CIM before checkpoint inspection. No legacy outcome closed; estimates remain 38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded 145-200/about 170. See [structured evidence](../archive/evidence/b06-client-component-restore-recovery-gate-2026-10-23-1354.json).

## Sysinternals license decision reaffirmed, 2026-10-23 14:01 UTC

The user reiterated that RIDE v2's license specialist approved Sysinternals for
RIDE, whose workflow downloads from Microsoft and installs on devices supported
by the user. RIDE does not transfer or publish Sysinternals, and there are no
legal issues or license blockers for this package migration. All ten exact Suite
and individual-product versions remain `Reviewed`; do not reopen this decision
or require another license review. The Defender-detected executables remain
excluded from package selection. The remaining Suite blockers are technical
Windows lifecycle, exact recovery and target acceptance; current VM/checkpoint
access is still unavailable. No legacy outcome closes, so estimates remain
38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded 145-200/about 170.
See [decision evidence](../archive/evidence/sysinternals-license-scope-reaffirmation-2026-10-23-1401.json).
## Sysinternals licensing rationale reaffirmed, 2026-10-23 17:56 UTC

The user clarified that RIDE is a direct download-and-install tool: it obtains
Sysinternals from Microsoft for installation on supported devices and does not
transfer or publish copies. The prior RIDE v2 license-specialist assessment
approved this workflow. The user states there are no legal issues using
Sysinternals in RIDE and directs that generalized or strict redistribution
reasoning must not block package migration. Licensing remains settled; no new
license review or distribution gate applies. Defender-detected files remain
excluded. Technical lifecycle, exact recovery and Windows target acceptance are
still pending because VM/checkpoint access is unavailable. This decision-only
update closes no legacy outcome; estimates remain 38-58 / 52-67 / 19-24 / 25-35 /
8-12, exact 142-196, rounded 145-200/about 170. See [decision evidence](../archive/evidence/sysinternals-license-scope-reaffirmation-2026-10-23-1756.json).

## PSScriptTools complete local source-lifecycle regression, 2026-10-23 14:19 UTC

`tests/PSScriptToolsPackage.Tests.ps1` passed **7/7** in one PowerShell 7.6.5
invocation with Pester 5.7.1, TestRegistry disabled and repository-local
temporary storage. The pinned 360-file PSScriptTools 3.2.0 source passed
install/repeat/remove/snapshot/restore in **706.06 seconds**. Six compact tests
also passed for notices, incomplete payloads, operator modifications, unowned
collisions, changed recovery bytes and prior absence. No upstream script was
imported or executed; the unowned analyst output was preserved.

Resolved: the full local portable lifecycle suite now completes in one run.
Deferred: exact ThreadJob 2.2.0 Gallery acquisition, dependency-present Windows
PowerShell 5.1 runtime acceptance and target VM acceptance while host Hyper-V/CIM
access is denied. Partial: PSScriptTools activation, dependency ownership and the
whole legacy outcome remain open. No legacy outcome closes; estimates remain
38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded 145-200/about 170.
See [structured evidence](../archive/evidence/psscripttools-complete-local-lifecycle-regression-2026-10-23-1419.json).

## B06 LocalSource fail-closed lifecycle guard, 2026-10-23 14:34 UTC

An existing local folder previously passed the lifecycle candidate's LocalSource preflight despite the recorded `SourceValidated = false` status. State-changing LocalSource applies now stop before snapshot creation or DISM until the source can be matched to the target build, edition, architecture, language and required payloads; configured-source fallback remains unverified. Restore to Present from an older LocalSource snapshot is also refused because the saved record cannot prove source identity or completeness. A fresh read-only observation that already matches the desired state may still return NoChange. The unregistered candidate has no supported targets.

Preparation and lifecycle Pester suites passed **43/43** on PowerShell 7.6.5 with TestRegistry disabled and native servicing mocked. Windows PowerShell 5.1 parsing and repository validation passed (393 operations, 8 groups, 5 profiles and 257 PowerShell files). No DISM, VM, Defender or Windows state changed.

Resolved: directory existence or an older snapshot alone no longer permits a state-changing LocalSource operation. Deferred: exact source validation, dependency/configured-source behavior, payload recovery, registration and Windows acceptance. Partial: no component outcome closed. VM acceptance remains blocked by the 14:06 UTC CIM access failure before checkpoint inspection. Estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [component guide](../windows-component-inventory.md), [VM access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1406.json), and [structured regression evidence](../archive/evidence/b06-local-source-validation-guard-regression-2026-10-23-1434.json).

## B06 OpenSSH LocalSource identity preflight, 2026-10-23 14:56 UTC

The unregistered lifecycle candidate now allows LocalSource only for the OpenSSH Client capability. Before apply it requires the exact architecture-specific `OpenSSH-Client-Package` CAB, reads one CBS package identity, matches its architecture and Windows build to the target, and records the source CAB SHA-256. Restore to Present repeats those checks and refuses if the identity or hash changed. Telnet LocalSource remains blocked. The OpenSSH CAB is non-satellite; configured-source fallback is still `NotInspected`, `NetworkBoundaryVerified` remains false, and dependencies, exact payload recovery and Windows behavior are not established.

The focused mocked lifecycle suite passed **18/18** on PowerShell 7.6.5 with Pester TestRegistry disabled. It covers matching-source apply and restore, changed-CAB refusal, build mismatch, missing CAB, Telnet refusal, old unvalidated snapshots and existing removal guards. No DISM, VM, package source or Windows state was used. Resolved: source identity/build/hash preflight and restore revalidation. Deferred: Telnet source validation, configured-source fallback, dependencies, payload recovery, registration and target acceptance. Partial: no B06 legacy outcome closed. VM access remains blocked by the 14:43 UTC CIM denial before checkpoint inspection. Estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [component guide](../windows-component-inventory.md), [VM access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1443.json), and [structured regression evidence](../archive/evidence/b06-openssh-local-source-preflight-2026-10-23-1456.json).

## Sysmon Modular pinned profile artifacts, 2026-10-23

Implemented the user's three requested choices as separate download-only artifacts: Balanced, Balanced with FileDelete and Excludes only. Current upstream documentation identifies them as generated assets in the signed release `configs-a45dedb13a43`; the unversioned assets target Sysmon 15.21, which is pinned in each operation. Resolver checks the release's `SHA256SUMS` record for the selected exact filename and compares downloaded bytes to that digest before retaining them. The release page identifies the tag's commit as GitHub-verified. Upstream states that Balanced omits FileDelete archiving, Balanced with FileDelete enables file archiving, and Excludes only is very verbose; these costs are in catalog descriptions and operator guidance. These artifacts do not install Sysmon or apply a configuration.

Focused mocked resolver/catalog tests passed **4/4**. Catalog export and repository validation passed for **400 operations, 8 groups, 5 profiles and 257 PowerShell files**; Windows PowerShell 5.1 parsing passed for the changed modules and test file. No network artifact, Sysmon service, VM, Defender or Windows state was changed. Resolved: selected profile choices, exact release/target pins and checksum-bound download planning. Retired/excluded: none. Deferred: live release manifest acquisition, retained-file lifecycle and user/VM acceptance; profile application remains separate. Partial: legacy selector now has candidate IDs but no completed source acquisition or runtime acceptance. The migration estimate remains unchanged until the specified acceptance and legacy outcome criteria pass: **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [operator guidance](../application-packages.md#sysmon-modular-configuration-choices), [official release](https://github.com/olafhartong/sysmon-modular/releases/tag/configs-a45dedb13a43) and [structured evidence](../archive/evidence/sysmon-modular-profile-artifacts-2026-10-23.json).

## BloodHound CE 9.8.0 collector version match, 2026-10-23

The official `SpecterOps/BloodHound` v9.8.0 Dockerfile pins its embedded collectors to SharpHound v2.17.0 and AzureHound v3.1.1. It identifies the exact SharpHound Windows x86 ZIP and `.sha256` sidecar; AzureHound assets are checked against their `.sha256` companions before the backend repackages them for its collector API. This establishes the selected matching versions and their publisher asset names. It does not prove local acquisition, lifecycle, actual backend-served bytes or runtime interoperability.

The focused source check passed against the official raw Dockerfile at the immutable v9.8.0 tag and the exact v2.17.0/v3.1.1 license sources. No release ZIP, checksum or executable was acquired; no collector or backend was run. Resolved: backend-to-collector version matching. Deferred: pinned collector catalog candidates, source bytes/sidecar verification, notices and owned portable lifecycle, Windows acceptance and no-collection smoke checks. Backend/container provisioning, WSL/features, credential/data ownership and application remain separate and deferred. No legacy outcome closed; all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [official pinned Dockerfile](https://raw.githubusercontent.com/SpecterOps/BloodHound/v9.8.0/dockerfiles/bloodhound.Dockerfile), [SharpHound v2.17.0](https://github.com/SpecterOps/SharpHound/tree/v2.17.0), [AzureHound v3.1.1](https://github.com/SpecterOps/AzureHound/tree/v3.1.1), and [structured evidence](../archive/evidence/bloodhound-ce-9.8.0-collector-match-2026-10-23.json).

## Microsoft OpenJDK side-by-side compatibility package candidates, 2026-10-23 15:08 UTC

Added pinned x64 MSI candidates for Microsoft Build of OpenJDK 25.0.4.1, 21.0.12.1, 17.0.20.1 and 11.0.32.1. JDK 25 is the default Java package; the three older LTS versions are independent compatibility choices, unrelated to BloodHound. Each MSI installs only `FeatureMain` into a separate major-version directory, preserving `JAVA_HOME`, `PATH` and `.jar` associations. The resolver validates Microsoft's versioned SHA-256 sidecar and binds a returned digest to the exact MSI filename before payload acquisition. Microsoft documents these LTS versions/checksum files and the optional MSI environment/JAR features on its [download](https://learn.microsoft.com/en-us/java/openjdk/download) and [installation](https://learn.microsoft.com/en-us/java/openjdk/install) pages.

The focused mocked provider and catalog checks passed **4/4**. A broader `ApplicationPackages.Tests.ps1` attempt could not complete: the first run was blocked by Pester's TestRegistry plugin trying to write HKCU; with that plugin disabled, unrelated portable lifecycle tests failed because the sandbox denied rename/write under the default temporary directory. The new OpenJDK tests passed. No MSI was downloaded or run, and no VM was accessed. All four candidates remain unsupported with Windows 11 and Server 2025 acceptance pending. No legacy outcome closed; the five ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. Sysinternals remains approved for RIDE direct download/install under the prior v2 specialist assessment; licensing is not a blocker. See [structured candidate evidence](../archive/evidence/microsoft-openjdk-package-candidates-2026-10-23-1508.json).
## Windows 11 and Server 2025 VM access recheck, 2026-10-23 14:43 UTC

Fresh read-only Get-VM queries for RIDE-Win11-Test and RIDE-Srv2025Test both returned Access to a CIM resource was not available to the client before VM/checkpoint inspection. No task submission, host service/controller/WinRM change, elevation prompt, Defender action, guest mutation or Windows-state change occurred. Package, setting and component Windows acceptance remains deferred; independent local preparation may continue. No legacy outcome closed, retired or newly excluded. All five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1443.json).

## BloodHound pinned collector release resolver, 2026-10-23 15:33 UTC

Added exact tagged-release support to the existing GitHub package resolver for the CE 9.8.0-matched SharpHound v2.17.0 and AzureHound v3.1.1 candidates. A package declaration must match the repository, tag, normalized version, exact ZIP filename and `.sha256` sidecar filename. Resolution verifies the GitHub release tag and publisher download URLs, reads one bounded checksum record from the same tag, and retains the checksum URI and digest for byte verification. Anonymous and enrolled PAT metadata paths both support exact tagged endpoints. Catalog validation checks the tag/version/asset/sidecar shape.

The focused provider/catalog regression passed **6/6** on PowerShell 7; the full GitHub authentication suite passed **53/53**. Repository validation passed for **400 operations, 8 groups, 5 profiles and 257 PowerShell files**, and Windows PowerShell 5.1 parsing passed for all five changed PowerShell files. Pester could not be loaded in Windows PowerShell 5.1 because the host AuthorizationManager blocked the module import. Direct requests for both official checksum sidecars failed before HTTP with DNS resolution failure for `github.com`; no archive, notice or executable bytes were acquired. No collector package candidate was added because exact ZIP members remain unknown. No collector or backend was run, and VM access remains a separate acceptance blocker.

Resolved: exact-tag GitHub release and sidecar metadata handling. Retired/excluded: none. Deferred: publisher bytes, checksum verification, exact ZIP-member selection, companion notices, portable lifecycle/recovery, no-collection smoke checks and Windows acceptance. Backend/container, WSL/features and credential/data setup remain separately deferred. No legacy collector outcome closed; estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. Sysinternals' prior RIDE v2 specialist approval for direct download/install remains settled; licensing is not a blocker. See [official CE 9.8.0 Dockerfile](https://raw.githubusercontent.com/SpecterOps/BloodHound/v9.8.0/dockerfiles/bloodhound.Dockerfile), [SharpHound v2.17.0](https://github.com/SpecterOps/SharpHound/tree/v2.17.0), [AzureHound v3.1.1](https://github.com/SpecterOps/AzureHound/tree/v3.1.1), and [structured implementation and blocker evidence](../archive/evidence/bloodhound-pinned-release-provider-2026-10-23.json).

## Microsoft OpenJDK publisher sidecar source recheck, 2026-10-23 15:42 UTC

Microsoft Learn currently lists the exact selected x64 MSI versions and SHA-256 sidecar links for 25.0.4.1, 21.0.12.1, 17.0.20.1 and 11.0.32.1. Its sidecar links resolve to version-specific `download.visualstudio.microsoft.com` URLs; those exact targets are retained in structured evidence. Direct shell requests failed before HTTP because this host could not resolve `aka.ms` or `download.visualstudio.microsoft.com`. The web reader also could not fetch the sidecar files. No MSI bytes or publisher digest were acquired; no third-party digest was substituted and the catalog was not changed.

A fresh read-only Hyper-V query for `RIDE-Win11-Test` and `RIDE-Srv2025Test` again returned CIM access denied before VM/checkpoint inspection. No VM, Windows, Defender or elevation state changed. The new OpenJDK package candidates remain unsupported pending publisher bytes, signature/MSI inspection and Windows 11/Server 2025 install, repeat, uninstall and recovery acceptance. Resolved: current official versioned source-link identities. Retired/excluded: none. Deferred: checksum/MSI acquisition and technical lifecycle/target acceptance. Partial: no OpenJDK legacy outcome closes. All five ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. Sysinternals remains approved for RIDE's direct download-and-install workflow under the prior RIDE v2 specialist review; no license blocker remains. See [Microsoft's current OpenJDK download page](https://learn.microsoft.com/en-us/java/openjdk/download), [structured source and access evidence](../archive/evidence/microsoft-openjdk-sidecar-source-recheck-2026-10-23-1542.json), and [Sysinternals decision](../archive/evidence/sysinternals-license-scope-reaffirmation-2026-10-23-1401.json).

## CCleaner-family current distribution and availability review, 2026-10-23 15:47 UTC

The four products remain independent package outcomes under the accepted installed-primary and publisher-portable-when-available decision. Current publisher sources show CCleaner has installed/offline builds and an official portable ZIP; its advanced-build page says those builds are not for distribution or mirroring. RIDE's selected workflow is direct publisher download and installation for the user, so this wording is not treated as a legal blocker. The publisher announced CCleaner v7.13 on 2026-10-21, while the current page-reader snapshot of the builds page showed v7.11; exact selected installer/portable bytes and version need verification before pinning.

Recuva's current builds page lists a standard installer only and does not expose a version in the retrieved page text. Speccy's official page identifies 1.34.84 (2026-06-22), limits Free/Professional to home use, and its builds page lists a standard installer only. Neither page currently lists a portable build. Do not substitute third-party or self-converted artifacts. Defraggler's builds page lists an installer, while the publisher's 2026-09-11 EOL announcement says the last build shipped in August 2020 and the publisher will no longer distribute, sell or support it. Preserve the legacy product outcome; resolve the page/EOL conflict and obtain publisher-verified bytes before adding new acquisition metadata.

Shell requests for all four official pages failed before HTTP because this host could not resolve `www.ccleaner.com`; the web reader could inspect the published page text, but no local artifact files, exact hashes or signatures were available. No catalog operation was added and no installer ran. Licensing is not a migration blocker; where version-specific owner review applies, record it as informational `NeedsReview` after the exact package identity/version is pinned. The independent scope includes no trial/paid upgrade, no activation change, no automatic cleanup/defragmentation/recovery scan and preservation of existing installations.

Resolved: current publisher distribution and portable-availability evidence for the four products. Retired/excluded: none. Deferred: exact publisher payload/version/hash/signature, Defraggler EOL/page reconciliation, per-product installer and portable lifecycle, privacy/feature verification, and disposable Windows 11/Server acceptance. Partial: no package outcome is complete. All five ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [official CCleaner builds and portable page](https://www.ccleaner.com/ccleaner/builds), [CCleaner v7.13 notice](https://community.ccleaner.com/t/ccleaner-v7-13/167187), [Defraggler EOL notice](https://community.ccleaner.com/t/defraggler-end-of-life/166405), [Recuva builds](https://www.ccleaner.com/recuva/builds), [Speccy product/download page](https://www.ccleaner.com/speccy/download), and [structured evidence](../archive/evidence/ccleaner-family-distribution-source-review-2026-10-23-1547.json).
## MiTeC Structured Storage Viewer portable candidate preparation, 2026-10-23

Added `package.mitec-ssview` as a Windows 11 candidate using the retained
MiTeC `SSView.zip` source. The retained archive length is 3,572,814 bytes and
its SHA-256 still matches the 2026-10-17 inventory. The publisher provides no
digest. Static inventory identifies `SSView.exe` as version 4.1.2.0, x86, with
the recorded member hash; only this executable is selected for staging. The
optional `ZLibCodec.dll`, `ZLibCodec.dpr` source and `test.ss` sample are not
selected, built, loaded or used.

The exact-version checkout-local `NeedsReview` record is informational and does
not block RIDE's direct-download candidate or package planning. MiTeC describes
unregistered use as non-commercial and lists paid license tiers; this record
does not decide owner-specific entitlement. The candidate's `SupportedTargets`
remain empty. The publisher's Windows XP through 11 and Server 2003 through
2025 claims do not establish tested RIDE support.

Resolved: retained archive/member identity, executable architecture/version,
and candidate package metadata. Retired/excluded: none; optional codec, source
and sample are outside this package selection. Deferred: synthetic-only viewer
behavior, byte-exact file recovery, unowned activation/configuration/plugin
preservation, Windows 11 lifecycle acceptance and any separate review before
optional components are selected. No legacy outcome closes; this is partial
candidate preparation. All estimates remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured
evidence](../archive/evidence/mitec-ssview-candidate-preparation-2026-10-23.json),
[terms and targets review](../archive/evidence/mitec-ssview-current-terms-targets-follow-up-2026-10-21.json),
and [portable package behavior](../application-packages.md#mitec-structured-storage-viewer-portable-candidate).

## MiTeC Structured Storage Viewer package lifecycle regression, 2026-10-23 16:17 UTC

Added `tests/MiTeCSSView.Tests.ps1`. The focused Windows PowerShell 7.6.5 / Pester
5.7.1 run passed **2/2**. It checked catalog metadata against the checked-in
source evidence and used an inert ZIP fixture to prove that repeat staging
selects only `SSView.exe`, while snapshot/removal/restore preserves an unowned
user note. The cited candidate-preparation evidence separately rechecked the
retained archive SHA-256 and streamed the selected executable to verify its
length/hash without extracting or executing it. Windows PowerShell 5.1 parser
validation passed. Its Pester suite
could not load because the host AuthorizationManager blocked Pester's format
data and module import before test discovery.

Resolved: focused inert package lifecycle and source-pin regression. Retired or
excluded: none; no tool is executed and the optional codec/source/sample remain
outside the selected members. Partial: candidate package staging/recovery is
covered locally. Deferred: synthetic structured-storage behavior, byte-exact
file recovery, activation/configuration/plugin preservation and native Windows
acceptance on a registered VM. No legacy outcome closes. All estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [structured regression evidence](../archive/evidence/mitec-ssview-package-lifecycle-regression-2026-10-23-1614.json),
[candidate evidence](../archive/evidence/mitec-ssview-candidate-preparation-2026-10-23.json),
and the [focused test](../../tests/MiTeCSSView.Tests.ps1).

## MiTeC Network Scanner portable candidate preparation, 2026-10-23 16:23 UTC

The current [MiTeC product page](https://www.mitec.cz/wp/mns/) identifies
version 6.1.0 dated 2026-04-23, describes a broad multi-threaded discovery and
scan surface, and lists Windows XP-11 and Server 2003-2025. Those are publisher
claims; RIDE target support remains unset. The current [MiTeC support terms](https://www.mitec.cz/wp/support/)
describe unregistered use as non-commercial freeware and separate purchased
license types. An exact-version local `NeedsReview` marker is informational and
does not block direct-download package planning.

The retained 11,317,163-byte `NetScanner.zip` was read without extraction; its
SHA-256 and both executable-member hashes match the frozen evidence. The x86
`NetScanner.exe` and x64 `NetScanner64.exe` report FileVersion 6.1.0.0 and
ProductVersion 6.0.0.0. Added `package.mitec-network-scanner`, with `x64` as
default and an explicit `x86` variant, each selecting only its matching
executable. Both remain pending Windows 11 acceptance with no supported targets.

Resolved: current publisher version/feature/licensing observations and exact
archive/member identity. Retired/excluded: none. Partial: both architecture
variants are pinned package candidates. Deferred: local entitlement
administration, synthetic bounded network-behavior tests, credential/result
privacy, activation/UI and Windows acceptance. No payload was extracted or run;
no network was scanned, no host/directory data queried and VirusTotal was not
used. No legacy outcome closes. All ranges remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [source
and variant evidence](../archive/evidence/mitec-network-scanner-candidate-preparation-2026-10-23-1623.json).

## MiTeC Network Scanner offline lifecycle and review-plan regression, 2026-10-23 16:26 UTC

The self-contained `tests/MiTeCNetworkScanner.Tests.ps1` passed **2/2** on
PowerShell 7.6.5. Both x86 and x64 variants passed offline repeat staging,
selected-member ownership, snapshot, uninstall and restore while preserving an
unowned note. The test uses only inert generated files and checked-in source
pins. `LicenseReviews.Tests.ps1` passed **21/21**, including the pending-package
planning regression with version-specific `NeedsReview` data. Windows
PowerShell 5.1 parser validation passed. No scanner ran and no network activity
occurred. The 16:27 UTC read-only `Get-VM -Name RIDE-Win11-Test` check again
failed with CIM access denied before VM/checkpoint inspection; no elevation or
system state change occurred.

Resolved: offline architecture-specific package lifecycle and informational
license-review planning are tested. Partial: package behavior/recovery is
prepared; no full migration outcome closes. Deferred: actual scanner behavior
on a deliberately isolated owned network, sensitive-result handling and VM
lifecycle acceptance. All ranges remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See [focused
regression evidence](../archive/evidence/mitec-network-scanner-package-regression-2026-10-23-1626.json),
[candidate evidence](../archive/evidence/mitec-network-scanner-candidate-preparation-2026-10-23-1623.json),
and [focused tests](../../tests/MiTeCNetworkScanner.Tests.ps1).

## MiTeC Interbase Query portable candidate preparation, 2026-10-23 16:32 UTC

Added `package.mitec-interbase-query` at version 9.5.0 with x64 and x86
variants, defaulting to x64. Both variants stage only their matching executable
and the seven shared publisher localization files. The retained ZIP digest and
all selected member hashes match the frozen source inventory. FileVersion
9.5.0.0 and ProductVersion 9.0.0.0 remain distinct. The exact-version local
`NeedsReview` record is informational and does not block direct-download package
planning.

Resolved: retained source identity, variant mapping and package-candidate
metadata. Retired or excluded whole legacy outcomes: none. Partial: the package
candidate now represents the Interbase Query product. Deferred: inert offline
staging/recovery regression, client dependency version/bitness, synthetic-only
database behavior, exact database backup/recovery, UI/activation and disposable
Windows 11 acceptance. The product page documents SQL/scripts, user and
privilege management, service controls and data import/export; acceptance must
use synthetic disposable databases and must not connect to real services or
touch real data. No executable, database or service was opened or changed. See
[candidate evidence](../archive/evidence/mitec-interbase-query-candidate-preparation-2026-10-23-1632.json)
and the [publisher product page](https://www.mitec.cz/wp/mibq/).

## MiTeC Interbase Query offline lifecycle regression, 2026-10-23 16:35 UTC

The self-contained `tests/MiTeCInterbaseQuery.Tests.ps1` passed **2/2** on
PowerShell 7.6.5. It checks x86/x64 metadata and repeat offline staging from an
inert ZIP, selecting only one executable plus localization files, then verifies
snapshot, uninstall and restore while preserving an unowned note. The test uses
checked-in source evidence and does not need the ignored retained archive.
No executable or database behavior ran. The read-only 16:35 UTC
`Get-VM -Name RIDE-Win11-Test` query again failed at Hyper-V CIM access before
checkpoint inspection; no elevation or state change occurred.

The license-review planning regression also passed **21/21**; the exact-version
`NeedsReview` record does not remove the package's install plan. Windows
PowerShell 5.1 parser validation passed. See [license-plan evidence](../archive/evidence/mitec-interbase-query-license-plan-regression-2026-10-23-1636.json).

Resolved: candidate metadata, offline architecture selection and local file
recovery. Retired/excluded: none. Partial: package lifecycle is locally covered;
no whole Interbase Query legacy outcome closes. Deferred: synthetic database
behavior and recovery, client dependency details, activation and registered
Windows 11 acceptance. All ranges remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See [focused test
evidence](../archive/evidence/mitec-interbase-query-package-regression-2026-10-23-1634.json),
[candidate evidence](../archive/evidence/mitec-interbase-query-candidate-preparation-2026-10-23-1632.json),
[VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-1635.json),
and [focused tests](../../tests/MiTeCInterbaseQuery.Tests.ps1).

## PSScriptTools current-code offline lifecycle regression, 2026-10-23 16:52 UTC

The complete `tests/PSScriptToolsPackage.Tests.ps1` suite passed **7/7** on
PowerShell 7.6.5 with Pester 5.7.1. The 360-file case generated an inert ZIP
from the reviewed member paths and exercised repeat staging, snapshot,
uninstall and restore, including preservation of unowned analyst output and
refusal of modified owned files. The temporary directory was inside `.local`;
Pester TestRegistry was disabled. No upstream code was imported or run, no
dependency was installed, and no network or Windows product state was used.
Windows PowerShell 5.1 parser checks passed for the portable package module,
both focused package test files and the catalog data file; this is syntax
validation, not dependency-present runtime acceptance.

Resolved: current portable-package code passes the local source-file lifecycle
and recovery suite. Retired/excluded: none. Partial: only local package-file
behavior is covered; no whole PSScriptTools legacy outcome closes. Deferred:
exact ThreadJob 2.2.0 publisher acquisition, dependency-present Windows
PowerShell 5.1 import, Windows PowerShell 7 runtime availability and registered
Windows target acceptance. A fresh 16:47 UTC `RIDE-Win11-Test` inventory query
failed at Hyper-V CIM access before checkpoint inspection; no elevation or
state change occurred. All five ranges remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. No estimate deduction
is justified without runtime/dependency acceptance and whole-outcome
reconciliation. See [test evidence](../archive/evidence/psscripttools-current-local-lifecycle-regression-2026-10-23-1652.json),
[VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-1647.json),
and [focused tests](../../tests/PSScriptToolsPackage.Tests.ps1).

## Microsoft OpenJDK 25 publisher checksum retry, 2026-10-23 16:55 UTC

The current Microsoft Learn download table still lists the pinned 25.0.4.1
Windows x64 MSI and its SHA-256 sidecar. A bounded PowerShell request to the
official `aka.ms` sidecar failed with `No such host is known` before HTTP; the
web reader also could not access the exact Microsoft redirect target. No
sidecar or MSI bytes were retrieved, no package metadata changed, and no
installer ran. This confirms the current source-link identity but closes no
legacy outcome.

Resolved: current official source listing and selected sidecar URL. Retired or
excluded: none. Partial: the four pinned Java candidates remain implemented,
but exact publisher digests and MSI bytes are not local. Deferred: source
acquisition, signature/MSI table inspection, and Windows 11/Server 2025
install, repeat, uninstall and recovery acceptance. All five estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [retry evidence](../archive/evidence/microsoft-openjdk-checksum-retry-2026-10-23-1655.json)
and [Microsoft's current download table](https://learn.microsoft.com/en-us/java/openjdk/download).

## MiTeC Task Manager DeLuxe portable candidate preparation, 2026-10-23 16:59 UTC

Added `package.mitec-task-manager-deluxe` version 5.1.1 with x64 and x86
variants, defaulting to x64. Each stages its matching Task Manager DeLuxe and
Desktop Explorer executable pair from the retained ZIP. The retained archive
hash and all four member hashes match the frozen static review. Task Manager
DeLuxe reports FileVersion 5.1.1.0 and ProductVersion 5.0.0.0; Desktop Explorer
reports 2.0.0.0. The current publisher page lists 5.1.1 dated 2026-09-08 and
describes a portable utility; these page claims do not establish RIDE target
support.

The exact-version local `NeedsReview` marker is informational and does not
block direct-download package planning. The publisher describes process,
service, driver, account, session, network and hardware views, optional controls,
minidumps, CSV export, update checks and VirusTotal links. The candidate stages
files only and launches none of them. Later behavior checks must use a
disposable Windows guest and synthetic process fixtures; process/service
changes, minidumps, account/session/journal export, VirusTotal queries, API keys
and update/network behavior remain out of scope.

Resolved: current version and official source identity, archive/member hashes,
variant mapping and package-candidate metadata. Retired or excluded whole
legacy outcomes: none. Partial: portable package staging is prepared; no whole
Task Manager DeLuxe outcome closes. Deferred: persistence and network behavior,
synthetic process/UI behavior, activation and disposable Windows 11 acceptance.
No payload was extracted or
executed, and no live process, service, account, session, network or reputation
data was queried. See [candidate evidence](../archive/evidence/mitec-task-manager-deluxe-candidate-preparation-2026-10-23-1659.json),
[static behavior review](../archive/evidence/mitec-task-manager-deluxe-static-risk-review-2026-10-21.json),
and the [current publisher page](https://www.mitec.cz/wp/tmx/).

## MiTeC Task Manager DeLuxe offline lifecycle regression, 2026-10-23 17:01 UTC

The self-contained `tests/MiTeCTaskManagerDeluxe.Tests.ps1` passed **2/2** on
PowerShell 7.6.5. It checks x86/x64 catalog selection and repeat offline
staging from inert ZIP fixtures, selecting only the matching executable pair,
then tests snapshot, uninstall and restore while preserving an unowned note.
Windows PowerShell 5.1 parser validation passed for the portable module, test
file and catalog. `LicenseReviews.Tests.ps1` passed **21/21** and confirmed
that all **65** pending package install plans remain available with
version-matched local `NeedsReview` records. No TMX executable, live system
data or network behavior ran. See [license-plan evidence](../archive/evidence/mitec-task-manager-deluxe-license-plan-regression-2026-10-23-1702.json).

Resolved: archive/member identity, x86/x64 candidate mapping and local file
staging/recovery. Retired/excluded: none. Partial: the package lifecycle is
covered, but no whole Task Manager DeLuxe legacy outcome closes. Deferred:
owner-specific review, synthetic process/UI behavior, persistence and network
behavior, activation and Windows acceptance on a disposable guest. All five
estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See [focused regression evidence](../archive/evidence/mitec-task-manager-deluxe-package-regression-2026-10-23-1701.json),
[candidate evidence](../archive/evidence/mitec-task-manager-deluxe-candidate-preparation-2026-10-23-1659.json),
and [focused tests](../../tests/MiTeCTaskManagerDeluxe.Tests.ps1).

## MiTeC UUID, certificate, and mail/history offline lifecycle regression, 2026-10-23 17:07 UTC

The combined focused Pester run passed **18/18** on PowerShell 7.6.5. It
rechecked source and selected-member pins for UUID Generator, both certificate
utilities, Mail Viewer, and three history viewers, then exercised inert
repeat-staging and recovery fixtures. No UUID was read from the host, no
certificate or key was created, and no real mailbox, browser profile or message
store was opened. No payload ran and no network activity occurred.
Windows PowerShell 5.1 parser validation also passed for the package module,
all three focused test files and the catalog data file; this is syntax evidence,
not Windows runtime acceptance.

Resolved: current catalog-to-source and local file lifecycle coverage for these
seven package versions. Retired/excluded: none. Partial: only package file
behavior is covered; no whole legacy product outcomes close. Deferred:
synthetic functional/privacy checks, certificate parsing and generation,
activation and disposable Windows target acceptance. The latest
`RIDE-Win11-Test` inventory query at 17:06 UTC again failed at Hyper-V CIM access
before checkpoint inspection; no elevation or state change occurred. All five
estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See [combined regression evidence](../archive/evidence/mitec-uuid-certificate-mail-history-lifecycle-regression-2026-10-23-1707.json)
and [latest VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-1706.json).

## MiTeC review-data, analysis, historical-file and viewer lifecycle regression, 2026-10-23 17:12 UTC

Four focused package suites passed **32/32** on PowerShell 7.6.5 with Pester 5.7.1 and TestRegistry disabled. The tests rechecked retained pins and exercised synthetic offline staging, explicit install planning, repeat/removal/recovery, and ownership boundaries across MiTeC OLE/COM Explorer, Windows Registry Recovery, SMBIOS Explorer, EXE Explorer, HexEdit, Windows File Analyzer, Icon Explorer, JSON Viewer and XML Viewer variants. They opened no host artifacts, process memory, raw disks, registry hives, firmware reports, certificates, mail stores or browser profiles. Windows PowerShell 5.1 parser validation also passed for the portable package module, all four focused test files and catalog data. No upstream executable, VM, network or Windows state change was used. Windows 11 product behavior and acceptance remain deferred; no legacy outcome closed. Estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured run evidence](../archive/evidence/mitec-review-analysis-history-viewer-lifecycle-regression-2026-10-23-1712.json) and [latest VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-1706.json).
## BloodHound collector and disposable VM source/access recheck, 2026-10-23 17:17 UTC

Read-only `Get-VM` inventory again failed for `RIDE-Win11-Test` and `RIDE-Srv2025Test` at Hyper-V CIM access before either VM or checkpoint state could be inspected. No elevation, controller, guest, Defender, or Windows state was changed.

The official SpecterOps release pages identify BloodHound CE 9.8.0, SharpHound v2.17.0 and AzureHound v3.1.1 with GitHub-verified signed release commits. Exact Windows x86/x64 collector checksum-sidecar requests returned web-reader cache-miss errors. No sidecar or ZIP bytes were acquired, so the existing package candidate remains unchanged and exact payload pins, member inventories, notices and lifecycle checks remain open. This does not add a licensing blocker; local license-review status remains separate from technical package completion.

Resolved: current signed release-tag evidence. Retired/excluded: none. Partial: collector sources are not yet locally verified. Deferred: publisher ZIP/sidecar acquisition, member/notice review, package lifecycle and Windows 11 acceptance. No legacy outcome closed; estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured evidence](../archive/evidence/ride-vm-bloodhound-source-recheck-2026-10-23-1717.json), [BloodHound CE release](https://github.com/SpecterOps/BloodHound/releases/tag/v9.8.0), [SharpHound release](https://github.com/SpecterOps/SharpHound/releases/tag/v2.17.0), and [AzureHound release](https://github.com/SpecterOps/AzureHound/releases/tag/v3.1.1).
## Gpg4win accepted-scope disposition reconciliation, 2026-10-23 17:21 UTC

The install-programs disposition had incorrectly left Gpg4win component and scope choices pending. The 2026-10-12 decision ledger already records the accepted current-user scope, GnuPG command line and Kleopatra only, with Explorer and Outlook integration excluded. The stale disposition now reflects those choices.

Technical gates remain open. The retained 5.1.1 installer matches the publisher SHA-256 and its g10 Code GmbH Authenticode signer reference; the retained source archive matches its published digest. Source inspection shows multiuser support, a required nested GnuPG installer, explicit component sections and outer-uninstaller behavior that queries and invokes registered GnuPG uninstallers. No installer or application ran. Verify that both installer layers honor current-user scope, explicitly include GnuPG/Kleopatra and exclude other integrations, and preserve existing user keys/configuration while handling nested GnuPG ownership and coexistence. Package lifecycle and disposable Windows acceptance remain pending.

Resolved: decision-ledger consistency and accepted component scope. Retired/excluded: none. Partial: Gpg4win remains unimplemented. Deferred: nested scope/component verification, dependency ownership, key/configuration preservation, package lifecycle and Windows 11/Server acceptance. No legacy outcome closed; estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [reconciliation evidence](../archive/evidence/gpg4win-decision-ledger-reconciliation-2026-10-23-1721.json), [confirmed decision](application-review-rounds-2026-10-12.md#confirmed-first-round-choices), and [installed disposition](install-programs-dispositions.md).
## Gpg4win 5.1.1 installer scope and component-control source review, 2026-10-23 17:25 UTC

Rehashed the retained 5.1.1 installer and source archive. The EXE remains 44,831,736 bytes with SHA-256 `ed19c0c89ec42fe32c52a7abd6e3da5f491752700546b9eed7ddf82fd303cddf`; Authenticode is valid for g10 Code GmbH with thumbprint `83CC4E382E5E4AF554C66E429E8F66FFE499910D`. The 270,321,920-byte source archive SHA-256 remains `b486d80ae235dcc1aab72c276291a989bcc1ee947055565f5bae8842cfe8d907`.

Source inspection shows the current user decision is expressible: `inst-sections.nsi` reads optional-component booleans for Kleopatra, Okular, Gpgpass, Outlook JS/COM, Explorer, Paperkey and browser integration from a config file supplied with `/C=<path>`. The outer installer enables the MultiUser command-line mode and explicitly supports user mode. `/MINIMAL=1` is unsuitable because it deselects Kleopatra and selects Paperkey. GnuPG remains a required nested installer. On removal, the outer uninstaller searches both registry views and invokes registered GnuPG uninstallers, so RIDE must detect and refuse unsafe adoption of an unrelated existing GnuPG registration before install or remove. This review did not run the installer or application.

Resolved: current source and publisher pin; explicit GnuPG/Kleopatra selection has a vendor configuration mechanism. Partial: Gpg4win remains unimplemented. Deferred: generate and clean up the explicit component config, prove nested current-user scope, preflight dependency ownership, preserve `%APPDATA%/gnupg` through install/remove/recovery, and complete disposable Windows acceptance. No legacy outcome closed; all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured evidence](../archive/evidence/gpg4win-installer-scope-component-controls-2026-10-23-1725.json), [confirmed scope](application-review-rounds-2026-10-12.md#confirmed-first-round-choices), and [decision-ledger reconciliation](#gpg4win-accepted-scope-disposition-reconciliation-2026-10-23-1721).

## Gpg4win 5.1.1 current-user package candidate implementation, 2026-10-23 17:42 UTC

Added `package.gpg4win` as an unsupported Windows 11 candidate using the retained official 5.1.1 installer, measured SHA-256 and valid g10 Code GmbH Authenticode signature. The package declares the accepted non-elevated current-user workflow, a per-user `Programs/Gpg4win` destination, GnuPG command-line tools plus Kleopatra, and explicit false values for Okular, Gpgpass, GpgOL, GpgEX, Paperkey, browser integration and desktop shortcuts. A Start Menu shortcut remains enabled. The official [system requirements](https://www.gpg4win.org/system-requirements.html) state that Gpg4win 5.x supports 64-bit Windows and Windows 11; no Server target is declared. The publisher's [download page](https://www.gpg4win.org/download.html) publishes the selected release and matching digest, while the official [license page](https://www.gpg4win.org/license.html) documents the GPL-family and bundled component notices. No separate license gate was added.

The package handler now stages its catalog-declared Boolean configuration into a unique ASCII INI file, supplies the exact path to the vendor's `/C=` option, and removes the temporary file after success or failure. Catalog validation restricts configuration names to known Gpg4win settings and requires exactly one path token. Nested GnuPG uninstall registrations block installation unless the exact Gpg4win current-user install is registered at its declared path; the nested sibling registration is accepted only alongside that exact parent registration. Install and removal now refuse to move `%APPDATA%/gnupg` while Kleopatra, GnuPG, gpg-agent, gpgsm or dirmngr is running, then restore the preserved directory after the package process boundary.

The initial focused Gpg4win suite passed **8/8**; after install-time data preservation was added, the focused suite passed **10/10**. The combined ApplicationPackages/Catalog Pester run passed **177** of **178** discovered tests, with zero failures and one test not run; Windows integration and Pester TestRegistry were excluded. Windows PowerShell 5.1 parser checks passed for the two changed modules and new test file. Catalog export and repository validation passed for **405 operations, 8 groups, 5 profiles and 262 PowerShell files**; the catalog now contains **96 packages, 66 pending acceptance**. No installer, GnuPG process, user key/configuration, VM or Defender setting was touched.

A fresh read-only `Get-VM -Name RIDE-Win11-Test` call failed with CIM access denied before VM or checkpoint state could be inspected. Therefore actual outer/nested current-user scope, exact Windows component selection, repeat install, vendor removal, saved-run recovery and synthetic-key-data preservation remain pending. This candidate preparation closes no legacy package outcome; all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured implementation and blocker evidence](../archive/evidence/gpg4win-package-candidate-implementation-2026-10-23-1755.json).

## Gpg4win user-data recovery boundary confirmed, 2026-10-23 17:44 UTC

The user confirmed the accepted non-elevated current-user scope with GnuPG
command-line tools and Kleopatra only, excluding Explorer and Outlook
integration. Preserve any pre-existing `%APPDATA%/gnupg` keys/configuration
through install, removal and recovery; remove only package-owned files and do
not discard that directory. This confirms the implementation boundary without
authorizing access to or changes to real user data.

The unsupported candidate's mocked preservation coverage is in place, but actual
outer/nested installer scope, component selection, coexistence, repeat/remove,
saved-run recovery and target acceptance remain deferred. No legacy outcome
closed. See the [decision ledger](decision-session-2026-10-17.md#gpg4win-user-data-recovery-boundary-confirmation-2026-10-23)
and [candidate evidence](../archive/evidence/gpg4win-package-candidate-implementation-2026-10-23-1755.json).

## Gpg4win install-time user-data preservation implementation, 2026-10-23 17:55 UTC

Applied the user's confirmation that pre-existing `%APPDATA%/gnupg` keys and configuration must survive install, removal and package recovery. `package.gpg4win` now opts into the shared package-data preservation boundary for install as well as removal. The handler refuses to proceed while Kleopatra, GnuPG, gpg-agent, gpgsm or dirmngr is running, moves existing data aside within the same roaming-data directory while the vendor process runs, and restores the original directory on success or failure. If the installer/uninstaller creates a new directory at the original path, it is retained under a unique `.ride-created-*` name before the exact original is restored. The user-data boundary remains limited to this selected package for install; existing package removals retain their prior behavior.

The Gpg4win synthetic suite passes **10/10**, including exact original-data restoration through a mocked install and retention of a simulated installer-created collision. The shared PackageEvidence suite passes **27/27**, including active-process, interrupted-operation and collision behavior. The combined ApplicationPackages/Catalog suite passes **177** of **178** discovered tests with zero failures and one not run. Windows PowerShell 5.1 parsed the two changed modules and three affected test files. Catalog generation and repository validation pass for **405 operations, 8 groups, 5 profiles and 262 PowerShell files**. No real user data, Gpg4win installer, GnuPG process or VM was used.

The latest read-only `Get-VM -Name RIDE-Win11-Test` call again failed with CIM access denied before VM/checkpoint inspection. Native install/repeat/remove/recovery and component visibility remain deferred; no legacy outcome closed, and all estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured implementation and acceptance evidence](../archive/evidence/gpg4win-package-candidate-implementation-2026-10-23-1755.json) and the [user recovery-boundary decision](decision-session-2026-10-17.md#gpg4win-user-data-recovery-boundary-confirmation-2026-10-23).

## Sysinternals migration rationale corrected, 2026-10-23 18:18 UTC

The user clarified that the v2 specialist approval covers RIDE's real workflow:
download Sysinternals directly from Microsoft and install it on supported devices.
RIDE does not publish Sysinternals or create a shared redistribution bundle. The
user states there are no legal issues for this workflow and directs that generalized
redistribution analysis must not block package migration. Treat the ten version
records as `Reviewed`; do not reopen licensing or add a license acceptance gate.
The Defender-detected tools remain excluded separately. Remaining blockers are
technical lifecycle, exact recovery and supported-target acceptance while VM access
is unavailable. This clarification closes no legacy product outcome; estimates are
unchanged. See [dated evidence](../archive/evidence/sysinternals-license-scope-clarification-2026-10-23-1818.json).
## OpenJDK publisher-link and VM access recheck, 2026-10-23 18:21 UTC

Microsoft Learn still lists versioned Windows x64 MSI and SHA-256 sidecar links
for the four selected builds. The browser could resolve the link identities but
could not access redirected sidecar bytes. Do not substitute third-party checksum
values; no MSI or checksum was acquired. Fresh read-only `Get-VM` for
`RIDE-Win11-Test` and `RIDE-Srv2025Test` returned CIM access denied before
checkpoint inspection. No installer, package, VM, Defender or Windows state
changed, and no elevation was requested. Resolved: official versioned source-link
identities. Retired/excluded: none. Deferred: publisher sidecar bytes, MSI
acquisition, technical package lifecycle and Windows 11/Server 2025 acceptance.
Partial: no OpenJDK legacy outcome closed. All five ranges remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[Microsoft's download page](https://learn.microsoft.com/en-us/java/openjdk/download)
and [structured recheck evidence](../archive/evidence/package-source-and-vm-access-recheck-2026-10-23-1821.json).
## Focused package/settings/components local regression, 2026-10-23 18:28 UTC

Six current-code suites passed **204/204** on PowerShell 7.6.5/Pester 5.7.1:
application package handling, package evidence, license review, B06 component
preparation/lifecycle, and the inert E08 password-complexity candidate. Pester's
TestRegistry plugin was disabled and temporary storage was rooted in repository
`.local`. The first invocation used the protected sandbox temp and failed atomic
manifest moves; it was stopped, staged paths were not touched, and the rerun passed.
The test suite retained one test-created Signal data directory under `.local` as
its safety contract requires. No installer, DISM, secedit, VM, Windows policy,
Defender or elevation action occurred.

Resolved: current local regressions pass across the six selected suites. Retired or
excluded: none. Deferred: native package/component/setting lifecycle and recovery,
E08 security-policy isolation and exact rollback, OpenJDK sidecar acquisition, and
Windows 11/Server 2025 acceptance. Partial: no legacy outcome closed; B06/E08 remain
unregistered with no supported targets. Estimates remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured
evidence](../archive/evidence/local-cross-group-package-settings-components-regression-2026-10-23-1828.json).
## Post-regression VM access recheck, 2026-10-23 18:29 UTC

After the 204/204 local regression and repository validation, fresh read-only
`Get-VM` queries for `RIDE-Win11-Test` and `RIDE-Srv2025Test` again returned CIM
access denied before checkpoint inspection. No VM, guest, Defender or Windows
state changed; no elevation requested. Package, setting and component guest
acceptance remains deferred. See [structured VM-access evidence](../archive/evidence/ride-win11-and-server2025-vm-access-recheck-2026-10-23-1829.json).
## PSScriptTools ThreadJob Gallery and VM recheck, 2026-10-23 20:55 UTC

The official Gallery page reconfirms ThreadJob 2.2.0, PowerShell 5.1 minimum,
no package dependencies, and the package's listed license, notices and signature
file. Direct acquisition from the official package API failed before transfer
because this host could not resolve `www.powershellgallery.com`. No package bytes,
hash or local artifact resulted; the module was not installed or imported. A
read-only `Get-VM` call for both test targets again failed at CIM before checkpoint
inspection. Hyper-V Manager UI inspection timed out before returning guest details.
No VM, Defender or Windows state changed. Resolved: publisher package metadata.
Deferred: artifact verification, WinPS 5.1 dependency and PowerShell 7.6 built-in
module probes, and guest acceptance. Partial: no legacy outcome closed. See the
[Gallery metadata and transfer evidence](../archive/evidence/psscripttools-threadjob-gallery-vm-recheck-2026-10-23-2055.json).

## FTK Imager InstallShield bundle static recheck, 2026-10-24 03:21 UTC

The retained official 8.3.0.27 ZIP still matches its recorded SHA-256. 7-Zip
extracted the setup launcher's PE sections and resources as data, but its 228 MB
`[0]` payload was opaque to archive listing; no MSI/CAB package layout or
documented prerequisite contract was exposed. The main setup and bundled
CodeMeter Runtime remain separately signed executables. No silent switch,
prerequisite behavior, service/driver changes, reboot behavior, or removal
semantics were inferred. No candidate was added because the current generic EXE
package contract cannot prove or recover this multi-component install. This is a
technical integration gap, not a license blocker. No installer/product/VM ran.
Continue FTK source preparation once a documented supported install path or a
reproducible package layout can be verified. See [structured static evidence](../archive/evidence/ftk-imager-static-bundle-recheck-2026-10-24-0321.json).

## B10 offline execution current-source regression, 2026-10-24 03:29 UTC

The current byte-bound selected-profile preflight and offline `install`/`apply`
dispatch passed **100/100** focused Pester checks across
`OfflineExecution.Tests.ps1` and `OfflineProfileCoverage.Tests.ps1` on PowerShell
7.6.5/Pester 5.7.1, with TestRegistry disabled and temporary files under `.local`.
The tests cover whole-plan coverage before handler dispatch, target/source/dependency
refusal and no-network-fallback boundaries, plus hash-bound portable/EXE/MSI
fixtures. No real deployment, installer, VM, or Windows state change occurred.
This verifies local mocked gate behavior; offline media, installer activation and
disposable-target recovery remain deferred. No legacy outcome closes. See
[structured regression evidence](../archive/evidence/b10-offline-execution-current-source-regression-2026-10-24-0329.json).
## CCleaner family official-source and license-scope recheck, 2026-10-24 03:16 UTC

The official version history lists CCleaner v7.13.1573 (2026-10-21), while the official builds page still displayed v7.12.1526. The publisher portable link resolves to `https://download.ccleaner.com/portable/ccsetup641.zip`; official history lists portable-era v6.41.11567 (2026-06-23). Direct acquisition failed before transfer because this host cannot resolve `download.ccleaner.com`; no bytes, digest, or archive member list are available. Recuva v1.55.133 and Speccy 1.34.84 are identified by official pages as home-use-only, and their builds pages list standard installers only. Defraggler's stale installer listing versus the publisher EOL notice remains unresolved.

The publisher EULA says CCleaner Free is licensed for personal, noncommercial use and restricts resale/further distribution. This requires an exact-version owner-specific `NeedsReview` record when a catalog package identity is registered. It does not impose a blanket RIDE license gate: RIDE's intended flow is direct publisher download for installation on the user's device, with no RIDE publication or transfer of copies. Preserve product outcomes and continue package preparation; the remaining acquisition blocker is unavailable exact bytes and package-member inventory. No catalog candidate or installer was added/run. No legacy outcome closed; all estimates remain unchanged. See [structured source and license evidence](../archive/evidence/ccleaner-family-source-recheck-2026-10-24-0316.json).

## B06 client-component current-source regression, 2026-10-24 03:30 UTC

`ClientComponentPreparation.Tests.ps1` and `ClientComponentLifecycle.Tests.ps1`
passed **47/47** on PowerShell 7.6.5/Pester 5.7.1 with TestRegistry disabled and
workspace-local temporary storage. The mocked suites cover explicit Online versus
LocalSource preparation, OpenSSH Client CAB identity/architecture/build checks,
`LimitAccess`, the unsupported Telnet LocalSource path, guarded removal/recovery,
and LocalSource revalidation before restoring Present. DISM remained mocked; no
VM or Windows state changed. This verifies local candidate behavior only. The
component remains unregistered and unsupported pending complete Telnet source
requirements, network/source proof and disposable Windows 11 acceptance. No legacy
outcome closed. See [structured regression evidence](../archive/evidence/b06-client-components-current-source-regression-2026-10-24-0330.json).
## Task Manager TMOG free-edition package candidate, 2026-10-24 03:45 UTC

Prepared `package.tmog` for the user-selected optional Windows free edition.
The current official release manifest identifies marketing version 1.0.1, build 0,
x64, its exact versioned installer URI and SHA-256. The retained 7,385,192-byte
installer matches that digest; Authenticode verifies the David Plummer publisher
signature (thumbprint `C1447E88A95D3589F860E4A50B96D8F23C9C2F8F`). Static setup
metadata identifies Inno Setup 6.7.0 and product file version 1.0.1.0. The member
list includes `TMOG.scr` in both application and system destinations, the embedded
license, and third-party notices. The installer and TMOG application were not run.

The package is a Windows 11 candidate with no supported targets pending native
install/repeat/uninstall, exact recovery, and screensaver-effect acceptance. The
exact-version local store row is `NeedsReview`/Unassigned because the bundled free
license is personal-use scoped and calls itself a release-candidate document
requiring publisher approval before public distribution. This informational mark
does not block RIDE direct-download/install planning. No PRO activation,
screensaver selection, installer, VM, or Windows state change occurred.

Resolved: exact publisher artifact/version/hash/signature and candidate metadata.
Retired/excluded: none. Deferred: real installer lifecycle, installed-state
detection, exact recovery, screensaver controls and Windows 11 acceptance. Partial:
the legacy TMOG install/remove outcome remains open. All estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [candidate evidence](../archive/evidence/tmog-package-candidate-2026-10-24-0345.json),
[operator guidance](../application-packages.md#task-manager-tmog-free-edition-candidate),
and the [publisher release notes](https://tmog.org/rtm/release-notes.html).

## Task Manager TMOG candidate focused regression, 2026-10-24 03:50 UTC

The selected TMOG catalog pin and informational `NeedsReview` planning checks
passed 2/2. Repository validation passed for 406 operations, 8 groups, 5 profiles
and 264 PowerShell files; the catalog contains 97 packages, 67 pending acceptance.
A broader catalog Pester run encountered sandbox-denied HKCU access in a registry
snapshot test and was stopped without a final suite summary. No installer or VM ran.

Resolved: candidate metadata and informational review-plan behavior. Retired,
excluded and legacy outcomes closed: none. Deferred: actual install/repeat/remove,
exact recovery, screensaver behavior and Windows 11 acceptance. Partial: the
candidate has no supported target. All five estimates remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[focused regression evidence](../archive/evidence/tmog-focused-regression-2026-10-24-0350.json)
and [candidate evidence](../archive/evidence/tmog-package-candidate-2026-10-24-0345.json).


## Python RIDE-managed runtime selection reaffirmed, 2026-10-24

The user selected RIDE-managed runtime selection, reaffirming explicit preparation of selected pinned runtimes, disabled implicit downloads, explicit-only online acquisition and separate updates. Existing command resolution and file associations remain preserved by default; RIDE uses the explicitly selected interpreter. Manager-managed runtimes remain per-user even when the manager MSI is machine-wide.

No runtime or Windows state changed. Exact release pins, architecture, installer controls, offline preparation, launcher coexistence, recovery and disposable-target acceptance remain open. No legacy outcome closes. See the [decision record](decision-session-2026-10-17.md#python-ride-managed-runtime-selection-reaffirmed-2026-10-24).

## Python manager and runtime sources, 2026-10-24 03:55 UTC

Official Python release pages identify install manager 26.4 (2026-10-09), current
CPython 3.15.1, 3.14.9 and 3.13.17. Their manifests provide exact standard
PythonCore tags, architecture-specific runtime ZIP URLs and publisher SHA-256
values. The exact values and evidence limits are in the [source record](../archive/evidence/python-managed-runtime-source-review-2026-10-24-0355.json).

The manager supports the accepted policy mechanically: set per-user
`automatic_install=false`, install explicit version tags, prepare a local index
with `py install --download`, and use `--source=<local index>` for offline install.
Important integration behavior remains: the manager automatically updates within
a day of each release; its MSI is machine-only and attempts to change system PATH;
all managed runtimes remain per-user; Store and python.org MSIX variants cannot
coexist; and command aliases can conflict with existing Python launchers. Source
hashes were read from publisher pages/manifests but no local artifact bytes were
acquired, so they are not yet rechecked against downloads. No package candidate,
runtime, configuration or Windows state changed.

Resolved: exact current publisher release and runtime-manifest source identities.
Retired/excluded and legacy outcomes closed: none. Deferred: choose and pin the
supported release/architecture set, acquire and rehash artifacts, model the manager
and reversible per-user policy configuration, preserve launcher behavior, define
manager auto-update handling, and complete offline/lifecycle/recovery acceptance.
At 03:55, no Python manager/runtime package candidate existed and no legacy
outcome closed. All estimates remained **38-58 / 52-67 / 19-24 / 25-35 / 8-12**,
exact **142-196**, rounded **145-200/about 170**.

## Python manager no-implicit-install setting candidate, 2026-10-24 04:04 UTC

Added `windows.python-manager-automatic-install` as a user-scoped registry-backed
environment setting. `Disabled` stores the string `false` under the current
user's `HKCU:\Environment\PYTHON_MANAGER_AUTOMATIC_INSTALL`; `WindowsDefault`
removes the override. It uses the existing exact saved-run registry lifecycle.
The setting does not install a manager/runtime or alter PATH/aliases, explicit
`py install` commands, manager self-updating, or already-running shell
environments. The operation has no supported targets until native behavior and
propagation are accepted.

The focused catalog metadata/plan test passed 1/1. Repository validation passed
with 407 operations, 8 groups, 5 profiles and 264 PowerShell files (97 packages,
67 pending). No registry value was written and no manager, runtime or VM ran.

Resolved: declarative policy-setting candidate and exact restore metadata.
Retired, excluded and legacy outcomes closed: none. Deferred: native environment
propagation, Python manager consumption, exact version/runtime acquisition,
offline-index ownership, launcher conflicts and VM lifecycle/recovery acceptance.
Partial: `InstallPython` has a no-implicit-install setting candidate but still no
manager/runtime package candidate or complete lifecycle. All five estimates
remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [implementation evidence](../archive/evidence/python-manager-auto-install-setting-implementation-2026-10-24-0404.json).

## Zimmerman and Arsenal scope reconciliation, 2026-10-24

The user selected Zimmerman for focused review, then selected JoeWare as the next
System Tools family later the same day. JoeWare supersedes Zimmerman for ordering
only; the accepted Zimmerman 26-member list is unchanged. After the JoeWare
review, continue Zimmerman source/helper validation, pinned artifact provenance
and updater integration. No additional Zimmerman member was selected. See the
[current priority record](decision-session-2026-10-17.md#joeware-product-review-priority-2026-10-24).

Arsenal scope now includes all publisher products for which a free-use scenario
is available, including products that also offer paid editions. Exclude only
licensed-only products. The original eight accepted products remain in scope;
the additional product inventory, current terms, artifacts, dependencies and
recovery must be reviewed individually. MEGAcmd remains separately deferred
unless an approved source requires it or it is independently selected. This
scope does not authorize activation, driver changes, AV exceptions or forensic
execution. No product was acquired or installed. See the [authoritative
decision](decision-session-2026-10-17.md#zimmerman-arsenal-and-openssh-server-scope-decisions-2026-10-24).

## KAPE Defender compatibility and exclusion decision, 2026-10-24 04:01 UTC

The user requested official KAPE guidance and user reports. CISA's collection
procedure says responders should disable antivirus or host-protection controls
only if they prevent KAPE from executing from removable media, then re-enable
them afterward. This establishes a documented compatibility risk for that
workflow, not a KAPE-specific Microsoft Defender malware verdict. Kroll's
KAPEDocs FAQ does not describe a Defender false positive. The reviewed user
report for KAPE 1.3.0.2 in Microsoft Defender for Endpoint Live Response is a
module-validation failure because `Export Format` is missing; it is not an
antivirus detection or quarantine report.

The user authorized a Defender exclusion limited to KAPE's dedicated install
directory, with prior-state capture and removal only of the exclusion added by
RIDE. Defer individual-file exclusions to v3.1. Do not exclude the shared tools
root, `C:\Tools`, Downloads or other packages, and do not create per-file allow
actions. The decision does not classify KAPE or any bundled file as safe from
Defender detection. The directory exclusion covers Defender Antivirus scanning
of KAPE's installed directory only; it does not bypass DLP, removable-media
controls, other Defender for Endpoint protections, tamper protection, or
organization-managed policy. Record any such acceptance blocker without
broadening the exclusion. No Defender setting, package or Windows state changed.

Resolved: exclusion scope and individual-file deferral. Retired/excluded: none.
Deferred: exact publisher artifact/source, pinned definition inventory and
dependency checks, managed-file ownership, lifecycle and disposable Windows acceptance. No KAPE legacy outcome
closes. See the [decision ledger](decision-session-2026-10-17.md#kape-defender-compatibility-and-exclusion-decision-2026-10-24),
[CISA KAPE procedure](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/2c5011c),
[KAPEDocs FAQ](https://github.com/EricZimmerman/KapeDocs/blob/master/Pages/50-Frequently-asked-questions.md),
[user MDE Live Response report](https://github.com/EricZimmerman/KapeFiles/issues/1099),
and [Microsoft exclusion guidance](https://learn.microsoft.com/en-us/defender-endpoint/navigate-defender-endpoint-antivirus-exclusions).

## Sysinternals license disposition reaffirmed, 2026-10-24 04:05 UTC

The user reaffirmed that the RIDE v2 license specialist approved Sysinternals
for RIDE's direct Microsoft download-and-install workflow. RIDE does not transfer
or publish Sysinternals, and the user states there are no legal issues in this
scope. The prior specialist approval and user direction govern; strict generalized
redistribution reasoning is not a package-migration blocker and no new license
review gate applies. Defender-detected tools remain excluded separately. Remaining
Sysinternals work is technical lifecycle, exact recovery and Windows target
acceptance, currently deferred by VM/checkpoint access. No additional legacy
outcome closed; all five ranges remain 38-58 / 52-67 / 19-24 / 25-35 / 8-12,
exact 142-196, rounded 145-200/about 170. See [decision evidence](../archive/evidence/sysinternals-approval-reaffirmation-2026-10-24-0405.json).

## Sysinternals migration scope reaffirmed, 2026-10-24 04:19 UTC

The user reiterates that the prior RIDE v2 license-specialist assessment approved
Sysinternals for RIDE. RIDE is a direct download-and-install tool in this workflow;
it does not transfer or publish Sysinternals. The user's determination that there
are no legal issues governs this migration. Do not use generalized redistribution
analysis to block package migration or require another license review. Defender-
detected tools remain excluded for the separate security reason. The only
remaining Sysinternals gates are technical lifecycle, exact recovery and Windows
target acceptance; VM/checkpoint access is currently unavailable. No additional
legacy outcome closed and estimates remain settings 38-58, packages 52-67,
components 19-24, files/assets 25-35, maintenance 8-12; exact 142-196, rounded
145-200/about 170. See [current decision evidence](../archive/evidence/sysinternals-approval-reaffirmation-2026-10-24-0419.json).

## Catalog-driven package prerequisites approved for v3, 2026-10-24

The user approved catalog-driven prerequisite installation as v3 scope after
reviewing the ImageMagick/Visual C++ runtime dependency. The implementation
should expand a package's declared prerequisite closure into normal install and
profile plans, order prerequisites before consumers, deduplicate shared packages,
and display each dependency and reason in preview. Each package remains a normal
catalog operation with its own `ShouldProcess`, source/evidence, captured state,
and partial-failure reporting. Existing offline bundle dependency closure should
reuse the same declaration and ordering.

Extend `PrerequisitePackageId` to support both executable and system-DLL/version
requirements. Version inspection must distinguish a sufficient installed
runtime from an absent or outdated one; an older installed runtime must not be
reported as absent because that could cause unsafe restore/removal behavior.
Represent an in-place runtime update explicitly and capture the prior version.
Where Microsoft servicing cannot restore the prior version exactly, tell the
operator and retain the working shared runtime during compensation. Removing a
consumer leaves the runtime installed; explicit removal of a runtime is refused
while any catalog-tracked dependent package needs it.

ImageMagick Q16 is the first consumer: it needs x64 v14 runtime with
`vcomp140.dll` at version 14.50.35710.0 or later. The v14 package candidate
currently has no supported target and cannot be selected for apply until its
RIDE-managed lifecycle is accepted. Catalog-driven prerequisite planning,
version-aware shared-runtime recovery, dependent-removal protection and offline
ordering are implemented. Focused package planning and offline regressions passed
244/244; the latest consumer-linked artifact-edge regressions passed 101/101.
Windows acceptance remains: install/repeat/remove and recovery on the disposable
Windows 11 VM, followed by separate Server acceptance before declaring Server
support.

Resolved: v3 scope, acceptance contract, prerequisite-plan expansion, ordering,
version checks, shared-runtime recovery guard, dependent-removal protection and
offline closure. Deferred: RIDE-managed Visual C++ v14 runtime VM lifecycle and
target acceptance. ImageMagick's DLL-version preflight is accepted, while full
runtime-dependent activation remains gated on that package acceptance. No
package/legacy outcome is closed and all five estimates remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See the
[authoritative scope decision](decision-session-2026-10-17.md#catalog-driven-package-prerequisites-2026-10-24),
[prerequisite regression evidence](../archive/evidence/offline-catalog-prerequisite-artifact-edge-regression-2026-10-24-0538.json),
[runtime planning regression evidence](../archive/evidence/vcredist-prerequisite-regression-2026-10-24-0542.json),
and [active acceptance queue](../../TODO.md#migration-closure-queue).

## JoeWare current publisher source recheck, 2026-10-24 04:08 UTC

The official JoeWare free-tools index still lists the frozen 41-member
collection. The official AdFind and AdMod pages and the publisher's versions
file agree on AdFind 1.64.00 and AdMod 1.29.00, both dated 2026-06-08. The
versions file itself still says `Updated: 2023.05.06` at its header while
containing those newer rows; treat the per-product rows and current product pages
as the version evidence, not that global header. AdFind's page continues to
describe publisher-observed AV/PUP blocking and a password-protected EXE ZIP with
an unprotected `password.txt`. This is specific to AdFind, not evidence for all
JoeWare products or a false-positive determination. AdMod warns that its
directory modifications can be dangerous; any later functional acceptance must
use an isolated owned directory fixture, never a real directory.

The official versions file still lists `rdp-sec-check` as 01.00.00 dated
2011-02-11, while its product page and usage page identify 0.9-beta / JoeWare
V02.00.00 dated 2014-11-17. The current publisher pages therefore reconfirm the
known mismatch but do not resolve which archive bytes the old list digests
identify. The product page describes GPLv2 Perl source in its ZIP, Portcullis
attribution and an embedded PerlApp executable. Its usage page documents outbound
RDP endpoint checks; do not probe a real endpoint during source review.

Artifact identity remains incomplete across the collection: the pages expose
download forms rather than stable versioned payload URLs, the publisher's
versions file supplies MD5/SHA-1 values but no SHA-256, and no download form was
submitted. No archive was acquired, no digest was locally verified, no tool was
run and no Defender exclusion or setting changed. AdFind/AdMod current version
identity is resolved; exact package bytes and the RDP list/archive mapping remain
deferred. The user's complete JoeWare collection selection and dedicated-folder
exclusion decision remain unchanged; licensing is not a blocker for the
publisher-approved internal direct-download/install workflow. Defender-blocked
AdFind remains excluded from selection/execution until its separate acceptance
blocker is addressed.

Resolved: current publisher page/version-list agreement for AdFind and AdMod;
current 41-name scope reconfirmed. Retired: none. Excluded: Defender-blocked
AdFind remains excluded from execution/selection. Deferred: exact publisher
payload bytes/SHA-256 pins, resolution of the `rdp-sec-check` mismatch, product
file inventories and individual technical acceptance. Partial: no JoeWare legacy
outcome closes. All five ranges remain settings 38-58, packages 52-67,
components 19-24, files/assets 25-35, maintenance 8-12; exact 142-196, rounded
145-200/about 170. See the [publisher index](https://joeware.net/freetools/),
[publisher versions file](https://joeware.net/freetools/versions.txt),
[AdFind](https://www.joeware.net/freetools/tools/adfind/index.htm),
[AdMod](https://joeware.net/freetools/tools/admod/index.htm),
[rdp-sec-check](https://www.joeware.net/freetools/tools/rdp-sec-check/index.htm),
[usage](https://www.joeware.net/freetools/tools/rdp-sec-check/usage.htm), and
[structured evidence](../archive/evidence/joeware-current-source-review-2026-10-24-0408.json).

## OpenSSH Server current Microsoft behavior review, 2026-10-24 04:12 UTC

Microsoft identifies `OpenSSH.Server~~~~0.0.1.0` as a Windows capability and
states that Server 2025 includes OpenSSH by default. Installing the capability
creates and enables `OpenSSH-Server-In-TCP`, allowing inbound TCP port 22;
service activation is a separate step. Starting `sshd` for the first time
generates host keys under `%ProgramData%\ssh` and creates the default
`sshd_config` if absent. Disabling the service and disabling the firewall rule
are separate from capability removal.

Implementation contract: keep the Server outcome distinct from OpenSSH Client,
individually selected and off by default. A present-capability install must not
start or auto-enable the service or leave a newly created inbound rule enabled.
Capture service state and exact firewall rule state independently; preserve any
pre-existing values and refuse removal when the rule or service has drifted.
Do not copy private host keys into snapshots or delete existing keys/config as
generic cleanup. Require exact matching recovery source and treat Windows
Server 2025's preinstalled capability as an observed no-op, not a profile
selection. The unregistered `RIDE.OpenSshServerObservation.psm1` candidate now
captures the capability, `sshd` service, built-in firewall rule and bounded
direct-child `%ProgramData%\ssh` file metadata/hashes separately. It does not
return private-key bytes and always reports `ReadyForMutation=false` and
`RecoverySupported=false`.

The read-only recheck of `RIDE-Win11-Test` and `RIDE-Srv2025Test` again failed at
Hyper-V CIM before VM or checkpoint inspection. No elevation was requested and
no VM or Windows state changed. Resolved: current Microsoft identity, default
installation behavior, firewall side effect and first-start data behavior.
Retired/excluded: none. Deferred: exact service/firewall/file inventory,
matching FoD source/recovery, guarded lifecycle implementation, and native
Windows 11/Server 2025 acceptance. Partial: no component or legacy outcome
closes. All five ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**142-196**, rounded **145-200/about 170**. See [Microsoft installation
guidance](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse),
[configuration guidance](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration),
[host-key guidance](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement),
[VM access evidence](../archive/evidence/openssh-server-current-source-review-2026-10-24-0412.json)
and [the operator inventory guide](../windows-component-inventory.md#openssh-server-component-boundary).

The read-only observer candidate is isolated from the catalog and every native
provider is mocked in its local regression. `OpenSshServerObservation.Tests.ps1`
passed **4/4** on PowerShell 7.6.5/Pester 5.7.1 with Pester's TestRegistry plugin
disabled after the default plugin setup failed before test execution on denied
HKCU registry access. Windows PowerShell 5.1 parsed both new files, and repository
validation passed for 407 operations, 8 groups, 5 profiles and 266 PowerShell
files. No service, firewall, host-key/configuration file, VM or Windows state was
read or changed during these mocked checks. Resolved: bounded read-only observation
and target mismatch/provider-failure tests. Deferred: write lifecycle, source and
exact recovery validation, catalog/profile integration, and Windows 11/Server
2025 acceptance. No legacy component outcome closes; all five estimates remain
unchanged. See [observer evidence](../archive/evidence/openssh-server-observation-candidate-2026-10-24-0413.json).

## QEMU guest-integration validation environments selected, 2026-10-24

The user selected recent 2026H2 Fedora 44, Debian and Ubuntu environments for
QEMU/GNOME Boxes guest-integration verification. Before acceptance, record the
exact Debian and Ubuntu release identifiers and the GNOME Boxes build used; the
user selected release families/current versions, not a specific Boxes build.
This does not establish compatibility or Linux support for RIDE. The matching
Windows guest and its device set still determine which VirtIO/SPICE components
are required; optional SPICE WebDAV remains separate for folder sharing. No
payload, package, VM or guest behavior was accepted by this scope decision.
Estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See the [decision record](decision-session-2026-10-17.md#hash-submenu-package-requirements-and-qemu-validation-targets-2026-10-24)
and [QEMU source review](remaining-migrations-follow-up.md#qemu-guest-integration-source-review-2026-10-22).

## Phoenix dependency gate and ImageMagick static variant reaffirmed, 2026-10-24

The user decided to defer any Phoenix .NET prerequisite until evidence proves
that the MSI requires it. If established, add the exact requirement using the
catalog-driven v3 prerequisite support. The MSI's .NET 2.0.50727 launch
condition remains unexplained; do not substitute .NET Framework 3.5 without
evidence. Matching Windows build, servicing source and recovery checks remain
separate acceptance gates.

The user reaffirmed the static x64 Q16 ImageMagick portable candidate. Its
Windows 11 package lifecycle and bounded feature behavior already passed on the
disposable guest; no Server support is inferred. The separately managed x64
Visual C++ v14 prerequisite remains a candidate pending its own lifecycle and
recovery acceptance. These choices close no additional legacy outcome and do
not change estimates: **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See the [decision record](decision-session-2026-10-17.md#phoenix-prerequisite-evidence-and-imagemagick-variant-2026-10-24),
[Phoenix static review](#ntcore-phoenix-protector-custom-action-identity-and-license-follow-up-2026-10-21),
and [ImageMagick Windows 11 acceptance](../archive/evidence/imagemagick-q16-win11-acceptance-2026-10-23.json).

## ImageMagick Q16 versioned runtime preflight and Windows 11 rerun, 2026-10-24 04:25 UTC

The protected Windows 11 controller ran ImageMagick batch `003f55dd7c964d27815ed6f3dea9bf9f` on build 26300 using the current working-tree source. The scenario passed 1/1 with lifecycle recovery and bounded functional acceptance passed. It installed the official Microsoft x64 v14 redistributable in the disposable guest; the signed `System32/vcomp140.dll` reported version 14.51.36247.0, above the catalogued 14.50.35710.0 minimum. ImageMagick encoded and identified only a generated 1x1 PNG. No user image was opened. Controller cleanup completed as `ResetAndOff`, with no cleanup, collection or export error. The runner reported preserving a modified managed `magick.exe` during its refusal/preservation checks.

This confirms the ImageMagick installed-file version preflight and package lifecycle with a sufficient runtime present. The RIDE-managed `package.vcredist-v14-x64` lifecycle was `NotSelected`; this run does not test catalog-driven prerequisite plan expansion, runtime update/recovery, or dependency removal protection. It also does not establish activation or Server support. No additional legacy outcome closed; all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See the [structured run evidence](../archive/evidence/imagemagick-q16-versioned-prerequisite-win11-2026-10-24.json) and the [approved v3 prerequisite scope](#catalog-driven-package-prerequisites-approved-for-v3-2026-10-24).

## OpenSSH Server observation local regression follow-up, 2026-10-24 04:24 UTC

Expanded the isolated provider coverage for the unregistered read-only observer.
Focused Pester passed **7/7** on PowerShell 7.6.5/Pester 5.7.1 with TestRegistry
disabled. PowerShell parsing and repository validation passed for 407 operations,
8 groups, 5 profiles and 266 PowerShell files. No native component, service,
firewall, server-data file, VM or Windows state was accessed or changed.
Resolved: expanded current-source mock coverage for target mismatch, provider
failure, capability/service separation, exact capability identity and bounded
synthetic file hashing. Retired/excluded: none. Deferred: guarded lifecycle,
exact source/recovery, catalog integration and Windows 11/Server 2025 acceptance;
VM access remains CIM-denied. Partial: no legacy component outcome closes. All
five ranges remain 38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded
145-200/about 170. See [structured evidence](../archive/evidence/openssh-server-observation-follow-up-2026-10-24-0424.json).


## Package-scoped Defender exclusions and deferred YARA/Sysmon work, 2026-10-24

The user approved reviewed, package/version-specific Defender exclusions only
for selected packages' RIDE-managed install directories. Capture the exact
path's prior membership and remove it on package removal only if RIDE introduced
the exclusion. Preserve pre-existing exclusions and report the exact package,
version, path and reason. Do not exclude shared roots, `C:\Tools`, Downloads or
individual files. NirSoft per-file handling remains deferred to v3.1; the four
reported alerts remain unclassified, subject to manual review, and no quarantined
file is restored or re-extracted by this decision. This supersedes the earlier
NirSoft no-exclusion direction for reviewed package directories only.

Classic YARA compatibility and `GetSysmonOlafXML` remain deferred, superseding
the 2026-10-23 selection of three Sysmon Modular profiles for active migration.
Keep YARA-X as the standalone default; do not advance classic-YARA acquisition or
implementation, or Sysmon Olaf acquisition/application under the earlier profile
selection. No catalog, Defender, package or Windows state changed; no legacy
outcome or estimate changed. Estimates remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See the [decision
ledger](decision-session-2026-10-17.md#package-scoped-defender-exclusions-and-deferred-yarasysmon-work-2026-10-24).

### Sysmon decision correction, 2026-10-24

The user corrected the later deferral: the three previously selected Sysmon
Modular profiles remain active for migration as download-only artifacts. The
catalog entries and pinned resolver remain in scope. Continue live acquisition,
retained-file recovery, and user/VM acceptance when available. Keep Sysmon
installation and configuration application separate; neither is authorized by
this correction. Classic YARA remains deferred. No estimate or Windows state
changed.

## Version-aware shared-runtime recovery follow-up, 2026-10-24 04:49 UTC

Package inspection now reports an installed runtime below `MinimumInstalledVersion`
as absent for satisfaction checks while retaining its detected version and
registration metadata. Recovery identifies a captured older shared runtime and
retains the newer working runtime, warning that exact downgrade recovery is
unavailable. Focused Pester passed **2/2** on PowerShell 7.6.5/Pester 5.7.1 with
TestRegistry disabled. Windows PowerShell 5.1 parsing passed for both changed
modules and test files; repository validation passed for **407 operations, 8
groups, 5 profiles and 266 PowerShell files**. The broader 130-test attempt was
interrupted after unrelated portable-package fixtures hit sandbox-denied
AppContainer temporary-file moves; no aggregate pass count is claimed. No
installer, package, VM, checkpoint, Defender setting or Windows state changed.

Resolved: version-aware observation and safe compensation for the outdated
shared-runtime case. Retired/excluded: none. Deferred: catalog-driven
prerequisite expansion and ordering, dependent-removal protection, RIDE-managed
v14 package lifecycle/Windows 11 acceptance, and Server support acceptance.
Partial: no package or legacy outcome closed. All five estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See the [structured regression evidence](../archive/evidence/vcredist-version-aware-recovery-local-regression-2026-10-24-0449.json).

## Sysinternals Suite current-source Windows 11 file-lifecycle acceptance, 2026-10-24 04:48 UTC

Current-source Windows 11 run `a77d0464523c4a85ba4db01e9c7b4b6a` passed **1/1** against the pinned 164-member Sysinternals archive. Install/repeat/remove/repeat-remove, saved-run restore, exact member selection, unowned-file preservation, original-absence recovery, collision refusal and modified-file refusal/preservation checks passed. The `accesschk.exe` collision and modified-file guards behaved as expected; the runner reported preserving a modified `accesschk.exe`. No Sysinternals utility executed (`ToolExecuted: false`), so functional behavior remains pending. Controller cleanup was `ResetAndOff`, evidence was collected, and cleanup/collection/export errors were null.

Resolved: current-source Windows 11 package file-lifecycle and saved-state recovery acceptance. Retired/excluded: none. Deferred: utility functional acceptance, activation and supported-target promotion; Defender-detected members remain excluded. Partial: no additional legacy outcome closed. All five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured guest evidence](../archive/evidence/sysinternals-suite-win11-file-lifecycle-2026-10-24.json) and [prior license/plan evidence](../archive/evidence/sysinternals-suite-and-license-plan-regression-2026-10-24-0312.json).

## MiTeC UUID and certificate package file-lifecycle Windows 11 acceptance, 2026-10-24 04:56 UTC

The protected Windows 11 controller ran batch `28d247d6b29b47919e492e28c95fa0c7` on build 26300. All three selected package scenarios passed: UUID Generator 1.0.0, Certificate Generator 1.0.0 and Certificate Information 1.5.0. Install/repeat/remove/repeat-remove, saved-run restore, exact-member selection, unowned-file preservation, original-absence recovery, destination-collision refusal and modified-file refusal/preservation checks passed. The runner reported preserving a modified `UUID.exe`, `CG.exe` and `CertInfo.exe`. No utility executed, no persistent identifier was read/generated, and no certificate was generated, parsed or exported. No certificate store or private key was accessed. Controller cleanup completed as `ResetAndOff`; no cleanup, collection or export error was reported.

The three retained archive hashes matched their run selections. The guest's Authenticode observation was `UnknownError` for each selected executable; do not treat this file-lifecycle run as positive signature verification. Functional behavior, certificate/identifier scenarios and supported-target promotion remain pending. Resolved: current-source Windows 11 package file lifecycle and saved-run recovery only. Retired/excluded: none. Deferred: each tool's synthetic functional acceptance and target support. Partial: no additional legacy outcome closed. All five ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured guest evidence](../archive/evidence/mitec-uuid-certificate-win11-file-lifecycle-2026-10-24.json) and [runner preparation](#mitec-uuid-and-certificate-utility-file-lifecycle-runner-preparation-2026-10-22).

## NTCore Windows 11 file lifecycle and 4GB Patch safety rejection, 2026-10-24 05:06 UTC

Current-source protected Windows 11 run `40e269c4d243442eb5cd78a122e58334`
completed all three NTCore package cases on build 26300. PE Detective and CFF
Explorer each passed install/repeat/remove, saved-state restore, exact-member
selection, unowned-file preservation, original-absence recovery, collision
refusal, and modified-file refusal/preservation. Their selected executables are
unsigned; this run did not launch them.

The 4GB Patch utility was executed only against a generated PE32/x86 fixture.
It set the large-address-aware flag and created an exact `.Backup` file when
that path was free. When the backup path was occupied by a sentinel, the utility
still modified the target, returned exit code 0, preserved the unrelated
sentinel, and created no backup of the original target. The acceptance runner
recovered the synthetic file from its in-memory original; it did not rely on
the utility for recovery. The pinned VM checkpoint reset succeeded and the VM
was powered off; evidence collection completed without cleanup/export errors.

Resolved: PE Detective and CFF Explorer Windows 11 package file lifecycle and
saved-state recovery only. Rejected: 4GB Patch functional safety acceptance;
do not support or run it against user executables until a safe invocation guard
or corrected upstream behavior passes collision and exact-recovery acceptance.
Runtime and activation behavior remain pending for the other NTCore products.
No whole legacy outcome closed and all five estimates remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[structured run evidence](../archive/evidence/ntcore-win11-4gb-patch-functional-rejection-2026-10-24-0506.json).

## PSScriptTools Windows 11 lifecycle and dependency-runtime acceptance, 2026-10-24 05:19 UTC

Current-source protected Windows 11 run
`cf3e8818c73b44439489e353968b1f15` passed the PSScriptTools package
file-lifecycle and saved-state recovery case. The runner staged the pinned
source archive, performed the exact member, repeat, remove, restore, collision
and modified-file checks, and preserved a modified `.github/FUNDING.yml` file.
No PSScriptTools function ran.

Positive runtime acceptance failed because Windows PowerShell 5.1 could not
load its required `Microsoft.PowerShell.ThreadJob` module. The probe stopped
before CIM enumeration, `System.Drawing` or ThreadJob-backed functions. The
missing-dependency negative probe passed and confirmed failure before creating
the isolated CIM file. PowerShell Core was not installed, so that edition's
probe was unavailable. No dependency was installed. The pinned VM checkpoint
was restored and powered off; evidence collection completed without cleanup,
collection or export errors.

Resolved: package file lifecycle and saved-state recovery only. Deferred:
exact publisher acquisition and hash/signature verification for ThreadJob,
RIDE-managed dependency lifecycle, positive PowerShell 5.1 runtime acceptance,
PowerShell Core runtime acceptance, catalog prerequisite integration and
supported-target promotion. No legacy package outcome closed. All five
estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See [structured run evidence](../archive/evidence/psscripttools-win11-runtime-dependency-acceptance-2026-10-24-0519.json)
and the [source/runtime probe design](#psscripttools-isolated-runtime-acceptance-probe-preparation-2026-10-22).

## OfflineCaffeine disconnected Windows 11 package/profile acceptance, 2026-10-24 05:28 UTC

Current-source protected Windows 11 run
`d94d0ff62e224f2b8435df297762b5e2` passed **16/16** checks for the pinned
Caffeine 1.98 portable package. The acceptance profile was bound to the guest's
Windows 11 Enterprise Evaluation build 26300 and architecture. The guest network
adapter started Up, was disabled before payload preflight, remained disabled
through test completion, and was restored by checkpoint recovery.

The run refused missing, corrupt and omitted payloads and a wrong target before
state writes. Offline preview, CLI install/repeat, exact restore to absence,
profile apply/repeat, removal and exact removal/profile recovery passed. The
bundle manifest pinned the RIDE engine, exact package archive and selected
profile. Caffeine was not executed, and Authenticode inspection was correctly
skipped in offline mode; application behavior is therefore not accepted. The
pinned checkpoint was restored and the VM powered off with evidence collected
and no cleanup, collection or export error.

Resolved: selected-profile offline install/apply/no-network and recovery checks
for Caffeine on Windows 11. Deferred: executable behavior and broader offline
installer, dependency, servicing, interruption and other-target acceptance. No
legacy outcome closed; all five estimates remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[structured run evidence](../archive/evidence/offline-caffeine-win11-disconnected-acceptance-2026-10-24-0528.json)
and the [offline execution guide](../offline-bundles.md).

## Package evidence thresholds and rejected-artifact review, 2026-10-24 05:31 UTC

The package verification guide now distinguishes publisher checksums, hosting
digests, observed pins and Authenticode identity/integrity. Available digest or
signature-hash mismatches, malformed archive paths and mismatches against the
reviewed RIDE pin stop acquisition. Missing publisher checksums/signatures and
non-`HashMismatch` Authenticode statuses remain accurately recorded evidence;
they do not impose a blanket package migration blocker. Focused security review
may still be appropriate for sensitive install contexts. License review,
installation, activation and target support remain separate decisions.

The guide also gives an exact-path review and cleanup procedure for rejected
bytes. It requires sidecar hash/size comparison and evidence export before any
manual deletion, prohibits wildcard/cache-tree cleanup, and keeps rejected bytes
from re-entering the canonical cache. This completes the package integrity
policy's evidence-threshold and operator-cleanup documentation item. No package
bytes were downloaded or deleted, and no installer, VM or Windows state changed.

Resolved: documentation of practical acquisition evidence thresholds and safe
rejected-artifact handling. Retired, excluded or deferred: no new legacy
outcome. Partial: implementation and regression behavior were already present;
this record closes the remaining procedure/documentation item only. All five
migration ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**142-196**, rounded **145-200/about 170**. See the [package verification
guidance](../package-verification-matrix.md#evidence-thresholds-and-rejected-artifact-review-2026-10-24)
and [prior implementation regression](../archive/evidence/package-rejected-artifact-retry-regression-2026-10-23.json).

## PSScriptTools ThreadJob exact package acquisition recheck, 2026-10-24 05:34 UTC

The official PowerShell Gallery page continues to identify
`Microsoft.PowerShell.ThreadJob` 2.2.0, minimum PowerShell 5.1, Microsoft
Corporation authorship, no declared dependencies, and a package file list that
includes `LICENSE`, `ThirdPartyNotices.txt` and `.signature.p7s`. The upstream
PowerShell/ThreadJob project identifies the MIT license. These facts support the
dependency selection and license metadata; they do not substitute for verifying
the exact package bytes.

A new request to the exact official Gallery v2 package endpoint failed at DNS
resolution before transfer. No `.nupkg` bytes or partial file were produced;
the local review directory is empty. Do not substitute a repository source ZIP
for the Gallery package. Keep RIDE-managed dependency ownership selected, but do
not add a package operation or digest until the exact package is acquired,
signature and notices are inspected, and the member inventory and source hash
are recorded. This is an acquisition/network blocker, not a license blocker.

Resolved: current Gallery metadata and MIT provenance recheck. Deferred: exact
package acquisition/integrity verification, RIDE-managed dependency lifecycle,
dependency-present PSScriptTools runtime acceptance, and Windows target
acceptance. No legacy package outcome closed, and estimates remain **38-58 /
52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about
170**. See [structured acquisition evidence](../archive/evidence/psscripttools-threadjob-acquisition-retry-2026-10-24-0534.json),
the [official Gallery package page](https://www.powershellgallery.com/packages/Microsoft.PowerShell.ThreadJob/2.2.0),
and [upstream project](https://github.com/PowerShell/ThreadJob).

## Catalog prerequisite artifact-edge execution, 2026-10-24 05:38 UTC

Offline execution now accepts a selected consumer artifact's dependency edge
only when that edge resolves to the consumer's direct `PrerequisitePackageId`,
the prerequisite has its own accepted selected bundle payload, and its normal
package operation appears earlier in the plan. The engine still rejects
unmatched or multi-artifact dependency edges; manifest metadata cannot create a
hidden installer action. The focused offline test now selects only the consumer
artifact and verifies that the prerequisite payload enters coverage through
that declared edge.

`OfflineExecution.Tests.ps1` and `OfflineProfileCoverage.Tests.ps1` passed
**101/101** on PowerShell 7.6.5/Pester 5.7.1 with TestRegistry disabled.
Windows PowerShell 5.1 parsing passed for the changed engine module and test;
repository validation passed for 407 operations, 8 groups, 5 profiles and 269
PowerShell files. No package, installer or Windows state changed. Offline VM
acceptance remains unavailable at host CIM and is separate from this local
contract check.

Resolved: the catalog-declared prerequisite artifact edge and ordered offline
dispatch contract. Deferred: Windows 11 and Server runtime package acceptance,
and any non-catalog installer dependency actions. No whole legacy outcome was
resolved; all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**,
exact **142-196**, rounded **145-200/about 170**. See [structured regression
evidence](../archive/evidence/offline-catalog-prerequisite-artifact-edge-regression-2026-10-24-0538.json)
and the [offline bundle contract](../offline-bundles.md).

## v14 prerequisite planning and shared-runtime recovery regression, 2026-10-24 05:42 UTC

The focused rerun selected the catalog-driven package prerequisite planning and
shared-runtime recovery cases. Pester 5.7.1 passed **9/9** on PowerShell 7.6.5
with TestRegistry disabled. The cases cover prerequisite plan expansion and
ordering, deduplication, minimum-version refusal, candidate-target guard,
consumer-only mutation-plan refusal, dependent removal protection and keeping a
newer shared runtime during restoration. An initial invocation failed before
test execution because Pester could not create its HKCU registry fixture; the
successful rerun disabled that unrelated registry plugin. No installer, VM,
checkpoint or Windows state changed.

Resolved: these local planning and recovery contracts pass in the current source.
Deferred: RIDE-managed v14 install/repeat/uninstall/saved-run recovery on Windows
11 and acceptance on declared Server targets; no target support is added. No
legacy outcome closed. All five estimates remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. Sysinternals
licensing remains settled under the prior RIDE v2 specialist approval for direct
download and installation; Defender-detected files remain separately excluded.
See [structured evidence](../archive/evidence/vcredist-prerequisite-regression-2026-10-24-0542.json).

## Microsoft Visual C++ v14 focused acceptance batch prepared, 2026-10-24 05:52 UTC

The pinned runtime candidate is now selectable as `ApplicationsBatch5` through
the existing Windows VM application-test controller. It is isolated to Windows
11 and keeps production `SupportedTargets` empty. The guest scenario preserves
the checkpoint baseline and reports `NotApplicable` without changes if a
sufficient runtime or catalog-dependent package is already installed. Otherwise
it verifies the RIDE-managed install, the minimum registered and
`System32/vcomp140.dll` versions, repeat install, removal/repeat removal, saved
removal recovery, and restoration of the original state. If the captured runtime
was below the declared minimum, recovery verifies that RIDE retains the newer
shared runtime rather than attempting an unsafe exact downgrade. The host
controller restores the configured checkpoint after the run.

The complete `TestAutomation.Tests.ps1` suite passed **103/103 executed tests**;
two existing tests were skipped. Focused catalog metadata and shared-runtime
recovery tests passed **2/2**. Windows PowerShell 5.1 parsing passed for seven
changed script/test files and repository validation passed for 407 operations,
8 groups, 5 profiles and 269 PowerShell files. No VM, installer or Windows state
was accessed. The last VM inventory attempt at 05:30 UTC was denied at CIM, so
Windows 11 runtime lifecycle and Server target acceptance remain deferred.

Resolved: focused batch selection, safety preconditions, lifecycle/recovery
procedure and local regressions. Deferred: guest execution, actual RIDE runtime
install/remove and recovery, and target promotion. No legacy outcome closed.
Estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See [structured preparation evidence](../archive/evidence/vcredist-applications-batch5-preparation-2026-10-24-0552.json)
and the [operator command](../../tests/integration/README.md#existing-application-suites).

## MiTeC SQLite Query Windows 11 lifecycle, 2026-10-24 06:04 UTC

The focused `SQLiteQuery` suite passed its one package file-lifecycle and
recovery case on Windows 11 build 26300. Install/repeat, remove/repeat, original
absence restoration, and refusal to overwrite or remove a modified managed file
passed. The expected warning confirmed that a modified `SQLiteQuery.exe` was
preserved. The test did not open a database or execute SQL; feature, runtime and
activation acceptance remain pending. The protected controller restored its
pinned checkpoint, powered off the guest, collected evidence, and reported no
cleanup, collection or export error.

Resolved: Windows 11 package file lifecycle and saved-state recovery for the
selected MiTeC SQLite Query candidate. Deferred: database-copy feature checks,
runtime/activation behavior, licensing and target support. No package or legacy
outcome is closed; all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured run
evidence](../archive/evidence/mitec-sqlite-query-win11-lifecycle-2026-10-24-0604.json)
and the [focused lifecycle contract](../../tests/integration/README.md#focused-portable-package-acceptance).

## NTCore guarded 4GB Patch Windows 11 synthetic acceptance, 2026-10-24 05:59 UTC

The guarded launcher passed its generated PE32/x86 guest acceptance twice. It
refused an occupied adjacent backup without mutation, ran the hash-pinned tool
only through the launcher, verified the large-address-aware flag and recomputed
PE checksum, retained the exact original backup, and restored the fixture. No
installed or user executable was used. Both guest runs reset the pinned
checkpoint, powered off, and collected evidence without cleanup/export errors.

The overall controller runs were marked failed because the installed protected
controller still expected `ToolExecuted=false` for NTCore. The current
repository validator now expects tool execution for NTCore, but refreshing the
registered controller requires an elevated PowerShell session. NTCore remains
unaccepted until that refresh and a full passing controller rerun. No package
support target or legacy outcome is closed. See [structured guest/controller
evidence](../archive/evidence/ntcore-win11-guarded-launcher-controller-validation-2026-10-24-0559.json).

## Sysinternals Suite current-source local package regression, 2026-10-24 06:10 UTC

The current-source `SysinternalsSuitePackage.Tests.ps1` suite passed **7/7** on
PowerShell 7.6.5/Pester 5.7.1 after disabling Pester's unused `TestRegistry`
plugin and redirecting Pester's temp root into a new repository-local `.local`
directory. The default setup could not access HKCU; the first registry-disabled
attempt used the sandbox system temp root and three file-move assertions failed
with access denied. The repository-local rerun completed all seven tests. It
covers the pinned archive/member snapshot and inert package staging, repeat,
remove, conflict preservation and saved-state recovery. No Sysinternals utility,
installer, VM, Defender setting or Windows state was touched.

Resolved: current-source local package lifecycle/recovery regression. Retired,
excluded or deferred: no new legacy outcome; licensing remains settled by the
prior RIDE v2 specialist approval, and the Defender-reported tools remain
separate security exclusions. Partial: utility behavior, activation and
supported-target acceptance remain open. All estimates remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[structured evidence](../archive/evidence/sysinternals-suite-local-regression-2026-10-24-0610.json).

## ApplicationsBatch1 stale controller-test snapshot and Gpg4win regression, 2026-10-24 06:29 UTC

The registered ApplicationsBatch1 request 4b4ab05256884fde810d04d0fb875998 failed the guest Pester gate before its integration suite ran: 317 passed, one failed and one was skipped. The failing NTCore dispatch test came from a stale staged test snapshot whose mock wrote ToolExecuted=false; current controller validation correctly expects the Boolean value true. Hash comparison confirmed the staged test file differed from the current checkout, while the automation module matched. The current focused dispatch tests pass 5/5. A corrected retry, 2e2b9cab185148318a0b29aa690a4501, is active in the same preregistered RIDE-Win11-Test runner; no second request is queued.

The current-source Gpg4winPackage.Tests.ps1 suite passed 10/10 on PowerShell 7.6.5/Pester 5.7.1 with TestRegistry disabled. Its temporary test root was inside .local and removed after the run. No Gpg4win installer, GnuPG process, VM or Windows state change was involved. Native install scope, selected components, configuration preservation and exact recovery remain open.

Resolved: current-source controller dispatch regression and Gpg4win mocked package lifecycle checks. Retired/excluded: none. Deferred: corrected ApplicationsBatch1 runtime acceptance; Gpg4win native install/remove/recovery and component visibility. Partial: Gpg4win package candidate only. No legacy product outcome closed and no estimate range changes. See [structured evidence](../archive/evidence/applications-batch1-stale-controller-test-and-gpg4win-regression-2026-10-24-0629.json).

## ApplicationsBatch1 retry state recheck, 2026-10-24 06:39 UTC

The corrected ApplicationsBatch1 request 2e2b9cab185148318a0b29aa690a4501 remains in the runner's queue/running directory, with no terminal result, finished entry or guest summary. Its last controller output is still waiting for the second AutomatedLab command. The request's process state cannot be confirmed: PowerShell Task Scheduler queries failed on CIM access denial, the COM query was denied, and schtasks.exe reported an invalid network address. These failures do not prove the runner stopped. No fresh UAC prompt was requested, no VM change or duplicate request was made. Preserve the request and recheck its exact result paths before later acceptance work. No new legacy outcome closed; estimates remain unchanged. See [structured status evidence](../archive/evidence/applications-batch1-retry-state-recheck-2026-10-24-0639.json).

## Gpg4win ApplicationsBatch1 acceptance routing, 2026-10-24 06:46 UTC

The Gpg4win 5.1.1 candidate now declares ApplicationsBatch1, so the generic disposable-VM application runner will select it for the existing limited-user install/remove/recovery workflow. The focused Gpg4win package suite passed 11/11, including resolution into that batch; repository validation passed. The current registered retry was staged before this catalog change and will not test Gpg4win. Its result and process state remain unresolved, so the same request must be verified before any subsequent VM request is queued.

Gpg4win remains unsupported until Windows 11 native behavior, selected component visibility, key/config preservation and exact recovery pass. The private local license-review record is kept separate; its status does not gate technical acceptance. No installer/GnuPG process or VM ran and no fresh UAC prompt was requested. No legacy outcome closed; all five estimates remain unchanged. See [structured evidence](../archive/evidence/gpg4win-applications-batch-routing-2026-10-24-0646.json).

## ApplicationsBatch1 current-pin Windows 11 acceptance, 2026-10-24 06:49 UTC

RIDE-Win11-Test completed request 2e2b9cab185148318a0b29aa690a4501 with controller status Passed. Windows 11 build 26300 guest validation passed 318 tests, failed none and skipped one; ApplicationsBatch1 integration passed. All eight selected package scenarios passed, including their compensating presence-recovery checks: Thunderbird 158.0.1, VS Code 1.143.1, Firefox 158.0.1, DB Browser for SQLite 3.13.1, Autopsy 4.23.1, Chrome 156.0.8078.48, Wireshark 4.6.9.0 and Signal 8.32.0. Thunderbird used the temporary limited account; its cleanup and batch-logon-right removal passed. Profile-preservation checks passed for Thunderbird, Chrome and Signal.

Controller cleanup, state collection and evidence collection reported no errors, and the controller cleanup restored the pinned checkpoint. These results prove the selected lifecycle and compensating presence recovery. They do not prove exact old-version recovery; Wireshark's existing-installation, association/shared-runtime and broader recovery cases remain open. Gpg4win was not present in this request's staged source because its ApplicationsBatch1 routing was added afterward. No Defender-blocked tools were selected.

Resolved: Windows 11 acceptance for the selected scenarios. Retired/excluded: none. Partial/deferred: Gpg4win acceptance, exact prior-version restoration where unavailable, and remaining Wireshark cases. No additional supported target or whole legacy outcome closed; estimates remain unchanged. See [structured evidence](../archive/evidence/applications-batch1-win11-current-pin-2026-10-24-0649.json).

## ApplicationsBatch1 current-source Windows 11 acceptance, 2026-10-24 06:46 UTC

The current-source Windows 11 run passed all eight selected package install/repeat/remove/recovery scenarios: Thunderbird 158.0.1, VS Code 1.143.1, Firefox 158.0.1, DB Browser for SQLite 3.13.1, Autopsy 4.23.1, Chrome 156.0.8078.48, Wireshark 4.6.9.0 and Signal 8.32.0. Guest validation passed 318/319 tests with one skip; the controller completed checkpoint reset/off and evidence collection without errors.

The installers provide compensating presence recovery; exact previous-version recovery is unavailable. Wireshark existing-installation, association/shared-runtime and feature-specific checks remain separately open. No application feature behavior, new target support, or legacy outcome is inferred from this package lifecycle run. See [structured evidence](../archive/evidence/applications-batch1-win11-acceptance-2026-10-24-0646.json).

## Gpg4win acceptance queue access blocker, 2026-10-24 06:51 UTC

The attempt to submit the next ApplicationsBatch1 run failed before enqueue: Set-Content was denied while creating the temporary request file in the protected pending queue. The pending/running queues remain empty and the runner has no blocked marker. The previous registered batch passed all eight selected scenarios with no controller cleanup or evidence collection error. Gpg4win is now routed to ApplicationsBatch1 and its local suite passes 11/11, but native acceptance must wait until the existing authorized queue writer can submit the request. No fresh elevation was requested and no queue ACL, VM or Defender state was changed. No legacy outcome closed; estimates remain unchanged. See [queue blocker evidence](../archive/evidence/gpg4win-acceptance-queue-access-block-2026-10-24-0651.json).
## TMOG ApplicationsBatch1 routing and queue dispatch, 2026-10-24 07:03 UTC

TMOG 1.0.1 is assigned to the existing ApplicationsBatch1 runner alongside
Gpg4win. The catalog route test passed 1/1 and the generated operation reference
and repository validation are current. TMOG remains a candidate with empty
SupportedTargets and PendingAcceptance true. The focused acceptance scenario is
limited to install, repeat, uninstall and recovery; it does not launch TMOG.scr,
select a screensaver or activate PRO. Owner-specific license review remains in
the private local store and does not gate package migration.

Dispatch through the registered RIDE-Win11-Test task failed before enqueue:
Windows denied creation of the temporary request file in the protected pending
queue. A read-only check found pending and running empty; no VM, checkpoint,
Defender or Windows state changed. The previously completed eight-package
ApplicationsBatch1 run remains valid for its own selection, but predates both
Gpg4win and TMOG routing. Native acceptance is therefore still pending. This
work closes no legacy outcome or supported target; estimates remain unchanged.
See [routing and dispatch evidence](../archive/evidence/tmog-applications-batch1-routing-queue-block-2026-10-24-0703.json).

## Gpg4win and license-planning regression, 2026-10-24 07:08 UTC

`Gpg4winPackage.Tests.ps1` passed 11/11 on PowerShell 7.6.5/Pester 5.7.1.
The combined Gpg4win and `LicenseReviews.Tests.ps1` run passed 30/32: the two
license-review fixture tests that atomically replace JSON files failed because
the sandbox denied removing the temporary destination. A read-only check
confirmed the private local store still contains records for Gpg4win and TMOG;
the shared evidence intentionally omits owner-specific review statuses. This
filesystem limitation does not block technical package migration.

The registered ApplicationsBatch1 dispatch remains blocked before enqueue by
protected pending-queue temporary-file creation. No installer, GnuPG process,
VM, checkpoint or Windows state changed. Gpg4win and TMOG remain candidates with
native Windows 11 acceptance pending. Estimates are unchanged. See [structured
regression evidence](../archive/evidence/gpg4win-tmog-license-planning-regression-2026-10-24-0708.json).

## Phoenix Protector ApplicationsBatch1 routing, 2026-10-24 07:13 UTC

Phoenix Protector 1.7.1 now resolves into the existing ApplicationsBatch1
acceptance runner. Its focused package test passed 3/3, including exact publisher
pin, machine-wide MSI arguments and the new batch assignment. Generated operation
documentation and repository validation passed (407 operations, eight groups,
five profiles and 269 PowerShell files). The private owner-specific review stays
in the local review store; it does not block technical migration.

Windows acceptance remains pending. The guest must establish the exact .NET
Framework 2.0.50727 launch-condition behavior, install path and shortcuts, repeat
install, uninstall cleanup, saved-state recovery and reboot reporting. The most
recent ApplicationsBatch1 request failed before enqueue on protected-queue file
creation, and the queue remains empty. No MSI, custom action, VM or Windows state
was touched. This adds no legacy outcome closure or target support. See
[structured evidence](../archive/evidence/phoenix-applications-batch1-routing-2026-10-24-0713.json).

## Sysinternals migration scope reaffirmed, 2026-10-24 07:20 UTC

The user reaffirmed that the prior RIDE v2 license-specialist review approved
Sysinternals for RIDE's workflow. RIDE downloads the tools directly from
Microsoft and installs them on user-supported devices; RIDE does not transfer,
publish or distribute Sysinternals copies. There are no legal or licensing
issues for this workflow, and generalized redistribution concerns must not be
used to block package migration. The prior specialist approval governs this
decision; no new legal review is required for the existing scope.

Keep technical acceptance separate: package implementation and native lifecycle
checks can proceed under the authorized migration batches. Defender-detected
utilities remain excluded as a security disposition, independent of licensing.
The current Sysinternals suite source regression passed 7/7; utility behavior
and any remaining native scenarios are technical acceptance items. This
reaffirmation closes no additional legacy outcome and does not change estimates.
See [decision evidence](../archive/evidence/sysinternals-migration-scope-reaffirmation-2026-10-24-0720.json).

## JoeWare rdp-sec-check current-version identity reconciliation, 2026-10-24 07:24 UTC

The official JoeWare product page identifies the offered tool as 0.9-beta / JoeWare
V02.00.00, dated 2014-11-17. The official usage page identifies the same version,
and the product version history lists JoeWare 2.00.00 on that date. This resolves
the current product-version identity. The older `versions.txt` V01.00.00 / 2011
row remains historical evidence; its hashes are not attributed to the V02.00.00
archive without inspecting that archive.

The product page says the ZIP includes GPLv2 Perl source and an ActiveState
PerlApp executable and credits Mark Lowe/Portcullis. The linked Portcullis page
returned 404 when checked, so source provenance still rests on the package's
included source and publisher notice until exact bytes are available. No download
form was submitted and no archive, executable or endpoint was used. Exact artifact
identity, source-member and dependency review, notice retention, package lifecycle
and isolated functional acceptance remain open; licensing is recorded for review
and does not block the authorized package migration. Estimates remain unchanged.
See [structured evidence](../archive/evidence/joeware-rdp-sec-check-current-version-reconciliation-2026-10-24-0724.json),
[product page](https://joeware.net/freetools/tools/rdp-sec-check/index.htm),
[usage page](https://joeware.net/freetools/tools/rdp-sec-check/usage.htm),
[versions file](https://joeware.net/freetools/versions.txt), and
[Portcullis source page](https://labs.portcullis.co.uk/application/rdp-sec-check/).

## OpenSSH Server observer current-source local regression, 2026-10-24 07:28 UTC

The focused `OpenSshServerObservation.Tests.ps1` suite passed **7/7** on
PowerShell **7.6.5** / Pester **5.7.1**, with the Pester TestRegistry plugin
disabled. The checks cover separate capability, service, firewall and bounded
server-data observations; target identity refusal; provider-unavailable results;
and the guarantee that observation does not activate `sshd` or return private-key
bytes. No catalog operation, mutation, service/firewall/host-key change, VM run,
elevation request or Defender change occurred.

This verifies only the unregistered read-only observer. OpenSSH Server capability
servicing, explicit activation, service/firewall ownership, configuration and host
key preservation, exact recovery, and Windows 11/Server 2025 acceptance remain
open. No component outcome closes and estimates remain unchanged. See
[structured evidence](../archive/evidence/openssh-server-observation-local-regression-2026-10-24-0728.json),
[operator boundary](../windows-component-inventory.md#openssh-server-component-boundary),
and [Microsoft install guidance](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse).

## Artcraft ApplicationsBatch6 technical routing, 2026-10-24 07:37 UTC

Assigned the twelve machine-scope Artcraft apps to a dedicated `ApplicationsBatch6`
route: PhotoCraft, VectorCraft, FilmCraft, LightCraft, PDFCraft, EffectCraft,
DesignCraft, WordCraft, SoundCraft, DeckCraft, CADCraft and GridCraft. The
separately selectable current-user ArtCraft Launcher remains outside the batch.
All twelve remain Windows 11 candidates with empty `SupportedTargets` and
`PendingAcceptance = true`.

The checkout-local license store currently contains version-specific
`NeedsReview` markers for all thirteen packages. As directed, those owner-specific
notes remain visible in that private store and do not gate technical package
routing or acceptance. This does not infer entitlement or redistribution
approval. The package-selection and automation regression passed **110/112**
tests with two skips and no failures on PowerShell **7.6.5** / Pester **5.7.1**;
the rerun used a unique `.local` temporary root after the default sandbox temp
directory denied fixture writes. Catalog export and repository validation
passed (407 operations, eight groups, five profiles, 269 PowerShell files).

No installer or launcher ran and no VM, checkpoint, Windows or Defender state
changed. The existing protected pending queue remains the last recorded
dispatch blocker before enqueue. Deferred: all twelve Windows 11 install/repeat/
uninstall/saved-run recovery scenarios, source-notice verification during guest
acceptance, and any future target-support promotion. No Artcraft legacy outcome
closes; estimates are unchanged. See [routing evidence](../archive/evidence/artcraft-applications-batch6-routing-2026-10-24-0737.json),
[the ApplicationsBatch6 procedure](../../tests/integration/README.md#existing-application-suites),
and [package guidance](../application-packages.md#artcraft-machine-scope-msi-candidates).

## ApplicationsBatch1 Server 2025 target-aware acceptance, 2026-10-24 07:34 UTC

The first request, `fb2befa172e84dd5977c741d551229d0`, passed guest Pester and Thunderbird's limited-user install/repeat/remove/recovery, profile preservation and account cleanup, but the coordinator rejected target-exclusion rows without worker identity fields. The checkpoint reset and power-off succeeded and no collection error was reported. The runner now emits target-exclusion rows only from the coordinator; focused package regressions passed 103/103.

The corrected request, `0365d89e5c4649ea94bd502ae737d2c7`, passed on Windows Server 2025 build 26100. Guest validation passed 319, failed 0 and skipped 1; eight target-eligible application lifecycle/recovery scenarios passed. Phoenix Protector, Gpg4win and TMOG were `NotApplicable` because each is a Windows 11 candidate, and the production catalog target metadata was not modified. The temporary account, batch-logon right, pinned checkpoint and evidence collection were cleaned up without reported errors. Exact previous-version recovery remains unavailable for these installers; Wireshark existing-installation, association/shared-runtime and broader feature checks remain open.

Resolved: Server 2025 acceptance for the eight eligible ApplicationsBatch1 packages and the worker evidence-routing defect. Retired/excluded: none. Partial/deferred: Windows 11 lifecycle acceptance for Phoenix Protector, Gpg4win and TMOG, exact prior-version recovery, and Wireshark follow-up. No whole legacy outcome closed; estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. Next, run ApplicationsBatch1 on Windows 11 for the three candidates and continue deferred VM acceptance. See [passing Server 2025 evidence](../archive/evidence/applications-batch1-server2025-acceptance-2026-10-24-0734.json), [initial harness failure](../archive/evidence/applications-batch1-server2025-worker-identity-retry-2026-10-24-0711.json) and [runner procedure](../../tests/integration/README.md#existing-application-suites).

## ArtCraft Launcher ApplicationsBatch7 routing and ApplicationsBatch1 result, 2026-10-24 07:51 UTC

Routed the separately selectable current-user ArtCraft Launcher 0.2.1 to a
Windows 11-only `ApplicationsBatch7`. The batch selects exactly this MSI and
covers preview, install/repeat, uninstall and saved-run recovery without starting
the launcher, downloading app payloads, or changing launcher configuration.
Owner-specific license review stays in the local store and does not block the
technical migration.

The focused `ArtcraftPackages.Tests.ps1` and `TestAutomation.Tests.ps1` run passed
112/114 with two skips and no failures on PowerShell 7.6.5/Pester 5.7.1, with the
unused TestRegistry plugin disabled and a unique checkout-local temporary root.
Catalog export and repository validation passed for 407 operations, eight groups,
five profiles and 269 PowerShell files. `Invoke-RideApplicationBatch.ps1 -Version`
reports 0.9.0.

The previously queued Windows 11 ApplicationsBatch1 request
`158f5e1bd21c496e8048e71982df81e6` has now completed with status Failed. Guest
Pester passed 321/322 (zero failures, one skip), but the limited-user lifecycle
worker recorded Thunderbird 158.0.1 Passed and Gpg4win Failed because its installer
exited with code -1073741819. The guest summary is Failed, so no aggregate package
pass count is claimed. Controller `CleanupError` and `CollectionError` are null;
the request is absent from pending and running queues. Investigate the Gpg4win
installer failure and queue access before another request. No fresh UAC or
controller refresh was attempted.

Resolved: ArtCraft Launcher batch routing and local selection plumbing. Retired
or excluded: none. Deferred: launcher native lifecycle/recovery, Gpg4win native
lifecycle/recovery after the installer crash, and further ApplicationsBatch1
acceptance. No whole legacy product outcome closes; all five estimate ranges
remain unchanged. See [structured evidence](../archive/evidence/artcraft-launcher-batch7-routing-and-applicationsbatch1-result-2026-10-24-0751.json)
and the [batch procedure](../../tests/integration/README.md#existing-application-suites).

## ApplicationsBatch7 queue write denied, 2026-10-24 07:54 UTC

After the prior ApplicationsBatch1 request reached terminal Failed status, the
pending and running queues were both empty. A single ApplicationsBatch7 submission
through the existing RIDE-Win11-Test registered configuration was denied before
enqueue when Windows refused creation of the temporary request JSON under the
protected pending queue. No fresh UAC was requested, and no VM/checkpoint state
changed. The attempt ID is `cef30af6937b48c19ec79a311f6b2a56`.

The ArtCraft Launcher batch route and its 112/114 local Pester result remain
valid, but native install/repeat/uninstall/recovery has no guest result. The
previous ApplicationsBatch1 run remains failed on the Gpg4win installer exit
`-1073741819`; its aggregate suite is not accepted. Do not retry the protected
queue write or overlap VM requests. Continue independent local migration work
until the authorized queue writer is available. No estimates or legacy outcomes
changed. See [dispatch evidence](../archive/evidence/artcraft-launcher-applicationsbatch7-queue-access-block-2026-10-24-0754.json)
and [the prior guest result](../archive/evidence/artcraft-launcher-batch7-routing-and-applicationsbatch1-result-2026-10-24-0751.json).

Microsoft maps `0xC0000005` to `STATUS_ACCESS_VIOLATION`; that identifies the process termination class, not the failing module or underlying cause. See [NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55).

## ApplicationsBatch7 versioned runner regression, 2026-10-24 07:57 UTC

The dedicated launcher route remains wired through the catalog, guest dispatch,
task client, host VM runner and registered controller validation. Script/module
versions are `Invoke-RideApplicationBatch` 0.9.0, `Invoke-RideVmTestTask` 1.1.0,
`Invoke-RideVmTest` 0.13.0, `Invoke-RideGuestTests` 1.0.0 and
`RIDE.TestAutomation` 1.1.0. The focused Artcraft and task automation suites
passed 112/114 with two skips and no failures; repository validation passed for
407 operations, eight groups, five profiles and 269 PowerShell files. The four
standalone version checks and `git diff --check` passed.

ApplicationsBatch7's VM request remains denied before enqueue by protected queue
write access. No VM/runtime state or license record changed, and no fresh UAC was
requested. The prior ApplicationsBatch1 Gpg4win installer crash and the Batch7
guest lifecycle remain deferred; estimates are unchanged. See [regression
evidence](../archive/evidence/artcraft-launcher-batch7-runner-version-regression-2026-10-24-0757.json),
[queue evidence](../archive/evidence/artcraft-launcher-applicationsbatch7-queue-access-block-2026-10-24-0754.json),
and [batch procedure](../../tests/integration/README.md#existing-application-suites).


## JoeWare per-product publisher version recheck, 2026-10-24 08:00 UTC

The official AdFind and AdMod product pages still list AdFind 1.64.00 and AdMod
1.29.00, both dated 2026-06-08. The versions match their per-product rows; the
global versions-file header remains historical. The `rdp-sec-check` current page
still identifies 0.9-beta / V02.00.00 (2014-11-17), while the older V01.00.00
versions-file row remains unmapped to the current archive. The 41-name scope is
unchanged. No download form was submitted, no payload or digest was acquired, and
no executable, VM, Defender setting or Windows state was touched. AdFind remains
separately excluded from selected batches because of its Defender block; this
records no threat classification or false-positive finding.

Resolved: current AdFind/AdMod product versions and dates reconfirmed. Retired:
none. Excluded: AdFind remains separately excluded. Deferred: exact payloads and
hashes, `rdp-sec-check` old-row mapping, complete file inventory and technical
lifecycle/acceptance. Partial: no JoeWare legacy outcome closes. Estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [structured evidence](../archive/evidence/joeware-per-product-version-source-recheck-2026-10-24-0800.json),
[AdFind](https://www.joeware.net/freetools/tools/adfind/) and
[AdMod](https://joeware.net/freetools/tools/admod/index.htm).


## OpenSSH Server activation lifecycle local candidate, 2026-10-24 08:16 UTC

Added the unregistered `RIDE.OpenSshServerLifecycle.psm1` candidate for an
explicitly selected, already-installed OpenSSH Server capability. It requires an
already elevated administrator session and no pending servicing restart; the
caller selects `Manual` or `Automatic` service startup and `Keep`, `Enabled` or
`Disabled` for the exact existing local `OpenSSH-Server-In-TCP` TCP/22 rule.
It creates no firewall rule and does not install/remove the Windows capability.
The protected machine snapshot records prior service/firewall literals before
mutation. Restore checks target/build/edition/servicing revision and refuses
literal drift. The observer's bounded file names/lengths/hashes are used only to
report first-start data changes. Private key contents are never copied; generated
keys/configuration are retained and exact data recovery is explicitly unsupported.

The combined `OpenSshServerObservation.Tests.ps1` and
`OpenSshServerLifecycle.Tests.ps1` suites passed **18/18** on PowerShell **7.6.5**
with Pester **5.7.1** (the observer's seven cases and activation's eleven cases).
Windows PowerShell **5.1** parser checks passed for the new module and tests.
All service, firewall, capability and data providers were mocked; no native state
or VM was changed. Repository validation passed for 407 operations, eight groups, five profiles and 271 PowerShell files. Native Windows 11 and Server 2025 acceptance remains deferred,
including first-start effects, actual rule scope, apply/repeat, exact service and
firewall restore, and data retention. The existing VM queue/access blocker was
not retried. No component or legacy outcome closes; all five estimate ranges
remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [candidate evidence](../archive/evidence/openssh-server-activation-lifecycle-local-candidate-2026-10-24-0816.json),
[component boundary](../windows-component-inventory.md#openssh-server-component-boundary),
and [Microsoft first-use guidance](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse).

## Sysinternals license rationale corrected, 2026-10-24 08:17 UTC

The user corrected the rationale for treating the Sysinternals Suite as needing
further license review. General redistribution analysis is too strict and is not
a practical blocker for this deployment model. The prior RIDE v2 license
specialist reviewed and approved Sysinternals for RIDE. RIDE downloads directly
from Microsoft and installs on the user's supported devices; RIDE does not
transfer or publish Sysinternals copies. The user's determination is that there
are no legal issues using Sysinternals in RIDE. Treat the approval as settled for
this scope and do not reopen review or gate migration on licensing. Defender-
alerted utilities remain excluded separately on security grounds. The ten exact
Suite/product version records remain `Reviewed`; their utility behavior,
package lifecycle/recovery and native Windows acceptance are technical work.
This decision closes no additional legacy outcome and leaves estimates unchanged.
See the [dated decision evidence](../archive/evidence/sysinternals-license-rationale-correction-2026-10-24-0817.json).

## Sysinternals license administration disposition reaffirmed, 2026-10-24 11:31 UTC

The user reaffirmed that the prior RIDE v2 license-specialist review approved
Sysinternals for RIDE's normal deployment workflow. RIDE downloads the tools
directly from Microsoft for installation on supported devices; it does not
transfer or publish Sysinternals copies. The user's determination is that there
are no legal issues for this use. Do not apply a generalized redistribution
analysis, require another license review, or make licensing a package-migration
gate. The package's source inventory and retained Microsoft notices document
the selected bytes; they do not reopen the settled license disposition.

Defender-detected utilities remain excluded as a separate security decision.
Remaining blockers are technical package lifecycle, exact recovery, functional
behavior where selected, and target acceptance. This reaffirmation closes no
additional legacy outcome and leaves estimates unchanged. See the [dated
decision evidence](../archive/evidence/sysinternals-license-administration-disposition-2026-10-24-1131.json).

## JoeWare latest-offered downloader and acceptance inputs, 2026-10-24

The user accepts the `rdp-sec-check` page/version-list discrepancy and directs
the downloader to resolve the latest version offered for each selected product
at acquisition time. The page/list difference is recorded in
[`joeware-version-discrepancies.md`](../joeware-version-discrepancies.md); the
actual archive has not been acquired, so no ZIP identity or member match is
claimed. Do not attach the old V01.00.00 digest to the current page's
V02.00.00 artifact. Record any page/response/archive difference and add a short
note to the affected package description when the catalog candidate is added.
The [decision ledger](decision-session-2026-10-17.md#joeware-latest-download-and-acceptance-resource-decisions-2026-10-24)
owns this acquisition rule. AdFind remains separately excluded from selected
acceptance batches due to its publisher-reported Defender block.

For GNOME Boxes guest acceptance, Fedora 44 remains selected; Debian, Ubuntu
and Boxes versions are not pre-pinned. Capture actual versions when the guest
is prepared. GNOME Apps lists Boxes 50.0 as the latest release observed for
this decision, not as a compatibility or support claim.

For TPM/boot recovery acceptance, USB storage or a password manager may be used.
Ask the user to confirm retrieval of the saved key before a recovery-changing
step, unless portable storage is verified by the procedure. Do not require a
specific recovery destination or independent verifier; never store key material
in evidence. The acceptance target and confirmation remain pending.

No payload was downloaded, package code was not changed in this decision pass,
and no legacy outcome or target-support declaration changed. Estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**.
## Package planning and AdMod source recheck, 2026-10-24 08:30 UTC

`ApplicationPackages.Tests.ps1` and `LicenseReviews.Tests.ps1` passed **124/124**
combined on PowerShell **7.6.5** with Pester **5.7.1**, with the Pester
`TestRegistry` plugin disabled and repository-local temporary storage. Synthetic
version-matched `NeedsReview` records left every pending package install plan
available, and all ten Sysinternals install plans remained available with
technical acceptance pending. Per-test review stores were isolated and cleaned;
the ignored owner-specific store was not written.

The AdMod-only `Download-JoeWareCollection.ps1 -WhatIf` run failed during
metadata lookup because `www.joeware.net` could not be resolved by the shell. The
script parsed, but no ZIP was acquired, extracted or executed. AdFind remained
excluded from selection. A read-only Hyper-V query for the test VMs still fails
at host CIM access before checkpoint inspection. No VM, installer, Defender or
Windows state changed. No legacy outcome closes; estimates remain **38-58 /
52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about
170**. See [structured evidence](../archive/evidence/package-license-planning-and-joeware-admod-source-recheck-2026-10-24-0830.json).
## Unsigned package eligibility acquisition regression, 2026-10-24 08:38 UTC

The user confirmed 7-Zip and ShareX remain eligible when their installers report
`NotSigned`; available source/version and digest checks remain. The focused
`PackageEvidence.Tests.ps1` suite passed **28/28** on PowerShell **7.6.5** with
Pester **5.7.1**, with the `TestRegistry` plugin disabled. It accepted a synthetic
unsigned artifact with matching provider SHA-512 and rejected altered bytes
before recording success. No real payload, installer, external network, VM,
Defender or Windows state was used. The prior 124/124 application-package and
license-review regression also remains current; `NeedsReview` does not block
pending install planning. No legacy outcome or estimate range closes. See the
[decision ledger](decision-session-2026-10-17.md#unsigned-package-eligibility-decision-2026-10-24),
[verification matrix](../package-verification-matrix.md), and [test evidence](../archive/evidence/unsigned-package-eligibility-acquisition-regression-2026-10-24-0838.json).
## RIDE test VM host-CIM access recheck, 2026-10-24 08:40 UTC

A read-only `Get-VM -Name RIDE-Win11-Test,RIDE-Srv2025Test` query again failed
with `Access to a CIM resource was not available to the client` before VM or
checkpoint inspection. No elevation prompt, queue write, VM, checkpoint,
Defender or Windows state change occurred. Package and component VM acceptance
remain deferred behind host CIM access. No legacy outcome closes and estimate
ranges remain unchanged. See the [unsigned-package regression and VM access
evidence](../archive/evidence/unsigned-package-eligibility-acquisition-regression-2026-10-24-0838.json).

## Independent Sysinternals product inert lifecycle regression, 2026-10-24 08:58 UTC

`SysinternalsProductPackages.Tests.ps1` discovered and passed **72/72** focused
checks across the nine individually pinned candidates: Process Explorer,
Autoruns, TCPView, Process Monitor, RAMMap, Disk2vhd, Sigcheck, Strings and
Handle. Pester **5.7.1** ran under PowerShell **7.6.5** with TestRegistry
disabled. The tests used synthetic inert ZIP members and mocked network/signature
calls; they covered pin/member reconciliation, digest rejection, required EULA
presence, repeat, snapshot recovery, collision handling and preservation of
operator-modified or separately owned files. No Sysinternals executable, EULA,
installer, network, VM, Defender or Windows state was touched. Prior RIDE v2
license-specialist approval remains settled for direct download-and-install;
Defender-detected files remain separately excluded. Technical utility behavior,
activation and disposable Windows target acceptance remain open. No legacy
outcome or supported target closes. All estimates remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[structured test evidence](../archive/evidence/sysinternals-independent-products-local-regression-2026-10-24-0858.json).

## Independent Sysinternals portable acceptance runner-routing regression, 2026-10-24 09:28 UTC

`PortableAcceptanceAutomation.Tests.ps1` and `TestAutomation.Tests.ps1` passed
**141/141 executed**, with **two existing skips** and no failures, on PowerShell
**7.6.5** / Pester **5.7.1**. The dedicated nine-product selector rejects the
Defender-detected tools, and the fixed batch is accepted by the portable and VM
runner routing. Licensing remains settled under the prior RIDE v2 specialist
approval for direct Microsoft download-and-install; no redistribution review
blocks migration. No archive was acquired and no executable, EULA, installer,
VM, Defender setting or Windows state was touched. The prepared batch still
needs its pinned local payload manifest and Windows file-lifecycle acceptance.
No legacy outcome or supported target closes. Estimates remain **38-58 /
52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about
170**. See [structured regression evidence](../archive/evidence/sysinternals-independent-products-runner-routing-regression-2026-10-24-0928.json).

## Independent Sysinternals exact-source acquisition blocked by DNS, 2026-10-24 09:34 UTC

RIDE's `Save-RidePackageArtifact` acquisition path attempted the nine individually
pinned products from their declared direct Microsoft download URLs. All nine
requests failed before transfer because the host could not resolve
`download.sysinternals.com`; no payload bytes were acquired, no manifest was
written, and no executable, EULA, installer, VM, Defender or Windows state was
touched. The retry does not change RIDE v2 specialist approval or create a
license blocker. Defender-detected tools remain separately excluded. The
independent-product selection and runner tests still pass; package payload
preparation and Windows lifecycle acceptance remain deferred to working DNS and
VM access. No legacy outcome or supported target closes. Estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [structured acquisition evidence](../archive/evidence/sysinternals-products-official-download-dns-block-2026-10-24-0934.json).

## Independent Sysinternals cached archive and member-pin verification, 2026-10-24 09:42 UTC

Although the fresh-source attempt above stopped at DNS, all nine exact archives
were already present in the local review cache. Their SHA-256 digests match the
catalog pins, and read-only ZIP central-directory inspection matched every
expected member exactly, including `Eula.txt`. The verified local manifest at
`.local/acceptance-input/SysinternalsProducts.json` passes
`Get-RidePortableAcceptancePayloads` for all nine candidates. This verification
did not extract archives. Earlier source-review work had already extracted the
member files into ignored `.local/sysinternals-*` caches; their acquisition
sidecars date the direct Microsoft-hosted downloads to 2026-10-17 and record no
execution. No utility, installer or EULA was executed or accepted in this run.
Defender-detected collections remain excluded. This resolves payload/manifest
preparation for the pinned batch but closes no legacy outcome or Windows target.
The live ApplicationsBatch1 request occupies RIDE-Win11-Test. The fixed
SysinternalsProducts request `cf9a9049bc0745c08d7e0c3abcb67024` was submitted to
the existing serialized queue and remains pending behind it; it will run only
after the active request ends and checkpoint restoration completes. No guest
result is claimed yet. Licensing remains settled under prior RIDE v2 specialist approval. Estimates
remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [structured payload verification evidence](../archive/evidence/sysinternals-products-cached-payload-verification-2026-10-24-0942.json).

## PSScriptTools local lifecycle rerun and Windows queue write block, 2026-10-24 10:44 UTC

The focused PSScriptTools source-package suite was invoked with Pester's default
registry test disabled. Its first run passed three tests and failed four when
the restricted default temp directory denied the manifest's atomic rename. The
failure was in the sandbox temp path; it did not execute package code. A rerun
with `TEMP` and `TMP` redirected into a unique checkout-local `.local` directory
passed the metadata and incomplete-payload tests. At this observation it was
still running the 360-member repeat-install and exact snapshot/recovery case, so
no final suite result is claimed.

The initial unelevated request on `RIDE-Win11-Test` was denied before enqueue
because a temporary file under the protected pending queue returned access
denied. It caused no UAC prompt or VM/checkpoint change. A subsequent request
through the existing registered RIDE VM task was accepted as
`2c4c9348bbb541059ea9e38e7fb796cd`; queue inspection confirms it is pending
behind the earlier `SysinternalsProducts` request and active `ApplicationsBatch1`
run. No guest result is claimed. Resolved/retired/excluded: none. Partial: local
PSScriptTools lifecycle verification. Deferred: the final local suite result,
guest source lifecycle and separate runtime/dependency probe. No legacy outcome
or target closes. Estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**,
exact **142-196**, rounded **145-200/about 170**. See [structured
evidence](../archive/evidence/psscripttools-full-local-lifecycle-2026-10-24-1101.json).

## PSScriptTools Windows 11 acceptance request queued, 2026-10-24 10:46 UTC

The first request attempt stopped before enqueue because the sandboxed shell could not write the protected pending-queue temporary file. The same registered runner succeeded through the elevated host path and queued request `2c4c9348bbb541059ea9e38e7fb796cd` for the `PSScriptTools` suite, with a 60-minute budget. The current `ApplicationsBatch1` request remains active, and `SysinternalsProducts` is already pending ahead of it; the worker will serialize PSScriptTools after those requests. The local acceptance input points to the pinned PSScriptTools archive, but no guest validation, activation or restore result is claimed yet. Submission changed no VM, package or Windows state. All five migration estimate ranges remain unchanged. See [structured queue evidence](../archive/evidence/psscripttools-win11-queue-submission-2026-10-24-1045.json).
## ApplicationsBatch5-7 Windows 11 acceptance requests queued, 2026-10-24 10:50 UTC

The ApplicationsBatch7 request's earlier sandboxed enqueue failed before a queue item was created. The elevated registered runner then queued three Windows 11 batches successfully: ApplicationsBatch7 `cf8f187288c4464db54b96e7db103c08` for ArtCraft Launcher (no launch), ApplicationsBatch5 `a4bf331470b44d829ae3fddb4b7cfd40` for Microsoft Visual C++ v14 x64, and ApplicationsBatch6 `d4cfc6d0a0364f4782ebf4b373ac33e3` for the twelve Artcraft machine-scope apps. They follow the active ApplicationsBatch1, SysinternalsProducts and PSScriptTools requests in the serialized queue. No guest validation, package lifecycle, checkpoint recovery or target-support result is claimed. The Visual C++ batch may report NotApplicable when the pinned checkpoint already contains an adequate runtime; otherwise it tests install, repeat, removal and recovery. Artcraft license review markers do not gate these technical acceptance runs. No production target support is promoted before evidence review. See [structured queue evidence](../archive/evidence/applications-batch5-7-win11-queue-submission-2026-10-24-1050.json).

## PSScriptTools full local source lifecycle regression, 2026-10-24 11:01 UTC

The repository-local-temp rerun of `PSScriptToolsPackage.Tests.ps1` passed 7/7
with no skips on PowerShell 7.6.5/Pester 5.7.1. It exercised the complete pinned
360-member file set: initial and repeat staging, analyst-output preservation,
modified-file refusal, complete backup, uninstall, exact restore and restored
hash/health checks, changed-recovery refusal, collision refusal and prior
absence. The inert source fixture was not executed or imported. The earlier
default-temp run's four failures remain classified as sandbox temp-file rename
denials, superseded by this passing writable-temp run. Resolved: local
PSScriptTools source file lifecycle regression. Retired/excluded: none. Partial:
no whole legacy package outcome or Windows target closes. Deferred: its separate
registered Windows file-lifecycle request, PowerShell/dependency runtime probe
and native target acceptance. The registered request is running in the VM queue;
no guest result is yet available. Estimates remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[structured local regression and queue evidence](../archive/evidence/psscripttools-full-local-lifecycle-2026-10-24-1101.json)
and [registered request evidence](../archive/evidence/psscripttools-win11-queue-submission-2026-10-24-1045.json).

## PSScriptTools Windows 11 file lifecycle and runtime result, 2026-10-24 11:04 UTC

Request `2c4c9348bbb541059ea9e38e7fb796cd` ran on Windows 11 build 26300. The
pinned 360-file source package passed its install, exact-member, repeat, remove,
restore, unowned-file preservation, collision and modified-file recovery checks;
the guest record marks `LifecycleRecovery` true and `ToolExecuted` false. The
separate dependency/runtime probe failed overall because Windows PowerShell
5.1.26100.9444 could not import the module without `Microsoft.PowerShell.ThreadJob`.
Its negative missing-dependency guard passed before writing the isolated CIM
file. PowerShell 7 was unavailable; no dependency was installed and no module
functions ran. The aggregate task is Failed with evidence collected and
checkpoint `ResetAndOff` cleanup; the package file lifecycle itself passed. The
completed local inert-source lifecycle regression also passed 7/7, including
exact 360-file snapshot recovery. Resolved: Windows 11 file lifecycle and local
source lifecycle. Retired/excluded: none. Partial/deferred: dependency ownership
and source, runtime/function verification, functional acceptance and target
support. No whole legacy package outcome closes. Estimates remain **38-58 /
52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**.
See [Windows 11 evidence](../archive/evidence/psscripttools-win11-acceptance-2026-10-24-1104.json)
and [full local lifecycle evidence](../archive/evidence/psscripttools-full-local-lifecycle-2026-10-24-1101.json).

## SysinternalsProducts request restored after missing queue record, 2026-10-24 11:04 UTC

The original fixed nine-product request `cf9a9049bc0745c08d7e0c3abcb67024` was
no longer present in pending/running queue state and had no correlated result
directory when checked at 11:01 UTC. No guest result can be attributed to it.
The exact `SysinternalsProducts` suite was resubmitted via the existing
registered controller as `f89afa96a4154019a66b3413b4e64d71`, with a 180-minute
budget; it was confirmed pending after the active serialized queue. The pinned
input is the previously verified nine-archive manifest. Defender-blocked tools
remain excluded, and Sysinternals remains free of a legal/licensing migration
blocker under the prior RIDE v2 specialist approval. No VM or checkpoint state
changed on submission. Resolved/retired/excluded: none. Partial/deferred: all
nine independent product lifecycles and exact recovery await guest acceptance.
No legacy outcome closes; estimates remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See [queue recovery
evidence](../archive/evidence/sysinternals-products-win11-queue-retry-2026-10-24-1104.json).

## MiTeC utility file lifecycle on Windows 11, 2026-10-24 11:09 UTC

The registered `MiTeCUtilityFiles` suite passed all three product cases on
Windows 11 build 26300: UUID Generator, Certificate Generator and Certificate
Information. Each passed exact member selection, repeat install/remove,
saved-state exact recovery, unowned-content preservation, collision refusal and
modified-file safeguards. The guest did not execute any utility. The controller
collected evidence and completed checkpoint recovery with no cleanup or
collection error. Resolved: Windows 11 source-file lifecycle/recovery for these
three packages. Retired/excluded: none. Partial/deferred: functional behavior,
Authenticode `UnknownError` assessment, target support and any license disposition
remain separate. No whole legacy product outcome closes. Estimates remain
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See [structured Windows 11 evidence](../archive/evidence/mitec-utility-files-win11-acceptance-2026-10-24-1109.json).

## MiTeC SQLite Query local synthetic lifecycle regression, 2026-10-24 11:16 UTC

`MiTeCSqliteQuery.Tests.ps1` passed **2/2** on PowerShell **7.6.5** with
Pester **5.7.1** and TestRegistry disabled. The tests verified the pinned
three-member candidate metadata and an inert synthetic ZIP install/repeat,
owned-file removal and snapshot restore while preserving an unowned note. The
product binaries were not extracted or run, and no database was opened. This is
local package-fixture evidence only; the active Windows 11 request remains the
separate file-lifecycle check, while database-feature behavior, exact database
recovery, provenance, target support and activation remain open. The package's
license-review marker does not block its migration plan. Resolved: focused local
candidate regression. Retired/excluded: none. Deferred: database GUI/features,
Windows/Server acceptance and remaining technical review. Partial: no whole
legacy package outcome closes. Estimates remain **38-58 / 52-67 / 19-24 / 25-35
/ 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured
regression evidence](../archive/evidence/mitec-sqlite-query-local-synthetic-regression-2026-10-24-1116.json).

## MiTeC SQLite Query Windows 11 file lifecycle, 2026-10-24 11:14 UTC

Request `9dfc912015a441c88b073e760e7b1b65` passed its one selected
`package.mitec-sqlite-query` case on RIDE-Win11-Test, Windows 11 build 26300.
All 14 reported install/remove/restore and safety checks passed, including exact
member selection, repeat operations, snapshot recovery, prior-absence restore,
unowned-file preservation, and collision/modified-file refusals. Evidence was
collected and checkpoint cleanup completed as `ResetAndOff`, with no controller,
collection or cleanup error. The application and payload were not executed. The
result keeps functional acceptance pending, runtime acceptance not selected and
activation pending. Windows 11 is observed as the test environment; catalog
target promotion, database behavior, exact database-content recovery, runtime
and activation remain unaccepted. The package's license-review marker does not
block migration. Resolved: Windows 11 file lifecycle and package recovery for
the selected candidate. Retired/excluded: none. Deferred: functional and
database acceptance, activation, target support and remaining technical review.
Partial: no whole legacy outcome closes. Estimates remain **38-58 / 52-67 /
19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See
[structured Windows 11 evidence](../archive/evidence/mitec-sqlite-query-win11-file-lifecycle-2026-10-24-1114.json).

## Zimmerman helper source pin and license review, 2026-10-24 11:23 UTC

The official `EricZimmerman/Get-ZimmermanTools` repository history identifies
`d808d1dfe6446faf884576a8a1c11b6875197a19` as the current `master` commit,
dated 2026-05-02. The repository has no GitHub release. Its repository-level
`LICENSE` is MIT; this applies to the downloader/helper source and does not
replace per-product review markers for the 26 selected tools. The current helper
is a mutable collection updater: it checks for and may replace itself, discovers
ZIP/TXT links from the live publisher site, downloads multiple results and
extracts archives into the caller-selected destination, overwriting existing
files. This behavior is useful provenance evidence but is not a pinned,
package-scoped RIDE lifecycle or recovery contract.

An exact-commit GitHub archive request failed before transfer because the local
host could not resolve `github.com`; no partial file was created. Source bytes,
archive hash and exact files at the pinned commit therefore remain unavailable
locally. The approved 26-member inventory remains unchanged; no updater or tool
was executed, and no tool archive was extracted. Resolved: immutable upstream
commit identity, repository-level MIT notice and official release absence.
Retired/excluded: none. Deferred: exact source archive and hash, selected-member
publisher version/artifact mapping, per-product review records, RIDE-managed
package selection and lifecycle/recovery acceptance. Partial: no Zimmerman
legacy product outcome closes. Estimates remain **38-58 / 52-67 / 19-24 / 25-35
/ 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured
source review evidence](../archive/evidence/zimmerman-helper-pinned-source-review-2026-10-24-1123.json),
[official repository history](https://github.com/EricZimmerman/Get-ZimmermanTools/commits/master/),
[official MIT license](https://github.com/EricZimmerman/Get-ZimmermanTools/blob/master/LICENSE),
[official helper source](https://github.com/EricZimmerman/Get-ZimmermanTools/blob/master/Get-ZimmermanTools.ps1)
and [release page](https://github.com/EricZimmerman/Get-ZimmermanTools/releases).

## Zimmerman current publisher version matrix, 2026-10-24 11:24 UTC

The current official tools page maps the unchanged 26-member selection to
publisher version labels from **2026.10.0** through **2026.10.3** and links
current artifacts. For 25 members, the linked `.NET 10` variant is available.
Hasher is listed under the `.NET 4.7.2` column, but its linked URL contains
`/net/`, which the publisher's downloader treats as the `.NET 10` variant. Keep
this page/path discrepancy unresolved until exact bytes or a publisher
clarification establish the correct framework. The page recommends `.NET 10`
by default; RIDE has not selected a framework variant or accepted target
requirements for these packages. These are mutable download URLs and displayed
version labels, not artifact hashes or immutable release pins. No product ZIP
bytes were acquired, inspected or extracted, so archive size/digest, members,
signatures, exact version contents and runtime requirements remain unverified.
An unauthenticated `HEAD` request to the selected AmcacheParser `.NET 10`
archive host also failed before HTTP because the local host could not resolve
`download.ericzimmermanstools.com`.
Per-product license review remains a tracked, non-blocking migration item. No
tool ran, no additional member was selected and no legacy outcome closed. See
[structured version-mapping evidence](../archive/evidence/zimmerman-current-publisher-version-mapping-2026-10-24-1124.json)
and the [official publisher page](https://ericzimmerman.github.io/).

## SysinternalsSuite Windows 11 lifecycle follow-up, 2026-10-24 11:33 UTC

Current registered request `7b0d5560d7104eeb8d9094c6139ac3cb` passed 1/1 on
RIDE-Win11-Test, Windows 11 build 26300. The pinned 164-member package passed
install/repeat, remove/repeat, exact restore, member selection and all ownership,
collision and modified-file checks (14 checks). The source inventory contained
151 valid Microsoft signatures and 13 non-executable files. The runner preserved
a modified `accesschk.exe`; no Sysinternals utility ran. Evidence collection
succeeded and the checkpoint reset/off without cleanup or collection errors.
This establishes file lifecycle/recovery only; functional behavior, activation
and target support remain pending.

The follow-on `SysinternalsProducts` request
`f89afa96a4154019a66b3413b4e64d71` was rejected into the registered queue's
`finished/invalid` folder because the installed controller's suite allowlist does
not contain that batch. It has no guest result. The controller refresh requires
an elevated Windows PowerShell token; the user has asked to save fresh-UAC work
for later. Keep the nine-product lifecycle acceptance deferred until the existing
admin-terminal refresh is available. Resolved: whole-Suite Windows 11
file-lifecycle/recovery evidence. Retired/excluded: none. Partial: whole-Suite
lifecycle only. Deferred: functional/activation/target acceptance and the nine
independent product lifecycles. No complete legacy outcome closes; all estimate
ranges remain unchanged. See [structured Suite evidence](../archive/evidence/sysinternals-suite-win11-file-lifecycle-2026-10-24-1131.json),
[product request submission](../archive/evidence/sysinternals-products-win11-queue-retry-2026-10-24-1104.json).

## SysinternalsProducts local inert lifecycle regression, 2026-10-24 11:45 UTC

The focused `SysinternalsProductPackages.Tests.ps1` suite passed all **72/72**
assertions across Process Explorer, Autoruns, TCPView, Process Monitor, RAMMap,
Disk2vhd, Sigcheck, Strings and Handle under PowerShell 7.6.5 and Pester 5.7.1,
with TestRegistry disabled and Pester's temporary root inside `.local`. Synthetic
inert ZIP members and mocked publisher/signature calls covered pinned manifests,
digest refusal, EULA-file presence, repeat, removal, recovery, collision handling
and modified-file retention. No publisher payload, utility, installer, EULA
acceptance, VM, Defender or Windows state was touched.

Pester's post-test NUnit XML environment-report step then failed because the host
denied `Get-CimInstance`; all 72 assertions had already passed, but Pester
returned exit code 1. It wrote a partial XML report with total=72, errors=0,
failures=0 and an empty environment section. An earlier attempt using the
sandbox's default temporary path failed atomic fixture moves with access denied;
it is not counted as a product assertion failure. Resolved: current-source local
inert lifecycle/recovery coverage for nine product candidates. Retired: none.
Excluded: separately Defender-detected binaries remain outside these candidates.
Partial: no legacy product outcome closes. Deferred: native utility behavior,
activation, target support and the nine-product Windows file lifecycle because
the installed controller rejects `SysinternalsProducts` under its stale suite
allowlist; refresh remains saved for the next approved admin-terminal session.
The estimate ranges remain unchanged. See the [structured regression evidence]
(../archive/evidence/sysinternals-products-local-regression-2026-10-24-1145.json)
and the [rejected VM request evidence]
(../archive/evidence/sysinternals-products-win11-queue-retry-2026-10-24-1104.json).

## Sysinternals license disposition reaffirmed, 2026-10-24 12:37 UTC

The user reiterated that RIDE's Sysinternals use is covered by the prior RIDE v2
license-specialist approval: RIDE downloads directly from Microsoft for
installation on user-supported devices and does not transfer or publish copies.
The user's disposition is that there are no legal issues for this workflow.
Do not apply generalized redistribution reasoning or request another license
review as a package-migration gate. Defender-detected files remain separate
security exclusions. Technical lifecycle, exact recovery, selected utility
behavior and Windows target acceptance remain. No legacy outcome closes; all
five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**142-196**, rounded **145-200/about 170**. See the [dated decision
evidence](../archive/evidence/sysinternals-package-migration-disposition-2026-10-24-1237.json).

## ApplicationsBatch1 Windows PowerShell 5.1 regression correction, 2026-10-24 13:18 UTC

Two RIDE-Win11-Test ApplicationsBatch1 attempts, `5843bcf609d04d0d9ffc0af824554b42`
and `c2295dddd2704b9db3008a0a0958cb0b`, both completed with guest Pester at
329/331 passed, one failed and one skipped. The sole failure was in the new
incremental-evidence serialization regression test: Windows PowerShell 5.1
wraps a JSON array returned by `ConvertFrom-Json` differently when the pipeline
is immediately enclosed in `@(...)`, so the test counted one array object
instead of its two rows. The helper wrote the expected two-row JSON correctly.
The second request had captured a source snapshot before the correction.

The test now assigns `ConvertFrom-Json` output directly before reading `.Count`.
Its focused regression passed 1/1 on PowerShell 7.6.5 and Windows PowerShell
5.1. The full `TestAutomation.Tests.ps1` file passed 112/114 with two skips on
PowerShell 7.6.5 and 114/114 on Windows PowerShell 5.1. The new corrected-source
ApplicationsBatch1 request `023b0d9b5c4c4dbc90649be8fea296b7` is running on the
existing Windows 11 checkpoint. A second request
`14f6722a78f54ce8b931235eae5014ac` for the same suite is queued behind it; the
queue serializes these requests. The two failed attempts report no controller
cleanup, collection or evidence-export errors, but neither establishes a
package lifecycle outcome. Defender-blocked tools remain excluded.

A separate local `PSScriptToolsPackage.Tests.ps1` attempt discovered seven tests
and expanded the retained 360-file fixture, then stopped producing output. It
was interrupted without a final summary; no pass count is claimed. The prior
focused PSScriptTools file-lifecycle acceptance remains the latest completed
result, while the full fixture regression remains open. No legacy package
outcome closes in this entry; estimates remain **37-57 / 52-67 / 19-24 / 25-35 /
8-12**, exact **141-195**, rounded **140-195/about 170**. See the [run and
regression evidence](../archive/evidence/applications-batch1-win11-powershell51-array-regression-2026-10-24-1318.json).

## ApplicationsBatch1 limited-user failure, 2026-10-24 13:32 UTC

The corrected-source Windows 11 request `023b0d9b5c4c4dbc90649be8fea296b7`
passed guest validation and Pester 330/331 with no failed tests and one skip,
but integration failed when access to the limited-user worker evidence directory
was denied. The preserved user-scope rows show Thunderbird 158.0.1 passed
install/repeat/removal/recovery with profile preservation. Gpg4win 5.1.1 failed
when its installer exited `-1073741819` (`0xC0000005`); recovery did not pass,
and the artifact remained in the disposable user's RIDE cache. The worker
exited with code 1. No `applications-batch1.json` was exported, so no
machine-scope package result is claimed. Controller cleanup, evidence
collection and export report no errors.

The previously queued ApplicationsBatch1 request `14f6722a78f54ce8b931235eae5014ac`
is now running in the serialized queue. Do not submit an overlapping run.
Investigate the limited-user evidence-path access and Gpg4win crash separately;
neither is a license blocker, and Defender-blocked tools remain excluded. No
whole legacy package outcome closes. Estimates remain **37-57 / 52-67 / 19-24 /
25-35 / 8-12**, exact **141-195**, rounded **140-195/about 170**. See the
[run evidence](../archive/evidence/applications-batch1-win11-limited-user-failure-2026-10-24-1332.json).

## ApplicationsBatch1 pre-fix path rerun, 2026-10-24 13:39 UTC

The serialized request `14f6722a78f54ce8b931235eae5014ac` reached terminal
failure on RIDE-Win11-Test, Windows 11 build 26300. Guest validation passed and
Pester 5.7.1 reported 330/331 passed, zero failures and one skip. The staged
source snapshot was created before the worker evidence-path fix and contained
`$evidencePath=$workerRoot.Replace(...)`; the guest repeated the limited-user
coordinator path denial. It therefore does not verify the fix.

The user-scope evidence again reports Thunderbird 158.0.1 passed with recovery
and profile preservation under the disposable non-elevated account. Gpg4win
5.1.1 exited with `0xC0000005`, failed recovery and remained cached in that
disposable profile. No machine-scope package result was exported. Controller
cleanup, evidence collection and export reported no errors. The locally fixed
runner's regression test has passed on both PowerShell editions, and repository
validation passed (408 operations, eight groups, five profiles, 272 PowerShell
files). After the old request reached the finished queue, corrected-source
ApplicationsBatch1 request `ddf032acbdbd4843b519d42877baa49f` was submitted to
the same serialized registered task using its existing checkpoint configuration.
An earlier ApplicationsBatch1 request, `ac22583d29ea463c82727bf2c4a62c83`, was
already running with the fixed source snapshot, so `ddf032acbdbd4843b519d42877baa49f`
is queued behind it; the registered task runs only one VM request at a time. No
additional legacy outcome closed. Resolved/retired/excluded: none. Partial:
Thunderbird's user-scope slice remains passed; Gpg4win user-scope install and
recovery remain failed; no machine-scope evidence. Deferred: verification of the
path correction, remaining machine packages, Gpg4win crash analysis and all
unfinished native acceptance. Defender-detected utilities remain excluded.
The five ranges remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**141-195**, rounded **140-195/about 170**. See the [structured rerun evidence]
(../archive/evidence/applications-batch1-win11-pre-fix-path-rerun-2026-10-24-1339.json).

## Gpg4win 5.1.1 automated component-control source follow-up, 2026-10-24 14:13 UTC

The official [Gpg4win change history](https://gpg4win.org/change-history.html)
still lists 5.1.1, released 2026-09-23, as its latest release. A same-day
[GnuPG/Gpg4win forum report](https://forum.gnupg.org/t/issue-with-automated-installation-of-gpg4win-5-0-1/7098)
states that `/C` INI component controls remain broken in 5.1.1 and traces the
problem to `config_fetch_bool` returning through `SetUserVariableA` with
incorrect WCHAR pointer arithmetic. The report says false component values can
be ignored or assigned incorrectly. The [publisher's unattended-install
documentation](https://www.gpg4win.org/doc/en/gpg4win-compendium_35.html)
documents `/C` but no supported workaround for this defect.

RIDE's Windows 11 evidence separately records Gpg4win 5.1.1 exiting with
`0xC0000005`; it does not identify the failing module, so the upstream
component-control defect is relevant but is not proven to be the direct cause of
that access violation. Do not promote or repeat the same 5.1.1 `/C` component
configuration as an expected passing acceptance. Revisit after a publisher fix
or a separately documented and independently tested workaround that keeps the
user-approved per-user scope and selected components. The forum-mentioned HKLM
uninstall-key preseed is not adopted for this per-user operation. This is a
technical acceptance blocker, not a license blocker; Defender exclusions are
unrelated. No test, installer or Windows state was changed in this source review.
No legacy product outcome closes; all five estimate ranges remain **37-57 /
52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**, rounded **140-195/about
170**. See [structured source evidence]
(../archive/evidence/gpg4win-5.1.1-automated-component-control-source-follow-up-2026-10-24-1413.json).

## Sysinternals licensing disposition closed, 2026-10-24 14:33 UTC

The user clarified that earlier migration reasoning was too strict and focused
on a redistribution scenario that does not describe RIDE's use. The prior RIDE
v2 license-specialist review approved Sysinternals for RIDE. RIDE downloads
directly from Microsoft and installs on user-supported devices; RIDE does not
transfer or publish copies. The user's decision is that there are no legal
issues using Sysinternals in RIDE. Treat licensing as closed: no second legal
review or distribution analysis is a migration prerequisite. Exact-version
license records are local administration and do not hold up package planning,
acceptance, or migration. Defender-detected utilities remain separately
excluded. Remaining work is technical lifecycle, selected utility behavior,
exact recovery and Windows acceptance. No legacy outcome closes; all five
estimate ranges remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**141-195**, rounded **140-195/about 170**. See the [decision evidence]
(../archive/evidence/sysinternals-license-disposition-2026-10-24-1433.json).

## peStudio publisher source and edition review, 2026-10-24 14:47 UTC

The publisher identifies peStudio Basic 9.61 as a portable ZIP and publishes
SHA-256 `C1E2D0C1FBF5951486CF3D850CC24B11B66E25E0A5B77A623E2EB13FFAD9DDD9`.
Basic is restricted to private, occasional malware static analysis and may not
be used professionally or in a corporate environment. The publisher offers
peStudio Pro for professional use at EUR 159 per user/year. Record the exact edition and intended use as needing local license review; this does not block source review or package implementation planning. The local review tool requires a catalog package ID, so create the versioned record when a candidate is established. Do not assume Basic fits organization
use or that a Pro entitlement exists. The publisher ZIP URL is known, but this
review acquired no bytes, so its local hash and archive members remain
unverified. No catalog change, install, activation or legacy outcome closure
occurred. All estimate ranges remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**,
exact **141-195**, rounded **140-195/about 170**. See the [structured source
evidence](../archive/evidence/pestudio-publisher-source-review-2026-10-24-1447.json),
[publisher download page](https://www.winitor.com/download2), and
[publisher licensing PDF](https://www.winitor.com/tools/pestudio/current/pestudio-licensing.pdf).

## ExifTool Windows release-track follow-up, 2026-10-24 14:53 UTC

The official installation page names the Windows ZIP `exiftool-13.59_64.zip`;
the publisher history identifies 13.55 as the latest production release and
labels 13.59 a development release. Treat these as distinct release tracks.
Keep the exact Windows artifact choice, URL and hash open until the intended
track is established and publisher bytes can be checked. Do not infer a URL or
hash from the filename. The official pages returned HTTP 403 to direct fetch in
this review; indexed official page content exposed the version data. Prior local
acquisition failed DNS before transfer. No package/catalog change or legacy
outcome closure. All five estimates remain **37-57 / 52-67 / 19-24 / 25-35 /
8-12**, exact **141-195**, rounded **140-195/about 170**. See [structured
follow-up evidence](../archive/evidence/exiftool-version-track-follow-up-2026-10-24-1453.json),
[installation instructions](https://exiftool.org/install.html), and
[version history](https://exiftool.org/history.html).
## ExifTool Windows artifact source pin, 2026-10-24 14:58 UTC

The publisher-linked SourceForge project identifies the Windows x64 ZIP as
`exiftool-13.59_64.zip` and provides SourceForge SHA-256
`44b512b25af500724ba579d0a53c8fc5851628b692dd5e5d94ae4a15c2cba9ec`.
The project homepage says the executable archive includes Perl and must retain
`exiftool(-k).exe` beside `exiftool_files`; command-line use renames the launcher
to `exiftool.exe`. Version 13.59 is the current Windows executable and contains
a security update, but the publisher history labels it a development release
and 13.55 the latest production release. Keep the development status visible in
acceptance. Native acquisition from the exact publisher-linked URL failed DNS
before transfer; no partial file exists, and no local hash/member result is
claimed. The exact source route is now ready for candidate preparation; no
catalog change or legacy outcome closure yet. All estimate ranges remain
**37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**, rounded
**140-195/about 170**. See [structured source-pin evidence]
(../archive/evidence/exiftool-source-pin-2026-10-24-1458.json), [publisher
Windows package page](https://exiftool.sourceforge.net/), and [version
history](https://exiftool.sourceforge.net/history.html).

## Sysinternals practical license administration reaffirmed, 2026-10-24 15:05 UTC

The user reiterated that RIDE's prior v2 license-specialist review approved
Sysinternals for the normal direct-download-and-install workflow. RIDE obtains
the tools from Microsoft for installation on user-supported devices and does
not transfer or publish copies. Licensing is settled for this migration: do not
reopen generalized redistribution analysis or require another license review
as a package gate. Defender-detected tools remain excluded on the separate
security disposition. Remaining work for eligible packages is technical
lifecycle, exact recovery and Windows acceptance. No legacy outcome closed;
estimates remain 37-57 / 52-67 / 19-24 / 25-35 / 8-12, exact 141-195,
rounded 140-195/about 170. See the [decision evidence](../archive/evidence/sysinternals-practical-license-administration-reaffirmation-2026-10-24-1505.json).
## ExifTool portable candidate implementation, 2026-10-24 15:10 UTC

Added `package.exiftool` as a Windows 11 candidate for the publisher's 13.59
x64 ZIP. The pinned SourceForge digest is publisher-reported only; DNS failed
before transfer, so no local archive hash or member inspection is claimed.
Because the publisher marks 13.59 as development and 13.55 as latest production,
this version remains explicitly experimental and `PendingAcceptance`.

The portable package lifecycle now supports a bounded, validated mapping that
copies the publisher's `exiftool(-k).exe` launcher to the command-line name
`exiftool.exe`. The copy is tracked as RIDE-owned content for uninstall and exact
saved-run recovery. Synthetic ZIP fixtures also verify notice retention and
refusal when the destination already exists in the archive. The focused
`ApplicationPackages.Tests.ps1` suite passed 105/105 with Pester's optional
registry fixture disabled and temporary storage under `.local`; repository
validation passed 409 operations, 8 groups, 5 profiles and 272 PowerShell files,
and focused parser checks passed 4/4.

No ExifTool executable ran and no media was opened or changed. Windows 11
acceptance, local archive verification and exact-member inspection remain open.
No whole legacy outcome closed; estimates remain **37-57 / 52-67 / 19-24 /
25-35 / 8-12**, exact **141-195**, rounded **140-195/about 170**. See the
[structured evidence](../archive/evidence/exiftool-portable-candidate-implementation-2026-10-24-1510.json),
[operator guidance](../application-packages.md#exiftool-portable-candidate), and
[ExifTool publisher page](https://exiftool.sourceforge.net/).
## Thumbcache Viewer publisher dependency recheck, 2026-10-24 15:14 UTC

The publisher lists x64 GUI 1.0.4.0 and command-line 1.0.2.1 with exact
release URLs, declares GPL-3.0-or-later, and requires the Visual C++ 2008
runtime. The tagged GUI v1.0.4.0 source loads `sqlite3.dll` first and falls back
to `SearchIndexerCore.dll`, documented in that source as native to Windows 11.
The publisher says Windows 11 Search `Windows.db` mapping can use Windows 11 or
an SQLite DLL. This dependency is needed for Windows Search mapping, not basic
thumbcache extraction. A separately downloaded SQLite DLL is therefore not
required for the basic candidate.

Both exact ZIP requests failed at local GitHub hostname resolution before
transfer; there are no partial files, local hashes or member inventories. The
command-line release's exact SQLite behavior and the runtime package's exact
architecture/handling remain unverified. Do not silently install the old VC++
runtime. No catalog candidate or supported target was added. License review is
not a migration gate. No legacy outcome closes; estimates remain **37-57 /
52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**, rounded **140-195/about
170**. See [structured source evidence](../archive/evidence/thumbcache-viewer-dependency-source-recheck-2026-10-24-1514.json),
[publisher requirements and behavior](https://thumbcacheviewer.github.io/),
[GUI release source](https://raw.githubusercontent.com/thumbcacheviewer/thumbcacheviewer/v1.0.4.0/thumbcache_viewer/lite_sqlite3.cpp),
[GUI release](https://github.com/thumbcacheviewer/thumbcacheviewer/releases/tag/v1.0.4.0),
and [command-line release](https://github.com/thumbcacheviewer/thumbcacheviewer/releases/tag/v1.0.2.1).
## Volatility Workbench offline-mode source review, 2026-10-24 15:15 UTC

PassMark confirms Volatility Workbench 3.0.1017 bundles Volatility Framework
2.28.2, a command-line executable and source. Missing Windows symbols are
queried from Microsoft, converted and cached. Framework CLI documentation for
2.28.0 documents `--offline`, which disables remote symbol/banner/JSON lookups;
the exact bundled 2.28.2 executable and Workbench GUI handling have not been
verified. The package also writes a `.CFG` file containing platform and process
list metadata alongside a dump. These facts make offline enforcement and
sidecar/cache locations explicit acceptance requirements. The exact 3.0.1017
ZIP remains unacquired, so no archive hash, member inventory or catalog
candidate is claimed. No licence gate applies. No legacy outcome closed;
estimates remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**,
rounded **140-195/about 170**. See [structured source evidence](../archive/evidence/volatility-workbench-offline-mode-source-review-2026-10-24-1515.json),
[PassMark source](https://www.osforensics.com/tools/volatility-workbench.html),
[Framework CLI manual](https://volatility3.readthedocs.io/en/v2.28.0/vol-cli.html),
and [2.28.2 symbol documentation](https://volatility3.readthedocs.io/en/v2.28.2/symbol-tables.html).
## ApplicationsBatch1 Windows 11 timeout and practical Sysinternals disposition, 2026-10-24 15:20 UTC

The failed ApplicationsBatch1 attempt `ac22583d29ea463c82727bf2c4a62c83` and corrected-source attempt `ddf032acbdbd4843b519d42877baa49f` have now both completed unsuccessfully. The latter timed out after 330/331 Pester cases (one skipped); its nine successful package lifecycle/recovery subresults include Thunderbird's limited-user recovery with profile preservation. Gpg4win 5.1.1 exited `0xC0000005`, recovery failed and the installer artifact was retained. The same Gpg4win result appeared in the prior request; upstream `/C` component controls are known to fail in 5.1.1, but the crash cause is unconfirmed. Partial subresults are useful evidence, not aggregate acceptance. Controller cleanup reported no error, but the VM checkpoint's restored state has not been verified. The next registered request `cd4fcbdd21ed4b1081fcaede9c1e6075` is running serially; do not submit an overlapping request. See [structured Windows 11 evidence](../archive/evidence/applications-batch1-win11-corrected-source-timeout-2026-10-24-1520.json).

The user also reaffirmed the practical Sysinternals license disposition: the prior RIDE v2 license-specialist review approved the RIDE download-and-install workflow; RIDE downloads directly from Microsoft and does not transfer or publish copies. License review and generalized redistribution analysis are not migration gates. Continue eligible package work. Defender-detected members remain excluded as a separate security decision. No whole legacy outcome closed and estimate ranges remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**, rounded **140-195/about 170**. See [Sysinternals disposition evidence](../archive/evidence/sysinternals-license-disposition-reaffirmation-2026-10-24-1520.json).

## Windows PowerShell 5.1 repository validation, 2026-10-24 15:24 UTC

`tools/validate.ps1` passed under Windows PowerShell 5.1. Operation documentation
was current; validation checked 409 operations, 8 groups, 5 profiles and 272
PowerShell files. This repository/catalog check closes no legacy package, setting
or component outcome and does not establish runtime acceptance. Ranges remain
**37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**, rounded
**140-195/about 170**. The queued ApplicationsBatch1 guest command remains
unresolved and was not overlapped. See [structured validation evidence]
(../archive/evidence/ride-windows-powershell51-validation-2026-10-24-1524.json)
and the [migration overview](../MIGRATION-PLAN.md).
## Sysinternals approval and pending-package planning regression, 2026-10-24 15:29 UTC

`tests/LicenseReviews.Tests.ps1` passed **21/21** on PowerShell **7.6.5** with
Pester **5.7.1** and Pester TestRegistry disabled. All ten previously reviewed
Sysinternals suite/product install plans remain available while technical
acceptance is pending. The suite also verifies that local `NeedsReview` records
are informational for pending package install planning. No package was
installed or downloaded, no VM was used, and no Windows state changed. This
confirms the license metadata is not blocking migration; it does not close a
legacy package outcome or replace functional/recovery acceptance. Ranges remain
**37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**, rounded
**140-195/about 170**. The serial ApplicationsBatch1 request
`cd4fcbdd21ed4b1081fcaede9c1e6075` remains awaiting the guest command. See
[structured regression evidence](../archive/evidence/license-review-sysinternals-package-planning-regression-2026-10-24-1529.json).

## JoeWare Unlock publisher version and behavior recheck, 2026-10-24 15:31 UTC

The official Unlock product page and publisher `versions.txt` row agree on
2.1.0 / 02.01.00, released 2004-08-16. The page says the tool queries and
unlocks Active Directory accounts; query access uses the caller's permissions,
while clearing `lockoutTime` requires directory write permission. Its publisher
platform list names Windows 2000, Server 2003 and XP; this does not establish
Windows 11 support. The page's email field is optional, but no form was
submitted and no payload acquired. The versions row supplies MD5/SHA-1 only;
without the exact ZIP, neither digest can be correlated to bytes and there is no
SHA-256. The package remains unregistered pending exact archive/member review.
Functional acceptance requires an isolated synthetic AD fixture; no live
directory or VM was contacted. No license gate applies. No whole JoeWare legacy
outcome closed; estimates remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**,
exact **141-195**, rounded **140-195/about 170**. See [structured evidence]
(../archive/evidence/joeware-unlock-publisher-review-2026-10-24-1531.json),
[official product page](https://www.joeware.net/freetools/tools/unlock/index.htm)
and [versions file](https://joeware.net/freetools/versions.txt).
## RIDE-Win11-Test ApplicationsBatch1 controller state unresolved, 2026-10-24 15:33 UTC

The registered request `cd4fcbdd21ed4b1081fcaede9c1e6075` remains represented in
`queue/running` with no `result.json`. Its last controller log (15:20:48 UTC)
was waiting for the guest command. Host `Get-ScheduledTask` and
`Get-ScheduledTaskInfo` calls fail because CIM access is denied, so the controller
process and checkpoint state cannot currently be confirmed. Do not overlap or
restart this request. Aggregate Windows 11 ApplicationsBatch1 acceptance remains
open. This uncertainty does not block local repository validation, package
source review or Pester planning tests. Estimate ranges remain **37-57 / 52-67 /
19-24 / 25-35 / 8-12**, exact **141-195**, rounded **140-195/about 170**. See
[structured controller-state evidence]
(../archive/evidence/applications-batch1-win11-controller-state-unresolved-2026-10-24-1533.json).
## JoeWare Unlock exact-source acquisition blocked before transfer, 2026-10-24 15:35 UTC

The approved bounded downloader was run for Unlock alone into a new workspace
`.local` review directory. It failed while retrieving the official `versions.txt`
source because the local shell could not resolve the JoeWare hostname. Failure
occurred before the optional-email form submission; no payload bytes arrived, the
new directory remains empty, and no partial archive exists. No extraction,
execution, Active Directory contact, VM use or Windows change occurred. Retry the
same publisher source when local DNS works; do not substitute a mirror. This is
an acquisition/network blocker, not a licensing gate. No whole legacy outcome
closed and estimates remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**141-195**, rounded **140-195/about 170**. See [structured acquisition
record](../archive/evidence/joeware-unlock-publisher-acquisition-dns-block-2026-10-24-1535.json).
## JoeWare AdQueueLoop, MemberOf and OldCmp source review, 2026-10-24 15:36 UTC

The publisher's version list agrees with official product/usage identities for
AdQueueLoop 02.00.00 (2006-03-23), MemberOf 02.03.00 (2006-06-10), and OldCmp
01.05.00 (2004-12-28). AdQueueLoop polls an AD replication queue with optional
file/CSV output. MemberOf queries membership for a user, group or computer and
retrieves primary-group data separately. OldCmp can report, disable, move or
delete old AD objects. Its instructions cap actions at 10 by default, require
objects to be disabled before deletion, include explicit unsafe/for-real gates,
and exclude domain controllers from modification. Preserve report-only as the
first functional scenario. Exercise any mutation only on disposable AD objects
with exact recovery. Publisher platform claims are historical and do not
establish Windows 11 support. Exact ZIPs, hashes and member inventories remain
open; no download form was submitted and no binary, VM or AD was touched. No
license gate applies. No whole outcome closes; estimates remain **37-57 /
52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**, rounded **140-195/about
170**. See [structured review](../archive/evidence/joeware-adqueueloop-memberof-oldcmp-source-review-2026-10-24-1536.json),
[publisher version list](https://joeware.net/freetools/versions.txt),
[AdQueueLoop usage](https://joeware.net/freetools/tools/adqueueloop/usage.htm),
[MemberOf usage](https://joeware.net/freetools/tools/memberof/usage.htm), and
[OldCmp page](https://joeware.net/freetools/tools/oldcmp/index.htm).
## JoeWare FindExpAcc, GCChk and UserName source review, 2026-10-24 15:37 UTC

The official publisher versions file and product pages agree on FindExpAcc
01.01.00 (2005-06-19), GCChk 01.03.00 (2004-08-30), and UserName 01.00.00
(2002-10-08). FindExpAcc queries expired/expiring directory account data;
GCChk compares Global Catalog records and warns that read permissions affect
missing-object findings. UserName reads current-user directory identity formats
and can write optional command/batch output. Product pages list Windows 2000,
Server 2003 and XP; Windows 11 support is not established. Exact artifacts,
hashes and archive members remain open. No download form, AD, VM or executable
was used. License does not block RIDE migration. No whole outcomes close;
estimates remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**,
rounded **140-195/about 170**. See [structured source evidence]
(../archive/evidence/joeware-findexpacc-gcchk-username-source-review-2026-10-24-1537.json),
[FindExpAcc](https://joeware.net/freetools/tools/findexpacc/index.htm),
[GCChk](https://joeware.net/freetools/tools/gcchk/index.htm),
[UserName](https://joeware.net/freetools/tools/username/index.htm), and
[publisher versions list](https://joeware.net/freetools/versions.txt).
## JoeWare FindPDC, SidToName and GetUserInfo source review, 2026-10-24 15:39 UTC

The publisher version file and product/usage pages agree on FindPDC 01.00.01
(2001-09-28) and SidToName 02.00.00 (2003-03-03). FindPDC checks name
resolution and repeated NetLogon/PDC response; SidToName resolves a SID locally
or against a selected computer. The versions list records GetUserInfo 02.07.00
(2003-09-27), and the publisher index describes its user-information query, but
product-page correlation remains open. No publisher form, endpoint, AD, VM or
binary was contacted. The historical OS claims do not establish Windows 11.
Exact archives/hashes/member inventories remain open; licensing is not a gate.
No whole legacy outcome closed. Ranges remain **37-57 / 52-67 / 19-24 / 25-35 /
8-12**, exact **141-195**, rounded **140-195/about 170**. See [structured
evidence](../archive/evidence/joeware-findpdc-sidtoname-getuserinfo-source-review-2026-10-24-1539.json),
[FindPDC page](https://joeware.net/freetools/tools/findpdc/index.htm),
[SidToName usage](https://joeware.net/freetools/tools/sidtoname/usage.htm), and
[publisher versions file](https://joeware.net/freetools/versions.txt).
## JoeWare AccExp, ATSN and Auth source review and DNS-blocked acquisition, 2026-10-24 15:43 UTC

The publisher version list and product/usage pages identify AccExp 01.01.00
(2002-08-04), ATSN 01.00.00 (2004-03-27), and Auth 01.01.00 (2001-08-17).
AccExp reads or changes account expiration, not password expiration; changing
it requires appropriate account rights. ATSN queries IP-to-site/subnet data
from Active Directory and can read an input list or write a report. Auth tests
a user credential; any functional test must use an isolated disposable account,
not live credentials or a production directory. The publisher's old platform
lists do not establish Windows 11 support.

The approved download-only retry failed before the version-list request
completed because local DNS could not resolve the JoeWare host. No publisher
form was submitted, no bytes were received, and the destination contained no
files. No execution, directory/endpoint contact, VM, Defender or Windows change
occurred. License review is not a migration gate. Resolved: source version and
purpose observations only. Deferred: exact ZIPs, local SHA-256, member
inventories, isolated behavior and Windows target support. No whole outcome
closes; estimates remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**141-195**, rounded **140-195/about 170**. See [structured evidence]
(../archive/evidence/joeware-accexp-atsn-auth-source-and-acquisition-review-2026-10-24-1543.json),
[publisher versions list](https://joeware.net/freetools/versions.txt),
[AccExp usage](https://joeware.net/freetools/tools/accexp/usage.htm),
[ATSN page](https://www.joeware.net/freetools/tools/atsn/index.htm),
[ATSN usage](https://joeware.net/freetools/tools/atsn/usage.htm), and
[Auth page](https://joeware.net/freetools/tools/auth/index.htm).

## ApplicationsBatch1 Windows 11 result and dependency blockers, 2026-10-24 15:43 UTC

RIDE-Win11-Test request cd4fcbdd21ed4b1081fcaede9c1e6075 completed with
Pester 332 passed, zero failed and one skipped. Nine of eleven package rows
passed: Thunderbird, VS Code, Firefox, DB Browser for SQLite, Autopsy, Chrome,
Wireshark, Signal and TMOG. User profile/data fixtures remained preserved for
Thunderbird, Chrome and Signal.

Gpg4win 5.1.1 failed in the limited-user context with 0xC0000005; its cause
remains unconfirmed. Phoenix Protector failed with MSI exit 1603. Its MSI log
names VSDFrameworkVersion=2.0.50727 and requires .NET Framework 2.0. Microsoft
documents that .NET Framework 3.5 supplies the CLR 2.0 layer on Windows 11
25H2 and earlier; on build 26300 this is a shared Windows feature prerequisite,
not Phoenix-owned uninstall state. Do not enable it implicitly through Phoenix.
Implement the prerequisite dependency or a fail-closed gate before retesting.
Catalog-driven prerequisite installation is approved for v3, but feature
activation/recovery acceptance remains separate.

The v0.14.2 runner now incrementally writes package rows and correctly separates
coordinator and limited-user evidence paths. All eleven rows were collected;
cleanup, collection and evidence export reported no errors. No whole legacy
package outcome closes. Windows Server 2025 and remaining target acceptance
stay open. Estimates remain **37-57 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**141-195**, rounded **140-195/about 170**. See [structured evidence]
(../archive/evidence/applications-batch1-win11-follow-up-2026-10-24-1543.json),
[Microsoft Framework versions and CLR dependencies](https://learn.microsoft.com/en-us/dotnet/framework/install/versions-and-dependencies),
and [Microsoft .NET 3.5 on Windows 11](https://learn.microsoft.com/en-us/dotnet/framework/install/dotnet-35-windows-11).
## Phoenix Protector shared .NET Framework prerequisite gate, 2026-10-24 15:53 UTC

The Windows 11 ApplicationsBatch1 run found Phoenix Protector's MSI launch
condition requires .NET Framework 2.0 and exited 1603 on the guest without that
prerequisite. Microsoft documents that .NET Framework 2.0, 3.0 and 3.5 use the
CLR 2.0 runtime and that .NET Framework 3.5 supplies the earlier layers. The
catalog now declares PrerequisiteDotNetFramework35; the package handler
checks the shared NDP\v3.5\Install registry value before artifact
acquisition and fails closed if the feature is absent or the state cannot be
read. It never enables the feature or treats it as package-owned recovery.

PhoenixPackage.Tests.ps1 passed 4/4 on PowerShell 7.6.5/Pester 5.7.1, including
a mocked missing-prerequisite case that proves no download or installer starts,
and a mocked present-prerequisite dispatch case. Windows PowerShell 5.1
repository validation passed for 409 operations, 8 groups, 5 profiles and 272
PowerShell files; generated operation documentation is current. No registry
state, feature, installer, VM or target metadata was changed. The exact Phoenix
MSI launch condition with the feature enabled remains to be verified on a
disposable guest. No whole legacy outcome closes; estimates remain **37-57 /
52-67 / 19-24 / 25-35 / 8-12**, exact **141-195**, rounded **140-195/about
170**. See [structured evidence]
(../archive/evidence/phoenix-dotnet35-prerequisite-gate-implementation-2026-10-24-1553.json),
[Microsoft CLR/version mapping](https://learn.microsoft.com/en-us/dotnet/framework/install/versions-and-dependencies),
and [.NET Framework 3.5 on Windows 11](https://learn.microsoft.com/en-us/dotnet/framework/install/dotnet-35-windows-11).

## Phoenix prerequisite current-source regression, 2026-10-24 15:57 UTC

The focused Phoenix Protector suite was rerun against the current source with
PowerShell 7.6.5 and Pester 5.7.1: **4 passed, 0 failed, 0 skipped**. The
missing-prerequisite case still stops before acquisition or installer dispatch;
the present-prerequisite case permits the mocked installer path. The run used
no VM, registry, artifact, installer or Windows feature. A separate attempt to
invoke the focused suite through Windows PowerShell 5.1 stopped before Pester
output with `AuthorizationManager check failed`, so it produced no PS 5.1 test
result. Previously completed PS 5.1 repository validation remains valid but is
not a substitute for that focused test. Resolved: current-source focused
regression. Retired/excluded: none. Deferred: focused PS 5.1 execution in an
authorized runner and exact Phoenix MSI behavior with the prerequisite enabled
on a disposable guest. Partial: no whole legacy outcome closes. Estimates
remain **37-57 / 50-65 / 19-24 / 25-35 / 8-12**, exact **139-193**, rounded
**140-195/about 170**. See [structured evidence]
(../archive/evidence/phoenix-prerequisite-current-source-regression-2026-10-24-1557.json).

## Current-source package and license-planning regression, 2026-10-24 16:04 UTC

The combined Phoenix, application-package and license-planning suites passed
**130/130** on PowerShell 7.6.5/Pester 5.7.1, with TestRegistry disabled and
Windows integration excluded. All ten Sysinternals install plans remain
available while technical acceptance is pending; `NeedsReview` is informational
for package planning and is not a licensing migration gate. This follows the
prior RIDE v2 specialist approval for Sysinternals in RIDE's direct
download-and-install workflow. Phoenix missing/present prerequisite paths also
remain covered.

During this run, ApplicationsBatch4 completed. Archived Windows 11 evidence
confirms ControllerStatus Passed, Pester 332 passed/0 failed/1 skipped, Slack
and Discord package lifecycle/recovery passed, and cleanup/collection/export
reported no errors. The queue record is now absent; no duplicate was submitted.
Resolved: local package/planning regression and ApplicationsBatch4 acceptance.
Retired/excluded: none in this run. Deferred: focused PS 5.1 Pester execution
and remaining Windows package acceptance. Partial: no whole legacy package
outcome closes. Estimates remain **37-57 / 50-65 / 19-24 / 25-35 / 8-12**,
exact **139-193**, rounded **140-195/about 170**. See [package regression
evidence](../archive/evidence/current-source-package-and-license-planning-regression-2026-10-24-1604.json)
and [ApplicationsBatch4 evidence](../archive/evidence/applications-batch4-win11-follow-up-2026-10-24-1600.json).
## ExifTool, Zimmerman Hasher and ShimCacheParser scope decisions, 2026-10-24 16:00 UTC

The user kept both ExifTool Windows release tracks open. The existing 13.59
catalog candidate remains provisional; 13.55 is the latest production release,
and 13.59 is the publisher-linked Windows ZIP labeled development. Artifact
acquisition, byte verification and intended track selection remain pending.

The user deferred only Zimmerman Hasher until publisher clarification or exact
archive evidence resolves its .NET framework. The other 25 members of the
accepted 26-member selection remain in scope. No framework is inferred from the
conflicting Hasher page label and `/net/` link.

The user retired ShimCacheParser from v3 because its pinned implementation
requires Python 2 and no supported migration route was selected. Preserve the
source review as historical evidence; do not port it or substitute a parser.
Retired: one package legacy outcome. No artifact or tool was acquired or run,
and no Windows, VM, or Defender state changed. The package estimate changes from
51-66 to 50-65 and the exact total from 140-194 to 139-193; rounded total remains
140-195/about 170. See the [decision record](decision-session-2026-10-17.md#exiftool-zimmerman-hasher-and-shimcacheparser-decisions-2026-10-24).

## Sysinternals current-source local lifecycle regression, 2026-10-24 16:23 UTC

The whole-suite and independent-product Sysinternals package suites passed
**79/79** on PowerShell 7.6.5/Pester 5.7.1 with TestRegistry disabled and
Windows integration excluded. They cover pinned digest rejection, repeat,
removal/recovery and preservation of conflicting, modified or independently
owned files using synthetic payloads. No Sysinternals executable ran, no
artifact was acquired, and no Defender, registry, VM or Windows state changed.

An initial attempt using Pester's sandbox AppData temp root produced 40 passes
and 39 filesystem failures when atomic moves were denied. The identical suites
passed 79/79 when rerun with their temp root under `.local`; record the first
attempt as a test-environment issue, not a package failure. Licensing remains
settled by the prior RIDE v2 specialist approval for RIDE's direct-download-
and-install workflow and is not a migration gate. Defender-detected tools stay
separately excluded. Resolved: current-source local lifecycle regression.
Retired/excluded: none beyond existing Defender security exclusions. Deferred:
Windows 11/Server package and functional behavior acceptance. Partial: no whole
legacy outcome closes. Estimates remain **37-57 / 50-65 / 19-24 / 25-35 / 8-12**,
exact **139-193**, rounded **140-195/about 170**. See [structured evidence]
(../archive/evidence/sysinternals-current-source-local-lifecycle-regression-2026-10-24-1623.json).

## WinPmem production asset source review and package candidate, 2026-10-24 16:27 UTC

The user-required `package.winpmem` candidate stages one pinned x64 executable
as a portable file. It has no supported targets and does not execute WinPmem,
load a driver, create a driver service or capture memory. The official release
page labels v4.1.dev1 a pre-release with test-signed new drivers and explicitly
directs production users to the separate
`go-winpmem_amd64_1.0-rc2_signed.exe` asset. The official asset listing gives
SHA-256 `86691bb4af2c17dd9ec4834c04a99ad51e04f780a07d1b05bc382a5d1892e0c4`.
The publisher identifies the source and signed binaries as Apache-2.0. This is
the asset file identity, not a claim that the 4.1 pre-release drivers are
production-ready.

The direct publisher download failed before receiving bytes because this host
could not resolve `github.com`; no partial file exists, so the publisher hash
and Authenticode signer remain unverified locally. Focused candidate tests
passed **3/3**, and repository validation passed for 410 operations, 8 groups,
5 profiles and 273 PowerShell files with generated operation documentation
current. No driver, utility, VM, Defender or Windows state was touched.

Resolved: source/asset identity, published hash and Apache license reference;
deployment-only candidate with exact file lifecycle metadata. Licensing is not
a migration blocker. Retired/excluded: none. Deferred: local bytes/signature,
driver compatibility and load/unload recovery, reboot recovery, functional
behavior and Windows 11/Server acceptance. Partial: no legacy outcome closes
and no target is declared. Estimates remain **37-57 / 50-65 / 19-24 / 25-35 /
8-12**, exact **139-193**, rounded **140-195/about 170**. See [structured
evidence](../archive/evidence/winpmem-production-asset-source-review-and-candidate-2026-10-24-1627.json),
the [publisher release page](https://github.com/Velocidex/WinPmem/releases),
the [exact release asset listing](https://github.com/Velocidex/WinPmem/releases/expanded_assets/v4.1.dev1),
and the [publisher license](https://github.com/Velocidex/WinPmem/blob/master/LICENSE).

## WinPmem synthetic file-lifecycle regression, 2026-10-24 16:31 UTC

The focused `WinPmemPackage.Tests.ps1` suite now passes **4/4** on PowerShell
7.6.5/Pester 5.7.1. The added case uses inert synthetic bytes to exercise the
catalog candidate's exact-file staging, healthy-state detection, owned-file
removal and preservation of operator-owned content. Repository validation
passed for 410 operations, 8 groups, 5 profiles and 273 PowerShell files; the
generated operation documentation is current.

No publisher bytes were used and no WinPmem executable, driver, VM, Defender or
Windows state was touched. The earlier publisher download attempt remains
blocked at local DNS, so the official hash and Authenticode signer are not
locally verified. Licensing is not a migration blocker. Resolved: candidate
file lifecycle with synthetic input. Retired/excluded: none. Deferred: exact
publisher bytes/signature, driver load/unload and reboot recovery, functional
capture behavior, and Windows 11/Server acceptance. Partial: no legacy outcome
closes and no target is supported. Estimates remain **37-57 / 50-65 / 19-24 /
25-35 / 8-12**, exact **139-193**, rounded **140-195/about 170**. See
[structured evidence](../archive/evidence/winpmem-synthetic-file-lifecycle-regression-2026-10-24-1631.json)
and the [WinPmem source/candidate evidence](../archive/evidence/winpmem-production-asset-source-review-and-candidate-2026-10-24-1627.json).

## Sysinternals practical license administration correction, 2026-10-24 16:35 UTC

The user corrected an overly strict interpretation of Sysinternals terms. RIDE
downloads Sysinternals directly from Microsoft and installs it on user-supported
devices; RIDE does not publish or transfer copies. The prior RIDE v2 review by a
license specialist approved Sysinternals for this workflow, and the user's
disposition is that there are no legal issues using Sysinternals in RIDE.
Licensing is settled: do not use generalized distribution analysis to create a
new legal review, acceptance gate, or migration blocker. The ten exact suite and
product versions remain `Reviewed`. Defender-detected items stay excluded under
the separate security disposition. Remaining Sysinternals work is technical
Windows lifecycle, recovery, functional behavior and target acceptance. This
correction closes no additional legacy outcome, so estimates remain **37-57 /
50-65 / 19-24 / 25-35 / 8-12**, exact **139-193**, rounded
**140-195/about 170**. See the [dated disposition record](../archive/evidence/sysinternals-license-practical-administration-correction-2026-10-24-1635.json).

## Client components and OpenSSH Server current-source regression, 2026-10-24 16:38 UTC

The current-source preparation/lifecycle tests for client components and the
OpenSSH Server observer/lifecycle tests passed **65/65** on PowerShell 7.6.5
with Pester 5.7.1. The run disabled the unused TestRegistry plugin and excluded
WindowsIntegration tests. Provider operations were mocked; no Windows feature,
capability, service, firewall rule, registry value, VM or supported-target state
changed. The first invocation failed during Pester setup because the sandbox
denied registry access while that unused plugin was enabled; no test bodies ran
in that attempt. The corrected rerun passed all tests.

The RIDE-Win11-Test queue still records ApplicationsBatch5 request
`929ea539ce89404d8ed0d50a8fbbac52`, submitted at 16:28 UTC. No guest result was
accessible at this check, so no overlapping VM request was submitted. Native
component servicing, exact recovery, and Windows 11/Server 2025 acceptance remain
deferred. This run closes no legacy outcome; estimates remain **37-57 / 50-65 /
19-24 / 25-35 / 8-12**, exact **139-193**, rounded **140-195/about 170**. See
the [structured evidence](../archive/evidence/client-components-openssh-current-source-regression-2026-10-24-1638.json).
## Microsoft Visual C++ v14 ApplicationsBatch5 Windows 11 acceptance, 2026-10-24 16:42 UTC

RIDE-Win11-Test request `929ea539ce89404d8ed0d50a8fbbac52` completed with
controller status Passed on Windows 11 Enterprise Evaluation build 26300. Guest
validation passed for 410 operations, 8 groups, 5 profiles and 273 PowerShell
files; generated operation documentation was current. Pester 5.7.1 reported
342 passed, 0 failed and 1 skipped of 343 tests. The `package.vcredist-v14-x64`
scenario passed at 14.51.36247.0, including managed install, minimum registered
and `System32/vcomp140.dll` checks, repeat install, removal/repeat removal, and
saved-run recovery. Collection, cleanup and evidence export reported no errors.

The result is bounded: recovery ensures the shared runtime is present using the
catalog-pinned current version; exact recovery of a previously installed older
version is unavailable and no downgrade is attempted. The catalog already
declares Windows 11 support; Server support remains undeclared. Although the
guest prints a generic instruction to restore the clean checkpoint, the
registered host controller invokes `Reset-RideAutomationVm` in its `finally`
path against the pinned checkpoint. The request status is Passed with
`CleanupError` null, and no runtime blocked marker exists, so clean-checkpoint
recovery completed. The next pre-existing ApplicationsBatch5 request
`919bd92ac3ab4b358906230eae728169` was already running; at the latest check its
guest result was not yet available. Its normal controller path validates and
resets the checkpoint before dispatch. No additional request was submitted.

This is acceptance for a new v3 runtime dependency, not a completed legacy
package outcome. No legacy outcome closed; estimates remain **37-57 / 50-65 /
19-24 / 25-35 / 8-12**, exact **139-193**, rounded **140-195/about 170**. See
the [structured Windows 11 evidence](../archive/evidence/vcredist-applicationsbatch5-win11-acceptance-2026-10-24-1642.json)
and [operator guidance](../application-packages.md#microsoft-visual-c-v14-redistributable-x64).
## ApplicationsBatch5 repeated pass and ApplicationsBatch6 queue, 2026-10-24 16:51 UTC

A second serialized ApplicationsBatch5 request, `919bd92ac3ab4b358906230eae728169`,
also passed on Windows 11 build 26300. It reported 342/343 Pester tests passed,
zero failures and one skip; `package.vcredist-v14-x64` 14.51.36247.0 again passed
install, minimum registered/DLL version, repeat, removal and saved-run recovery.
The registered controller reset the pinned clean checkpoint after both runs;
both results have `CleanupError` null. The only runtime limit remains exact
recovery of an older previously installed version; no downgrade is attempted.
No legacy outcome closes and estimates remain unchanged.

After confirming the queue empty, checkpoint reset successful and no runtime
blocked marker, ApplicationsBatch6 was submitted through the existing registered
controller without a new UAC prompt. Request `f7b20b6524bf4f99a80a1f19962b7cfd`
selects the 12 Artcraft machine-scope packages: PhotoCraft, VectorCraft,
FilmCraft, LightCraft, PDFCraft, EffectCraft, DesignCraft, WordCraft, SoundCraft,
DeckCraft, CADCraft and GridCraft. It is running with no guest result yet.
None of these packages is among the separately excluded Defender-detected
NirSoft/x64 tools. This is an acceptance request, not a result; do not promote
support or close outcomes until the correlated guest evidence and controller
checkpoint cleanup are inspected. No legacy outcome closed; estimates remain
**37-57 / 50-65 / 19-24 / 25-35 / 8-12**, exact **139-193**, rounded
**140-195/about 170**. See [repeated v14 acceptance evidence](../archive/evidence/vcredist-applicationsbatch5-win11-acceptance-2026-10-24-1642.json)
and [ApplicationsBatch6 queue evidence](../archive/evidence/applications-batch6-win11-queue-submission-2026-10-24-1651.json).

## ApplicationsBatch6 live-run status recheck, 2026-10-24 17:05 UTC

The registered ApplicationsBatch6 request `f7b20b6524bf4f99a80a1f19962b7cfd`
remains in `queue/running`. The host controller's exclusive `runtime/worker.lock`
handle is still held, so the request is active. Its controller log last advanced
at 16:57:22 UTC and is waiting for the guest command; no correlated guest result
exists yet. The result directory has no error log content and no
`runtime/blocked.json` marker. Read-only Task Scheduler/CIM inspection is denied
to this non-elevated session. No replacement or overlapping VM request was sent,
and no fresh UAC prompt was requested. This is not a pass, failure, or checkpoint
recovery result; await the same request, then inspect guest results and controller
cleanup before continuing to ApplicationsBatch7. No legacy outcome closed; ranges
remain **37-57 / 50-65 / 19-24 / 25-35 / 8-12**, exact **139-193**, rounded
**140-195/about 170**. See the [live controller evidence](../archive/evidence/applications-batch6-win11-live-controller-check-2026-10-24-1705.json)
and [queue submission evidence](../archive/evidence/applications-batch6-win11-queue-submission-2026-10-24-1651.json).

## ApplicationsBatch6 serialized queue recheck, 2026-10-24 17:15 UTC

A read-only queue inspection found the active request f7b20b6524bf4f99a80a1f19962b7cfd
still in queue/running with the worker's exclusive lock held and no result. A
second same-scope ApplicationsBatch6 request, 9f6bec44b84c4855917bd6913b0b792f,
is present in queue/pending (submitted 16:53:16 UTC). Preserve it and let the
registered serialized worker drain it; do not enqueue Batch7 until both requests
are terminal and the pinned checkpoint is verified. Task Scheduler/CIM inspection
remains unavailable without host elevation, so no direct VM state is claimed. No
runtime blocked marker is present and no fresh UAC prompt was requested. Neither
request has a guest result yet; no legacy outcome closes and estimates remain
**37-57 / 50-65 / 19-24 / 25-35 / 8-12**, exact **139-193**, rounded
**140-195/about 170**. See the [serialized queue evidence](../archive/evidence/applications-batch6-serialized-queue-recheck-2026-10-24-1715.json).

## ApplicationsBatch6 first Windows 11 install pass and lifecycle gap, 2026-10-24 17:22 UTC

Request `f7b20b6524bf4f99a80a1f19962b7cfd` passed on RIDE-Win11-Test,
Windows 11 Enterprise Evaluation build 26300, with guest PowerShell 5.1.26100.9444.
Validation passed 410 operations, eight groups, five profiles and 273 PowerShell
files. Pester 5.7.1 passed 347/348 tests, failed zero and skipped one. All twelve
Artcraft machine-scope packages installed at their currently pinned versions;
the run also checked repeat-install idempotence and restored each original
absence through the saved install run. The controller result is `Passed`, with
`CleanupError`, `CollectionError` and `EvidenceExportError` all null. The
registered worker's `finally` path resets the configured clean checkpoint, the
blocked marker is absent, and the next serialized request began. This verifies
Windows 11 install and saved-install recovery, but not uninstall: review of the
runner snapshot shows the 12 machine-scope packages did not enter its removal
branch. Keep their Windows 11 target as a candidate and acceptance pending.

Corrected `Invoke-RideApplicationBatch.ps1` to check exact pinned Artcraft
versions and include removal preview, removal, repeat removal, saved removal
recovery and saved install recovery in both ApplicationsBatch6 and
ApplicationsBatch7. The runner is now 0.14.5. PowerShell parsing passed;
focused Artcraft package/controller Pester passed 118, failed zero, skipped two.
A second request
`9f6bec44b84c4855917bd6913b0b792f` was already running from the prior runner
snapshot. Updated request `6a896d6621304fdfbbb89e702488239f` is queued behind it
for the corrected full lifecycle. Do not promote Windows 11 support until the
updated guest result passes. No legacy outcome closes; estimate ranges remain
**37-57 / 50-65 / 19-24 / 25-35 / 8-12**, exact **139-193**, rounded
**140-195/about 170**. See the [first-run evidence](../archive/evidence/applications-batch6-win11-first-run-2026-10-24-1715.json),
[live second-run evidence](../archive/evidence/applications-batch6-serialized-queue-recheck-2026-10-24-1715.json),
and [corrected runner evidence](../archive/evidence/applications-batch6-runner-lifecycle-coverage-2026-10-24-1722.json).

## ApplicationsBatch7 lifecycle gap correction, 2026-10-24 17:28 UTC

Review of the old runner snapshot showed that the separately routed current-user
ArtCraft Launcher also missed the removal branch: package-level tests exercised
install/repeat and saved install recovery, but not uninstall or saved removal
recovery. Expanded runner 0.14.5 to apply the same pinned-version check and full
install/uninstall/recovery sequence to both ApplicationsBatch6 and
ApplicationsBatch7. `Invoke-RideApplicationBatch.ps1 -Version` reports 0.14.5;
PowerShell parsing passed; focused Artcraft/controller Pester passed 118/120
(zero failures, two skips). The old-snapshot Batch6 request
`9f6bec44b84c4855917bd6913b0b792f` remains in progress, and corrected Batch6
request `6a896d6621304fdfbbb89e702488239f` remains queued for dispatch after it.
Do not schedule Batch7 until the serialized Batch6 queue finishes and checkpoint
recovery is verified. No VM or Windows state changed in this local source/test
run. No legacy outcome closes; estimates remain **37-57 / 50-65 / 19-24 / 25-35 /
8-12**, exact **139-193**, rounded **140-195/about 170**. See the [runner
coverage evidence](../archive/evidence/applications-batch6-runner-lifecycle-coverage-2026-10-24-1722.json).

## ApplicationsBatch6 second install-only pass and corrected lifecycle run, 2026-10-24 17:31 UTC

The second old-snapshot request `9f6bec44b84c4855917bd6913b0b792f` passed on
Windows 11 Enterprise Evaluation build 26300. Guest validation passed 410
operations, eight groups, five profiles and 273 PowerShell files; Pester 5.7.1
passed 347/348, failed zero and skipped one. All twelve pinned versions installed,
repeat installation was idempotent, and saved install recovery restored original
absence. The controller result is `Passed` with all error fields null; it reset the
clean checkpoint and immediately started the next serialized request. Together,
requests `f7b20b6524bf4f99a80a1f19962b7cfd` and `9f6bec44b84c4855917bd6913b0b792f`
confirm install/repeat/install-restore only; both snapshots used runner 0.14.3
and omitted uninstall coverage.

Corrected request `6a896d6621304fdfbbb89e702488239f` is now running from snapshot
runner 0.14.4, which adds pinned-version checks, removal preview, RIDE uninstall,
repeat removal, saved removal recovery and saved install recovery for Batch6. The
current checkout is runner 0.14.5, which extends the same checks to Batch7. The
focused Artcraft/controller suites pass 118/120 (zero failures, two skips), the
PowerShell parser passes, and `-Version` reports 0.14.5. Do not promote Windows 11
support until corrected Batch6 acceptance passes; dispatch Batch7 only after the
serialized queue and checkpoint are clear. No legacy outcome closes; estimates
remain **37-57 / 50-65 / 19-24 / 25-35 / 8-12**, exact **139-193**, rounded
**140-195/about 170**. See the [second-pass evidence](../archive/evidence/applications-batch6-win11-second-install-only-pass-2026-10-24-1726.json)
and [runner coverage evidence](../archive/evidence/applications-batch6-runner-lifecycle-coverage-2026-10-24-1722.json).

## ApplicationsBatch7 serialized Windows 11 request, 2026-10-24 17:33 UTC

Queued request `2ce98ec80d5c45fe8826c384b81de378` for the single current-user
ArtCraft Launcher MSI through the existing RIDE-Win11-Test controller, behind
corrected ApplicationsBatch6 request `6a896d6621304fdfbbb89e702488239f`. It
uses the pinned `RIDE-clean-test-base` checkpoint and a 180-minute request window.
The registered worker remains serialized; Batch7 is pending and has not started.
Runner 0.14.5 will check the pinned launcher version, install/repeat/uninstall,
and both saved-run recovery paths, without launching the app. The package remains
a Windows 11 candidate with support pending until its result passes. It is outside
the separately excluded Defender utility set. The local `NeedsReview` asset/brand
record is informational and does not gate package migration. No new UAC prompt,
Windows state change, or legacy-outcome closure occurred. Estimates remain
**37-57 / 50-65 / 19-24 / 25-35 / 8-12**, exact **139-193**, rounded
**140-195/about 170**. See the [queue evidence](../archive/evidence/applications-batch7-win11-queue-submission-2026-10-24-1732.json).

## ApplicationsBatch6 full Windows 11 lifecycle acceptance, 2026-10-24 17:38 UTC

Corrected request `6a896d6621304fdfbbb89e702488239f` passed on RIDE-Win11-Test,
Windows 11 Enterprise Evaluation build 26300, using runner snapshot 0.14.4.
All twelve pinned Artcraft packages passed exact-version verification, RIDE install,
repeat install, removal preview, RIDE uninstall, repeat removal, saved removal
recovery and saved install recovery. Pester 5.7.1 passed 347/348 (zero failures,
one skip). The controller reported no run, cleanup, collection or evidence-export
errors and restored checkpoint `RIDE-clean-test-base`. Windows 11 support is now
declared for these twelve package operations; Server targets and functional-launch
behavior remain unverified. No legacy outcome closes, so the package estimate and
total ranges remain unchanged. ArtCraft Launcher ApplicationsBatch7 request
`2ce98ec80d5c45fe8826c384b81de378` has started with runner 0.14.5 and remains
pending acceptance. See the [structured Batch6 evidence](../archive/evidence/applications-batch6-win11-full-lifecycle-acceptance-2026-10-24-1738.json).

Local post-promotion validation passed catalog/schema generation (410 operations,
8 groups, 5 profiles, 273 PowerShell files) and Artcraft package metadata Pester
(6/6). A broader local focused run could not fully execute in this sandbox: 56 of
203 Catalog/controller tests hit denied registry or sandbox AppData temp-path
access; it passed 145 and skipped 2. This environment limitation does not alter
the VM result, whose selected Pester suite passed 347/348 with one skip.
## Sysinternals direct download-and-install disposition reaffirmed, 2026-10-24 17:48 UTC

The user reaffirmed that the prior RIDE v2 license-specialist review approved
Sysinternals for RIDE's direct Microsoft download-and-install workflow. RIDE does
not transfer or publish copies; the user's disposition is that there are no legal
issues and no additional license or generalized redistribution gate applies to
package migration. Defender-detected tools remain separate exclusions. Windows
lifecycle and target acceptance are technical blockers only. This decision closes
no additional legacy outcome and does not change estimates. See the [decision
evidence](../archive/evidence/sysinternals-direct-download-install-approval-reaffirmed-2026-10-24-1748.json).
## ApplicationsBatch7 Windows 11 launcher detection failure, 2026-10-24 17:50 UTC

Request `2ce98ec80d5c45fe8826c384b81de378` ran on Windows 11 Enterprise build
26300 using runner 0.14.5. Catalog validation passed; Pester passed 347/348 with
zero failures and one skip. The publisher MSI returned an accepted success exit,
but `Get-RideInstalledPackage` did not detect ArtCraft Launcher afterward. The
runner stopped before uninstall or recovery, so no lifecycle checks passed and no
Windows 11 support is promoted for the launcher. The controller completed cleanup
and restored `RIDE-clean-test-base`; cleanup, collection and evidence export had
no errors, and no blocked marker remains. Diagnose user-scope MSI registration or
detection before a corrected retry. This closes no legacy outcome; all estimates
remain unchanged. See the [structured failure evidence](../archive/evidence/applications-batch7-win11-full-lifecycle-failure-2026-10-24-1750.json).

## ApplicationsBatch7 diagnostic lifecycle retry queued, 2026-10-24 17:55 UTC

After the first Windows 11 attempt returned MSI success but no RIDE-detectable
launcher registration, runner 0.14.7 was prepared to record the bounded per-user
vendor marker, uninstall registry entries, expected install files and recent MSI
installer events if detection fails again. Request
`1a0ec19a4e8e4517ad800bf3ac9f21dc` is running through the existing registered
RIDE-Win11-Test worker against `RIDE-clean-test-base`; the initial failure's
checkpoint cleanup succeeded and no blocked marker was present. The launcher
remains a Windows 11 candidate. No legacy outcome closes while this retry is
pending, so estimates remain unchanged. See the [queue evidence](../archive/evidence/applications-batch7-diagnostic-retry-queue-2026-10-24-1755.json).

## SysinternalsProducts Windows 11 acceptance queued, 2026-10-24 17:57 UTC

Reverified all nine prepared Sysinternals ZIPs against their recorded archive hashes
and confirmed every manifest path is present. The fixed selection contains zero
Defender-detected tools; no utility execution or EULA acceptance is part of this
file-lifecycle suite. Prior RIDE v2 license-specialist approval governs direct
Microsoft download-and-install, so no license gate applies. Request
`ae3bb5af12ee4b329c88cc51ff3d2bc2` is pending behind ApplicationsBatch7 diagnostic
retry `1a0ec19a4e8e4517ad800bf3ac9f21dc` on the serialized RIDE-Win11-Test worker.
No guest result or target support is claimed yet. No legacy outcome closes; all
estimate ranges remain unchanged. See the [queue and current-hash evidence](../archive/evidence/sysinternals-products-win11-queue-submission-2026-10-24-1757.json).
