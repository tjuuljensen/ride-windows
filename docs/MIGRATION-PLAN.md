# Legacy-to-v3 Migration Plan

## Purpose and inventory

This is the batch inventory for migrating the selectable commands in `legacy/v2/default.preset` to the v3 catalog and profiles. It includes active and commented selectors. The inventory below contains **732 distinct legacy function names** referenced by the preset across **30 family groups**. Active selectors are marked **default**. Paired legacy commands should become states of one v3 operation only when inspection confirms that they control the same setting or package.

The catalog supports `RegistryValue`, `RegistryKeySet`, `Package`, `DefenderExclusion`, `WindowsService`, `BackgroundAppOverrides`, `BootConfiguration`, and `NetworkProfile`. Migration of the other groups requires the minimum additional operation kinds and focused handlers for Windows components, account/configuration changes, files/assets, and system tasks. Each handler must participate in planning, `ShouldProcess`, state capture or declared compensating behavior, status/reporting, and partial-failure reporting.

## PowerShell model and script follow-ups

Repository-specific models belong in `docs/models/`; `docs/repository-portfolio/`
is reserved for network-devices governance. Maintained PowerShell scripts and
exported commands follow the [native help and version contract](models/script-repository-model.md).

The [8 October 2026 PowerShell walkthrough](migrations/powershell-script-walkthrough.md)
records every script's disposition, preserved upstream/legacy exceptions, and
validation evidence. Its **Remaining operational work and exceptions** section
is the follow-up inventory for bootstrap argument handling and safety, disk
helpers, AutomatedLab guest-path staging, decoder provenance, profile/image/OpenSSH
helpers, and VM-only validation. Those repairs remain open; completion of the
help rewrite does not complete them or establish additional Windows support.

That walkthrough passed 102 isolated tests and excluded one live-registry test
for disposable-VM execution. These results supplement the batch-specific
evidence below; no new state-changing integration run occurred in the walkthrough.

## Batch rules

- Migrate active default selectors first, in the order shown, then commented selectors within each family. A single migration request may cover several consecutive batches or complete low-risk family groups; preserve each type/family boundary and review batch results before moving to a new handler type.
- Keep each batch within one operation type and family. Use **up to 10 new v3 operations** for the pilot batch. After an established handler and its mocked tests pass, allow up to **25 operations** in homogeneous, low-risk settings batches. Keep packages, Windows components, account/configuration changes, files/assets, system tasks, and any batch using a new handler at 10 or fewer until their behavior is proven. Keep related state pairs and multi-state settings together.
- Add stable catalog IDs, per-operation supported Windows targets, scope, privilege, actions, rollback behavior, and target defaults as each operation is migrated. Do not infer support from the legacy preset header.
- Mark existing v3 equivalents complete instead of re-adding them: `ShowKnownExtensions` → `windows.show-known-extensions`; `DisableAutoplay` → `windows.autoplay-policy`; `DisableAutorun` → `windows.autorun-policy`; `Install7Zip` → `package.7zip`; and the commented `InstallNotepadPlusPlus` → `package.notepadpp`.
- Keep detailed type metadata in the operation catalog and generate `docs/OPERATIONS.md` through its exporter. This plan is the migration inventory, not a second catalog.

## Migration inventory

### Unattended migration session, 2026-10-08

Git for Windows now passed installation, repeat installation, local repository
init/add/commit/HEAD verification and uninstall in the Windows 11 VM (run
`20cb460af8be447dafcfc62662f99d35`, 103 guest tests passed). Latest patch releases
with four-part installer filenames are supported. The Git publisher's exact
release-note SHA-256 is checked separately from GitHub's asset digest.

The accepted batch adds standalone Git LFS, Joplin, ShareX, WinDirStat and PowerShell
7. New MSI support handles quiet install/removal and the declared restart-needed
exit code without rebooting implicitly. User packages query HKCU instead of
mistaking a machine installation for current-user presence. Git LFS requires
Git; the ordered `solution.git-development` group expresses install/removal
order. Full Windows 11 request `9744844940fd4ca498ef6486092ac831` passed 128
guest tests and integration, including all five install/repeat/remove scenarios
and the installed PowerShell executable/version check. Both new user policies
passed apply/repeat/exact-restore/WindowsDefault checks. Collection and checkpoint
recovery succeeded; the VM is off at the pinned clean baseline and host UAC is
unchanged. Native host checks passed 127 isolated tests on PowerShell 5.1 and 7.
See [the session results](migrations/2026-10-08-unattended-results.md) for run IDs,
corrected failures, coverage limits and remaining work.

All **53 Install programs selectors** are individually reconciled in
[the disposition ledger](migrations/install-programs-dispositions.md), including
specific deferred work. Reconciliation does not mean every selector is
implemented. No portable tool tree, Defender exclusion, license acceptance or
replacement community Sysmon policy is applied implicitly.

The Windows Configuration family gains `windows.edge-friendly-url-format`
and `windows.start-run-as-different-user`, selected in `profiles/default.psd1`.
They cover `DisableFriendlyURLFormat`/`UnconfigureFriendlyURLFormat` and
`EnableRunAsInStartMenu`/`DisableRunAsInStartMenu`. The Start policy uses the
documented **HKCU user scope**, correcting the legacy HKLM write. Its Disabled
state is explicit zero; WindowsDefault removes the override. Both operations
capture exact prior values; VM tests cover repeat, baseline and restore.
Other selectors in that family remain pending.

The larger catalog exceeds PowerShell 5.1's whole-file safe-data complexity
limit. A bounded metadata reader evaluates each literal operation/group with
SafeGetValue, rejects executable entries and preserves schema 1. Execution,
validation, generation and read-only completion use that same reader.

Provisioning now accepts a local PSD1 and generates a per-VM controller seed;
the runbook explains every field and downstream inheritance. Server 2025 media
is unavailable, so its creation and runtime acceptance remain pending.
Concurrent multi-lab networking also requires a reviewed shared-NAT design:
the script now blocks creating a second host NAT instead of risking the
working Windows 11 network. Unique VM/controller names do not solve WinNAT's
one-network limitation.

Publisher/signature investigations and the evidence workflow are maintained in
[PACKAGE-VERIFICATION-MATRIX.md](PACKAGE-VERIFICATION-MATRIX.md). The shared
library contains observations, not an approval policy or automatic signer gate.

Each group lists exact legacy function names found in the preset. Test demand is required for every batch; complex Windows integration checks are deferred to the later VM phase.

**Batch 1 implemented:** Settings / Privacy configurations migrates `DisableInkingAndTypingData` to `windows.inking-typing-data` and adds it to the workstation default profile. Catalog validation and the Pester 5.7 unit suite pass; the Windows 11 disposable-VM check remains deferred. The reverse `EnableInkingAndTypingData` selector has no legacy implementation and remains unresolved below.

**Batch 2 implemented:** Settings / Defender configuration migrates the two active default selectors `ExcludeToolsDirDefender` and `ExcludeBootstrapDirDefender` to `windows.defender-tools-exclusion` and `windows.defender-bootstrap-exclusion`. Both are in the workstation default profile. Catalog validation and the Pester 5.7 mocked unit suite pass; disposable Windows 11 VM verification remains deferred.

**Low-risk family 1/5 complete:** Network Functions maps the scalar registry selectors `DisableAutoconfigURL` and `DisableMulticastDNS` to `windows.proxy-autoconfig-url` and `windows.llmnr-policy`, both selected in the workstation default profile. The legacy `DisableIEProxyAutoconfig` selector mutates a packed binary value and remains deferred. The `DisableMulticastDNS` name is misleading: the implementation changes the LLMNR policy value.

**Low-risk family 2/5 complete:** Privacy Tweaks maps eight scalar registry values from `DisableTailoredExperiences`, `DisableActivityHistory`, `DisableLocation`, `DisableAdvertisingID`, and `DisableWebLangList` to eight reversible operations in the default profile. Telemetry's task changes, service changes, app removal/cache mutation, feedback/error-reporting tasks, and legacy Wi-Fi Sense/Maps settings remain deferred for complexity or current-Windows applicability review.

**Low-risk family 3/5 complete:** Service Tweaks maps four scalar registry values from `DisableMaintenanceWakeUp`, `DisableSharedExperiences`, and `EnableNTFSLongPaths` to reversible operations. The existing Autoplay and Autorun selectors remain complete; COM-based update enrollment and the Windows Update debugger override are deferred.

**Low-risk family 4/5 complete:** UI Tweaks maps 19 scalar registry operations to the default workstation profile in three reviewable batches (9, 9, and 1 operation). This includes Action Center/toast behavior, accessibility prompts, taskbar controls, startup sound, and the Alt+Tab Edge-tab filter. The binary shortcut-name value, Task Manager process/polling behavior, packed visual-effects value, dynamic sound-scheme changes, and OS-branching or special-key settings remain deferred. Catalog/profile validation and mocked Pester checks pass (31 tests total); disposable-VM checks remain required before broadening declared Windows support.

**Low-risk family 5/5 complete:** Explorer UI Tweaks adds eight scalar registry operations in one batch for hidden files, navigation-pane expansion, sync notifications, recent/frequent shortcuts, Explorer start location, and thumbnail cache behavior. The already-migrated Show Known Extensions operation remains the existing equivalent. The initial scalar batch deferred the three This PC folder visibility selectors; those were later migrated under Family 12 using a reversible registry key-set handler.

**Family 11/30 active defaults migrated:** UI Tweaks maps the active scalar registry defaults into the workstation profile. The binary shortcut-name value, Task Manager process/polling behavior, packed visual-effects value, dynamic sound-scheme changes, and OS-branching or special-key settings remain deferred. Catalog/profile validation and mocked Pester checks pass; full disposable-VM coverage remains outstanding.

**Family 12/30 migrated and validated:** Explorer UI Tweaks includes eight reversible scalar registry settings plus `windows.music-folder-this-pc`, `windows.videos-folder-this-pc`, and `windows.3d-objects-folder-this-pc`. The new allowlisted `RegistryKeySet` handler captures recursive key values, registry types, and security descriptors before changing registration keys, so restore can reconstruct the prior tree. Windows may recalculate the DACL auto-inherited control flag when a key is recreated; validation confirms the restored owner, group, ACL entries, registry values, and value kinds. All active default selectors are represented in the default profile. Catalog validation, all 55 Pester tests, and Windows 11 disposable-VM round trips pass.

**Family 6/30 migrated:** Hardening Windows maps the active defaults `DisableSSDPdiscovery`, `DisableUniversalPlugAndPlay`, and `DisableWinHttpAutoProxySvc`. The first two use a reversible Windows service handler that captures and restores startup mode and running state; both are disabled and stopped by the default workstation profile. Enabled means Manual and Running for both services. The WPAD selector maps to the documented `DisableWpad` WinHTTP registry value; despite its legacy name, it does not disable the WinHTTP Auto-Proxy service. Catalog validation passes. Pester could not run in the restricted execution session because its framework's temporary registry keys are denied; mocked checks and disposable Windows 11 and Server 2025 VM checks remain outstanding.

**Family 7/30 migrated:** UWP Privacy Tweaks adds 19 reversible registry settings for the active background policy, app privacy policies, four file-system capabilities, and the UWP swap-file setting. `EnableUWPBackgroundApps` also maps to a separate user-scoped reset operation that captures and restores existing per-app `Disabled` and `DisabledByUser` values. The swap-file registry mapping is not documented by Microsoft; its operation links to the closest UWP lifecycle behavior reference and flags the mapping for review. Catalog validation passes. Pester could not run in the restricted execution session because its framework's temporary registry keys are denied; mocked checks and disposable Windows 11 VM checks remain outstanding.

**Family 8/30 active defaults migrated:** Security Tweaks adds the AutoShareServer and AutoShareWks settings, the current user's Windows Security account-protection warning, both 64-bit and 32-bit .NET strong-crypto values, and reversible BCDEdit operations for the F8 boot menu and DEP policy. The existing Windows Script Host operation covers `DisableScriptHost`. BCDEdit changes are recorded exactly and take effect after restart. AutoShareServer is supported on Windows Server 2025 and is not selected in the workstation profile; AutoShareWks is selected there. Catalog validation passes. Pester and disposable Windows VM checks remain outstanding; Pester is blocked in this session by denied temporary registry keys.

**Family 9/30 migrated:** Network Tweaks adds `windows.current-network-category`, which applies Private or Public to all reported non-domain profiles and captures the individual prior categories for exact restore. `windows.remote-assistance-policy` reversibly controls `fAllowToGetHelp`; Quick Assist removal remains a separate deferred operation because Windows 11 delivers it as a Store app and its lifecycle needs its own reliable reinstall behavior. Both defaults are selected in the workstation profile. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trips pass.

**Family 10/30 active defaults migrated with one deferral:** Service Tweaks adds `windows.microsoft-product-updates`, using the documented `AllowMUUpdateService` preference to opt in to Microsoft product updates; it is selected in the workstation default profile. `DisableUpdateRestart` remains deferred because the legacy implementation installs an experimental Image File Execution Options debugger for `MusNotification.exe`, and its exact effect and safe restoration need review before reproducing it. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trip passes.

**Family 14/30 active default migrated:** BitLocker adds `windows.bitlocker-encryption-method`, mapping the legacy AES-256 selector to the exact reversible `EncryptionMethod=4` policy value. The operation is Windows 11-only pending target-specific integration coverage and describes that it affects future encryption, not existing encrypted drives. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trip passes. Windows Server support remains undeclared.

**Family 15/30 reconciled, implementation incomplete:** The active Git default has passed install, repeat, local init/add/commit/HEAD and removal in Windows 11. 7-Zip, Notepad++, Sysmon and standalone Git LFS, Joplin, ShareX, WinDirStat and PowerShell 7 use the package lifecycle. The XML artifact remains download-only at an immutable commit; Sysmon installation uses its default configuration. All 53 selectors have an explicit disposition in [the ledger](migrations/install-programs-dispositions.md). Deferred selectors require the stated handler/source/licensing work before implementation; the current batch's acceptance is recorded in the session section above.

### Settings

#### Power Scheme Settings (power-scheme-settings)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetPowerSchemeBalanced`, `SetPowerSchemeHighPerf`, `SetPowerSchemeUltimate`, `SetPwrSchemeDesktopMenu`,
`RemovePwrSchemeDesktopMenu`, `SetLidCloseActionBattSleep`, `SetLidCloseActionBattDoNothing`,
`SetLidCloseActionPwrDoNothing`, `SetLidCloseActionPwrSleep`

#### Privacy configurations (privacy-configurations)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableInkingAndTypingData` **default**

#### Defender configuration (defender-configuration)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`ExcludeToolsDirDefender` **default**, `ExcludeBootstrapDirDefender` **default**, `RemoveToolsDirDefender`,
`RemoveBootstrapDirDefender`

#### Hardening Windows (hardening-windows)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableSSDPdiscovery` **default**, `DisableUniversalPlugAndPlay` **default**,
`DisableWinHttpAutoProxySvc` **default**, `EnableSSDPdiscovery`, `EnableUniversalPlugAndPlay`,
`EnableWinHttpAutoProxySvc`

#### Network Functions (network-functions)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableIEProxyAutoconfig` **default**, `DisableAutoconfigURL` **default**, `DisableMulticastDNS` **default**,
`EnableIEProxyAutoconfig`, `EnableAutoconfigURL`, `EnableMulticastDNS`, `GetNoTelemetryHostsFile`,
`SetDefaultHostsfile`

#### Privacy Tweaks (privacy-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableTelemetry` **default**, `DisableCortana` **default**, `DisableWiFiSense` **default**,
`DisableAppSuggestions` **default**, `DisableActivityHistory` **default**, `DisableLocation` **default**,
`DisableMapUpdates` **default**, `DisableFeedback` **default**, `DisableTailoredExperiences` **default**,
`DisableAdvertisingID` **default**, `DisableWebLangList` **default**, `DisableErrorReporting` **default**,
`DisableDiagTrack` **default**, `DisableWAPPush` **default**, `EnableTelemetry`, `EnableCortana`,
`EnableWiFiSense`, `DisableSmartScreen`, `EnableSmartScreen`, `DisableWebSearch`, `EnableWebSearch`,
`EnableAppSuggestions`, `EnableActivityHistory`, `DisableSensors`, `EnableSensors`, `EnableLocation`,
`EnableMapUpdates`, `EnableFeedback`, `EnableTailoredExperiences`, `EnableAdvertisingID`, `EnableWebLangList`,
`DisableBiometrics`, `EnableBiometrics`, `DisableCamera`, `EnableCamera`, `DisableMicrophone`,
`EnableMicrophone`, `EnableErrorReporting`, `SetP2PUpdateLocal`, `SetP2PUpdateInternet`, `SetP2PUpdateDisable`,
`EnableDiagTrack`, `EnableWAPPush`, `EnableClearRecentFiles`, `DisableClearRecentFiles`, `DisableRecentFiles`,
`EnableRecentFiles`

#### UWP Privacy Tweaks (uwp-privacy-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableUWPBackgroundApps` **default**, `EnableUWPBackgroundApps`, `DisableUWPVoiceActivation`,
`EnableUWPVoiceActivation`, `DisableUWPNotifications`, `EnableUWPNotifications`, `DisableUWPAccountInfo`,
`EnableUWPAccountInfo`, `DisableUWPContacts`, `EnableUWPContacts`, `DisableUWPCalendar`, `EnableUWPCalendar`,
`DisableUWPPhoneCalls`, `EnableUWPPhoneCalls`, `DisableUWPCallHistory`, `EnableUWPCallHistory`,
`DisableUWPEmail`, `EnableUWPEmail`, `DisableUWPTasks`, `EnableUWPTasks`, `DisableUWPMessaging`,
`EnableUWPMessaging`, `DisableUWPRadios`, `EnableUWPRadios`, `DisableUWPOtherDevices`, `EnableUWPOtherDevices`,
`DisableUWPDiagInfo`, `EnableUWPDiagInfo`, `DisableUWPFileSystem`, `EnableUWPFileSystem`, `DisableUWPSwapFile`,
`EnableUWPSwapFile`

#### Security Tweaks (security-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableAdminShares` **default**, `HideAccountProtectionWarn` **default**, `DisableScriptHost` **default**,
`EnableDotNetStrongCrypto` **default**, `EnableF8BootMenu` **default**, `SetDEPOptOut` **default**,
`SetUACLow`, `SetUACHigh`, `EnableSharingMappedDrives`, `DisableSharingMappedDrives`, `EnableAdminShares`,
`EnableBrowserServiceView`, `DisableFirewall`, `EnableFirewall`, `HideDefenderTrayIcon`,
`ShowDefenderTrayIcon`, `DisableDefender`, `EnableDefender`, `DisableDefenderCloud`, `EnableDefenderCloud`,
`EnableCtrldFolderAccess`, `DisableCtrldFolderAccess`, `EnableCIMemoryIntegrity`, `DisableCIMemoryIntegrity`,
`EnableDefenderAppGuard`, `DisableDefenderAppGuard`, `ShowAccountProtectionWarn`, `DisableDownloadBlocking`,
`EnableDownloadBlocking`, `EnableScriptHost`, `DisableDotNetStrongCrypto`, `EnableMeltdownCompatFlag`,
`DisableMeltdownCompatFlag`, `DisableF8BootMenu`, `DisableBootRecovery`, `EnableBootRecovery`,
`DisableRecoveryAndReset`, `EnableRecoveryAndReset`, `SetDEPOptIn`

#### Network Tweaks (network-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetCurrentNetworkPrivate` **default**, `DisableRemoteAssistance` **default**, `SetCurrentNetworkPublic`,
`SetUnknownNetworksPrivate`, `SetUnknownNetworksPublic`, `DisableNetDevicesAutoInst`,
`EnableNetDevicesAutoInst`, `DisableHomeGroups`, `EnableHomeGroups`, `DisableSMB1`, `EnableSMB1`,
`DisableSMBServer`, `EnableSMBServer`, `DisableNetBIOS`, `EnableNetBIOS`, `DisableLLMNR`, `EnableLLMNR`,
`DisableLLDP`, `EnableLLDP`, `DisableLLTD`, `EnableLLTD`, `DisableMSNetClient`, `EnableMSNetClient`,
`DisableQoS`, `EnableQoS`, `DisableIPv4`, `EnableIPv4`, `DisableIPv6`, `EnableIPv6`, `DisableNCSIProbe`,
`EnableNCSIProbe`, `DisableConnectionSharing`, `EnableConnectionSharing`, `EnableRemoteAssistance`,
`EnableRemoteDesktop`, `DisableRemoteDesktop`

#### Service Tweaks (service-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`EnableUpdateMSProducts` **default**, `DisableUpdateRestart` **default**,
`DisableMaintenanceWakeUp` **default**, `DisableSharedExperiences` **default**, `DisableAutoplay` **default**,
`DisableAutorun` **default**, `EnableNTFSLongPaths` **default**, `DisableUpdateMSRT`, `EnableUpdateMSRT`,
`DisableUpdateDriver`, `EnableUpdateDriver`, `DisableUpdateMSProducts`, `DisableUpdateAutoDownload`,
`EnableUpdateAutoDownload`, `EnableUpdateRestart`, `EnableMaintenanceWakeUp`, `DisableAutoRestartSignOn`,
`EnableAutoRestartSignOn`, `EnableSharedExperiences`, `EnableClipboardHistory`, `DisableClipboardHistory`,
`EnableAutoplay`, `EnableAutorun`, `DisableRestorePoints`, `EnableRestorePoints`, `EnableStorageSense`,
`DisableStorageSense`, `DisableDefragmentation`, `EnableDefragmentation`, `DisableSuperfetch`,
`EnableSuperfetch`, `DisableIndexing`, `EnableIndexing`, `DisableRecycleBin`, `EnableRecycleBin`,
`DisableNTFSLongPaths`, `DisableNTFSLastAccess`, `EnableNTFSLastAccess`, `SetBIOSTimeUTC`, `SetBIOSTimeLocal`,
`EnableHibernation`, `DisableHibernation`, `DisableSleepButton`, `EnableSleepButton`, `DisableSleepTimeout`,
`EnableSleepTimeout`, `DisableFastStartup`, `EnableFastStartup`, `DisableAutoRebootOnCrash`,
`EnableAutoRebootOnCrash`

#### UI Tweaks (ui-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableActionCenter` **default**, `DisableLockScreenBlur` **default**, `DisableAccessibilityKeys` **default**,
`ShowTaskManagerDetails` **default**, `ShowFileOperationsDetails` **default**, `HideTaskbarSearch` **default**,
`HideTaskView` **default**, `SetTaskbarCombineWhenFull` **default**, `HideTaskbarPeopleIcon` **default**,
`ShowTrayIcons` **default**, `DisableSearchAppInStore` **default**, `DisableNewAppPrompt` **default**,
`DisableShortcutInName` **default**, `SetVisualFXPerformance` **default**, `SetSoundSchemeNone` **default**,
`DisableStartupSound` **default**, `EnableVerboseStatus` **default**, `DisableF1HelpKey` **default**,
`DisableTaskbarWidgets` **default**, `DisableTaskbarChat` **default**, `RemoveEdgeTabsFromAltTab` **default**,
`EnableActionCenter`, `DisableLockScreen`, `EnableLockScreen`, `DisableLockScreenRS1`, `EnableLockScreenRS1`,
`HideNetworkFromLockScreen`, `ShowNetworkOnLockScreen`, `HideShutdownFromLockScreen`,
`ShowShutdownOnLockScreen`, `EnableLockScreenBlur`, `DisableAeroShake`, `EnableAeroShake`,
`EnableAccessibilityKeys`, `HideTaskManagerDetails`, `HideFileOperationsDetails`, `EnableFileDeleteConfirm`,
`DisableFileDeleteConfirm`, `ShowTaskbarSearchIcon`, `ShowTaskbarSearchBox`, `ShowTaskView`,
`ShowSmallTaskbarIcons`, `ShowLargeTaskbarIcons`, `SetTaskbarCombineNever`, `SetTaskbarCombineAlways`,
`ShowTaskbarPeopleIcon`, `HideTrayIcons`, `ShowSecondsInTaskbar`, `HideSecondsFromTaskbar`,
`EnableSearchAppInStore`, `EnableNewAppPrompt`, `HideRecentlyAddedApps`, `ShowRecentlyAddedApps`,
`HideMostUsedApps`, `ShowMostUsedApps`, `SetWinXMenuPowerShell`, `SetWinXMenuCmd`, `SetControlPanelSmallIcons`,
`SetControlPanelLargeIcons`, `SetControlPanelCategories`, `EnableShortcutInName`, `HideShortcutArrow`,
`ShowShortcutArrow`, `SetVisualFXAppearance`, `EnableTitleBarColor`, `DisableTitleBarColor`, `SetAppsDarkMode`,
`SetAppsLightMode`, `SetSystemDarkMode`, `SetSystemLightMode`, `AddENKeyboard`, `RemoveENKeyboard`,
`EnableNumlock`, `DisableNumlock`, `DisableEnhPointerPrecision`, `EnableEnhPointerPrecision`,
`SetSoundSchemeDefault`, `EnableStartupSound`, `DisableChangingSoundScheme`, `EnableChangingSoundScheme`,
`DisableVerboseStatus`, `EnableF1HelpKey`, `DisableTaskbarDesktops`, `EnableTaskbarDesktops`,
`EnableTaskbarWidgets`, `EnableTaskbarChat`, `SetTaskbarAlignmentLeft`, `SetTaskbarAlignmentMiddle`,
`SetEdgeTabsWindowsAnd5tabs`, `SetEdgeTabsWindowsAnd3tabs`, `SetEdgeTabsWindowsAndAll`

#### Explorer UI Tweaks (explorer-ui-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`ShowKnownExtensions` **default**, `ShowHiddenFiles` **default**, `EnableNavPaneExpand` **default**,
`HideSyncNotifications` **default**, `HideRecentShortcuts` **default**, `SetExplorerThisPC` **default**,
`HideMusicFromThisPC` **default**, `HideVideosFromThisPC` **default**, `Hide3DObjectsFromThisPC` **default**,
`DisableThumbnailCache` **default**, `DisableThumbsDBOnNetwork` **default**, `ShowExplorerTitleFullPath`,
`HideExplorerTitleFullPath`, `HideKnownExtensions`, `HideHiddenFiles`, `ShowSuperHiddenFiles`,
`HideSuperHiddenFiles`, `ShowEmptyDrives`, `HideEmptyDrives`, `ShowFolderMergeConflicts`,
`HideFolderMergeConflicts`, `DisableNavPaneExpand`, `ShowNavPaneAllFolders`, `HideNavPaneAllFolders`,
`ShowNavPaneLibraries`, `HideNavPaneLibraries`, `EnableFldrSeparateProcess`, `DisableFldrSeparateProcess`,
`EnableRestoreFldrWindows`, `DisableRestoreFldrWindows`, `ShowEncCompFilesColor`, `HideEncCompFilesColor`,
`DisableSharingWizard`, `EnableSharingWizard`, `HideSelectCheckboxes`, `ShowSelectCheckboxes`,
`ShowSyncNotifications`, `ShowRecentShortcuts`, `SetExplorerQuickAccess`, `HideQuickAccess`, `ShowQuickAccess`,
`HideRecycleBinFromDesktop`, `ShowRecycleBinOnDesktop`, `ShowThisPCOnDesktop`, `HideThisPCFromDesktop`,
`ShowUserFolderOnDesktop`, `HideUserFolderFromDesktop`, `ShowControlPanelOnDesktop`,
`HideControlPanelFromDesktop`, `ShowNetworkOnDesktop`, `HideNetworkFromDesktop`, `HideDesktopIcons`,
`ShowDesktopIcons`, `ShowBuildNumberOnDesktop`, `HideBuildNumberFromDesktop`, `HideDesktopFromThisPC`,
`ShowDesktopInThisPC`, `HideDesktopFromExplorer`, `ShowDesktopInExplorer`, `HideDocumentsFromThisPC`,
`ShowDocumentsInThisPC`, `HideDocumentsFromExplorer`, `ShowDocumentsInExplorer`, `HideDownloadsFromThisPC`,
`ShowDownloadsInThisPC`, `HideDownloadsFromExplorer`, `ShowDownloadsInExplorer`, `ShowMusicInThisPC`,
`HideMusicFromExplorer`, `ShowMusicInExplorer`, `HidePicturesFromThisPC`, `ShowPicturesInThisPC`,
`HidePicturesFromExplorer`, `ShowPicturesInExplorer`, `ShowVideosInThisPC`, `HideVideosFromExplorer`,
`ShowVideosInExplorer`, `Show3DObjectsInThisPC`, `Hide3DObjectsFromExplorer`, `Show3DObjectsInExplorer`,
`HideNetworkFromExplorer`, `ShowNetworkInExplorer`, `HideIncludeInLibraryMenu`, `ShowIncludeInLibraryMenu`,
`HideGiveAccessToMenu`, `ShowGiveAccessToMenu`, `HideShareMenu`, `ShowShareMenu`, `DisableThumbnails`,
`EnableThumbnails`, `EnableThumbnailCache`, `EnableThumbsDBOnNetwork`

#### Server Specific Tweaks (server-specific-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`HideServerManagerOnLogin`, `ShowServerManagerOnLogin`, `DisableShutdownTracker`, `EnableShutdownTracker`,
`DisablePasswordPolicy`, `EnablePasswordPolicy`, `DisableCtrlAltDelLogin`, `EnableCtrlAltDelLogin`,
`DisableIEEnhancedSecurity`, `EnableIEEnhancedSecurity`, `EnableAudio`, `DisableAudio`, `AudioMute`,
`AudioUnmute`

#### Bitlocker (bitlocker)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetDefaultBitLockerAES256` **default**, `SetDefaultBitLockerAES128`, `PutBitlockerShortCutOnDesktop`,
`EnableLockOutThreshold`, `DisableLockOutThreshold`, `EnableEnhancedPIN`, `DisableEnhancedPIN`,
`EnableAdditionalAuthAtStart`, `EnableBitlockerTPMandPIN`, `EnableBitlocker`, `DisableBitlocker`,
`AddBitlockerRecoveryPswd`, `DisplayBitlockerRecoveryPwd`


### Packages

#### Install programs (install-programs)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`Install7Zip` **default**, `InstallGit4Win` **default**, `GetSysmonSwiftXML` **default**,
`InstallSysmon64` **default**, `Remove7Zip`, `InstallGitLFS`, `RemoveGitLFS`, `RemoveGit4Win`,
`InstallPSScriptTools`, `RemovePSScriptTools`, `InstallVSCode`, `RemoveVSCode`, `InstallGPGwin`,
`InstallNotepadPlusPlus`, `RemoveNotepadPlusPlus`, `GetSysmonOlafXML`, `RemoveSysmon64`,
`InstallVMwareWorkstation`, `RemoveVMwareWorkstation`, `SetVMDirUserhome`, `SetVMDirDocuments`,
`InstallThunderbird`, `InstallJoplin`, `InstallImageMagick`, `InstallImageMagickPortable`,
`RemoveImageMagickPortable`, `InstallSignal`, `InstallPython`, `InstallYara`, `RemoveYara`, `GetCyberChef`,
`RemoveCyberChef`, `InstallCaffeine`, `RemoveCaffeine`, `InstallPutty`, `RemovePutty`, `InstallWinSCP`,
`InstallKAPE`, `RemoveKAPE`, `InstallVeraCrypt`, `InstallVeraCryptPortable`, `InstallADReplStatus`,
`RemoveADReplStatus`, `InstallFirewallNotifier`, `RemoveFirewallNotifier`, `InstallWinDirStat`,
`RemoveWinDirStat`, `InstallShareX`, `RemoveShareX`, `InstallShareXportable`, `RemoveShareXportable`,
`InstallPowerShell`, `InstallAutomatedLab`

#### Office Apps (office-apps)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`DisableOneDrive` **default**, `UninstallOneDrive` **default**, `InstallOffice365` **default**,
`DisableTeamsAutoStart` **default**, `RemoveTeamsStoreApp` **default**, `EnableOneDrive`, `InstallOneDrive`,
`ResetTeamsAutoStart`, `RemoveTeamsWideInstaller`, `InstallVisioPro`

#### System Tools (system-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`GetSysinternalsSuite`, `RemoveSysinternalsSuite`, `InstallJoeWare`, `RemoveJoeWare`, `InstallCCleaner`,
`RemoveCCleaner`, `InstallMitec`, `RemoveMitec`, `InstallNtcore`, `RemoveNTCore`, `InstallTMOG`, `RemoveTMOG`,
`InstallWireshark`, `RemoveWireshark`, `InstallZimmermanTools`, `RemoveZimmermanTools`,
`InstallNirsoftLauncher`, `RemoveNirsoftLauncher`, `InstallNirsoftToolsX64`, `RemoveNirsoftToolsX64`,
`InstallNirsoftPkgFiles`, `RemoveNirsoftPkgFiles`, `InstallArsenalRecon`, `InstallWinget`,
`InstallWingetAutoUpdate`

#### Active Directory Tools (active-directory-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallRSAT`, `RemoveRSAT`, `InstallOpenJDK`, `InstallNeo4j`, `GetBloodhound`, `RemoveBloodhound`,
`GetSharphound`, `RemoveSharphound`, `GetAzurehound`, `RemoveAzurehound`, `GetImproHound`, `RemoveImprohound`,
`GetPingCastle`, `RemovePingCastle`

#### For Linux VMs (for-linux-vms)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallVirtIOGuestTool`, `InstallSpiceGuestTool`, `InstallSpiceWebDAV`

#### Browsers and Internet (browsers-and-internet)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`DisableEdgePagePrediction` **default**, `InstallFirefox` **default**,
`CreateFirefoxPreferenceFiles` **default**, `InstallChrome` **default**,
`CreateChromePreferenceFile` **default**, `RemoveFirefox`, `RemoveFirefoxPreferenceFiles`, `RemoveChrome`,
`RemoveChromePreferenceFile`, `InstallOpera`

#### Forensic Tools (forensic-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallAutopsy`, `InstallNetworkMiner`, `RemoveNetworkMiner`, `InstallAutorunner`, `RemoveAutorunner`,
`InstallChainsaw`, `RemoveChainsaw`, `GetChromeParser`, `RemoveChromeParser`, `InstallCyLR`, `RemoveCyLR`,
`InstallDejsonlz4`, `RemoveDejsonlz4`, `GetHex2text`, `RemoveHex2text`, `InstallHindsight`, `RemoveHindsight`,
`InstallSqlitebrowser`, `GetShimCacheParser`, `RemoveShimCacheParser`, `GetPSTViewer`, `GetOSTViewer`,
`InstallLoki`, `RemoveLoki`, `InstallSSView`, `RemoveSSView`, `InstallSrumMonkey`, `RemoveSrumMonkey`,
`InstallSrumDump`, `RemoveSrumDump`, `InstallThumbcacheviewer`, `RemoveThumbcacheviewer`,
`InstallSuperFetchTools2`, `RemoveSuperFetchTools2`, `InstallUserAssist`, `RemoveUserAssist`,
`InstallThumbsviewer`, `RemoveThumbsviewer`, `InstallRegRipper`, `RemoveRegRipper`, `InstallWinhex`,
`RemoveWinhex`, `InstallWinPmem`, `RemoveWinPmem`, `InstallVolatility2`, `RemoveVolatility2`,
`InstallVolatility3`, `InstallPartDiagParser`, `RemovePartDiagParser`, `InstallGglCookieCruncher`,
`RemoveGglCookieCruncher`, `InstallSigma`, `RemoveSigma`

#### Offensive Tools (offensive-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallHashcat`, `RemoveHashcat`, `InstallHashcatLauncher`, `RemoveHashcatLauncher`


### Windows components

#### Windows Subsystem for Linux (windows-subsystem-for-linux)

**Test demand:** Required per batch: mocked Pester tests for feature/app state, apply/remove calls, ShouldProcess, and failures. Defer OS-image, reboot, and broad component integration to disposable VMs.

**Legacy selectors:**

`EnableWSL`, `DisableWSL`, `InstallWSLubuntu`, `RemoveWSLubuntu`, `InstallWSLdebian`, `RemoveWSLdebian`,
`InstallWSLkali`, `RemoveWSLkali`, `InstallWSLFedora`

#### Application Tweaks (application-tweaks)

**Test demand:** Required per batch: mocked Pester tests for feature/app state, apply/remove calls, ShouldProcess, and failures. Defer OS-image, reboot, and broad component integration to disposable VMs.

**Legacy selectors:**

`UninstallMsftBloat` **default**, `UninstallThirdPartyBloat` **default**, `DisableXboxFeatures` **default**,
`DisableAdobeFlash` **default**, `DisableEdgePreload` **default**, `DisableEdgeShortcutCreation` **default**,
`DisableIEFirstRun` **default**, `DisableFirstLogonAnimation` **default**, `DisableMediaSharing` **default**,
`UninstallInternetExplorer` **default**, `SetPhotoViewerAssociation` **default**,
`AddPhotoViewerOpenWith` **default**, `UninstallXPSPrinter` **default**, `RemoveFaxPrinter` **default**,
`InstallMsftBloat`, `InstallThirdPartyBloat`, `UninstallWindowsStore`, `InstallWindowsStore`,
`EnableXboxFeatures`, `DisableFullscreenOptims`, `EnableFullscreenOptims`, `EnableAdobeFlash`,
`EnableEdgePreload`, `EnableEdgeShortcutCreation`, `EnableIEFirstRun`, `EnableFirstLogonAnimation`,
`EnableMediaSharing`, `DisableMediaOnlineAccess`, `EnableMediaOnlineAccess`, `EnableDeveloperMode`,
`DisableDeveloperMode`, `UninstallMediaPlayer`, `InstallMediaPlayer`, `InstallInternetExplorer`,
`UninstallWorkFolders`, `InstallWorkFolders`, `UninstallHelloFace`, `InstallHelloFace`,
`UninstallMathRecognizer`, `InstallMathRecognizer`, `UninstallPowerShellV2`, `InstallPowerShellV2`,
`UninstallPowerShellISE`, `InstallPowerShellISE`, `InstallLinuxSubsystem`, `UninstallLinuxSubsystem`,
`InstallHyperV`, `UninstallHyperV`, `UninstallSSHClient`, `InstallSSHClient`, `InstallSSHServer`,
`UninstallSSHServer`, `InstallTelnetClient`, `UninstallTelnetClient`, `InstallNET23`, `UninstallNET23`,
`UnsetPhotoViewerAssociation`, `RemovePhotoViewerOpenWith`, `UninstallPDFPrinter`, `InstallPDFPrinter`,
`InstallXPSPrinter`, `AddFaxPrinter`, `UninstallFaxAndScan`, `InstallFaxAndScan`, `InstallSandbox`,
`RemoveSandbox`


### Accounts and configuration

#### Windows configuration (windows-configuration)

**Current disposition:** The two registry-policy defaults for Edge URL copying
and Start's Run as different user command are migrated. Account creation,
administrator membership, built-in-account changes, language packs and copying
regional settings require account/locale handlers and multi-user recovery
coverage. `AddUserBinToPath` requires exact per-user environment capture and
restore; it is not represented as an installer or a machine PATH change.
The remaining optional selectors need their own component, credential/network,
activation or security-policy workflows before migration.

**Test demand:** Required per batch: mocked Pester tests for user/locale/configuration discovery, apply, restore or compensating behavior, and failures. Defer multi-user, locale, and machine-wide scenarios to disposable VMs.

**Legacy selectors:**

`CreateNewLocalAdmin` **default**, `DisableBuiltinAdministrator` **default**,
`DisableFriendlyURLFormat` **default**, `EnableRunAsInStartMenu` **default**,
`InstallLanguagePackGB` **default**, `SetRegionalSettings` **default**, `CopyRegionSettingsToAll` **default**,
`AddUserBinToPath` **default**, `ActivateWindows`, `ActivateWindowsOEM`, `MakeLoggedOnUserAdmin`,
`MakeLoggedOnUserNoAdmin`, `AddWiFi`, `DisableWindowsStoreApp`, `EnableWindowsStoreApp`,
`UnconfigureFriendlyURLFormat`, `DisableRunAsInStartMenu`, `EnableInternetPrinting`, `DisableInternetPrinting`,
`EnableMemoryIntegrity`, `DisableMemoryIntegrity`, `InstallLanguagePackDK`, `InstallLanguagePackCustom`,
`CopyRegionSettingsWelcome`, `CopyRegionSettingsNewUser`


### Files and assets

#### Customization (customization)

**Test demand:** Required per batch: isolated Pester tests using temporary paths or mocked file/registry calls for content, idempotence, WhatIf, and restore. Defer real shell/profile integration to disposable VMs.

**Legacy selectors:**

`InstallFonts` **default**, `ReplaceDefaultWallpapers` **default**, `SetLockScreen`, `SetDefaultLockScreen`,
`InstallLenovoVantage`, `RemoveLenovoVantage`


### System tasks

#### Unpinning (unpinning)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`CleanPublicDesktop` **default**, `UnpinStartMenuTiles`, `UnpinTaskbarIcons`

#### Operational Tasks (operational-tasks)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`GetWindowsUpdatesWithPwsh`, `CleanLocalWindowsUpdateCache`, `RunDiskCleanup`, `GetWindowsProductKey`,
`RunSysprepGeneralizeOOBE`

#### Other Functions (other-functions)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`SetHostname` **default**

#### Auxiliary Functions (auxiliary-functions)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`WaitForKey` **default**, `Restart` **default**, `StopComputer`

## Preset references to reconcile

These selectors do not exactly match a function name in the legacy modules. Resolve or explicitly mark them unsupported before their family batch is migrated. Do not silently create catalog entries for misspelled or missing functions.

| Preset selector | Reconciliation |
| --- | --- |
| `DisableAdditionalAuthAtStart` | The library defines `DisableAdditionaAuthAtStart` (missing “l”); verify and correct the intended legacy behavior. |
| `DisableBrowserServiceView` | The library defines `DisableBrowserSvcView`; verify whether the shortened function is the intended implementation. |
| `EnableInkingAndTypingData` | No matching function is defined; preserve as unresolved until implementation or removal is decided. |
| `InstallNucleusKernelFATNFTS` | The library defines `InstallNucleusKernelFATNTFS`; reconcile the transposed letters. |
| `RemoveWinCSP` | The library defines `RemoveWinSCP`; reconcile the preset typo and keep the removal selector with the WinSCP package batch. |
| `RemoveWSLFedora` | No matching function is defined; the Fedora install selector has no matching removal implementation. |
| `RequireAdmin` | This is a preset prerequisite directive, not a function. Represent the privilege requirement in operation metadata and profile/run guidance rather than as an operation. |

## Library functions outside the preset inventory

The following 23 function names are defined in the legacy modules but are not selected by name in `default.preset`; keep them out of these batches and record them as a separate future-review backlog:

`DisableAdditionaAuthAtStart`, `DisableBrowserSvcView`, `DisableFirewallDomain`, `DisableFirewallPrivate`, `DisableFirewallPublic`, `DisableWSUS`, `EnableFirewallDomain`, `EnableFirewallPrivate`, `EnableFirewallPublic`, `EnableWSUS`, `Export-FunctionFromFile`, `Get-PackageInfo`, `Get-RideBootstrapFolder`, `Get-RideSoftwareFolder`, `Get-RIDEvars`, `Install-RideDownloadedExe`, `Install-RideDownloadedMsi`, `InstallEntraConnect`, `InstallNucleusKernelFATNTFS`, `RemoveWinSCP`, `Save-RideDownload`, `Test-FunctionName`, and `Test-RideDownloadOnly`.

Several items overlap with misspelled preset selectors listed above. Those functions remain outside the inventory until the selector mismatch is reconciled.

## Package download and artifact records

The current minimum is a working **download latest** path. Package operations must be able to resolve the current release, select the declared Windows artifact, download it without installing it, and report the version and file location. Installing the latest release uses the same resolver and acquisition path. A missing publisher checksum or signature must not prevent acquisition or ordinary package installation; report the available evidence and the locally observed hash accurately so users can make an informed choice. The first provider adapters are 7-Zip, Notepad++, and Git for Windows.

Each provider adapter returns structured release metadata: package ID, resolved version, architecture, filename, artifact URI, release/source URI, any provider-reported digest, and available checksum/signature sidecar URIs. Reject malformed URLs, ambiguous asset matches, and a provider digest mismatch. Do not discard a downloaded installer after a successful install; retain it in the configured artifact repository for reuse and record its observed SHA-256.

The shared, version-controlled `catalog/artifact-observations.json` is an append-only metadata library, not a binary repository or trust store. Each observation binds package ID, resolved version, filename, source URI, acquisition time, route/transport label, and observed SHA-256 to one exact file. It may also record a provider digest, signature/checksum evidence and result, Authenticode signer details, and file size. A hash computed only after download is an observation, not publisher authentication. Multiple observations for the same exact artifact are retained so later work can compare downloads made through independent internet paths. Do not claim independence solely because observations have different timestamps or users.

Maintain `docs/PACKAGE-VERIFICATION-MATRIX.md` from per-package source investigations. Record whether the official source resolves latest, provides exact versioned URLs, publishes checksums, offers detached signatures and a key identity, or supplies an Authenticode signature. Distinguish publisher-provided evidence from hosting-provider metadata and from hashes RIDE observes itself. The matrix informs a later policy decision; it does not block latest acquisition. The CLI `download` command acquires without installing; artifacts are retained by package and version, and observations are appended to `catalog/artifact-observations.json`.

Package presence remains separate from acquisition: downloading an installer does not make its operation `Present`. A later install-from-repository mode should install an already acquired artifact without network fallback. Download-only `Artifact` catalog entries are separate from packages and desired Windows state; the first is the user-selected SwiftOnSecurity Sysmon XML, resolved to an immutable Git commit URL and retained without applying it.

### Verification vocabulary and future policy decision

The earlier policy names `Bypass`, `Verified`, and `Strict` are provisional. `Verified` was intended to mean validation using provider/publisher evidence (for example a published checksum, detached signature, or Authenticode identity); a RIDE-computed SHA-256 alone is only an observed hash. Do not make `Verified` the default or require pinned exact versions until the package matrix shows which evidence is actually available. Keep download/install latest usable while collecting that evidence.

Any provider-reported digest that RIDE chooses to check must match the downloaded bytes; a mismatch is a hard failure. Record unavailable, invalid, or untrusted signature/checksum evidence without mislabeling the file. After the matrix is populated, decide which policies should gate installation, whether a trust exception is needed for checksum-only sources, and how machine-enforced minimums interact with user choices. Strict could later require exact version pinning, trusted publisher signatures, a signed repository manifest, and approved providers; those are decisions for the evidence review rather than prerequisites for this phase.

### Package-specific Defender exclusions

Before migrating additional packages that are known to trigger Microsoft Defender alerts, add package-level compatibility metadata and use it as the source for narrowly scoped directory exclusions. Dual-use forensic and security tools can exhibit behavior that overlaps with malicious activity; an observed alert is a reason to record and review the exception, not a blanket verdict that the package is safe.

- Record the package ID, affected exact version and artifact digest where known, Defender detection name or ID, affected file, observation date, evidence/source, rationale, and review status. Keep the record tied to the reviewed package artifact; require renewed review when the artifact changes.
- Install each package that needs an exception into an isolated, deterministic package directory under the configured `ToolsDirectory`. Metadata must identify the exclusion scope as that package directory. Do not derive a package exception by excluding the shared `ToolsDirectory` parent or a general Downloads directory.
- Generate exclusions only for packages selected for installation by the applicable analyst/tooling profile and whose metadata contains a reviewed exception. Show each package, exact resolved path, and recorded reason in the plan and run report; provide a readable grouped summary when several packages share a path.
- Preserve the existing repository-tools and bootstrap exclusions as separately documented compatibility decisions while this step is implemented. Do not silently remove or broaden them as a side effect of package metadata work. Review whether each remains needed against the repository functions and bootstrap workflow that prompted it.
- Capture pre-change exclusion state and restore only the state changed by the run. Deduplicate identical exact paths without broadening the resulting set.

**Verification required:** Add mocked Pester coverage proving that reviewed packages selected by the profile produce only their declared package-directory exclusions; unreviewed or unselected packages produce none; configured `ToolsDirectory` changes resolve correctly; duplicate paths are deduplicated without promoting them to a parent directory; `WhatIf` makes no change; existing exclusions are preserved; and restore removes only exclusions introduced by the run. In a disposable Windows 11 and Windows Server 2025 VM, inspect effective Defender exclusions and verify that a reviewed package's intended functions work while a neighboring, unexcluded directory remains scanned. Do not use live malware as a test fixture. The plan/report must make the longer exception list reviewable by package, path, version, evidence, and reason.

Expose the `download` command explicitly through the CLI and keep it separate from `RIDEVAR-Download-Only` and other legacy environment flags. Mock HTTP requests, digest comparison, and installer processes in Pester; verify that download-only never starts an installer and that installation uses the same acquisition path. Provider digests, when offered and checked, must match the downloaded bytes. Add installer failure, idempotence, and `WhatIf` cases. Future local-repository and signature-enforcement modes remain follow-up work informed by the source matrix.

7-Zip, Notepad++, and Git for Windows now resolve the latest GitHub release to a versioned asset. The release API endpoint remains mutable by design to satisfy the latest-download baseline; each resolved artifact URI and version are recorded in the observation library. Publisher signature verification and reproducible installation from the local artifact repository remain future work.

## Multiple package sources

Represent all approved acquisition/install providers for a package in its single package record or referenced manifest. For example, a package can describe both a direct GitHub release artifact and a WinGet source, with each provider's package identifier, exact version mapping, architecture, artifact metadata, and verification requirements. Provider adapters implement the mechanics; package-specific PSM1 files must not duplicate the package lifecycle or make implicit source choices.

Source selection should be deterministic and policy-driven: allow an explicit source choice and a configured preference among approved providers. Auto-selection may move to another provider only when it is approved for the same package/version and satisfies that provider's pinned artifact and trust metadata. A transport or availability failure may permit trying the next approved provider; a version mismatch, hash mismatch, invalid signature, or unexpected publisher must stop the operation and report the integrity failure. Do not silently retry an integrity failure through a different source.

When providers supply different installers or materially different package builds, model them as distinct artifacts with provider-specific metadata and verification, even when they install the same logical package. Record the selected provider and artifact digest in the download manifest and run report so an installation can be reproduced and audited. Tests should cover provider preference, explicit source selection, approved transport fallback, and fail-closed verification errors.

**Agreed storage choices:** customizable values live in data-only, schema-versioned local configuration, split by scope: machine configuration under `%ProgramData%\RIDE\configuration.psd1` and user configuration under `%LocalAppData%\RIDE\configuration.psd1`. `ToolsDirectory` is machine-scoped and defaults to the system-drive `Tools` directory; it is not a catalog default or process environment variable. Package profiles currently resolve latest; exact-version selection and repository-backed reproducibility are later options, not prerequisites for acquisition.

## Acceptance and later integration

- For every batch, run catalog/profile validation and Pester coverage for planning, handler behavior through mocks, idempotence, `WhatIf`, and applicable restore or compensating behavior before accepting the batch.
- Keep package tests offline and deterministic by mocking download resolution and installer processes.
- Before accepting package migrations that use Defender exceptions, complete the package-specific exclusion metadata step and its mocked and disposable-VM verification above; ensure plans and reports identify every package-scoped exception.
- Defer complex disposable-VM scenarios—including reboot/Sysprep, broad Windows component changes, multi-user or machine-wide configuration, destructive cleanup, and live installer recovery—to a later integration phase.
- Add or retain Windows support declarations only after the affected operations pass their applicable disposable-VM checks on Windows 11 and Windows Server 2025.
