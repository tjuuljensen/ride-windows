# Legacy-to-v3 Migration Plan

## Purpose and inventory

This is the batch inventory for migrating the selectable commands in `legacy/v2/default.preset` to the v3 catalog and profiles. It includes active and commented selectors. The inventory below contains **732 distinct legacy function names** referenced by the preset across **30 family groups**. Active selectors are marked **default**. Paired legacy commands should become states of one v3 operation only when inspection confirms that they control the same setting or package.

The catalog currently supports `RegistryValue`, `Package`, and `DefenderExclusion`. Migration of the other groups requires the minimum additional operation kinds and focused handlers for Windows components, account/configuration changes, files/assets, and system tasks. Each handler must participate in planning, `ShouldProcess`, state capture or declared compensating behavior, status/reporting, and partial-failure reporting.

## Batch rules

- Migrate active default selectors first, in the order shown, then commented selectors within each family. A single migration request may cover several consecutive batches or complete low-risk family groups; preserve each type/family boundary and review batch results before moving to a new handler type.
- Keep each batch within one operation type and family. Use **up to 10 new v3 operations** for the pilot batch. After an established handler and its mocked tests pass, allow up to **25 operations** in homogeneous, low-risk settings batches. Keep packages, Windows components, account/configuration changes, files/assets, system tasks, and any batch using a new handler at 10 or fewer until their behavior is proven. Keep related state pairs and multi-state settings together.
- Add stable catalog IDs, per-operation supported Windows targets, scope, privilege, actions, rollback behavior, and target defaults as each operation is migrated. Do not infer support from the legacy preset header.
- Mark existing v3 equivalents complete instead of re-adding them: `ShowKnownExtensions` → `windows.show-known-extensions`; `DisableAutoplay` → `windows.autoplay-policy`; `DisableAutorun` → `windows.autorun-policy`; `Install7Zip` → `package.7zip`; and the commented `InstallNotepadPlusPlus` → `package.notepadpp`.
- Keep detailed type metadata in the operation catalog and generate `docs/OPERATIONS.md` through its exporter. This plan is the migration inventory, not a second catalog.

## Migration inventory

Each group lists exact legacy function names found in the preset. Test demand is required for every batch; complex Windows integration checks are deferred to the later VM phase.

**Batch 1 implemented:** Settings / Privacy configurations migrates `DisableInkingAndTypingData` to `windows.inking-typing-data` and adds it to the workstation default profile. Catalog validation and the Pester 5.7 unit suite pass; the Windows 11 disposable-VM check remains deferred. The reverse `EnableInkingAndTypingData` selector has no legacy implementation and remains unresolved below.

**Batch 2 implemented:** Settings / Defender configuration migrates the two active default selectors `ExcludeToolsDirDefender` and `ExcludeBootstrapDirDefender` to `windows.defender-tools-exclusion` and `windows.defender-bootstrap-exclusion`. Both are in the workstation default profile. Catalog validation and the Pester 5.7 mocked unit suite pass; disposable Windows 11 VM verification remains deferred.

**Low-risk family 1/5 complete:** Network Functions maps the scalar registry selectors `DisableAutoconfigURL` and `DisableMulticastDNS` to `windows.proxy-autoconfig-url` and `windows.llmnr-policy`, both selected in the workstation default profile. The legacy `DisableIEProxyAutoconfig` selector mutates a packed binary value and remains deferred. The `DisableMulticastDNS` name is misleading: the implementation changes the LLMNR policy value.

**Low-risk family 2/5 complete:** Privacy Tweaks maps eight scalar registry values from `DisableTailoredExperiences`, `DisableActivityHistory`, `DisableLocation`, `DisableAdvertisingID`, and `DisableWebLangList` to eight reversible operations in the default profile. Telemetry's task changes, service changes, app removal/cache mutation, feedback/error-reporting tasks, and legacy Wi-Fi Sense/Maps settings remain deferred for complexity or current-Windows applicability review.

**Low-risk family 3/5 complete:** Service Tweaks maps four scalar registry values from `DisableMaintenanceWakeUp`, `DisableSharedExperiences`, and `EnableNTFSLongPaths` to reversible operations. The existing Autoplay and Autorun selectors remain complete; COM-based update enrollment and the Windows Update debugger override are deferred.

**Low-risk family 4/5 complete:** UI Tweaks maps 19 scalar registry operations to the default workstation profile in three reviewable batches (9, 9, and 1 operation). This includes Action Center/toast behavior, accessibility prompts, taskbar controls, startup sound, and the Alt+Tab Edge-tab filter. The binary shortcut-name value, Task Manager process/polling behavior, packed visual-effects value, dynamic sound-scheme changes, and OS-branching or special-key settings remain deferred. Catalog/profile validation and mocked Pester checks pass (31 tests total); disposable-VM checks remain required before broadening declared Windows support.

**Low-risk family 5/5 complete:** Explorer UI Tweaks adds eight scalar registry operations in one batch for hidden files, navigation-pane expansion, sync notifications, recent/frequent shortcuts, Explorer start location, and thumbnail cache behavior. The already-migrated Show Known Extensions operation remains the existing equivalent. Hiding Music, Videos, or 3D Objects removes shell registration keys and is deferred for a focused reversible handler. Catalog/profile validation and mocked Pester checks pass (32 tests total); disposable-VM checks remain required before broadening declared Windows support.

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

## Package acquisition and installation modes

Before migrating package batches beyond the current 7-Zip and Notepad++ pilot, extend the package workflow to support three explicit modes:

1. **Download only:** acquire selected package artifacts into a user-chosen software repository without running installers or changing installed-state records.
2. **Download and install:** acquire a missing artifact, verify it, and run its installer. Reuse a verified cached artifact when available.
3. **Install from repository:** install only from a supplied local repository directory. This mode must work without network access and fail clearly when an artifact is missing or invalid; it must never fall back to downloading.

The package workflow must be forward-compatible with a general artifact record, rather than making a URL or one download event the artifact's identity. An artifact is identified by its content digest and records its filename, size, media type, platform/architecture where relevant, and any publisher-signature metadata. Package ID and exact version metadata reference that artifact. This keeps package installation separate from acquisition and leaves room for non-package artifacts such as Windows or Linux installation images.

The repository manifest should map stable package IDs to a collection of concurrently retained, approved version records. Each exact version record maps its provider-specific immutable artifacts to source metadata and SHA-256 hashes. Profile selections pin the exact install version, while other verified versions can remain available for repeatable installs and rollback. Do not use an unscoped list of acceptable hashes: every digest and signature identity must be bound to its exact package, version, architecture, and artifact. Do not resolve mutable `latest` URLs during apply. Package updates add or retire reviewed version records and their artifact/trust data together without replacing verification data for other retained versions.

Model each acquisition as a separate provenance observation associated with an artifact: source URI or image, acquisition time, transport/path label, and observed SHA-256. Allow multiple observations for the same artifact so a future known-good image workflow can acquire a file through two independent internet paths, compare the resulting digests, and retain both records. Recompute and compare the digest whenever an artifact is later imported, copied, or used. Matching independent downloads strengthen confidence in transfer integrity, while publisher signatures or independently trusted checksums remain the evidence for publisher authenticity.

Known-good image intake and approval remain a later workflow, outside the package install/uninstall lifecycle. The shared artifact model should support ISO/WIM and other large media without treating them as packages; a later image workflow can add its own source policy, signature/checksum validation, independent-download comparison, and approval state.

Verify package integrity before placing an artifact in the repository and again before execution. When an upstream publisher provides a detached GPG signature, verify it against a pinned full key fingerprint obtained from a trusted source. For Authenticode-signed Windows installers, validate the signature and expected publisher identity. Where a publisher provides only a checksum, compare it with a reviewed, pinned SHA-256 obtained through an authenticated and preferably independent channel. A hash calculated from the downloaded file alone records its bits but does not establish publisher authenticity. Retain signatures and checksum provenance with repository metadata where available; authenticate the repository manifest through the reviewed catalog/repository revision or an explicit signature.

Catalog/package metadata must declare the selected exact version and immutable artifact reference, expected SHA-256 when one is available, and whichever signature type and trusted identity apply (GPG fingerprint or Authenticode publisher). It must explicitly record when a source has no publisher signature or independently published checksum. The repository manifest may retain additional approved exact-version records for that package.

If a package offers no signature or independently published checksum, do not label it verified. Verified requires reviewed package metadata and a pinned checksum; a source with no trustworthy checksum is Bypass-only unless a stronger trust proof is added. Keep artifact acquisition separate from package presence: downloading a package does not make its operation `Present`.

### Package verification policy

Support named verification policies, including a deliberately loose `Bypass` option for users who choose convenience over publisher-authenticated verification:

- **Verified** is the default. Require an exact profile-pinned version and expected SHA-256. Validate publisher signatures when available; a checksum-only package needs reviewed package metadata and an explicit exception. Sources without a trustworthy checksum are not eligible.
- **Strict** requires the exact version, expected SHA-256, trusted publisher signature, signed repository manifest, and an approved provider. It does not allow checksum-only exceptions.
- **Bypass** permits installation when an expected hash or publisher signature is unavailable. Still compute and record the observed SHA-256, resolved source/provider, selected version, timestamp, and that verification was bypassed; show that status in the plan and run report. An artifact acquired under Bypass remains marked unverified in the repository.

Bypass does not discard contradictory evidence: a supplied hash mismatch, invalid signature, unexpected publisher, or selected-version mismatch remains a hard failure under every policy. Profiles continue to pin exact versions under Bypass. A machine-level policy may set a minimum verification level; user configuration or a command may choose the same or a stricter level, but cannot weaken an enforced machine policy. Without an enforced machine minimum, users may explicitly choose Bypass. An unverified artifact is not eligible for Strict installation without subsequent verification and approval.

Expose these modes explicitly through the CLI and keep them separate from `RIDEVAR-Download-Only` and other legacy environment flags. Mock HTTP requests, signature/hash verification, and installer processes in Pester; verify that download-only never starts an installer, normal installation reuses a verified artifact, and local-repository installation makes no network request. Reject unpinned versions, mutable artifact references, missing files, manifest mismatches, hash mismatches, invalid signatures, and unexpected signing identities before starting an installer. Add installer failure, idempotence, and `WhatIf` cases.

The current 7-Zip and Notepad++ pilot metadata does not yet meet this pinned-artifact contract: 7-Zip resolves a mutable upstream page at install time, and Notepad++ uses a `latest` URL. Replace those with reviewed, version-pinned artifact metadata and verification before treating the package workflow as production-ready.

## Multiple package sources

Represent all approved acquisition/install providers for a package in its single package record or referenced manifest. For example, a package can describe both a direct GitHub release artifact and a WinGet source, with each provider's package identifier, exact version mapping, architecture, artifact metadata, and verification requirements. Provider adapters implement the mechanics; package-specific PSM1 files must not duplicate the package lifecycle or make implicit source choices.

Source selection should be deterministic and policy-driven: allow an explicit source choice and a configured preference among approved providers. Auto-selection may move to another provider only when it is approved for the same package/version and satisfies that provider's pinned artifact and trust metadata. A transport or availability failure may permit trying the next approved provider; a version mismatch, hash mismatch, invalid signature, or unexpected publisher must stop the operation and report the integrity failure. Do not silently retry an integrity failure through a different source.

When providers supply different installers or materially different package builds, model them as distinct artifacts with provider-specific metadata and verification, even when they install the same logical package. Record the selected provider and artifact digest in the download manifest and run report so an installation can be reproduced and audited. Tests should cover provider preference, explicit source selection, approved transport fallback, and fail-closed verification errors.

**Agreed storage choices:** customizable values live in data-only, schema-versioned local configuration, split by scope: machine configuration under `%ProgramData%\RIDE\configuration.psd1` and user configuration under `%LocalAppData%\RIDE\configuration.psd1`. `ToolsDirectory` is machine-scoped and defaults to the system-drive `Tools` directory; it is not a catalog default or process environment variable. Package profiles pin exact versions, while the repository retains multiple approved versions and their verified artifacts.

## Acceptance and later integration

- For every batch, run catalog/profile validation and Pester coverage for planning, handler behavior through mocks, idempotence, `WhatIf`, and applicable restore or compensating behavior before accepting the batch.
- Keep package tests offline and deterministic by mocking download resolution and installer processes.
- Defer complex disposable-VM scenarios—including reboot/Sysprep, broad Windows component changes, multi-user or machine-wide configuration, destructive cleanup, and live installer recovery—to a later integration phase.
- Add or retain Windows support declarations only after the affected operations pass their applicable disposable-VM checks on Windows 11 and Windows Server 2025.
