# Legacy-to-v3 Migration Plan

## Purpose and inventory

This is the batch inventory for migrating the selectable commands in `legacy/v2/default.preset` to the v3 catalog and profiles. It includes active and commented selectors. The inventory below contains **732 distinct legacy function names** referenced by the preset across **30 family groups**. Active selectors are marked **default**. Paired legacy commands should become states of one v3 operation only when inspection confirms that they control the same setting or package.

The new catalog currently supports `RegistryValue` and `Package`. Migration of the other groups requires the minimum additional operation kinds and focused handlers for Windows components, account/configuration changes, files/assets, and system tasks. Each handler must participate in planning, `ShouldProcess`, state capture or declared compensating behavior, status/reporting, and partial-failure reporting.

## Batch rules

- Migrate active default selectors first, in the order shown, then commented selectors within each family. A single migration request may cover several consecutive batches or complete low-risk family groups; preserve each type/family boundary and review batch results before moving to a new handler type.
- Keep each batch within one operation type and family. Use **up to 10 new v3 operations** for the pilot batch. After an established handler and its mocked tests pass, allow up to **25 operations** in homogeneous, low-risk settings batches. Keep packages, Windows components, account/configuration changes, files/assets, system tasks, and any batch using a new handler at 10 or fewer until their behavior is proven. Keep related state pairs and multi-state settings together.
- Add stable catalog IDs, per-operation supported Windows targets, scope, privilege, actions, rollback behavior, and target defaults as each operation is migrated. Do not infer support from the legacy preset header.
- Mark existing v3 equivalents complete instead of re-adding them: `ShowKnownExtensions` → `windows.show-known-extensions`; `DisableAutoplay` → `windows.autoplay-policy`; `DisableAutorun` → `windows.autorun-policy`; `Install7Zip` → `package.7zip`; and the commented `InstallNotepadPlusPlus` → `package.notepadpp`.
- Keep detailed type metadata in the operation catalog and generate `docs/OPERATIONS.md` through its exporter. This plan is the migration inventory, not a second catalog.

## Migration inventory

Each group lists exact legacy function names found in the preset. Test demand is required for every batch; complex Windows integration checks are deferred to the later VM phase.

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

## Acceptance and later integration

- For every batch, run catalog/profile validation and Pester coverage for planning, handler behavior through mocks, idempotence, `WhatIf`, and applicable restore or compensating behavior before accepting the batch.
- Keep package tests offline and deterministic by mocking download resolution and installer processes.
- Defer complex disposable-VM scenarios—including reboot/Sysprep, broad Windows component changes, multi-user or machine-wide configuration, destructive cleanup, and live installer recovery—to a later integration phase.
- Add or retain Windows support declarations only after the affected operations pass their applicable disposable-VM checks on Windows 11 and Windows Server 2025.
