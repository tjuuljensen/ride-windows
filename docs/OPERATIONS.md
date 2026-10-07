# RIDE operation catalog

Generated from `catalog/operations.psd1`. Edit catalog metadata, then run `tools/Export-RideCatalog.ps1`.

## Operations

| ID | Name | Category | Scope | Admin | Actions | Supported targets | Rollback | Description | Reference |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| package.7zip | 7-Zip | Software / Utilities | Machine | Yes | Get, Test, Install, Uninstall, Restore | Windows 11, Windows Server 2025 | Compensating | Install or remove the current 64-bit 7-Zip release. | [Product info](https://www.7-zip.org/) |
| package.notepadpp | Notepad++ | Software / Utilities | Machine | Yes | Get, Test, Install, Uninstall, Restore | Windows 11, Windows Server 2025 | Compensating | Install or remove the current 64-bit Notepad++ release. | [Product info](https://notepad-plus-plus.org/) |
| windows.autoplay-policy | Autoplay policy | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11, Windows Server 2025 | Exact | Set the current user's Autoplay preference. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg) |
| windows.explorer-start-location | File Explorer start location | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Open File Explorer to This PC instead of Home. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows) |
| windows.explorer-frequent-shortcuts | Frequent folder shortcuts in File Explorer | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Hide frequent folder shortcuts in File Explorer Home. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-backup-settings-catalog) |
| windows.hidden-files-visibility | Hidden files visibility | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Show hidden files in File Explorer. | [Microsoft docs](https://support.microsoft.com/en-us/windows/deployment/install-upgrade/find-lost-files-after-upgrading-windows) |
| windows.navigation-pane-auto-expand | Navigation pane auto-expand | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Expand the File Explorer navigation pane to the current folder. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows) |
| windows.network-thumbnail-database | Network folder thumbnail database | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Disable Thumbs.db creation on network folders. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer) |
| windows.explorer-recent-shortcuts | Recent file shortcuts in File Explorer | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Hide recent file shortcuts in File Explorer Home. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-backup-settings-catalog) |
| windows.show-known-extensions | Show known file extensions | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11, Windows Server 2025 | Exact | Show file extensions for registered file types in File Explorer. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/common-file-name-extensions-in-windows) |
| windows.sync-provider-notifications | Sync provider notifications | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Hide sync provider notifications in File Explorer. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows) |
| windows.thumbnail-cache-creation | Thumbnail cache creation | Windows settings / Explorer | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Disable creation of thumbnail cache files for the current user. | [Microsoft docs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f) |
| windows.proxy-autoconfig-url | Automatic proxy configuration URL | Windows settings / Network | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Clear the current user's automatic proxy configuration URL override. | [Microsoft docs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-proxy-server-settings) |
| windows.llmnr-policy | LLMNR multicast name resolution policy | Windows settings / Network | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable Link-Local Multicast Name Resolution through the Windows policy value set by the legacy DisableMulticastDNS selector. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient) |
| windows.activity-history-feed-policy | Activity history feed policy | Windows settings / Privacy | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable the activity feed through the machine policy value used by the legacy activity-history selector. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy) |
| windows.activity-history-publish-policy | Activity history publishing policy | Windows settings / Privacy | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable publishing user activities through machine policy. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy) |
| windows.activity-history-upload-policy | Activity history upload policy | Windows settings / Privacy | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable uploading user activities through machine policy. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy) |
| windows.advertising-id-policy | Advertising ID policy | Windows settings / Privacy | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable the advertising ID through machine policy. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy) |
| windows.inking-typing-data | Inking and typing data | Windows settings / Privacy | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Stop sending the current user's inking and typing data to Microsoft. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/privacy/windows-10-and-privacy-compliance) |
| windows.location-scripting-policy | Location scripting policy | Windows settings / Privacy | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable location scripting through machine policy. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors) |
| windows.location-service-policy | Location service policy | Windows settings / Privacy | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable location services through machine policy. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-sensors) |
| windows.tailored-experiences-policy | Tailored experiences policy | Windows settings / Privacy | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Disable tailored experiences based on diagnostic data for the current user. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience) |
| windows.website-language-list-policy | Website language-list access policy | Windows settings / Privacy | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Opt out of sharing the current user's language list with websites. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/privacy/windows-10-and-privacy-compliance) |
| windows.autorun-policy | Autorun policy | Windows settings / Security | Machine | Yes | Get, Test, Set, Restore | Windows 11, Windows Server 2025 | Exact | Set the machine policy for Autorun on removable and other drives. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg) |
| windows.defender-bootstrap-exclusion | Defender bootstrap directory exclusion | Windows settings / Security | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Create the current user's Downloads\bootstrap directory and add it to Microsoft Defender exclusions. | [Microsoft docs](https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus) |
| windows.defender-tools-exclusion | Defender tools directory exclusion | Windows settings / Security | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Add the configured tools directory to Microsoft Defender exclusions. | [Microsoft docs](https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus) |
| windows.script-host-policy | Windows Script Host policy | Windows settings / Security | Machine | Yes | Get, Test, Set, Restore | Windows 11, Windows Server 2025 | Exact | Set the Windows Script Host policy or restore its default value. | [Microsoft docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wscript) |
| windows.maintenance-wake-policy | Automatic maintenance wake policy | Windows settings / System | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable the Windows Update automatic-maintenance power-management policy value. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update) |
| windows.maintenance-wake-timer | Automatic maintenance wake timer | Windows settings / System | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable the Windows automatic-maintenance wake timer. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-maintenence) |
| windows.long-paths-policy | Long paths policy | Windows settings / System | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Set whether Win32 long-path support is enabled for applications that opt in. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation) |
| windows.shared-experiences-policy | Shared experiences policy | Windows settings / System | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Set whether the current user allows shared experiences across devices. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/privacy/windows-10-and-privacy-compliance) |
| windows.action-center-policy | Action Center notifications | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Disable Action Center and toast notifications for the current user. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-taskbar) |
| windows.file-operation-details | File operation details | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Show detailed progress information for File Explorer operations. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows) |
| windows.filter-keys-prompts | Filter Keys prompts | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Disable the Filter Keys accessibility prompt for the current user. | [Microsoft docs](https://support.microsoft.com/en-us/accessibility/windows/make-your-mouse-keyboard-and-other-input-devices-easier-to-use) |
| windows.lock-screen-blur | Lock screen background blur | Windows settings / User interface | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable the acrylic blur on the sign-in screen. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon) |
| windows.edge-tabs-alt-tab | Microsoft Edge tabs in Alt+Tab | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Exclude Microsoft Edge tabs from the Alt+Tab switcher. | [Microsoft docs](https://support.microsoft.com/en-us/windows/how-to-multitask-in-windows-b4fa0333-98f8-ef43-e25c-06d4fb1d6960) |
| windows.store-app-suggestion | Microsoft Store open-with suggestion | Windows settings / User interface | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable searching the Microsoft Store for an app to open an unknown file type. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-icm) |
| windows.new-app-alert | New app open-with alert | Windows settings / User interface | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Disable the prompt asking how to open a file when no default app is set. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer) |
| windows.tray-icon-promotion | Notification area icon promotion | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Show all notification area icons without automatic overflow promotion. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings) |
| windows.taskbar-combine-primary | Primary taskbar button combining | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Choose when taskbar buttons combine on the primary display. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows) |
| windows.taskbar-combine-secondary | Secondary taskbar button combining | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Choose when taskbar buttons combine on secondary displays. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows) |
| windows.sticky-keys-prompts | Sticky Keys prompts | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Disable the Sticky Keys accessibility prompt for the current user. | [Microsoft docs](https://support.microsoft.com/en-us/accessibility/windows/make-your-mouse-keyboard-and-other-input-devices-easier-to-use) |
| windows.task-view-button | Task View taskbar button | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Control visibility of the Task View taskbar button. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start) |
| windows.taskbar-chat | Taskbar Chat button | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Control visibility of the Chat button on the taskbar. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows) |
| windows.taskbar-people-icon | Taskbar People icon | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Control visibility of the legacy People taskbar icon. | [Microsoft docs](https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings) |
| windows.taskbar-search-visibility | Taskbar search visibility | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Hide taskbar search for the current user. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows) |
| windows.taskbar-widgets | Taskbar Widgets button | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Control visibility of the Widgets button on the taskbar. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/personalization/stay-up-to-date-with-widgets-in-windows) |
| windows.toast-notifications-policy | Toast notifications | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Disable toast notifications for the current user. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/notifications-and-do-not-disturb-in-windows) |
| windows.toggle-keys-prompts | Toggle Keys prompts | Windows settings / User interface | User | No | Get, Test, Set, Restore | Windows 11 | Exact | Disable the Toggle Keys accessibility prompt for the current user. | [Microsoft docs](https://support.microsoft.com/en-us/accessibility/windows/make-your-mouse-keyboard-and-other-input-devices-easier-to-use) |
| windows.startup-sound | Windows startup sound | Windows settings / User interface | Machine | Yes | Get, Test, Set, Restore | Windows 11 | Exact | Control playback of the Windows startup sound. | [Microsoft docs](https://support.microsoft.com/en-us/windows/experience/personalization/personalize-your-windows-experience-with-themes) |

## Target defaults

Literal defaults describe the registry data or managed presence expected on a clean target. Effective defaults describe the behavior Windows uses when those values are in effect.

| Operation | Target | Literal default | Effective default |
| --- | --- | --- | --- |
| package.7zip | Windows 11 | Absent | Not installed in the default Windows image |
| package.7zip | Windows Server 2025 | Absent | Not installed in the default Windows image |
| package.notepadpp | Windows 11 | Absent | Not installed in the default Windows image |
| package.notepadpp | Windows Server 2025 | Absent | Not installed in the default Windows image |
| windows.autoplay-policy | Windows 11 | <unset> | Enabled (AutoPlay is allowed by this preference) |
| windows.autoplay-policy | Windows Server 2025 | <unset> | Enabled (AutoPlay is allowed by this preference) |
| windows.explorer-start-location | Windows 11 | 2 | File Explorer opens to Home by default |
| windows.explorer-frequent-shortcuts | Windows 11 | <unset> | Frequent folder shortcuts follow the Windows Home default when no user override exists |
| windows.hidden-files-visibility | Windows 11 | 2 | Hidden files are not shown by default |
| windows.navigation-pane-auto-expand | Windows 11 | <unset> | Navigation pane does not auto-expand unless enabled by the user |
| windows.network-thumbnail-database | Windows 11 | <unset> | Thumbs.db creation on network folders is enabled unless explicitly disabled |
| windows.explorer-recent-shortcuts | Windows 11 | <unset> | Recent file shortcuts follow the Windows Home default when no user override exists |
| windows.show-known-extensions | Windows 11 | 1 | Disabled (known file extensions are hidden) |
| windows.show-known-extensions | Windows Server 2025 | 1 | Disabled (known file extensions are hidden) |
| windows.sync-provider-notifications | Windows 11 | <unset> | Sync provider notifications follow the Windows shell default when no override exists |
| windows.thumbnail-cache-creation | Windows 11 | <unset> | Thumbnail cache creation is enabled unless explicitly disabled |
| windows.proxy-autoconfig-url | Windows 11 | <unset> | No proxy auto-configuration URL override unless configured by the user or administrator |
| windows.llmnr-policy | Windows 11 | <unset> | Windows default applies when the LLMNR policy value is absent |
| windows.activity-history-feed-policy | Windows 11 | <unset> | Windows activity-history behavior applies when no machine policy override is present |
| windows.activity-history-publish-policy | Windows 11 | <unset> | Windows activity publishing behavior applies when no machine policy override is present |
| windows.activity-history-upload-policy | Windows 11 | <unset> | Windows activity-upload behavior applies when no machine policy override is present |
| windows.advertising-id-policy | Windows 11 | <unset> | Windows advertising-ID behavior applies when no machine policy override is present |
| windows.inking-typing-data | Windows 11 | <unset> | Windows input-personalization behavior applies when no per-user override is present |
| windows.location-scripting-policy | Windows 11 | <unset> | Windows location-scripting behavior applies when no machine policy override is present |
| windows.location-service-policy | Windows 11 | <unset> | Windows location behavior applies when no machine policy override is present |
| windows.tailored-experiences-policy | Windows 11 | <unset> | Windows tailored-experience behavior applies when no user policy override is present |
| windows.website-language-list-policy | Windows 11 | <unset> | The language list is available to websites unless the user opts out |
| windows.autorun-policy | Windows 11 | <unset> | Windows built-in AutoRun default mask: 0x91 (145) |
| windows.autorun-policy | Windows Server 2025 | <unset> | Windows built-in AutoRun default mask: 0x91 (145) |
| windows.defender-bootstrap-exclusion | Windows 11 | Absent | No bootstrap directory exclusion is declared by RIDE unless the profile requests it |
| windows.defender-tools-exclusion | Windows 11 | Absent | No tools directory exclusion is declared by RIDE unless the profile requests it |
| windows.script-host-policy | Windows 11 | <unset> | Enabled when this policy value is absent |
| windows.script-host-policy | Windows Server 2025 | <unset> | Enabled when this policy value is absent |
| windows.maintenance-wake-policy | Windows 11 | <unset> | Windows automatic-maintenance power behavior applies when no policy override is present |
| windows.maintenance-wake-timer | Windows 11 | <unset> | Windows automatic-maintenance wake behavior applies when no explicit value is present |
| windows.long-paths-policy | Windows 11 | <unset> | Applications use the traditional path-length limit unless Windows and the application enable long paths |
| windows.shared-experiences-policy | Windows 11 | <unset> | Windows shared-experiences behavior applies when no user override is present |
| windows.action-center-policy | Windows 11 | <unset> | Action Center notifications remain enabled when no policy value exists |
| windows.file-operation-details | Windows 11 | <unset> | Compact file operation details are used unless detailed mode is enabled |
| windows.filter-keys-prompts | Windows 11 | 126 | Windows accessibility default flags enable the Filter Keys prompt |
| windows.lock-screen-blur | Windows 11 | <unset> | Windows controls the sign-in background when this policy is absent |
| windows.edge-tabs-alt-tab | Windows 11 | 1 | Alt+Tab includes open windows and recent Edge tabs by default |
| windows.store-app-suggestion | Windows 11 | <unset> | Windows offers Store search when this policy is absent |
| windows.new-app-alert | Windows 11 | <unset> | Windows shows the open-with prompt when this policy is absent |
| windows.tray-icon-promotion | Windows 11 | <unset> | Windows manages notification area icon overflow when no policy value exists |
| windows.taskbar-combine-primary | Windows 11 | <unset> | Taskbar buttons combine using the Windows default when no override exists |
| windows.taskbar-combine-secondary | Windows 11 | <unset> | Secondary taskbar buttons combine using the Windows default when no override exists |
| windows.sticky-keys-prompts | Windows 11 | 510 | Windows accessibility default flags enable the Sticky Keys prompt |
| windows.task-view-button | Windows 11 | <unset> | Task View button follows the Windows shell default when no override exists |
| windows.taskbar-chat | Windows 11 | <unset> | Chat button follows the Windows shell default when no per-user value exists |
| windows.taskbar-people-icon | Windows 11 | <unset> | The People icon is not configured by RIDE when its value is absent |
| windows.taskbar-search-visibility | Windows 11 | 2 | Search box is shown when Windows uses the full taskbar search preference |
| windows.taskbar-widgets | Windows 11 | <unset> | Widgets button follows the Windows shell default when no per-user value exists |
| windows.toast-notifications-policy | Windows 11 | <unset> | Toast notifications use the Windows default when no user value exists |
| windows.toggle-keys-prompts | Windows 11 | 62 | Windows accessibility default flags enable the Toggle Keys prompt |
| windows.startup-sound | Windows 11 | <unset> | Startup sound behavior follows the Windows default when no explicit value exists |

## Groups

| ID | Name | Category | Members, in apply order | Actions | Rollback | Description |
| --- | --- | --- | --- | --- | --- | --- |
| solution.analyst-basics | Analyst basics | Software / Groups | package.7zip, package.notepadpp | Install, Uninstall | Compensating | A small utility bundle with 7-Zip and Notepad++. |

